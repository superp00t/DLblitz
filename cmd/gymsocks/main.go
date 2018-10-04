package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/superp00t/DLblitz/bnet"
	"github.com/superp00t/DLblitz/s5"
	"golang.org/x/crypto/nacl/box"

	"github.com/superp00t/etc"

	pt "github.com/andanhm/go-prettytime"
	_ "github.com/go-sql-driver/mysql"
	"github.com/go-xorm/xorm"
	"github.com/gorilla/mux"
	"github.com/superp00t/etc/yo"
)

var DB *xorm.Engine
var Bucket = new(sync.Map)

const (
	BlockList   = "http://john.bitsurge.net/public/biglist.p2p.gz"
	SocksList   = "https://img.ikrypto.club/socks.txt"
	GeoliteCity = "https://geolite.maxmind.com/download/geoip/database/GeoLiteCity_CSV/GeoLiteCity-latest.zip"
)

type SocksServer struct {
	Id          int64     `json:"id"`
	Address     string    `json:"addr"`
	Online      bool      `json:"online"`
	Ping        int64     `json:"ping"`
	LastUpdated time.Time `json:"lastUpdated"`
}

type SocksTpl struct {
	Address     string
	Online      bool
	Regime      template.HTML
	Ping        string
	LastUpdated string
}

type ScanningState struct {
	Id      int64
	Address string
	Started time.Time
}

type BlockedRange struct {
	RangeName string
	Min       uint32
	Max       uint32
}

type GeoipLocation struct {
	LocID      uint32  `json:"locId" xorm:"not null autoincr pk 'locId'"`
	Country    string  `json:"country" xorm:"varchar(2) 'country'"`
	Region     string  `json:"region" xorm:"varchar(2) 'region'"`
	City       string  `json:"city" xorm:"varchar(1000) 'city'"`
	PostalCode string  `json:"postalCode" xorm:"varchar(10) 'postalCode'"`
	Lat        float32 `json:"lat" xorm:"latitude"`
	Long       float32 `json:"long" xorm:"longitude"`
	MetroCode  uint32  `json:"metroCode" xorm:"metroCode"`
	AreaCode   uint32  `json:"areaCode" xorm:"areaCode"`
}

type GeoipBlocks struct {
	Min   uint32 `xorm:"min"`
	Max   uint32 `xorm:"max"`
	LocID uint32 `xorm:"pk 'locId'"`
}

type BlockResult struct {
	Class string         `json:"class"`
	Geo   *GeoipLocation `json:"geo"`
}

func checkHTTPSStatus(socks5server string) (int64, bool) {
	confirmationToken := etc.GenerateRandomUUID().String()
	conf := make(chan bool)
	cancel := make(chan struct{})

	Bucket.Store(confirmationToken, conf)

	start := time.Now()

	go func() {
		hc, err := bnet.AcquireHTTPClient(socks5server)
		if err != nil {
			cancel <- struct{}{}
			return
		}

		st, _, err := bnet.HReq(false, hc, "GET", yo.StringG("c")+"/cb/"+confirmationToken, nil)
		if err != nil || st != 200 {
			cancel <- struct{}{}
			return
		}
	}()

	select {
	case <-conf:
		ms := time.Since(start)
		close(conf)
		Bucket.Delete(confirmationToken)
		i := int64(ms / time.Millisecond)
		return i, true
	case <-cancel:
		close(conf)
		Bucket.Delete(confirmationToken)
		return 0, false
	case <-time.After(20 * time.Second):
		close(conf)
		Bucket.Delete(confirmationToken)
		return 0, false
	}
}

func udpNet() string {
	frontend := yo.StringG("c")

	u, err := url.Parse(frontend)
	if err != nil {
		yo.Fatal(err)
	}

	return fmt.Sprintf("%s:%d", u.Hostname(), yo.Int64G("u"))
}

func httpNet() string {
	frontend := yo.StringG("c")
	u, err := url.Parse(frontend)
	if err != nil {
		yo.Fatal(err)
	}

	return fmt.Sprintf("http://%s:%d/check", u.Hostname(), yo.Int64G("t"))
}

func checkUDPAbility(socks5server string) (int64, bool) {
	confirmationToken := etc.GenerateRandomUUID()

	rs := make(chan bool)
	cancel := make(chan struct{})

	yo.Println("Storing UDP token", confirmationToken)
	Bucket.Store(confirmationToken.String(), rs)
	start := time.Now()

	go func() {
		prox, err := s5.NewDialer(socks5server, "", "")
		if err != nil {
			cancel <- struct{}{}
			return
		}

		spk, ssk, err := box.GenerateKey(rand.Reader)
		if err != nil {
			yo.Fatal(err)
		}

		msg := etc.NewBuffer()
		rnd := etc.NewBuffer()
		rnd.WriteRandom(100)

		msg.WriteUUID(confirmationToken)
		msg.WriteLimitedBytes(rnd.Bytes())

		nc := new([24]byte)
		io.ReadFull(rand.Reader, nc[:])

		bxx := box.Seal(nil, msg.Bytes(), nc, pk, ssk)

		env := etc.NewBuffer()
		env.Write(spk[:])
		env.Write(nc[:])
		env.Write(bxx[:])

		start = time.Now()

		conn, err := prox.ListenUDP()
		if err != nil {
			yo.Println("UDP failed on", socks5server, err)
			cancel <- struct{}{}
			return
		}

		adr, err := s5.ResolveUDPEndpoint(udpNet())
		if err != nil {
			yo.Warn("Failure to lookup", udpNet(), err)
			cancel <- struct{}{}
			conn.Close()
			return
		}

		for x := 0; x < 10; x++ {
			_, err := conn.WriteTo(env.Bytes(), adr)
			if err != nil {
				yo.Warn(err)
				cancel <- struct{}{}
				conn.Close()
				return
			}
			yo.Println("transmitting packet with", env.Size(), "bytes")
			time.Sleep(400 * time.Millisecond)
		}
	}()

	select {
	case <-rs:
		close(rs)
		Bucket.Delete(confirmationToken.String())
		return int64(time.Since(start) / time.Millisecond), true
	case <-cancel:
		return 0, false
	case <-time.After(20 * time.Second):
		yo.Println("UDP check timed out.")
		return 0, false
	}
}

type SocksHeader struct {
	Address string
	Header  string
	Value   string
}

type HTTPScan struct {
	Address string
	Ch      chan []SocksHeader
}

// Detect injection/tampering of HTTP headers by SOCKS5 server.
func checkHTTPInterference(socks5server string) (int64, []SocksHeader, bool) {
	confirmationToken := etc.GenerateRandomUUID().String()
	conf := new(HTTPScan)
	conf.Address = socks5server
	conf.Ch = make(chan []SocksHeader)

	cancel := make(chan struct{})

	Bucket.Store(confirmationToken, conf)

	start := time.Now()

	go func() {
		hc, err := bnet.AcquireHTTPClient(socks5server)
		if err != nil {
			cancel <- struct{}{}
			return
		}

		uri := httpNet()

		rq, err := http.NewRequest("GET", uri, nil)
		if err != nil {
			yo.Fatal(err)
		}

		rq.Header.Set("X-Gymsocks-Token", confirmationToken)

		rsp, err := hc.Do(rq)
		if err != nil || rsp.StatusCode != 200 {
			cancel <- struct{}{}
			return
		}
	}()

	select {
	case sh := <-conf.Ch:
		ms := time.Since(start)
		close(conf.Ch)
		Bucket.Delete(confirmationToken)
		i := int64(ms / time.Millisecond)
		return i, sh, true
	case <-cancel:
		close(conf.Ch)
		Bucket.Delete(confirmationToken)
		return 0, nil, false
	case <-time.After(20 * time.Second):
		close(conf.Ch)
		Bucket.Delete(confirmationToken)
		return 0, nil, false
	}
}

func initDB() {
	var err error
	DB, err = xorm.NewEngine("mysql", yo.StringG("d"))
	if err != nil {
		yo.Fatal(err)
	}

	err = DB.Sync2(
		new(BlockedRange),
		new(GeoipBlocks),
		new(GeoipLocation),
		new(SocksServer),
	)

	if err != nil {
		yo.Fatal(err)
	}
}

func jenc(rw http.ResponseWriter, r *http.Request, ss interface{}) {
	en := json.NewEncoder(rw)
	if r.URL.Query().Get("p") == "1" {
		en.SetIndent("", "  ")
	}
	en.Encode(ss)
}

func scannerWorker(ch chan SocksServer) {
	for {
		v := <-ch
		// Check that TLS has not been interfered with.
		ping, online := checkHTTPSStatus(v.Address)

		// Check whether this server supports UDP.
		uping, uonline := checkUDPAbility(v.Address)
		yo.Warn(v.Address, "status results", online, uonline)

		if !uonline || !online {
			v.Online = false
			v.LastUpdated = time.Now()
			v.Ping = -1
			_, err := DB.Id(v.Id).Cols("online", "last_updated", "ping").Update(v)
			if err != nil {
				yo.Println(err)
			}
			continue
		}

		ct := int64(2)
		pingSum := ping + uping

		// Determine whether this server is tampering with plaintext HTTP connections.
		pping, headers, ponline := checkHTTPInterference(v.Address)
		if ponline {
			ct++
			pingSum += pping
			DB.Where("address = ?", v.Address).Delete(new(SocksHeader))
			for _, n := range headers {
				DB.Insert(n)
			}
		}

		avgPing := pingSum / ct

		v.Online = true
		v.LastUpdated = time.Now()
		v.Ping = avgPing

		_, err := DB.Id(v.Id).Cols("online", "last_updated", "ping").Update(v)
		if err != nil {
			yo.Println(err)
		}
	}
}

func scan() {
	c := make(chan SocksServer)

	// Spawn worker goroutines
	for x := 0; x < 8; x++ {
		go scannerWorker(c)
	}

	// Continously query and delegate scanning work to workers
	for {
		var ss []SocksServer
		DB.Find(&ss)
		for _, v := range ss {
			c <- v
		}
		time.Sleep(1 * time.Minute)
	}
}

func getCountry(address string) string {
	str := strings.Split(address, ":")
	if len(str) != 2 {
		yo.Println("invalid address length", address, len(str))
		return "US"
	}
	ip := bnet.ParseIPv4(str[0]).Uint32()
	var s []GeoipBlocks
	err := DB.Where("? <= max", ip).Where("? >= min", ip).Find(&s)
	if err != nil {
		yo.Fatal(err)
	}
	if len(s) == 0 {
		yo.Println("Could not find country of ", address)
		return "US"
	}

	var y []GeoipLocation
	DB.Where("locId = ?", s[0].LocID).Find(&y)

	return y[0].Country
}

var sk, pk *[32]byte

func main() {
	var err error
	pk, sk, err = box.GenerateKey(rand.Reader)
	if err != nil {
		yo.Fatal(err)
	}

	yo.Stringf("d", "database", "SQL database to store ips", "")
	yo.Stringf("c", "callbackURL", "the public URL of this server", "https://gymsocks.pg.ikrypto.club/")
	yo.Int64f("u", "udp", "the IP port of the UDP verification service.", 40300)
	yo.Int64f("t", "tcp", "the IP port of the plaintext HTTP verification service.", 40301)

	yo.AddSubroutine("update-geoip", nil, "update MaxMind GeoIP database", func(args []string) {
		initDB()

		updateMaxmindDBs()
	})

	yo.AddSubroutine("install-databases", nil, "remove all current data and upload blocklists, proxy lists and other data", func(args []string) {
		initDB()

		updateSocksList()
		updateMaxmindDBs()
		updateBlockedRanges()
	})

	yo.AddSubroutine("update-blocked-ranges", nil, "update blocked IP spaces from blocklist server", func(args []string) {
		initDB()
		updateBlockedRanges()
	})

	yo.AddSubroutine("update-socks-list", nil, "update SOCKS5 IP list", func(args []string) {
		initDB()
		updateSocksList()
	})

	yo.AddSubroutine("serve", []string{"address"}, "serve socks address info over HTTP", func(args []string) {
		initDB()

		go scan()

		r := mux.NewRouter()
		r.HandleFunc("/servers", func(rw http.ResponseWriter, r *http.Request) {
			var ss []SocksServer
			DB.Find(&ss)
			jenc(rw, r, ss)
		})

		r.HandleFunc("/online", func(rw http.ResponseWriter, r *http.Request) {
			var ss []SocksServer
			DB.Where("online = true").Find(&ss)
			for _, v := range ss {
				fmt.Fprintf(rw, "%s\n", v.Address)
			}
		})

		r.HandleFunc("/meta/{address}", func(rw http.ResponseWriter, r *http.Request) {
			dip := bnet.ParseIPv4(mux.Vars(r)["address"])
			var brs []BlockedRange
			err := DB.Where("? >= min", dip).Where("? <= max", dip).Find(&brs)
			if err != nil {
				yo.Fatal(err)
			}

			bd := new(BlockResult)
			if len(brs) == 0 {
				bd.Class = "ok"
			} else {
				bd.Class = brs[0].RangeName
			}

			var geo []GeoipBlocks
			err = DB.Where("? >= min", dip).Where("? <= max", dip).Find(&geo)
			if err != nil {
				yo.Fatal(err)
			}

			if len(geo) > 0 {
				gn := new(GeoipLocation)
				var gns []GeoipLocation
				DB.Where("locId = ?", geo[0].LocID).Find(&gns)
				*gn = gns[0]
				bd.Geo = gn
			}

			jenc(rw, r, bd)
		})

		r.HandleFunc("/cb/{token}", func(rw http.ResponseWriter, r *http.Request) {
			uuid := mux.Vars(r)["token"]

			ch, ok := Bucket.Load(uuid)
			if !ok {
				return
			}

			go func() {
				yo.Println("Got callback from proxy for ", uuid)
				c := ch.(chan bool)
				c <- true
			}()
		})

		r.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
			var sn []SocksServer
			DB.Desc("online").Find(&sn)
			ss := make([]SocksTpl, len(sn))

			for i, v := range sn {
				png := "-"
				if v.Ping >= 0 {
					png = fmt.Sprintf("%dms", v.Ping)
				}

				cn := getCountry(v.Address)

				for _, rg := range []string{"US", "AU", "UM", "VI", "NZ", "GB", "CA"} {
					if cn == rg {
						cn = fmt.Sprintf(`<img src="//img.ikrypto.club/skull.png" alt="%s"/>`, cn)
						break
					}
				}

				ss[i] = SocksTpl{
					v.Address,
					v.Online,
					template.HTML(cn),
					png,
					pt.Format(v.LastUpdated),
				}
			}

			t, err := template.New("").Parse(tpl)
			if err != nil {
				yo.Fatal(err)
			}

			if err := t.Execute(rw, ss); err != nil {
				yo.Warn(err)
			}
		})

		go func() {
			mrout := mux.NewRouter()
			mrout.HandleFunc("/check", func(rw http.ResponseWriter, r *http.Request) {
				g, err := etc.ParseUUID(r.Header.Get("X-Gymsocks-Token"))
				if err != nil {
					return
				}

				rs, ok := Bucket.Load(g)
				if !ok {
					return
				}

				hi, ok := rs.(*HTTPScan)
				if ok {
					var s []SocksHeader
					for k := range r.Header {
						if r.Header.Get(k) != "X-Gymsocks-Token" {
							s = append(s, SocksHeader{
								hi.Address,
								k,
								r.Header.Get(k),
							})
						}
					}
					go func() {
						hi.Ch <- s
					}()
				}
			})

			yo.Fatal(http.ListenAndServe(fmt.Sprintf("0.0.0.0:%d", yo.Int64G("t")), mrout))
		}()

		go func() {
			udp := yo.Int64G("u")

			pn, err := net.ListenPacket("udp", fmt.Sprintf("0.0.0.0:%d", udp))
			if err != nil {
				yo.Fatal(err)
			}

			for {
				buf := make([]byte, 512)
				i, addr, err := pn.ReadFrom(buf)
				if err != nil {
					return
				}

				yo.Println("UDP Check Server: read", i, "bytes from", addr)

				go func(b []byte, n net.Addr) {
					if len(b) < 100 {
						yo.Println("UCS: too small")
						return
					}

					peerk := new([32]byte)
					copy(peerk[:], b[:32])

					nc := new([24]byte)

					copy(nc[:], b[32:32+24])
					msg, ok := box.Open(nil, buf[32+24:i], nc, peerk, sk)
					if !ok {
						yo.Println("UCS: Packet encryption malformed")
						return
					}

					e := etc.FromBytes(msg)
					token := e.ReadUUID()

					ifa, ok := Bucket.Load(token.String())
					if !ok {
						yo.Println("UCS: could not load token", token)
						return
					}

					i, ok := ifa.(chan bool)
					if ok {
						i <- true
					} else {
						yo.Println("UCS: failure to convert to chan bool")
					}
				}(buf[:i], addr)

			}
		}()

		yo.Fatal(http.ListenAndServe(args[0], r))
	})

	yo.Init()
}

const tpl = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Socks5 IP Checker</title><style>.skull{background-image: url("//img.ikrypto.club/skull.png");}.wrn{color: #ef1325;}.okc{color: #008e04;}.tblview{max-width: 500px; display: block; margin: auto;}.mon{font-family: "monospace";}</style><link rel="stylesheet" href="//img.ikrypto.club/bootstrap.css"/></head><body>
<div class="tblview">
<h3>Gymsocks</h3>
<img style="width: 128px; height: 128px;" src="//img.ikrypto.club/gymsocks.png"/>
<h5><i>Tracking stinky Socks5 servers</i></h5>
<p class="wrn">Warning: some of these proxies may be run by malicious entities, including governments, lawyers, and private hackers. Do not use these for any purpose other than research and experimentation. For free anonymous browsing, I recommend <a href="https://torproject.org">The Tor Project.</a></p>
<p>A server is considered "online" if it completes both a TLS and a UDP connectivity check, ensuring that it is useful for both secure browsing and P2P applications including WebRTC voice chat in your web browser.</p>
<p>If a server's country entry is marked <span class="skull"></span>, it is located in a country that is a part of the <a href="https://en.wikipedia.org/wiki/UKUSA_Agreement">Five Eyes surveillance regime.</a></p>
<p><a href="online">Bulk export list of newline separated online Socks5 servers</a></p>
<p><a href="servers">Bulk export list of all Socks5 servers in JSON formatted metadata, online or not</a></p>
<table class="table">
  <thead>
    <tr>
      <th scope="col">IP Address</th>
      <th scope="col">Online</th>
      <th scope="col">Country</th>
      <th scope="col">Ping</th>
      <th scope="col">Last Checked</th>
    </tr>
	</thead>
	<tbody>
{{range .}}
<tr>
<td><p class="mon">{{.Address}}</p></td>
<td>{{if .Online}}<span️ class="okc">✔</span>{{else}}<span️ class="wrn">❌</span>{{end}} </td>
<td>{{.Regime}}</td>
<td>{{.Ping}}</td>
<td>{{.LastUpdated}}</td>
</tr>
{{end}}
</tbody>
</table>
</div>
</body></html>
`
