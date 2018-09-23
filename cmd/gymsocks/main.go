package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"time"

	pt "github.com/andanhm/go-prettytime"
	_ "github.com/go-sql-driver/mysql"
	"github.com/go-xorm/xorm"
	"github.com/gorilla/mux"
	"github.com/superp00t/etc/yo"
	"golang.org/x/net/proxy"
)

var DB *xorm.Engine

type SocksServer struct {
	Id          int64     `json:"id"`
	Address     string    `json:"addr"`
	Online      bool      `json:"online"`
	LastUpdated time.Time `json:"lastUpdated"`
}

type SocksTpl struct {
	Id          int64
	Address     string
	Online      bool
	LastUpdated string
}

func isOnline(socks5server string) bool {
	_, err := proxy.SOCKS5("tcp", socks5server, nil, proxy.Direct)
	return err == nil
}

func scan() {
	ct, err := DB.Count(new(SocksServer))
	if err != nil || ct == 0 {
		err := DB.Sync2(new(SocksServer))
		if err != nil {
			yo.Fatal(err)
		}

		for _, v := range []string{
			"192.171.248.203:42599", "192.171.248.254:42599", "206.223.246.5:42599", "206.223.248.104:42599", "77.108.238.126:39880", "206.223.248.141:42599", "64.118.87.48:23641", "88.220.122.198:39880", "87.247.116.178:39880", "92.222.252.50:10080", "188.166.33.15:9050", "37.187.117.120:10080", "213.136.76.183:9626", "119.28.226.136:1080", "94.156.189.12:9050", "103.254.52.9:39880", "80.211.30.20:9050", "195.154.54.86:10080", "103.250.157.39:6667", "188.40.129.184:8080",
		} {
			DB.Insert(&SocksServer{
				Address:     v,
				Online:      isOnline(v),
				LastUpdated: time.Now(),
			})
		}
	}

	for {
		var ss []SocksServer
		DB.Find(&ss)
		for _, v := range ss {
			yo.Println("Scanning", v)
			is := isOnline(v.Address)
			v.Online = is
			v.LastUpdated = time.Now()
			_, err := DB.Id(v.Id).Cols("online", "last_updated").Update(v)
			if err != nil {
				yo.Println(err)
			}
		}
		time.Sleep(2 * time.Minute)
	}
}

func main() {
	yo.Stringf("d", "database", "SQL database to store ips", "")

	yo.AddSubroutine("serve", []string{"address"}, "serve socks address info over HTTP", func(args []string) {
		var err error
		DB, err = xorm.NewEngine("mysql", yo.StringG("d"))
		if err != nil {
			yo.Fatal(err)
		}

		go scan()

		r := mux.NewRouter()
		r.HandleFunc("/servers", func(rw http.ResponseWriter, r *http.Request) {
			var ss []SocksServer
			DB.Find(&ss)
			en := json.NewEncoder(rw)
			if r.URL.Query().Get("p") == "1" {
				en.SetIndent("", "  ")
			}
			en.Encode(ss)
		})

		r.HandleFunc("/online", func(rw http.ResponseWriter, r *http.Request) {
			var ss []SocksServer
			DB.Where("online = true").Find(&ss)
			for _, v := range ss {
				fmt.Fprintf(rw, "%s\n", v.Address)
			}
		})

		r.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
			var sn []SocksServer
			DB.Find(&sn)
			ss := make([]SocksTpl, len(sn))

			for i, v := range sn {
				ss[i] = SocksTpl{
					v.Id,
					v.Address,
					v.Online,
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

		yo.Fatal(http.ListenAndServe(args[0], r))
	})

	yo.Init()
}

const tpl = `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">	<title>Socks5 IP Checker</title><style>.tblview{max-width: 500px; display: block; margin: auto;} .mon{font-family: "monospace";}</style><link rel="stylesheet" href="//img.ikrypto.club/bootstrap.css"/></head><body>
<div class="tblview">
<h3>Socks5 Proxy Checker</h3>
<p><a href="online">Bulk export list of newline separated online Socks5 servers</a></p>
<p><a href="servers">Bulk export list of all Socks5 servers in JSON formatted metadata, online or not</a></p>
<table class="table">
  <thead>
    <tr>
      <th scope="col">ID</th>
      <th scope="col">IP Address</th>
      <th scope="col">Online</th>
      <th scope="col">Last Checked</th>
    </tr>
	</thead>
	<tbody>
{{range .}}
<tr>
<th scope="row">{{.Id}}</th>
<td><p class="mon">{{.Address}}</p></td>
<td>{{if .Online}}<span️ style="color: #008e04;">✔</span>{{else}}<span️ style="color: #ef1325;">❌</span>{{end}} </td>
<td>{{.LastUpdated}}</td>
</tr>
{{end}}
</tbody>
</table>
</div>
</body></html>
`
