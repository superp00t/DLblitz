package main

import (
	"archive/zip"
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cheggaaa/pb"
	"github.com/superp00t/DLblitz/bnet"
	"github.com/superp00t/etc"
	"github.com/superp00t/etc/yo"
	"golang.org/x/text/encoding/charmap"
)

// Download a file over HTTP to a temporary directory and return the file handle. Will halt process if error is discovered.
func getb(url string, gz bool) *etc.Buffer {
	cl := &http.Client{}
	_, h, err := bnet.HReq(cl, "GET", url, nil)
	if err != nil {
		yo.Fatal(err)
	}

	rnd := etc.TmpDirectory().Concat(etc.GenerateRandomUUID().String()).Render()

	f, err := etc.FileController(rnd)
	if err != nil {
		yo.Fatal(err)
	}

	if gz {
		g, err := gzip.NewReader(h)
		if err != nil {
			yo.Fatal(err)
		}
		io.Copy(f, g)
	} else {
		io.Copy(f, h)
	}

	f.SeekR(0)
	h.Close()

	return f
}

func updateBlockedRanges() {
	DB.DropTables(new(BlockedRange))
	err := DB.Sync2(new(BlockedRange))
	if err != nil {
		yo.Fatal(err)
	}

	f := getb(BlockList, true)

	ee := bufio.NewReader(f)

	bar := pb.StartNew(466000)

	for i := uint64(0); ; i++ {
		str, err := ee.ReadString('\n')
		if err != nil {
			break
		}

		s := strings.TrimRight(str, "\n")

		if s == "" {
			continue
		}

		if s[0] == '#' {
			continue
		}

		desci := strings.Split(s, ":")

		br := BlockedRange{}
		max := len(desci) - 1
		br.RangeName = desci[max-1]
		rng := strings.Split(desci[max], "-")

		if len(rng) != 2 {
			yo.Fatal("=>", s)
		}

		br.Min = bnet.ParseIPv4(rng[0]).Uint32()
		br.Max = bnet.ParseIPv4(rng[1]).Uint32()

		DB.Insert(br)
		bar.Increment()
	}

	bar.Finish()

	f.Delete()
}

func decMax(enc []byte) string {
	dec := charmap.Windows1250.NewDecoder()
	out, _ := dec.Bytes(enc)
	return string(out)
}

func decf(s string) float32 {
	f, err := strconv.ParseFloat(s, 32)
	if err != nil {
		yo.Fatal(err)
	}
	return float32(f)
}

func dec32(s string) uint32 {
	locID, _ := strconv.ParseInt(s, 10, 32)
	return uint32(locID)
}

func updateMaxmindDBs() {
	DB.DropTables(new(GeoipBlocks), new(GeoipLocation))
	DB.Sync2(new(GeoipBlocks), new(GeoipLocation))

	f := getb(GeoliteCity, false)
	zp, err := zip.NewReader(f, f.Size())
	if err != nil {
		yo.Fatal(err)
	}

	for _, fi := range zp.File {
		if strings.HasSuffix(fi.Name, "GeoLiteCity-Location.csv") {
			l, err := fi.Open()
			if err != nil {
				yo.Fatal(err)
			}

			le := bufio.NewReader(l)
			le.ReadString('\n')

			s := csv.NewReader(le)

			for i := uint64(0); ; i++ {
				recs, err := s.Read()
				if err != nil {
					yo.Println(err)
					break
				}

				if i == 0 {
					continue
				}

				rec := GeoipLocation{}

				rec.LocID = dec32(recs[0])
				rec.Country = recs[1]
				rec.Region = recs[2]
				rec.City = decMax([]byte(recs[3]))
				rec.PostalCode = recs[4]
				rec.Lat = decf(recs[5])
				rec.Long = decf(recs[6])
				rec.MetroCode = dec32(recs[7])
				rec.AreaCode = dec32(recs[8])

				DB.Insert(rec)
			}
		}

		if strings.HasSuffix(fi.Name, "GeoLiteCity-Blocks.csv") {
			l, err := fi.Open()
			if err != nil {
				yo.Fatal(err)
			}

			le := bufio.NewReader(l)
			le.ReadString('\n')

			s := csv.NewReader(le)

			for i := uint64(0); ; i++ {
				recs, err := s.Read()
				if err != nil {
					yo.Println(err)
					break
				}

				if i == 0 {
					continue
				}

				rec := GeoipBlocks{}

				rec.Min = dec32(recs[0])
				rec.Max = dec32(recs[1])
				rec.LocID = dec32(recs[2])

				DB.Insert(rec)
			}
		}
		yo.Println(fi.Name)
	}

	f.Delete()
}

func updateSocksList() {
	DB.DropTables(new(SocksServer))
	DB.Sync2(new(SocksServer))

	_, list, err := bnet.Req(false, "GET", SocksList, nil)
	if err != nil {
		yo.Fatal(err)
	}

	buf := bufio.NewReader(list)

	for {
		str, err := buf.ReadString('\n')
		if err != nil {
			yo.Println(err)
			break
		}

		r := strings.TrimRight(str, "\n")

		DB.Insert(&SocksServer{
			Address:     r,
			Online:      false,
			LastUpdated: time.Now(),
		})

		yo.Println(r)
	}

	list.Close()
}
