package bnet

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/cheggaaa/pb"
	"github.com/superp00t/DLblitz/s5"
	"github.com/superp00t/etc/yo"
)

var (
	torEnabled = false
	torURL     = ""
	UserAgent  = "Mozilla/5.0 (Windows NT 6.1; rv:31.0) Gecko/20100101 Firefox/31.0"
)

type IPv4 uint32

func (i IPv4) IP() string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, uint32(i))
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

func (i IPv4) Uint32() uint32 {
	return uint32(i)
}

func ParseIPv4(s string) IPv4 {
	rgx := regexp.MustCompile("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$")
	if !rgx.MatchString(s) {
		yo.Println("Invalid IP", s)
		return 0
	}

	str := strings.Split(s, ".")

	b := make([]byte, 4)

	for i, v := range str {
		c, err := strconv.ParseInt(v, 0, 64)
		if err != nil {
			yo.Println(err, "Invalid IP", s, "(", v, ")")
			return 0
		}

		b[i] = uint8(c)
	}

	return IPv4(binary.BigEndian.Uint32(b))
}

func init() {
	for _, v := range []string{
		"localhost:9050",
		"localhost:9150",
	} {
		_, err := AcquireProxy(v)
		if err == nil {
			torEnabled = true
			torURL = v
			return
		}
	}
}

type ReqReader struct {
	bar   *pb.ProgressBar
	proxy *pb.Reader
	rd    io.ReadCloser
}

func (r *ReqReader) Read(b []byte) (int, error) {
	if r.rd != nil {
		return r.rd.Read(b)
	}
	return r.proxy.Read(b)
}

func (r *ReqReader) Close() error {
	if r.rd != nil {
		return r.rd.Close()
	}
	r.bar.Finish()
	return r.proxy.Close()
}

func Req(showProgress bool, forceAnonymity bool, method, url string, body io.ReadCloser) (int, *ReqReader, error) {
	if forceAnonymity && !torEnabled {
		return 0, nil, fmt.Errorf("Tor could not be enabled")
	}

	var cl *http.Client
	if !forceAnonymity && !torEnabled {
		cl = &http.Client{}
	} else {
		var err error
		cl, err = AcquireHTTPClient(torURL)
		if err != nil {
			return 0, nil, err
		}
	}

	return HReq(showProgress, cl, method, url, body)
}

func HReq(showProgress bool, h *http.Client, method, url string, body io.ReadCloser) (int, *ReqReader, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return 0, nil, err
	}

	req.Header.Set("User-Agent", UserAgent)

	resp, err := h.Do(req)
	if err != nil {
		return 0, nil, err
	}

	yo.Println(method, url)

	var rr *ReqReader
	if showProgress {
		bar := pb.New(int(resp.ContentLength)).SetUnits(pb.U_BYTES)
		bar.Start()
		rr = &ReqReader{bar, bar.NewProxyReader(resp.Body), nil}
	} else {
		rr = &ReqReader{nil, nil, resp.Body}
	}

	return resp.StatusCode, rr, err
}

func AcquireProxy(urls string) (func(string, string) (net.Conn, error), error) {
	dl, err := s5.NewDialer(urls, "", "")
	if err != nil {
		return nil, err
	}
	return dl.Dial, nil
}

func AcquireHTTPClient(urls string) (*http.Client, error) {
	pr, err := AcquireProxy(urls)
	if err != nil {
		return nil, err
	}

	tr := &http.Transport{
		Dial: pr,
	}

	cl := &http.Client{
		Transport: tr,
	}

	return cl, nil
}
