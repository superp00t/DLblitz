package bnet

import (
	"fmt"
	"io"
	"net"
	"net/http"

	"golang.org/x/net/proxy"
)

var (
	torEnabled = false
	torURL     = ""
	UserAgent  = "Mozilla/5.0 (Windows NT 6.1; rv:31.0) Gecko/20100101 Firefox/31.0"
)

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

func Req(forceAnonymity bool, method, url string, body io.ReadCloser) (int, io.Reader, error) {
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

	return HReq(cl, method, url, body)

}

func HReq(h *http.Client, method, url string, body io.ReadCloser) (int, io.Reader, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return 0, nil, err
	}

	req.Header.Set("User-Agent", UserAgent)

	resp, err := h.Do(req)
	if err != nil {
		return 0, nil, err
	}

	return resp.StatusCode, resp.Body, err
}

func AcquireProxy(urls string) (func(string, string) (net.Conn, error), error) {
	dl, err := proxy.SOCKS5("tcp", urls, nil, proxy.Direct)
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
