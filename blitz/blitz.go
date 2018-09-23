package blitz

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/superp00t/etc"

	"github.com/superp00t/DLblitz/bnet"
)

const (
	SimpleProxy = iota
	BlitzOverlay
)

type Client struct {
	// Path to file containing ip ranges to block.
	BlocklistPath string

	ForceOverlay bool
	DiscoServer  string

	BackupProxy string
}

type PeerInfo struct {
	Type      string
	Address   string
	PublicKey [32]byte
}

func (c *Client) CreateCircuit() (*Circuit, error) {
	crc := &Circuit{
		Type:  SimpleProxy,
		Proxy: c.BackupProxy,
	}
	return crc, nil
}

func ebuf(r io.Reader) *etc.Buffer {
	e := etc.NewBuffer()
	io.Copy(e, r)
	return e
}

func (c *Client) RealIP() (string, error) {
	rsp, err := http.Get(c.DiscoServer + "/ip")
	if err != nil {
		return "", err
	}

	b, err := ioutil.ReadAll(rsp.Body)
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func (c *Client) RequestPeers(t string, limit uint64) ([]PeerInfo, error) {
	st, rsp, err := bnet.Req(
		false,
		"GET",
		fmt.Sprintf(
			"%s/peers/%s?l=%d",
			c.DiscoServer,
			url.QueryEscape(t),
			limit,
		),
		nil)

	if err != nil {
		return nil, err
	}

	if st != 200 {
		return nil, fmt.Errorf("invalid status %d", st)
	}

	e := ebuf(rsp)
	ln := e.ReadUint()
	if ln > limit {
		return nil, errors.New("server sent invalid length")
	}

	pi := make([]PeerInfo, int(ln))

	for i := range pi {
		pi[i].Address = e.ReadUString()
		copy(pi[i].PublicKey[:], e.ReadBytes(32))
	}

	return pi, nil
}
