//Package s5 implements a SOCKS5 client which supports TCP client-mode connections and UDP port associations.
package s5

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/superp00t/etc"
	"github.com/superp00t/etc/yo"
)

const (
	// Auth Methods
	Auth_None             = 0x00
	Auth_GSSAPI           = 0x01
	Auth_UsernamePassword = 0x02
	Auth_Failure          = 0xFF

	Socks5 = 0x05

	TCPStream = 0x01
	TCPBind   = 0x02
	UDPBind   = 0x03

	// IP types
	IPv4   = 0x01
	Domain = 0x03
	IPv6   = 0x04
)

var (
	errorCodes = map[uint8]string{
		0x00: "request granted",
		0x01: "general failure",
		0x02: "connection not allowed by ruleset",
		0x03: "network unreachable",
		0x04: "host unreachable",
		0x05: "connection refused by destination host",
		0x06: "TTL expired",
		0x07: "command not supported / protocol error",
		0x08: "address type not supported",
	}
)

type Dialer struct {
	Endpoint           string
	Username, Password string
}

type Conn struct {
	Dialer *Dialer

	Type    uint8
	c       net.Conn
	Address string

	ServerBoundAddr string
	ServerBoundPort uint16

	LocalUDP net.PacketConn
}

func NewDialer(direct, user, pass string) (*Dialer, error) {
	cn := new(Dialer)
	cn.Username, cn.Password = user, pass
	if len(cn.Username) > 255 {
		return nil, fmt.Errorf("s5: username is too long")
	}
	if len(cn.Password) > 255 {
		return nil, fmt.Errorf("s5: password is too long")
	}
	cn.Endpoint = direct
	return cn, nil
}

func readSocket(c net.Conn, size int) (*etc.Buffer, error) {
	buf := make([]byte, size)
	i, err := c.Read(buf)
	if err != nil {
		return nil, err
	}

	return etc.FromBytes(buf[:i]), nil
}

func writeSocket(c net.Conn, e *etc.Buffer) error {
	_, err := c.Write(e.Bytes())
	return err
}

func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	switch network {
	case "tcp":
	case "udp":
		return nil, fmt.Errorf("s5: you need to use Dialer.ListenUDP() to use UDP")
	}

	return d.CreateConn(network, address)
}

func (d *Dialer) CreateConn(network, address string) (*Conn, error) {
	var connectionType uint8
	switch network {
	case "tcp":
		connectionType = TCPStream
	case "udp":
		connectionType = UDPBind
	default:
		return nil, fmt.Errorf("s5: network %s not supported", network)
	}

	cn := new(Conn)
	cn.Dialer = d
	cn.Type = connectionType
	cn.Address = address

	yo.Println("Dialing", d.Endpoint, "...", "tcp")

	var err error
	cn.c, err = net.Dial("tcp", d.Endpoint)
	if err != nil {
		return nil, err
	}

	yo.Println("Success")

	addr, port, err := parseIP(address)
	if err != nil {
		return nil, err
	}

	e := etc.NewBuffer()
	e.WriteByte(Socks5) // Type

	supportedMethods := []uint8{
		Auth_None,
	}

	if d.Username != "" && d.Password != "" {
		supportedMethods = append(supportedMethods, Auth_UsernamePassword)
	}

	e.WriteByte(uint8(len(supportedMethods))) // Number of authentication methods supported
	for _, v := range supportedMethods {
		e.WriteByte(v)
	}

	err = writeSocket(cn.c, e)
	if err != nil {
		yo.Println("Failed to send first handshake")
		return nil, err
	}

	b, err := readSocket(cn.c, 10)
	if err != nil {
		yo.Println("Failed to read first response")
		return nil, err
	}

	if t := b.ReadByte(); t != Socks5 {
		return nil, fmt.Errorf("s5: not a socks5 server")
	}

	method := b.ReadByte()
	switch method {
	case Auth_None:
	case Auth_UsernamePassword:
		n := etc.NewBuffer()
		n.WriteByte(0x01)
		n.WriteByte(uint8(len(d.Username)))
		n.Write([]byte(d.Username))
		n.WriteByte(uint8(len(d.Password)))
		n.Write([]byte(d.Password))
		err := writeSocket(cn.c, n)
		if err != nil {
			yo.Println("Could not write auth packet")
			return nil, err
		}

		r, err := readSocket(cn.c, 10)
		if err != nil {
			return nil, err
		}

		if r.ReadByte() != 0x01 {
			return nil, fmt.Errorf("s5: unexpected opcode")
		}

		if r.ReadByte() != 0x00 {
			cn.c.Close()
			return nil, fmt.Errorf("s5: authentication failed")
		}
	default:
		return nil, fmt.Errorf("s5: unknown method 0x%x", method)
	}

	// Basic initializiation/authentication is now complete.

	in := etc.NewBuffer()
	in.WriteByte(Socks5)
	in.WriteByte(connectionType)
	in.WriteByte(0x00) // Reserved

	writeIP(in, addr)

	in.WriteBigUint16(port)

	err = writeSocket(cn.c, in)
	if err != nil {
		return nil, err
	}

	bind, err := readSocket(cn.c, 1000)
	if err != nil {
		return nil, err
	}

	if bind.ReadByte() != Socks5 {
		return nil, fmt.Errorf("s5: not a socks5 server")
	}

	status := bind.ReadByte()
	if status != 0x00 {
		return nil, fmt.Errorf("s5: connection failed: %s", errorCodes[status])
	}

	// reserved
	yo.Println("reserved", bind.ReadByte())

	cn.ServerBoundAddr, err = readIP(bind)

	if err != nil {
		yo.Spew(bind.Bytes())
		return nil, err
	}

	cn.ServerBoundPort = bind.ReadBigUint16()
	return cn, nil
}

func parseIP(src string) (string, uint16, error) {
	s := strings.Split(src, ":")
	if len(s) != 2 {
		return "", 0, fmt.Errorf("invalid IP %s", src)
	}

	addr := s[0]
	i, err := strconv.ParseInt(s[1], 0, 16)
	if err != nil {
		return "", 0, err
	}

	return addr, uint16(i), nil
}

func writeIP(e *etc.Buffer, ip string) error {
	var t uint8
	i := net.ParseIP(ip)
	if i == nil {
		t = Domain
		yo.Println("Writing IP str", ip)
	}

	if len(i) == 4 {
		t = IPv4
	}

	if len(i) == 16 {
		t = IPv6
	}

	e.WriteByte(t)

	switch t {
	case Domain:
		e.WriteByte(uint8(len(ip)))
		e.Write([]byte(ip))
	case IPv4:
		e.Write([]byte(i))
	case IPv6:
		e.Write([]byte(i))
	}

	return nil
}

func readIP(e *etc.Buffer) (string, error) {
	ty := e.ReadByte()
	switch ty {
	case Domain:
		ln := int(e.ReadByte())
		return string(e.ReadBytes(ln)), nil
	case IPv4:
		i := net.IP(e.ReadBytes(4))
		return i.String(), nil
	case IPv6:
		i := net.IP(e.ReadBytes(16))
		return i.String(), nil
	default:
		return "", fmt.Errorf("s5: peer sent invalid address type 0x%x", ty)
	}
}

// todo: route through anonymous proxy such as Tor
func ResolveUDPEndpoint(s string) (net.Addr, error) {
	return net.ResolveUDPAddr("udp", s)
}

func (c *Conn) Write(b []byte) (int, error) {
	if c.Type == TCPStream {
		return c.c.Write(b)
	}

	return 0, fmt.Errorf("s5: use WriteTo for UDP mode")
}

func (c *Conn) Read(b []byte) (int, error) {
	if c.Type == TCPStream {
		return c.c.Write(b)
	}

	return 0, fmt.Errorf("s5: use ReadFrom for UDP mode")
}

func (c *Conn) Close() error {
	if c.Type == UDPBind {
		c.LocalUDP.Close()
	}
	return c.c.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	t, err := net.ResolveTCPAddr("tcp", c.Dialer.Endpoint)
	if err != nil {
		yo.Warn("LocalAddr()", err)
		return nil
	}

	return t
}

func (c *Conn) RemoteAddr() net.Addr {
	if c.Type == UDPBind {
		return nil
	}

	t, err := net.ResolveTCPAddr("tcp", c.Address)
	if err != nil {
		yo.Warn("LocalAddr()", err)
		return nil
	}

	return t
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	if c.Type == UDPBind {
		return c.LocalUDP.SetWriteDeadline(t)
	}

	return c.c.SetWriteDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	if c.Type == UDPBind {
		return c.LocalUDP.SetReadDeadline(t)
	}

	return c.c.SetReadDeadline(t)
}

func (c *Conn) SetDeadline(t time.Time) error {
	if c.Type == UDPBind {
		return c.LocalUDP.SetDeadline(t)
	}

	return c.c.SetDeadline(t)
}
