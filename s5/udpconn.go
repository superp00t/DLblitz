package s5

import (
	"bytes"
	"fmt"
	"net"

	"github.com/superp00t/etc"
	"github.com/superp00t/etc/yo"
)

func (d *Dialer) ListenUDP() (*Conn, error) {
	var loc net.PacketConn
	var err error
	var x uint16 = 30000
	for ; x < 65535; x++ {
		loc, err = net.ListenPacket("udp", fmt.Sprintf("0.0.0.0:%d", x))
		if err == nil {
			goto success
		}
		yo.Println(err)
	}

	return nil, fmt.Errorf("s5: could not listen udp locally")

success:
	// ip, err := portForward(x)
	// if err != nil {
	// 	return nil, err
	// }

	// yo.Println("Pub IP", ip)

	nc, err := d.CreateConn("udp", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	nc.LocalUDP = loc

	return nc, nil
}

func (c *Conn) ReadFrom(b []byte) (int, net.Addr, error) {
	if c.Type == UDPBind {
	start:
		pkt := make([]byte, 40000)
		rd, ad, err := c.LocalUDP.ReadFrom(pkt)

		add, ok := ad.(*net.UDPAddr)
		if !ok {
			yo.Fatal("Received non-udp addr from udp socket")
		}

		// If this occurs, someone might be trying to inject packets
		if !bytes.Equal([]byte(add.IP), []byte(net.ParseIP(c.ServerBoundAddr))) {
			yo.Println("Received invalid packet from", add, "(possible packet injection attempt?)")
			goto start
		}

		e := etc.FromBytes(pkt[:rd])
		e.ReadUint16()
		frameID := e.ReadByte()
		if frameID != 0 {
			return 0, nil, fmt.Errorf("s5: Frame reception NYI")
		}
		ip, err := readIP(e)
		if err != nil {
			return 0, nil, err
		}

		pip := net.ParseIP(ip)
		if pip == nil {
			l, err := net.LookupHost(ip)
			if err != nil {
				yo.Warn("Could not lookup IP of", ip, err)
				return 0, nil, err
			}
			if len(l) == 0 {
				return 0, nil, fmt.Errorf("s5: could not read address")
			}
			pip = net.ParseIP(l[0])
		}

		remoteAddr := &net.UDPAddr{
			IP:   pip,
			Port: int(e.ReadBigUint16()),
		}

		bd := e.ReadRemainder()
		wr := copy(b, bd[:len(bd)-2])

		return wr, remoteAddr, nil
	}

	return 0, nil, nil
}

type udpAddr struct {
	Host string
	Port uint16
}

func (u udpAddr) String() string {
	return fmt.Sprintf("%s:%d", u.Host, u.Port)
}

func (u udpAddr) Network() string {
	return "udp"
}

func (c *Conn) WriteTo(b []byte, n net.Addr) (int, error) {
	if c.Type == UDPBind {
		u := &net.UDPAddr{IP: net.ParseIP(c.ServerBoundAddr), Port: int(c.ServerBoundPort)}

		pt, ok := n.(*net.UDPAddr)
		if !ok {
			return 0, fmt.Errorf("s5: you must use *net.UDPAddr")
		}

		requestHeader := etc.NewBuffer()
		requestHeader.Write([]byte{0, 0})
		requestHeader.WriteByte(0) // TODO: implement fragmentation

		if pt.IP == nil {
			return 0, fmt.Errorf("s5: incomplete address")
		}

		writeIP(requestHeader, pt.IP.String())

		requestHeader.WriteBigUint16(uint16(pt.Port))

		sz := requestHeader.Len()
		if sz+len(b) > 65535 {
			return 0, fmt.Errorf("s5: WriteTo buffer length exceeded maximum UDP datagram size")
		}

		requestHeader.Write(b)

		_, err := c.LocalUDP.WriteTo(requestHeader.Bytes(), u)
		return len(b), err
	}

	return 0, fmt.Errorf("s5: TCP WriteTo not implemented")
}
