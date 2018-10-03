package main

import (
	"bufio"
	"net"
	"os"

	"github.com/superp00t/DLblitz/s5"
	"github.com/superp00t/etc/yo"
)

func main() {
	yo.Boolf("u", "udp", "udp mode")

	yo.AddSubroutine("connect", []string{"server", "remote"}, "connect to a socks5 server and send/recv data", func(args []string) {
		dl, err := s5.NewDialer(args[0], "", "")
		if err != nil {
			yo.Fatal(err)
		}

		yo.Spew(dl)

		var pc *s5.Conn
		if yo.BoolG("u") {
			var err error
			pc, err = dl.ListenUDP()
			if err != nil {
				yo.Fatal(err)
			}
		} else {
			c, err := dl.Dial("tcp", args[1])
			if err != nil {
				yo.Fatal(err)
			}

			pc = c.(*s5.Conn)
		}

		go func() {
			for {
				var i int
				n := make([]byte, 63356)
				if !yo.BoolG("u") {
					var err error
					i, err = pc.Read(n)
					if err != nil {
						yo.Fatal(err)
					}
					yo.Println("read", i, "bytes")
				} else {
					var err error
					var addr net.Addr
					i, addr, err = pc.ReadFrom(n)
					if err != nil {
						yo.Fatal(err)
					}

					yo.Println("Read", i, "bytes from", addr)
					yo.Spew(n[:i])

				}
			}
		}()

		b := bufio.NewReader(os.Stdin)

		target, err := s5.ResolveUDPEndpoint(args[1])
		if err != nil {
			yo.Fatal(err)
		}

		for {
			str, err := b.ReadString('\n')
			if err != nil {
				yo.Fatal(err)
			}

			if yo.BoolG("u") {
				_, err = pc.WriteTo([]byte(str), target)
				if err != nil {
					yo.Fatal(err)
				}
			} else {
				_, err := pc.Write([]byte(str))
				if err != nil {
					yo.Fatal(err)
				}
			}
		}
	})

	yo.Init()
}
