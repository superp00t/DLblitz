package main

import (
	"bufio"
	"os"

	"github.com/superp00t/DLblitz/s5"
	"github.com/superp00t/etc/yo"
)

func main() {
	yo.AddSubroutine("connect", []string{"server", "remote"}, "connect to a socks5 server and send/recv UDP data", func(args []string) {
		dl, err := s5.NewDialer(args[0], "", "")
		if err != nil {
			yo.Fatal(err)
		}

		yo.Spew(dl)

		pc, err := dl.ListenUDP()
		if err != nil {
			yo.Fatal(err)
		}

		go func() {
			for {
				n := make([]byte, 5000)
				i, addr, err := pc.ReadFrom(n)
				if err != nil {
					yo.Fatal(err)
				}

				yo.Println("Read", i, "bytes from", addr)
				yo.Spew(n[:i])
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

			_, err = pc.WriteTo([]byte(str), target)
			if err != nil {
				yo.Fatal(err)
			}
		}
	})

	yo.Init()
}
