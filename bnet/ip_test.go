package bnet

import "testing"
import "github.com/superp00t/etc/yo"

func TestIP(t *testing.T) {
	v := "127.0.0.1"
	v2 := "127.0.0.2"

	n := ParseIPv4(v)
	n2 := ParseIPv4(v2)

	yo.Println(n)
	yo.Println(n2)

	yo.Println(ParseIPv4("104.255.105.98"))
}
