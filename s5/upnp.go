package s5

import (
	"github.com/NebulousLabs/go-upnp"
)

func portForward(num uint16) (string, error) {
	// connect to router
	d, err := upnp.Discover()
	if err != nil {
		return "", err
	}

	// discover external IP
	ip, err := d.ExternalIP()
	if err != nil {
		return "", err
	}

	// forward a port
	err = d.Forward(num, "s5")
	if err != nil {
		return "", err
	}

	return ip, nil
}
