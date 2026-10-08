//go:build !windows

package wg

import (
	"net"

	"golang.zx2c4.com/wireguard/ipc"
)

func uapiListen(name string) (net.Listener, error) {
	f, err := ipc.UAPIOpen(name)
	if err != nil {
		return nil, err
	}
	return ipc.UAPIListen(name, f)
}

func tunHint() string {
	return " (is /dev/net/tun available and are you root?)"
}
