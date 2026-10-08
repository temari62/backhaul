//go:build windows

package wg

import (
	"net"

	"golang.zx2c4.com/wireguard/ipc"
)

func uapiListen(name string) (net.Listener, error) {
	return ipc.UAPIListen(name)
}

func tunHint() string {
	return " (Windows needs wintun.dll next to backhaul.exe — run `backhaul doctor` to fetch it — and an elevated shell)"
}
