package osutil

import "net"

// LANIP returns this machine's primary LAN address: the source address the
// OS would use to reach the internet. A UDP "dial" sends no packets.
func LANIP() string {
	c, err := net.Dial("udp4", "192.0.2.1:9") // TEST-NET-1; only used for route selection
	if err != nil {
		return ""
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}
