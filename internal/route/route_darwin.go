//go:build darwin

package route

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"

	"backhaul/internal/osutil"
	"backhaul/internal/undo"
)

// pfAnchor sits under the stock `anchor "com.apple/*"` in /etc/pf.conf, so we
// never edit the main ruleset.
const pfAnchor = "com.apple/250.backhaul"

type darwinManager struct{}

func newManager() Manager { return darwinManager{} }

// ConfigureInterface assigns point-to-point addresses on the utun device and
// adds the on-link subnet route.
func ConfigureInterface(ctx context.Context, iface string, addrs []netip.Prefix, mtu int) error {
	if _, err := osutil.Run(ctx, "ifconfig", iface, "mtu", strconv.Itoa(mtu)); err != nil {
		return err
	}
	for _, a := range addrs {
		ip := a.Addr().String()
		if a.Addr().Is4() {
			if _, err := osutil.Run(ctx, "ifconfig", iface, "inet", ip, ip, "netmask", "255.255.255.255", "alias"); err != nil {
				return err
			}
			_, _ = osutil.Run(ctx, "route", "-q", "-n", "add", "-inet", a.Masked().String(), "-interface", iface)
		} else {
			if _, err := osutil.Run(ctx, "ifconfig", iface, "inet6", ip, "prefixlen", "128", "alias"); err != nil {
				return err
			}
			_, _ = osutil.Run(ctx, "route", "-q", "-n", "add", "-inet6", a.Masked().String(), "-interface", iface)
		}
	}
	_, err := osutil.Run(ctx, "ifconfig", iface, "up")
	return err
}

func gatewayFor(ctx context.Context, dst netip.Addr) (gw, iface string, err error) {
	fam := "-inet"
	if dst.Is6() {
		fam = "-inet6"
	}
	out, err := osutil.Run(ctx, "route", "-n", "get", fam, dst.String())
	if err != nil {
		return "", "", err
	}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		switch k {
		case "gateway":
			gw = strings.TrimSpace(v)
		case "interface":
			iface = strings.TrimSpace(v)
		}
	}
	if gw == "" && iface == "" {
		return "", "", fmt.Errorf("cannot determine route to %s", dst)
	}
	return gw, iface, nil
}

func (darwinManager) Apply(ctx context.Context, p Plan, j *undo.Journal) error {
	for _, ep := range p.Endpoints {
		ep = ep.Unmap()
		if ep.IsLoopback() {
			continue
		}
		gw, iface, err := gatewayFor(ctx, ep)
		if err != nil {
			return fmt.Errorf("find physical route to endpoint: %w", err)
		}
		fam := "-inet"
		if ep.Is6() {
			fam = "-inet6"
		}
		target := []string{gw}
		if gw == "" || strings.HasPrefix(gw, "link#") {
			target = []string{"-interface", iface}
		}
		args := append([]string{"-q", "-n", "add", fam, HostPrefix(ep).String()}, target...)
		if _, err := osutil.Run(ctx, "route", args...); err != nil {
			if !strings.Contains(err.Error(), "File exists") {
				return err
			}
			continue
		}
		del := append([]string{"route", "-q", "-n", "delete", fam, HostPrefix(ep).String()}, target...)
		_ = j.Push(undo.ExecBestEffort("remove endpoint host route", del...))
	}
	for _, pf := range SplitV4 {
		if _, err := osutil.Run(ctx, "route", "-q", "-n", "add", "-inet", pf.String(), "-interface", p.Iface); err != nil {
			return err
		}
		_ = j.Push(undo.ExecBestEffort("remove split route", "route", "-q", "-n", "delete", "-inet", pf.String(), "-interface", p.Iface))
	}
	if p.IPv6 {
		for _, pf := range SplitV6 {
			if _, err := osutil.Run(ctx, "route", "-q", "-n", "add", "-inet6", pf.String(), "-interface", p.Iface); err != nil {
				slog.Warn("IPv6 tunneling failed; disabling IPv6 for this session to prevent leaks", "err", err)
				p.IPv6 = false
				break
			}
			_ = j.Push(undo.ExecBestEffort("remove split route v6", "route", "-q", "-n", "delete", "-inet6", pf.String(), "-interface", p.Iface))
		}
	}
	services, err := networkServices(ctx)
	if err != nil {
		return err
	}
	if !p.IPv6 {
		for _, s := range services {
			// TODO(spec): restores to "automatic", not the exact previous v6 mode.
			_ = j.Push(undo.Exec("re-enable IPv6 on "+s, "networksetup", "-setv6automatic", s))
			_, _ = osutil.Run(ctx, "networksetup", "-setv6off", s)
		}
	}
	if len(p.DNS) > 0 {
		// TODO(spec): spec suggests scutil; networksetup per service is simpler
		// to restore exactly and covers every service, not just the primary.
		for _, s := range services {
			old, err := osutil.Run(ctx, "networksetup", "-getdnsservers", s)
			if err != nil {
				continue
			}
			restore := []string{"networksetup", "-setdnsservers", s}
			if strings.Contains(old, "aren't any") {
				restore = append(restore, "Empty")
			} else {
				restore = append(restore, strings.Fields(old)...)
			}
			_ = j.Push(undo.Exec("restore DNS on "+s, restore...))
			args := []string{"-setdnsservers", s}
			for _, d := range p.DNS {
				args = append(args, d.String())
			}
			if _, err := osutil.Run(ctx, "networksetup", args...); err != nil {
				return err
			}
		}
		_, _ = osutil.Run(ctx, "dscacheutil", "-flushcache")
		_, _ = osutil.Run(ctx, "killall", "-HUP", "mDNSResponder")
	}
	if p.KillSwitch {
		_ = j.Push(undo.Exec("flush kill-switch anchor", "pfctl", "-a", pfAnchor, "-F", "all"))
		if _, err := osutil.RunStdin(ctx, PfKillSwitch(p), "pfctl", "-a", pfAnchor, "-f", "-"); err != nil {
			return err
		}
		out, err := osutil.Run(ctx, "pfctl", "-E")
		if err != nil {
			return err
		}
		// `pfctl -E` takes a reference; release it with the token on undo.
		if tok := parsePfToken(out); tok != "" {
			_ = j.Push(undo.Exec("release pf reference", "pfctl", "-X", tok))
		}
	}
	return nil
}

func networkServices(ctx context.Context) ([]string, error) {
	out, err := osutil.Run(ctx, "networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	var s []string
	for _, line := range strings.Split(out, "\n")[1:] { // first line is a notice
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") { // "*" = disabled service
			continue
		}
		s = append(s, line)
	}
	return s, nil
}

func parsePfToken(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if _, v, ok := strings.Cut(line, "Token :"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func (darwinManager) RepairEndpoint(ctx context.Context, p Plan, j *undo.Journal) (bool, error) {
	repaired := false
	for _, ep := range p.Endpoints {
		ep = ep.Unmap()
		if ep.IsLoopback() {
			continue
		}
		_, iface, err := gatewayFor(ctx, ep)
		if err != nil {
			return repaired, err
		}
		if iface != p.Iface {
			continue
		}
		fam := "-inet"
		if ep.Is6() {
			fam = "-inet6"
		}
		// Our split routes are /1s, so "default" still names the real uplink.
		out, err := osutil.Run(ctx, "route", "-n", "get", fam, "default")
		if err != nil {
			return repaired, errOffline
		}
		gw, dif := "", ""
		for _, line := range strings.Split(out, "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok {
				switch k {
				case "gateway":
					gw = strings.TrimSpace(v)
				case "interface":
					dif = strings.TrimSpace(v)
				}
			}
		}
		if dif == "" || dif == p.Iface {
			return repaired, errOffline
		}
		target := []string{gw}
		if gw == "" || strings.HasPrefix(gw, "link#") {
			target = []string{"-interface", dif}
		}
		_, _ = osutil.Run(ctx, "route", "-q", "-n", "delete", fam, HostPrefix(ep).String())
		args := append([]string{"-q", "-n", "add", fam, HostPrefix(ep).String()}, target...)
		if _, err := osutil.Run(ctx, "route", args...); err != nil {
			return repaired, err
		}
		del := append([]string{"route", "-q", "-n", "delete", fam, HostPrefix(ep).String()}, target...)
		_ = j.Push(undo.ExecBestEffort("remove endpoint host route", del...))
		repaired = true
	}
	return repaired, nil
}

// OtherVPNs lists other VPN interfaces that hold full-tunnel routes.
func OtherVPNs(ctx context.Context, own string) ([]string, error) {
	out, err := osutil.Run(ctx, "netstat", "-rn", "-f", "inet")
	if err != nil {
		return nil, err
	}
	return UnixOtherVPNs(out, own), nil
}

// EndpointPath describes how macOS currently routes traffic to ep.
func EndpointPath(ctx context.Context, ep netip.Addr) string {
	gw, iface, err := gatewayFor(ctx, ep)
	if err != nil {
		return "unknown (" + err.Error() + ")"
	}
	return iface + " via " + gw
}

// DisableKillSwitch removes the kill-switch rules now.
func DisableKillSwitch(ctx context.Context) error {
	_, err := osutil.Run(ctx, "pfctl", "-a", pfAnchor, "-F", "all")
	return err
}
