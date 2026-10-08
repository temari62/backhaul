// Package dnsfwd is the exit node's tiny DNS relay: it listens on the
// tunnel IP (port 53, UDP+TCP) and passes queries verbatim to an upstream
// resolver, so the client's DNS leaves from the exit node. It does not parse
// DNS — it is a byte relay, not a resolver.
package dnsfwd

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"time"
)

// Timeout bounds one upstream exchange.
const Timeout = 5 * time.Second

// maxUDP is the largest DNS-over-UDP message we relay (EDNS0 maximum).
const maxUDP = 65535

// Forwarder is a bound DNS relay.
type Forwarder struct {
	pc       net.PacketConn
	ln       net.Listener
	upstream string
}

// Listen binds UDP and TCP on listen ("10.9.0.1:53").
func Listen(listen, upstream string) (*Forwarder, error) {
	pc, err := net.ListenPacket("udp", listen)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		pc.Close()
		return nil, err
	}
	return &Forwarder{pc: pc, ln: ln, upstream: upstream}, nil
}

// Serve binds listen and relays to upstream ("1.1.1.1:53") until ctx is done.
func Serve(ctx context.Context, listen, upstream string) error {
	f, err := Listen(listen, upstream)
	if err != nil {
		return err
	}
	return f.Serve(ctx)
}

// Serve relays until ctx is done.
func (f *Forwarder) Serve(ctx context.Context) error {
	pc, ln, upstream := f.pc, f.ln, f.upstream
	go func() { <-ctx.Done(); pc.Close(); ln.Close() }()
	slog.Info("dns forwarder listening", "addr", pc.LocalAddr(), "upstream", upstream)
	go serveTCP(ln, upstream)
	buf := make([]byte, maxUDP)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			resp, err := exchangeUDP(q, upstream)
			if err != nil {
				slog.Debug("dns upstream failed", "err", err)
				return
			}
			_, _ = pc.WriteTo(resp, from)
		}()
	}
}

func exchangeUDP(q []byte, upstream string) ([]byte, error) {
	c, err := net.DialTimeout("udp", upstream, Timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(Timeout))
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, maxUDP)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func serveTCP(ln net.Listener, upstream string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			u, err := net.DialTimeout("tcp", upstream, Timeout)
			if err != nil {
				return
			}
			defer u.Close()
			done := make(chan struct{}, 2)
			go func() { io.Copy(u, c); done <- struct{}{} }()
			go func() { io.Copy(c, u); done <- struct{}{} }()
			<-done
		}()
	}
}
