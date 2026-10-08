package tlspin

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Proxy is a loopback TCP listener that forwards each connection over TLS to
// a remote address with the certificate pinned. wstunnel's client speaks
// plain ws:// to the proxy, and the proxy provides the wss:// leg — giving us
// real fingerprint pinning, which wstunnel itself does not offer.
type Proxy struct {
	ln          net.Listener
	remote      func() string // returns current "ip:port" to dial (may change on re-resolve)
	cfg         *tls.Config
	dialTimeout time.Duration
	wg          sync.WaitGroup
	mu          sync.Mutex
	conns       map[net.Conn]struct{}
	lastErr     error
}

// NewProxy listens on 127.0.0.1:0.
func NewProxy(remote func() string, serverName, pinned string, dialTimeout time.Duration) (*Proxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &Proxy{
		ln:          ln,
		remote:      remote,
		cfg:         Config(serverName, pinned),
		dialTimeout: dialTimeout,
		conns:       map[net.Conn]struct{}{},
	}, nil
}

// Addr is the local listen address, e.g. "127.0.0.1:41234".
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// LastError returns the most recent upstream dial error (e.g. ErrMismatch).
func (p *Proxy) LastError() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastErr
}

// Serve accepts until ctx is done or Close is called.
func (p *Proxy) Serve(ctx context.Context) {
	go func() { <-ctx.Done(); p.Close() }()
	for {
		c, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.handle(ctx, c)
		}()
	}
}

func (p *Proxy) handle(ctx context.Context, local net.Conn) {
	defer local.Close()
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: p.dialTimeout}, Config: p.cfg}
	remote, err := d.DialContext(ctx, "tcp", p.remote())
	p.mu.Lock()
	p.lastErr = err
	p.mu.Unlock()
	if err != nil {
		slog.Warn("pinned TLS dial failed", "remote", p.remote(), "err", err)
		return
	}
	defer remote.Close()
	p.track(local, remote)
	defer p.untrack(local, remote)
	done := make(chan struct{}, 2)
	go func() { io.Copy(remote, local); done <- struct{}{} }()
	go func() { io.Copy(local, remote); done <- struct{}{} }()
	<-done
}

func (p *Proxy) track(cs ...net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range cs {
		p.conns[c] = struct{}{}
	}
}

func (p *Proxy) untrack(cs ...net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, c := range cs {
		delete(p.conns, c)
	}
}

// closeTimeout bounds Listener.Close. Some Windows Winsock layered service
// providers never complete a cancelled AcceptEx, which makes Close block
// forever; teardown must not hang on that.
const closeTimeout = 2 * time.Second

// Close stops listening and tears down active connections.
func (p *Proxy) Close() error {
	p.mu.Lock()
	for c := range p.conns {
		c.Close()
	}
	p.mu.Unlock()
	errc := make(chan error, 1)
	go func() { errc <- p.ln.Close() }()
	select {
	case err := <-errc:
		return err
	case <-time.After(closeTimeout):
		slog.Debug("listener close did not complete; abandoning it", "addr", p.Addr())
		return nil
	}
}
