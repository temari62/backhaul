package tlspin

import (
	"context"
	"crypto/tls"
	"errors"
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
	ln              net.Listener
	remote          func() string // returns current "ip:port" to dial (may change on re-resolve)
	cfg             *tls.Config
	dialTimeout     time.Duration
	wg              sync.WaitGroup
	mu              sync.Mutex
	conns           map[net.Conn]struct{}
	lastErr         error
	active          int // open upstream connections
	everConnected   bool
	blockedHintOnce sync.Once
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
	hadSuccess := p.everConnected
	if err == nil {
		p.everConnected = true
		p.active++
	}
	p.mu.Unlock()
	if err != nil {
		slog.Warn("pinned TLS dial failed", "remote", p.remote(), "err", err)
		var ne net.Error
		if hadSuccess && errors.As(err, &ne) && ne.Timeout() {
			p.blockedHintOnce.Do(func() {
				slog.Warn("the exit node answered earlier but new connections to it now time out. " +
					"If the exit node is still running, something between the two PCs started dropping this connection: " +
					"typically a firewall that detects and blocks VPN-like traffic (e.g. in China), or the exit node's router/ISP.")
			})
		}
		return
	}
	start := time.Now()
	defer func() {
		p.mu.Lock()
		p.active--
		p.mu.Unlock()
	}()
	defer remote.Close()
	p.track(local, remote)
	defer p.untrack(local, remote)
	type res struct {
		dir string
		n   int64
		err error
	}
	done := make(chan res, 2)
	go func() { n, err := io.Copy(remote, local); done <- res{"this PC → exit node", n, err} }()
	go func() { n, err := io.Copy(local, remote); done <- res{"exit node → this PC", n, err} }()
	r := <-done
	if ctx.Err() == nil {
		why := "closed"
		if r.err != nil {
			why = r.err.Error()
		}
		slog.Info("connection to the exit node ended", "after", time.Since(start).Round(time.Second), "first_direction_to_end", r.dir, "bytes", r.n, "reason", why)
	}
}

// Down reports that no connection to the exit node is open and the last
// attempt failed — the tunnel cannot carry traffic right now.
func (p *Proxy) Down() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.active == 0 && p.lastErr != nil
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
