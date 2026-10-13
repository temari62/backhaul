package transport

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// WSClient is a built-in replacement for the wstunnel *client*: it carries
// WireGuard's UDP datagrams to a wstunnel server over one WebSocket, speaking
// the same protocol as wstunnel v10 ("GET /<prefix>/events" upgrade with the
// tunnel described by a JWT in Sec-WebSocket-Protocol, one datagram per
// binary message). The exit node keeps running the real wstunnel server.
//
// Running it in-process avoids starting wstunnel.exe on the client, which
// crashed at start-up (0xc0000005) on some users' PCs, and needs no Visual
// C++ runtime.
type WSClient struct {
	o WSClientOptions

	mu       sync.Mutex
	pc       net.PacketConn
	peer     net.Addr // WireGuard's address, learnt from its packets
	sess     *wsSession
	dialing  bool
	backoff  time.Duration
	nextDial time.Time
	st       Status
	closed   bool
	pending  [][]byte // packets that arrived while connecting
}

// WSClientOptions configures a WSClient.
type WSClientOptions struct {
	// ServerAddr is "host:port" to connect to with plain TCP; Backhaul points
	// it at its local TLS proxy, which provides the TLS leg (pinned, or
	// verified for Cloudflare).
	ServerAddr string
	HostHeader string // Host of the upgrade request ("" = ServerAddr)
	PathPrefix string
	LocalUDP   string // where WireGuard sends ("127.0.0.1:51821")
	RemoteUDP  string // where the exit node delivers ("127.0.0.1:51820")
	DialTimeout,
	BackoffMin, BackoffMax time.Duration
	PingEvery time.Duration // WebSocket ping interval (keeps CDNs from idling it out)
}

// NewWSClient creates a WSClient.
func NewWSClient(o WSClientOptions) *WSClient {
	if o.DialTimeout == 0 {
		o.DialTimeout = 10 * time.Second
	}
	if o.BackoffMin == 0 {
		o.BackoffMin = 500 * time.Millisecond
	}
	if o.BackoffMax == 0 {
		o.BackoffMax = 30 * time.Second
	}
	if o.PingEvery == 0 {
		o.PingEvery = 30 * time.Second
	}
	return &WSClient{o: o, backoff: o.BackoffMin, st: Status{Kind: "wstunnel", State: "stopped"}}
}

// Kind implements Transport.
func (c *WSClient) Kind() string { return "wstunnel" }

// Start listens for WireGuard's packets; the tunnel is opened when the
// first one arrives (like wstunnel), and reopened after a drop.
func (c *WSClient) Start(ctx context.Context) error {
	pc, err := net.ListenPacket("udp", c.o.LocalUDP)
	if err != nil {
		return fmt.Errorf("listen %s: %w", c.o.LocalUDP, err)
	}
	c.mu.Lock()
	c.pc = pc
	c.st = Status{Kind: "wstunnel", State: "ready", Since: time.Now(), LocalUDP: pc.LocalAddr().String()}
	c.mu.Unlock()
	slog.Info("transport ready", "kind", "wstunnel", "role", "client", "impl", "built-in")
	go c.readUDP(ctx)
	go func() { <-ctx.Done(); c.Stop() }()
	return nil
}

// Status implements Transport.
func (c *WSClient) Status() Status {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.st
}

// Restart drops the current WebSocket; the next packet opens a new one.
func (c *WSClient) Restart() {
	c.mu.Lock()
	s := c.sess
	c.sess = nil
	c.st.Restarts++
	c.nextDial = time.Time{}
	c.mu.Unlock()
	if s != nil {
		s.close()
	}
}

// Stop implements Transport.
func (c *WSClient) Stop() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	pc, s := c.pc, c.sess
	c.sess = nil
	c.st.State = "stopped"
	c.mu.Unlock()
	if s != nil {
		s.close()
	}
	if pc != nil {
		closeAsync(pc)
	}
	return nil
}

// closeAsync closes without waiting: some Windows network hooks make Close
// block while a read is pending.
func closeAsync(c io.Closer) {
	done := make(chan struct{})
	go func() { c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

func (c *WSClient) readUDP(ctx context.Context) {
	buf := make([]byte, 65535)
	for {
		n, from, err := c.pc.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Windows reports an earlier ICMP "port unreachable" as a read
			// error (WSAECONNRESET) on UDP sockets; the socket still works.
			time.Sleep(10 * time.Millisecond)
			continue
		}
		c.mu.Lock()
		c.peer = from
		s := c.sess
		if s == nil && len(c.pending) < maxPending {
			// Sent once connected (queued under the same lock that publishes
			// the session, so none is lost); beyond that WireGuard retries.
			c.pending = append(c.pending, append([]byte(nil), buf[:n]...))
		}
		c.mu.Unlock()
		if s == nil {
			c.session(ctx)
			continue
		}
		s.send(buf[:n]) // never blocks: a stuck connection must not stall WireGuard
	}
}

// session returns the open session, or starts opening one in the
// background (respecting the back-off) and returns nil.
func (c *WSClient) session(ctx context.Context) *wsSession {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sess != nil || c.dialing || c.closed || time.Now().Before(c.nextDial) {
		return c.sess
	}
	c.dialing = true
	go func() {
		s, err := c.open(ctx)
		c.mu.Lock()
		c.dialing = false
		if err != nil || c.closed {
			c.st.LastError = errString(err)
			c.nextDial = time.Now().Add(c.backoff)
			slog.Warn("tunnel connection failed; retrying", "err", err, "in", c.backoff)
			c.backoff = min(c.backoff*2, c.o.BackoffMax)
			c.mu.Unlock()
			if s != nil {
				s.close()
			}
			return
		}
		c.sess, c.backoff, c.st.LastError = s, c.o.BackoffMin, ""
		queued := c.pending
		c.pending = nil
		c.mu.Unlock()
		go c.writeWS(s)
		for _, p := range queued {
			s.send(p)
		}
		go c.readWS(s)
		go c.pinger(s)
	}()
	return nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (c *WSClient) ended(s *wsSession, err error) {
	c.mu.Lock()
	if c.sess == s {
		c.sess = nil
		if !c.closed && err != nil {
			c.st.LastError = err.Error()
		}
	}
	c.mu.Unlock()
	s.close()
}

func (c *WSClient) readWS(s *wsSession) {
	for {
		op, payload, err := s.readMessage()
		if err != nil {
			c.ended(s, err)
			return
		}
		switch op {
		case opBinary:
			c.mu.Lock()
			pc, peer := c.pc, c.peer
			c.mu.Unlock()
			if peer != nil {
				pc.WriteTo(payload, peer)
			}
		case opPing:
			s.queue(opPong, payload)
		case opClose:
			c.ended(s, errors.New("the exit node closed the tunnel"))
			return
		}
	}
}

// writeWS is the session's only writer, so a blocked write (a dying
// connection) holds up nothing but this session.
func (c *WSClient) writeWS(s *wsSession) {
	for {
		select {
		case <-s.done:
			return
		case f := <-s.out:
			if err := s.write(f.op, f.p); err != nil {
				c.ended(s, err)
				return
			}
		}
	}
}

func (c *WSClient) pinger(s *wsSession) {
	t := time.NewTicker(c.o.PingEvery)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			s.queue(opPing, nil)
		}
	}
}

// open connects and performs the WebSocket upgrade.
func (c *WSClient) open(ctx context.Context) (*wsSession, error) {
	d := net.Dialer{Timeout: c.o.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", c.o.ServerAddr)
	if err != nil {
		return nil, err
	}
	host := c.o.HostHeader
	if host == "" {
		host = c.o.ServerAddr
	}
	jwt, err := tunnelJWT(c.o.RemoteUDP)
	if err != nil {
		conn.Close()
		return nil, err
	}
	var key [16]byte
	_, _ = rand.Read(key[:])
	wsKey := base64.StdEncoding.EncodeToString(key[:])
	path := "/events"
	if c.o.PathPrefix != "" {
		path = "/" + strings.Trim(c.o.PathPrefix, "/") + "/events"
	}
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + wsKey + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Protocol: v1, authorization.bearer." + jwt + "\r\n\r\n"
	_ = conn.SetDeadline(time.Now().Add(c.o.DialTimeout + 5*time.Second))
	if _, err := io.WriteString(conn, req); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("tunnel upgrade: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, fmt.Errorf("tunnel upgrade refused: %s", resp.Status)
	}
	if got, want := resp.Header.Get("Sec-WebSocket-Accept"), wsAccept(wsKey); got != want {
		conn.Close()
		return nil, fmt.Errorf("tunnel upgrade: bad Sec-WebSocket-Accept")
	}
	_ = conn.SetDeadline(time.Time{})
	return &wsSession{conn: conn, br: br, out: make(chan wsFrame, 256), done: make(chan struct{})}, nil
}

func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h[:])
}

// tunnelJWT describes the tunnel the way wstunnel v10 does: an HS256 JWT
// naming the protocol and where the exit node should deliver the datagrams.
// The wstunnel server reads it without checking the signature (it is a
// format, not a credential: the TLS pin or certificate and the secret path
// prefix are what protect the tunnel).
func tunnelJWT(remote string) (string, error) {
	host, portStr, err := net.SplitHostPort(remote)
	if err != nil {
		return "", err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", err
	}
	var id [16]byte
	_, _ = rand.Read(id[:])
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	u := hex.EncodeToString(id[:])
	claims, _ := json.Marshal(map[string]any{
		"id": u[0:8] + "-" + u[8:12] + "-" + u[12:16] + "-" + u[16:20] + "-" + u[20:],
		"p":  map[string]any{"Udp": map[string]any{"timeout": nil}},
		"r":  host,
		"rp": port,
	})
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString([]byte(`{"typ":"JWT","alg":"HS256"}`)) + "." + enc.EncodeToString(claims)
	mac := hmac.New(sha256.New, []byte(wstunnelJWTKey))
	mac.Write([]byte(signing))
	return signing + "." + enc.EncodeToString(mac.Sum(nil)), nil
}

const wstunnelJWTKey = "backhaul"

const maxPending = 16

// WebSocket opcodes.
const (
	opCont   = 0x0
	opBinary = 0x2
	opClose  = 0x8
	opPing   = 0x9
	opPong   = 0xA
)

type wsSession struct {
	conn net.Conn
	br   *bufio.Reader
	out  chan wsFrame // to writeWS
	once sync.Once
	done chan struct{}
}

type wsFrame struct {
	op byte
	p  []byte
}

func (s *wsSession) close() {
	s.once.Do(func() {
		close(s.done)
		closeAsync(s.conn)
	})
}

// send queues a datagram (copied); if the queue is full it is dropped, as
// a congested network would.
func (s *wsSession) send(p []byte) { s.queue(opBinary, append([]byte(nil), p...)) }

func (s *wsSession) queue(op byte, p []byte) {
	select {
	case s.out <- wsFrame{op, p}:
	case <-s.done:
	default:
	}
}

// write sends one frame (marked masked, as clients must).
func (s *wsSession) write(op byte, p []byte) error {
	var hdr [14]byte
	hdr[0] = 0x80 | op
	n := 2
	switch l := len(p); {
	case l < 126:
		hdr[1] = 0x80 | byte(l)
	case l <= 0xffff:
		hdr[1] = 0x80 | 126
		binary.BigEndian.PutUint16(hdr[2:], uint16(l))
		n = 4
	default:
		hdr[1] = 0x80 | 127
		binary.BigEndian.PutUint64(hdr[2:], uint64(l))
		n = 10
	}
	// Mask key of zeros, exactly like wstunnel's own client: the wstunnel
	// server does not unmask frames (it relies on this), and masking adds
	// nothing inside TLS anyway. XOR with zeros leaves the payload as is.
	n += 4 // hdr[n:n+4] is already zero
	frame := make([]byte, n+len(p))
	copy(frame, hdr[:n])
	copy(frame[n:], p)
	_, err := s.conn.Write(frame)
	return err
}

// readMessage returns the next complete message (control frames are
// returned as they come; data frames are reassembled).
func (s *wsSession) readMessage() (byte, []byte, error) {
	var msgOp byte
	var msg []byte
	for {
		var h [2]byte
		if _, err := io.ReadFull(s.br, h[:]); err != nil {
			return 0, nil, err
		}
		fin, op := h[0]&0x80 != 0, h[0]&0x0f
		masked, l := h[1]&0x80 != 0, uint64(h[1]&0x7f)
		switch l {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(s.br, b[:]); err != nil {
				return 0, nil, err
			}
			l = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(s.br, b[:]); err != nil {
				return 0, nil, err
			}
			l = binary.BigEndian.Uint64(b[:])
		}
		if l > 1<<20 {
			return 0, nil, fmt.Errorf("websocket frame too large (%d bytes)", l)
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(s.br, mask[:]); err != nil {
				return 0, nil, err
			}
		}
		p := make([]byte, l)
		if _, err := io.ReadFull(s.br, p); err != nil {
			return 0, nil, err
		}
		if masked {
			for i := range p {
				p[i] ^= mask[i&3]
			}
		}
		if op >= opClose { // control frame: never fragmented
			return op, p, nil
		}
		if op != opCont {
			msgOp, msg = op, p
		} else {
			msg = append(msg, p...)
		}
		if fin {
			return msgOp, msg, nil
		}
	}
}
