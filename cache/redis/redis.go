package redis

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/adeilh/go-rakh/cache"
)

// Store implements cache.Store using the Redis RESP protocol.
type Store struct {
	opts   Options
	dialFn dialFunc
	pool   chan *clientConn
}

type dialFunc func(context.Context, Options) (net.Conn, error)

// NewStore builds a Redis-backed cache store.
func NewStore(opts Options) *Store {
	cfg := opts.withDefaults()
	return &Store{opts: cfg, dialFn: defaultDial, pool: make(chan *clientConn, cfg.PoolSize)}
}

// WithDial allows overriding the dialer (useful for tests/mocks).
func (s *Store) WithDial(fn dialFunc) {
	if fn != nil {
		s.dialFn = fn
	}
}

func (s *Store) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}

	var payload []byte
	err := s.withConn(ctx, func(conn *clientConn) error {
		if err := s.send(conn, "GET", key); err != nil {
			return err
		}
		resp, err := s.read(conn)
		if err != nil {
			return err
		}
		switch v := resp.(type) {
		case nil:
			return cache.ErrNotFound
		case []byte:
			payload = append([]byte(nil), v...)
			return nil
		default:
			return fmt.Errorf("redis: unexpected GET response %T", resp)
		}
	})

	return payload, err
}

func (s *Store) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}

	return s.withConn(ctx, func(conn *clientConn) error {
		args := []string{"SET", key, string(value)}
		if ttl > 0 {
			ms := ttl.Milliseconds()
			if ms == 0 {
				ms = 1
			}
			args = append(args, "PX", strconv.FormatInt(ms, 10))
		}
		if err := s.send(conn, args...); err != nil {
			return err
		}
		resp, err := s.read(conn)
		if err != nil {
			return err
		}
		if msg, ok := resp.(string); ok && strings.EqualFold(msg, "OK") {
			return nil
		}
		return fmt.Errorf("redis: SET failed: %v", resp)
	})
}

func (s *Store) Delete(ctx context.Context, key string) error {
	if err := ctxErr(ctx); err != nil {
		return err
	}

	return s.withConn(ctx, func(conn *clientConn) error {
		if err := s.send(conn, "DEL", key); err != nil {
			return err
		}
		resp, err := s.read(conn)
		if err != nil {
			return err
		}
		switch v := resp.(type) {
		case int64:
			if v == 0 {
				return cache.ErrNotFound
			}
			return nil
		default:
			return fmt.Errorf("redis: DEL failed: %v", resp)
		}
	})
}

func (s *Store) withConn(ctx context.Context, fn func(*clientConn) error) error {
	conn, err := s.acquireConn(ctx)
	if err != nil {
		return err
	}
	broken := false
	defer func() {
		s.releaseConn(conn, broken)
	}()
	if err := fn(conn); err != nil {
		if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
			broken = true
		}
		return err
	}
	return nil
}

func (s *Store) dial(ctx context.Context) (net.Conn, error) {
	if s.dialFn == nil {
		s.dialFn = defaultDial
	}
	return s.dialFn(ctx, s.opts)
}

func (s *Store) handshake(conn net.Conn, reader *bufio.Reader) error {
	if s.opts.Password != "" {
		if err := s.sendRaw(conn, "AUTH", s.opts.Password); err != nil {
			return err
		}
		if err := s.expectOK(reader); err != nil {
			return err
		}
	}
	if s.opts.DB > 0 {
		if err := s.sendRaw(conn, "SELECT", strconv.Itoa(s.opts.DB)); err != nil {
			return err
		}
		if err := s.expectOK(reader); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) expectOK(reader *bufio.Reader) error {
	resp, err := decodeRESP(reader)
	if err != nil {
		return err
	}
	if msg, ok := resp.(string); ok && strings.EqualFold(msg, "OK") {
		return nil
	}
	return fmt.Errorf("redis: expected OK, got %v", resp)
}

func (s *Store) send(conn *clientConn, parts ...string) error {
	if err := applyDeadline(conn.SetWriteDeadline, s.opts.WriteTimeout); err != nil {
		return err
	}
	payload := buildCommand(parts...)
	_, err := conn.Write(payload)
	return err
}

func (s *Store) read(conn *clientConn) (any, error) {
	if err := applyDeadline(conn.SetReadDeadline, s.opts.ReadTimeout); err != nil {
		return nil, err
	}
	return decodeRESP(conn.reader)
}

// Pipeline acquires a dedicated connection and allows batching commands before
// reading their responses, reducing round-trips under load.
func (s *Store) Pipeline(ctx context.Context) (*Pipeline, error) {
	conn, err := s.acquireConn(ctx)
	if err != nil {
		return nil, err
	}
	return &Pipeline{store: s, conn: conn}, nil
}

type Pipeline struct {
	store   *Store
	conn    *clientConn
	cmds    [][]string
	closed  bool
	closing sync.Mutex
}

// Queue appends a command to the pipeline.
func (p *Pipeline) Queue(parts ...string) {
	if p.closed {
		return
	}
	p.cmds = append(p.cmds, append([]string(nil), parts...))
}

// Exec sends all queued commands and reads the replies in order.
func (p *Pipeline) Exec(ctx context.Context) ([]any, error) {
	if p.closed {
		return nil, errors.New("redis pipeline closed")
	}
	if len(p.cmds) == 0 {
		return nil, nil
	}
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	var broken bool
	defer func() {
		p.closeInternal(broken)
	}()
	for _, cmd := range p.cmds {
		if err := ctxErr(ctx); err != nil {
			return nil, err
		}
		if err := p.store.send(p.conn, cmd...); err != nil {
			broken = true
			return nil, err
		}
	}
	responses := make([]any, 0, len(p.cmds))
	for range p.cmds {
		if err := ctxErr(ctx); err != nil {
			return nil, err
		}
		resp, err := p.store.read(p.conn)
		if err != nil {
			broken = true
			return nil, err
		}
		responses = append(responses, resp)
	}
	return responses, nil
}

// Close releases the underlying connection without executing queued commands.
func (p *Pipeline) Close() {
	p.closeInternal(false)
}

func (p *Pipeline) closeInternal(broken bool) {
	p.closing.Lock()
	defer p.closing.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	p.store.releaseConn(p.conn, broken)
}

type clientConn struct {
	net.Conn
	reader *bufio.Reader
}

func (s *Store) acquireConn(ctx context.Context) (*clientConn, error) {
	select {
	case conn := <-s.pool:
		return conn, nil
	default:
		return s.newConn(ctx)
	}
}

func (s *Store) releaseConn(conn *clientConn, broken bool) {
	if conn == nil {
		return
	}
	if broken {
		_ = conn.Close()
		return
	}
	select {
	case s.pool <- conn:
	default:
		_ = conn.Close()
	}
}

func (s *Store) newConn(ctx context.Context) (*clientConn, error) {
	nc, err := s.dial(ctx)
	if err != nil {
		return nil, err
	}
	reader := bufio.NewReader(nc)
	if err := s.handshake(nc, reader); err != nil {
		_ = nc.Close()
		return nil, err
	}
	return &clientConn{Conn: nc, reader: reader}, nil
}

// sendRaw is used during handshake before the buffered reader is available.
func (s *Store) sendRaw(conn net.Conn, parts ...string) error {
	if err := applyDeadline(conn.SetWriteDeadline, s.opts.WriteTimeout); err != nil {
		return err
	}
	payload := buildCommand(parts...)
	_, err := conn.Write(payload)
	return err
}

func defaultDial(ctx context.Context, opts Options) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: opts.DialTimeout}
	return dialer.DialContext(ctx, "tcp", opts.Addr)
}

func buildCommand(parts ...string) []byte {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "*%d\r\n", len(parts))
	for _, part := range parts {
		fmt.Fprintf(buf, "$%d\r\n%s\r\n", len(part), part)
	}
	return buf.Bytes()
}

func decodeRESP(r *bufio.Reader) (any, error) {
	prefix, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	line = strings.TrimSuffix(line, "\r\n")
	switch prefix {
	case '+':
		return line, nil
	case '-':
		return nil, errors.New(line)
	case ':':
		n, err := strconv.ParseInt(line, 10, 64)
		if err != nil {
			return nil, err
		}
		return n, nil
	case '$':
		n, err := strconv.ParseInt(line, 10, 64)
		if err != nil {
			return nil, err
		}
		if n == -1 {
			return nil, nil
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(r, data); err != nil {
			return nil, err
		}
		if err := consumeCRLF(r); err != nil {
			return nil, err
		}
		return data, nil
	case '*':
		n, err := strconv.ParseInt(line, 10, 64)
		if err != nil {
			return nil, err
		}
		if n == -1 {
			return nil, nil
		}
		arr := make([]any, n)
		for i := 0; i < int(n); i++ {
			val, err := decodeRESP(r)
			if err != nil {
				return nil, err
			}
			arr[i] = val
		}
		return arr, nil
	default:
		return nil, fmt.Errorf("redis: unsupported RESP prefix %q", prefix)
	}
}

func consumeCRLF(r *bufio.Reader) error {
	b1, err := r.ReadByte()
	if err != nil {
		return err
	}
	b2, err := r.ReadByte()
	if err != nil {
		return err
	}
	if b1 != '\r' || b2 != '\n' {
		return errors.New("redis: malformed RESP terminator")
	}
	return nil
}

func applyDeadline(setter func(time.Time) error, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	return setter(time.Now().Add(timeout))
}

func ctxErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
