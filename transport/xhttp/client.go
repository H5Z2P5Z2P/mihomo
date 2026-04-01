package xhttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/common/httputils"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptrace"
	"github.com/metacubex/tls"
)

type DialRawFunc func(ctx context.Context) (net.Conn, error)
type WrapTLSFunc func(ctx context.Context, conn net.Conn, isH2 bool) (net.Conn, error)

const (
	defaultPacketUpMaxUploadSize   = 256 * 1024
	defaultPacketUpMaxBufferedSize = 4 * defaultPacketUpMaxUploadSize
)

type PacketUpWriter struct {
	ctx         context.Context
	cancel      context.CancelFunc
	cfg         *Config
	sessionID   string
	transport   http.RoundTripper
	requestURL  url.URL
	queue       *packetUploadBuffer
	maxUploadSz int
	done        chan struct{}
	closeOnce   sync.Once
	postWG      sync.WaitGroup
	failOnce    sync.Once

	inFlightMu       sync.Mutex
	inFlightCond     *sync.Cond
	inFlightBytes    int
	maxInFlightBytes int
}

type packetUploadBuffer struct {
	mu       sync.Mutex
	cond     *sync.Cond
	buf      bytes.Buffer
	maxBytes int
	closed   bool
	err      error
}

func newPacketUploadBuffer(maxBytes int) *packetUploadBuffer {
	b := &packetUploadBuffer{maxBytes: maxBytes}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *packetUploadBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	written := 0
	for written < len(p) {
		for b.maxBytes > 0 && b.buf.Len() >= b.maxBytes && b.err == nil && !b.closed {
			b.cond.Wait()
		}

		if b.err != nil {
			return written, b.err
		}
		if b.closed {
			return written, io.ErrClosedPipe
		}

		chunkSize := len(p) - written
		if b.maxBytes > 0 {
			available := b.maxBytes - b.buf.Len()
			if available < chunkSize {
				chunkSize = available
			}
		}

		if chunkSize <= 0 {
			continue
		}

		_, _ = b.buf.Write(p[written : written+chunkSize])
		written += chunkSize
		b.cond.Broadcast()
	}

	return written, nil
}

func (b *packetUploadBuffer) ReadChunk(maxBytes int) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for b.buf.Len() == 0 && b.err == nil && !b.closed {
		b.cond.Wait()
	}

	if b.buf.Len() == 0 {
		if b.err != nil {
			return nil, b.err
		}
		return nil, io.EOF
	}

	chunkSize := b.buf.Len()
	if maxBytes > 0 && chunkSize > maxBytes {
		chunkSize = maxBytes
	}

	chunk := make([]byte, chunkSize)
	_, _ = b.buf.Read(chunk)
	b.cond.Broadcast()
	return chunk, nil
}

func (b *packetUploadBuffer) Close() error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	b.cond.Broadcast()
	return nil
}

func (b *packetUploadBuffer) CloseWithError(err error) error {
	if err == nil {
		err = io.ErrClosedPipe
	}

	b.mu.Lock()
	b.closed = true
	if b.err == nil {
		b.err = err
	}
	b.mu.Unlock()
	b.cond.Broadcast()
	return nil
}

func newPacketUpWriter(ctx context.Context, cancel context.CancelFunc, cfg *Config, sessionID string, transport http.RoundTripper) *PacketUpWriter {
	w := &PacketUpWriter{
		ctx:       ctx,
		cancel:    cancel,
		cfg:       cfg,
		sessionID: sessionID,
		transport: transport,
		requestURL: url.URL{
			Scheme: "https",
			Host:   cfg.Host,
			Path:   cfg.NormalizedPath(),
		},
		queue:            newPacketUploadBuffer(defaultPacketUpMaxBufferedSize),
		maxUploadSz:      defaultPacketUpMaxUploadSize,
		done:             make(chan struct{}),
		maxInFlightBytes: defaultPacketUpMaxBufferedSize,
	}
	w.inFlightCond = sync.NewCond(&w.inFlightMu)

	go w.run()
	return w
}

func (c *PacketUpWriter) run() {
	defer close(c.done)
	defer c.postWG.Wait()

	var seq uint64
	for {
		chunk, err := c.queue.ReadChunk(c.maxUploadSz)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || errors.Is(err, io.ErrClosedPipe) {
				return
			}
			c.fail(err)
			return
		}

		if err := c.reserveInFlight(len(chunk)); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || errors.Is(err, io.ErrClosedPipe) {
				return
			}
			c.fail(err)
			return
		}

		started := make(chan error, 1)
		c.postWG.Add(1)
		go func(seq uint64, payload []byte) {
			defer c.postWG.Done()
			defer c.releaseInFlight(len(payload))

			if err := c.postChunk(seq, payload, started); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, io.ErrClosedPipe) {
					return
				}
				c.fail(err)
			}
		}(seq, chunk)

		if err := <-started; err != nil {
			c.fail(err)
			return
		}

		seq++
	}
}

func (c *PacketUpWriter) reserveInFlight(n int) error {
	c.inFlightMu.Lock()
	defer c.inFlightMu.Unlock()

	for c.maxInFlightBytes > 0 && c.inFlightBytes+n > c.maxInFlightBytes {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		c.inFlightCond.Wait()
	}

	if err := c.ctx.Err(); err != nil {
		return err
	}

	c.inFlightBytes += n
	return nil
}

func (c *PacketUpWriter) releaseInFlight(n int) {
	c.inFlightMu.Lock()
	if n >= c.inFlightBytes {
		c.inFlightBytes = 0
	} else {
		c.inFlightBytes -= n
	}
	c.inFlightMu.Unlock()
	c.inFlightCond.Broadcast()
}

func (c *PacketUpWriter) postChunk(seq uint64, payload []byte, started chan<- error) error {
	var startedOnce sync.Once
	signalStarted := func(err error) {
		startedOnce.Do(func() {
			started <- err
		})
	}

	reqCtx := httptrace.WithClientTrace(c.ctx, &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			signalStarted(info.Err)
		},
	})

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.requestURL.String(), nil)
	if err != nil {
		signalStarted(err)
		return err
	}

	seqStr := strconv.FormatUint(seq, 10)

	if err := c.cfg.FillPacketRequest(req, c.sessionID, seqStr, payload); err != nil {
		signalStarted(err)
		return err
	}
	req.Host = c.cfg.Host

	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		signalStarted(err)
		return err
	}
	signalStarted(nil)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("xhttp packet-up bad status: %s", resp.Status)
	}

	return nil
}

func (c *PacketUpWriter) fail(err error) {
	c.failOnce.Do(func() {
		_ = c.queue.CloseWithError(err)
		c.cancel()
		httputils.CloseTransport(c.transport)
		c.inFlightCond.Broadcast()
	})
}

func (c *PacketUpWriter) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	return c.queue.Write(b)
}

func (c *PacketUpWriter) Close() error {
	c.closeOnce.Do(func() {
		_ = c.queue.Close()
		c.cancel()
		httputils.CloseTransport(c.transport)
		c.inFlightCond.Broadcast()
		<-c.done
	})
	return nil
}

func newConnContext(setupCtx context.Context) (context.Context, context.CancelFunc) {
	if setupCtx == nil {
		setupCtx = context.Background()
	}
	return context.WithCancel(contextutils.WithoutCancel(setupCtx))
}

func NewTransport(dialRaw DialRawFunc, wrapTLS WrapTLSFunc) http.RoundTripper {
	return &http.Http2Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			raw, err := dialRaw(ctx)
			if err != nil {
				return nil, err
			}
			wrapped, err := wrapTLS(ctx, raw, true)
			if err != nil {
				_ = raw.Close()
				return nil, err
			}
			return wrapped, nil
		},
	}
}

type waitReadCloser struct {
	wait chan struct{}
	once sync.Once

	mu  sync.Mutex
	rc  io.ReadCloser
	err error
}

func newWaitReadCloser() *waitReadCloser {
	return &waitReadCloser{wait: make(chan struct{})}
}

func (w *waitReadCloser) signal() {
	w.once.Do(func() {
		close(w.wait)
	})
}

func (w *waitReadCloser) Set(rc io.ReadCloser) {
	w.mu.Lock()
	if w.rc != nil || w.err != nil {
		w.mu.Unlock()
		_ = rc.Close()
		return
	}
	w.rc = rc
	w.mu.Unlock()
	w.signal()
}

func (w *waitReadCloser) Fail(err error) {
	if err == nil {
		err = io.ErrClosedPipe
	}

	w.mu.Lock()
	if w.rc != nil {
		_ = w.rc.Close()
		w.rc = nil
	}
	if w.err == nil {
		w.err = err
	}
	w.mu.Unlock()
	w.signal()
}

func (w *waitReadCloser) Read(b []byte) (int, error) {
	<-w.wait

	w.mu.Lock()
	rc := w.rc
	err := w.err
	w.mu.Unlock()

	if rc == nil {
		if err == nil {
			err = io.ErrClosedPipe
		}
		return 0, err
	}

	return rc.Read(b)
}

func (w *waitReadCloser) Close() error {
	w.mu.Lock()
	rc := w.rc
	w.rc = nil
	if w.err == nil {
		w.err = io.ErrClosedPipe
	}
	w.mu.Unlock()
	w.signal()

	if rc != nil {
		return rc.Close()
	}

	return nil
}

func openStream(connCtx context.Context, setupCtx context.Context, addr *httputils.NetAddr, cfg *Config, transport http.RoundTripper, requestURL url.URL, sessionID string, body io.Reader, uploadOnly bool, waitForRequestWrite bool, badStatusPrefix string) (io.ReadCloser, error) {
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}

	if addr != nil {
		connCtx = httputils.NewAddrContext(addr, connCtx)
	}

	reqCtx, reqCancel := context.WithCancel(connCtx)

	started := make(chan error, 1)
	var startedOnce sync.Once
	stopSetupWatch := make(chan struct{})
	signalStarted := func(err error) {
		startedOnce.Do(func() {
			close(stopSetupWatch)
			started <- err
		})
	}

	reqCtx = httptrace.WithClientTrace(reqCtx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) {
			if !waitForRequestWrite {
				signalStarted(nil)
			}
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if waitForRequestWrite {
				signalStarted(info.Err)
			}
		},
	})

	if setupCtx != nil {
		go func(watchCtx context.Context) {
			select {
			case <-stopSetupWatch:
			case <-watchCtx.Done():
			case <-setupCtx.Done():
				reqCancel()
			}
		}(reqCtx)
	}

	req, err := http.NewRequestWithContext(reqCtx, method, requestURL.String(), body)
	if err != nil {
		reqCancel()
		return nil, err
	}
	req.Host = cfg.Host

	if body == nil {
		if err := cfg.FillDownloadRequest(req, sessionID); err != nil {
			reqCancel()
			return nil, err
		}
	} else {
		if err := cfg.FillStreamRequest(req, sessionID); err != nil {
			reqCancel()
			return nil, err
		}
	}

	reader := newWaitReadCloser()

	go func() {
		resp, err := transport.RoundTrip(req)
		if err != nil {
			signalStarted(err)
			reqCancel()
			reader.Fail(err)
			return
		}

		signalStarted(nil)

		if uploadOnly {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			reqCancel()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				reader.Fail(fmt.Errorf("%s bad status: %s", badStatusPrefix, resp.Status))
				return
			}
			reader.Fail(io.ErrClosedPipe)
			return
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			reqCancel()
			reader.Fail(fmt.Errorf("%s bad status: %s", badStatusPrefix, resp.Status))
			return
		}

		reader.Set(resp.Body)
	}()

	if err := <-started; err != nil {
		reqCancel()
		return nil, err
	}

	return reader, nil
}

func DialStreamOneContext(setupCtx context.Context, cfg *Config, transport http.RoundTripper) (net.Conn, error) {
	requestURL := url.URL{
		Scheme: "https",
		Host:   cfg.Host,
		Path:   cfg.NormalizedPath(),
	}
	pr, pw := io.Pipe()

	connCtx, connCancel := newConnContext(setupCtx)
	conn := &Conn{writer: pw}

	reader, err := openStream(connCtx, setupCtx, &conn.NetAddr, cfg, transport, requestURL, "", pr, false, false, "xhttp stream-one")
	if err != nil {
		connCancel()
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(transport)
		return nil, err
	}
	conn.reader = reader
	conn.onClose = func() {
		connCancel()
		_ = pr.Close()
		httputils.CloseTransport(transport)
	}

	return conn, nil
}

func DialStreamOne(cfg *Config, transport http.RoundTripper) (net.Conn, error) {
	return DialStreamOneContext(context.Background(), cfg, transport)
}

func DialStreamUpContext(setupCtx context.Context, cfg *Config, uploadTransport http.RoundTripper, downloadTransport http.RoundTripper) (net.Conn, error) {
	downloadCfg := cfg
	if ds := cfg.DownloadConfig; ds != nil {
		downloadCfg = ds
	}

	streamURL := url.URL{
		Scheme: "https",
		Host:   cfg.Host,
		Path:   cfg.NormalizedPath(),
	}

	downloadURL := url.URL{
		Scheme: "https",
		Host:   downloadCfg.Host,
		Path:   downloadCfg.NormalizedPath(),
	}
	pr, pw := io.Pipe()

	connCtx, connCancel := newConnContext(setupCtx)
	conn := &Conn{writer: pw}

	sessionID := newSessionID()

	downloadReader, err := openStream(connCtx, setupCtx, &conn.NetAddr, downloadCfg, downloadTransport, downloadURL, sessionID, nil, false, true, "xhttp stream-up download")
	if err != nil {
		connCancel()
		httputils.CloseTransport(uploadTransport)
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
		return nil, err
	}
	conn.reader = downloadReader

	if _, err := openStream(connCtx, setupCtx, nil, cfg, uploadTransport, streamURL, sessionID, pr, true, false, "xhttp stream-up upload"); err != nil {
		connCancel()
		_ = downloadReader.Close()
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(uploadTransport)
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
		return nil, err
	}
	conn.onClose = func() {
		connCancel()
		_ = pr.Close()
		httputils.CloseTransport(uploadTransport)
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
	}

	return conn, nil
}

func DialStreamUp(cfg *Config, uploadTransport http.RoundTripper, downloadTransport http.RoundTripper) (net.Conn, error) {
	return DialStreamUpContext(context.Background(), cfg, uploadTransport, downloadTransport)
}

func DialPacketUpContext(setupCtx context.Context, cfg *Config, uploadTransport http.RoundTripper, downloadTransport http.RoundTripper) (net.Conn, error) {
	downloadCfg := cfg
	if ds := cfg.DownloadConfig; ds != nil {
		downloadCfg = ds
	}
	sessionID := newSessionID()

	downloadURL := url.URL{
		Scheme: "https",
		Host:   downloadCfg.Host,
		Path:   downloadCfg.NormalizedPath(),
	}

	connCtx, connCancel := newConnContext(setupCtx)
	writer := newPacketUpWriter(connCtx, connCancel, cfg, sessionID, uploadTransport)
	conn := &Conn{writer: writer}

	reader, err := openStream(connCtx, setupCtx, &conn.NetAddr, downloadCfg, downloadTransport, downloadURL, sessionID, nil, false, true, "xhttp packet-up download")
	if err != nil {
		connCancel()
		httputils.CloseTransport(uploadTransport)
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
		return nil, err
	}
	conn.reader = reader
	conn.onClose = func() {
		connCancel()
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
	}

	return conn, nil
}

func DialPacketUp(cfg *Config, uploadTransport http.RoundTripper, downloadTransport http.RoundTripper) (net.Conn, error) {
	return DialPacketUpContext(context.Background(), cfg, uploadTransport, downloadTransport)
}

func newSessionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
