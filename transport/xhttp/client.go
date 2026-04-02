package xhttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/httputils"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptrace"
	"github.com/metacubex/tls"
)

type DialRawFunc func(ctx context.Context) (net.Conn, error)
type WrapTLSFunc func(ctx context.Context, conn net.Conn, isH2 bool) (net.Conn, error)

type TransportMaker func() http.RoundTripper

type PacketUpWriter struct {
	ctx       context.Context
	cfg       *Config
	sessionID string
	transport http.RoundTripper
	writeMu   sync.Mutex
	mu        sync.Mutex
	cond      *sync.Cond
	pending   [][]byte
	pendingN  int
	closed    bool
	err       error
	done      chan struct{}
	seq       uint64
}

func newPacketUpWriter(ctx context.Context, cfg *Config, sessionID string, transport http.RoundTripper) *PacketUpWriter {
	w := &PacketUpWriter{
		ctx:       ctx,
		cfg:       cfg,
		sessionID: sessionID,
		transport: transport,
		done:      make(chan struct{}),
	}
	w.cond = sync.NewCond(&w.mu)
	go w.run()
	return w
}

func (c *PacketUpWriter) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	var written int
	for len(b) > 0 {
		chunkLen := len(b)
		if chunkLen > xhttpPacketUpMaxEachPostBytes {
			chunkLen = xhttpPacketUpMaxEachPostBytes
		}

		chunk := make([]byte, chunkLen)
		copy(chunk, b[:chunkLen])

		c.mu.Lock()
		for c.err == nil && !c.closed && c.pendingN+len(chunk) > xhttpPacketUpMaxEachPostBytes {
			c.cond.Wait()
		}

		err := c.err
		closed := c.closed
		if err == nil && !closed {
			c.pending = append(c.pending, chunk)
			c.pendingN += len(chunk)
			c.cond.Signal()
		}
		c.mu.Unlock()

		if err != nil {
			return written, err
		}
		if closed {
			return written, io.ErrClosedPipe
		}

		written += chunkLen
		b = b[chunkLen:]
	}

	return written, nil
}

func (c *PacketUpWriter) run() {
	defer close(c.done)
	defer httputils.CloseTransport(c.transport)

	var lastPost time.Time
	for {
		batch, err := c.nextBatch()
		if err != nil {
			if err == io.EOF {
				return
			}
			c.setErr(err)
			return
		}

		if !lastPost.IsZero() {
			if wait := xhttpPacketUpMinPostsInterval - time.Since(lastPost); wait > 0 {
				timer := time.NewTimer(wait)
				select {
				case <-timer.C:
				case <-c.ctx.Done():
					if !timer.Stop() {
						<-timer.C
					}
					c.setErr(c.ctx.Err())
					return
				}
			}
		}
		lastPost = time.Now()

		if err := c.postBatch(batch); err != nil {
			c.setErr(err)
			return
		}
	}
}

func (c *PacketUpWriter) nextBatch() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for len(c.pending) == 0 {
		if c.err != nil {
			return nil, c.err
		}
		if c.closed {
			return nil, io.EOF
		}
		c.cond.Wait()
	}

	batchSize := c.pendingN
	if batchSize > xhttpPacketUpMaxEachPostBytes {
		batchSize = xhttpPacketUpMaxEachPostBytes
	}

	batch := make([]byte, 0, batchSize)
	for len(c.pending) > 0 && len(batch) < xhttpPacketUpMaxEachPostBytes {
		room := xhttpPacketUpMaxEachPostBytes - len(batch)
		chunk := c.pending[0]
		if len(chunk) <= room {
			batch = append(batch, chunk...)
			c.pending = c.pending[1:]
			c.pendingN -= len(chunk)
			continue
		}

		batch = append(batch, chunk[:room]...)
		c.pending[0] = chunk[room:]
		c.pendingN -= room
	}

	c.cond.Broadcast()
	return batch, nil
}

func (c *PacketUpWriter) postBatch(batch []byte) error {
	u := url.URL{
		Scheme: "https",
		Host:   c.cfg.Host,
		Path:   c.cfg.NormalizedPath(),
	}

	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return err
	}

	seqStr := strconv.FormatUint(c.seq, 10)
	c.seq++

	if err := c.cfg.FillPacketRequest(req, c.sessionID, seqStr, batch); err != nil {
		return err
	}
	req.Host = c.cfg.Host

	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("xhttp packet-up bad status: %s", resp.Status)
	}

	return nil
}

func (c *PacketUpWriter) setErr(err error) {
	if err == nil {
		err = io.ErrClosedPipe
	}

	c.mu.Lock()
	if c.err == nil {
		c.err = err
	}
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
}

func (c *PacketUpWriter) Close() error {
	c.mu.Lock()
	c.closed = true
	c.cond.Broadcast()
	c.mu.Unlock()
	<-c.done
	return nil
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

func openStream(ctx context.Context, addr *httputils.NetAddr, cfg *Config, transport http.RoundTripper, requestURL url.URL, sessionID string, body io.Reader, uploadOnly bool, waitForRequestWrite bool, badStatusPrefix string) (io.ReadCloser, error) {
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}

	if addr != nil {
		ctx = httputils.NewAddrContext(addr, ctx)
	}

	started := make(chan error, 1)
	var startedOnce sync.Once
	signalStarted := func(err error) {
		startedOnce.Do(func() {
			started <- err
		})
	}

	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
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

	req, err := http.NewRequestWithContext(ctx, method, requestURL.String(), body)
	if err != nil {
		return nil, err
	}
	req.Host = cfg.Host

	if body == nil {
		if err := cfg.FillDownloadRequest(req, sessionID); err != nil {
			return nil, err
		}
	} else {
		if err := cfg.FillStreamRequest(req, sessionID); err != nil {
			return nil, err
		}
	}

	reader := newWaitReadCloser()

	go func() {
		resp, err := transport.RoundTrip(req)
		if err != nil {
			signalStarted(err)
			reader.Fail(err)
			return
		}

		signalStarted(nil)

		if uploadOnly {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				reader.Fail(fmt.Errorf("%s bad status: %s", badStatusPrefix, resp.Status))
				return
			}
			reader.Fail(io.ErrClosedPipe)
			return
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = resp.Body.Close()
			reader.Fail(fmt.Errorf("%s bad status: %s", badStatusPrefix, resp.Status))
			return
		}

		reader.Set(resp.Body)
	}()

	if err := <-started; err != nil {
		return nil, err
	}

	return reader, nil
}

type Client struct {
	mode                  string
	cfg                   *Config
	makeTransport         TransportMaker
	makeDownloadTransport TransportMaker
	ctx                   context.Context
	cancel                context.CancelFunc
}

func NewClient(cfg *Config, makeTransport TransportMaker, makeDownloadTransport TransportMaker, hasReality bool) (*Client, error) {
	mode := cfg.EffectiveMode(hasReality)
	switch mode {
	case "stream-one", "stream-up", "packet-up":
	default:
		return nil, fmt.Errorf("xhttp mode %s is not implemented yet", mode)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{
		mode:                  mode,
		cfg:                   cfg,
		makeTransport:         makeTransport,
		makeDownloadTransport: makeDownloadTransport,
		ctx:                   ctx,
		cancel:                cancel,
	}, nil
}

func (c *Client) Dial() (net.Conn, error) {
	switch c.mode {
	case "stream-one":
		return c.DialStreamOne()
	case "stream-up":
		return c.DialStreamUp()
	case "packet-up":
		return c.DialPacketUp()
	default:
		return nil, fmt.Errorf("xhttp mode %s is not implemented yet", c.mode)
	}
}

func (c *Client) Close() error {
	c.cancel()
	return nil
}

func (c *Client) DialStreamOne() (net.Conn, error) {
	transport := c.makeTransport()

	requestURL := url.URL{
		Scheme: "https",
		Host:   c.cfg.Host,
		Path:   c.cfg.NormalizedPath(),
	}
	pr, pw := io.Pipe()

	conn := &Conn{writer: pw}

	req, err := http.NewRequestWithContext(httputils.NewAddrContext(&conn.NetAddr, c.ctx), http.MethodPost, requestURL.String(), pr)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	req.Host = c.cfg.Host

	if err := c.cfg.FillStreamRequest(req, ""); err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(transport)
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_ = resp.Body.Close()
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(transport)
		return nil, fmt.Errorf("xhttp stream-one bad status: %s", resp.Status)
	}
	conn.reader = resp.Body
	conn.onClose = func() {
		_ = pr.Close()
		httputils.CloseTransport(transport)
	}

	return conn, nil
}

func (c *Client) DialStreamUp() (net.Conn, error) {
	uploadTransport := c.makeTransport()
	downloadTransport := uploadTransport
	if c.makeDownloadTransport != nil {
		downloadTransport = c.makeDownloadTransport()
	}

	downloadCfg := c.cfg
	if ds := c.cfg.DownloadConfig; ds != nil {
		downloadCfg = ds
	}

	streamURL := url.URL{
		Scheme: "https",
		Host:   c.cfg.Host,
		Path:   c.cfg.NormalizedPath(),
	}

	downloadURL := url.URL{
		Scheme: "https",
		Host:   downloadCfg.Host,
		Path:   downloadCfg.NormalizedPath(),
	}
	pr, pw := io.Pipe()

	conn := &Conn{writer: pw}

	sessionID := newSessionID()

	downloadReader, err := openStream(c.ctx, &conn.NetAddr, downloadCfg, downloadTransport, downloadURL, sessionID, nil, false, true, "xhttp stream-up download")
	if err != nil {
		httputils.CloseTransport(uploadTransport)
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
		return nil, err
	}
	conn.reader = downloadReader

	if _, err := openStream(c.ctx, nil, c.cfg, uploadTransport, streamURL, sessionID, pr, true, false, "xhttp stream-up upload"); err != nil {
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
		_ = pr.Close()
		httputils.CloseTransport(uploadTransport)
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
	}

	return conn, nil
}

func (c *Client) DialPacketUp() (net.Conn, error) {
	uploadTransport := c.makeTransport()
	downloadTransport := uploadTransport
	if c.makeDownloadTransport != nil {
		downloadTransport = c.makeDownloadTransport()
	}

	downloadCfg := c.cfg
	if ds := c.cfg.DownloadConfig; ds != nil {
		downloadCfg = ds
	}
	sessionID := newSessionID()

	downloadURL := url.URL{
		Scheme: "https",
		Host:   downloadCfg.Host,
		Path:   downloadCfg.NormalizedPath(),
	}

	writer := newPacketUpWriter(c.ctx, c.cfg, sessionID, uploadTransport)
	conn := &Conn{writer: writer}

	resp, err := openStream(c.ctx, &conn.NetAddr, downloadCfg, downloadTransport, downloadURL, sessionID, nil, false, false, "xhttp packet-up download")
	if err != nil {
		_ = writer.Close()
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
		return nil, err
	}
	conn.reader = resp
	conn.onClose = func() {
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
	}

	return conn, nil
}

func newSessionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
