package xhttp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	stdtrace "net/http/httptrace"
	"net/url"
	"strconv"
	"sync"

	cryptotls "crypto/tls"

	"golang.org/x/net/http2"

	"github.com/metacubex/mihomo/common/httputils"
)

type DialRawFunc func(ctx context.Context) (net.Conn, error)
type WrapTLSFunc func(ctx context.Context, conn net.Conn, isH2 bool) (net.Conn, error)

type TransportMaker func() stdhttp.RoundTripper

type PacketUpWriter struct {
	ctx       context.Context
	cancel    context.CancelFunc
	cfg       *Config
	sessionID string
	transport stdhttp.RoundTripper
	writeMu   sync.Mutex
	seq       uint64
}

func (c *PacketUpWriter) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	u := url.URL{
		Scheme: "https",
		Host:   c.cfg.Host,
		Path:   c.cfg.NormalizedPath(),
	}

	req, err := stdhttp.NewRequestWithContext(c.ctx, stdhttp.MethodPost, u.String(), nil)
	if err != nil {
		return 0, err
	}

	seqStr := strconv.FormatUint(c.seq, 10)
	c.seq++

	if err := c.cfg.FillPacketRequest(req, c.sessionID, seqStr, b); err != nil {
		return 0, err
	}
	req.Host = c.cfg.Host

	resp, err := c.transport.RoundTrip(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != stdhttp.StatusOK {
		return 0, fmt.Errorf("xhttp packet-up bad status: %s", resp.Status)
	}

	return len(b), nil
}

func (c *PacketUpWriter) Close() error {
	c.cancel()
	closeTransport(c.transport)
	return nil
}

func NewTransport(dialRaw DialRawFunc, wrapTLS WrapTLSFunc) stdhttp.RoundTripper {
	return &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *cryptotls.Config) (net.Conn, error) {
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

type Client struct {
	ctx                   context.Context
	cancel                context.CancelFunc
	mode                  string
	cfg                   *Config
	makeTransport         TransportMaker
	makeDownloadTransport TransportMaker
	uploadManager         *ReuseManager
	downloadManager       *ReuseManager
}

func NewClient(cfg *Config, makeTransport TransportMaker, makeDownloadTransport TransportMaker, hasReality bool) (*Client, error) {
	mode := cfg.EffectiveMode(hasReality)
	switch mode {
	case "stream-one", "stream-up", "packet-up":
	default:
		return nil, fmt.Errorf("xhttp mode %s is not implemented yet", mode)
	}
	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		mode:                  mode,
		cfg:                   cfg,
		makeTransport:         makeTransport,
		makeDownloadTransport: makeDownloadTransport,
		ctx:                   ctx,
		cancel:                cancel,
	}
	if cfg.ReuseConfig != nil {
		var err error
		client.uploadManager, err = NewReuseManager(cfg.ReuseConfig, makeTransport)
		if err != nil {
			return nil, err
		}
		if cfg.DownloadConfig != nil {
			if makeDownloadTransport == nil {
				return nil, fmt.Errorf("xhttp: download manager requires download transport maker")
			}
			client.downloadManager, err = NewReuseManager(cfg.DownloadConfig.ReuseConfig, makeDownloadTransport)
			if err != nil {
				return nil, err
			}
		}
	}
	return client, nil
}

func (c *Client) Close() error {
	c.cancel()
	var errs []error
	if c.uploadManager != nil {
		err := c.uploadManager.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	if c.downloadManager != nil {
		err := c.downloadManager.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *Client) Dial() (net.Conn, error) {
	return c.DialContext(c.ctx)
}

func (c *Client) DialContext(ctx context.Context) (net.Conn, error) {
	switch c.mode {
	case "stream-one":
		return c.dialStreamOne(ctx)
	case "stream-up":
		return c.dialStreamUp(ctx)
	case "packet-up":
		return c.dialPacketUp(ctx)
	default:
		return nil, fmt.Errorf("xhttp mode %s is not implemented yet", c.mode)
	}
}

func (c *Client) DialStreamOne() (net.Conn, error) { return c.dialStreamOne(c.ctx) }
func (c *Client) DialStreamUp() (net.Conn, error)  { return c.dialStreamUp(c.ctx) }
func (c *Client) DialPacketUp() (net.Conn, error)  { return c.dialPacketUp(c.ctx) }

// onlyRoundTripper is a wrapper that prevents the underlying transport from being closed.
type onlyRoundTripper struct {
	stdhttp.RoundTripper
}

func (c *Client) getTransport() (uploadTransport stdhttp.RoundTripper, downloadTransport stdhttp.RoundTripper, err error) {
	if c.uploadManager == nil {
		uploadTransport = c.makeTransport()
		downloadTransport = onlyRoundTripper{uploadTransport}
		if c.makeDownloadTransport != nil {
			downloadTransport = c.makeDownloadTransport()
		}
	} else {
		uploadTransport, err = c.uploadManager.GetTransport()
		if err != nil {
			return
		}

		downloadTransport = onlyRoundTripper{uploadTransport}
		if c.downloadManager != nil {
			downloadTransport, err = c.downloadManager.GetTransport()
			if err != nil {
				closeTransport(uploadTransport)
				return
			}
		}
	}
	return
}

func (c *Client) startRoundTrip(waitCtx context.Context, req *stdhttp.Request, transport stdhttp.RoundTripper, onGotConn func(stdtrace.GotConnInfo), handle func(resp *stdhttp.Response, err error)) error {
	gotConn := make(chan struct{})
	gotConnOnce := sync.Once{}
	readyErrCh := make(chan error, 1)

	req = req.WithContext(stdtrace.WithClientTrace(req.Context(), &stdtrace.ClientTrace{
		GotConn: func(info stdtrace.GotConnInfo) {
			if onGotConn != nil {
				onGotConn(info)
			}
			gotConnOnce.Do(func() {
				close(gotConn)
			})
		},
	}))

	go func() {
		resp, err := transport.RoundTrip(req)
		if err != nil {
			select {
			case readyErrCh <- err:
			default:
			}
		}
		gotConnOnce.Do(func() {
			close(gotConn)
		})
		handle(resp, err)
	}()

	select {
	case <-gotConn:
		return nil
	case err := <-readyErrCh:
		return err
	case <-waitCtx.Done():
		return waitCtx.Err()
	}
}

func (c *Client) dialStreamOne(waitCtx context.Context) (net.Conn, error) {
	transport, _, err := c.getTransport()
	if err != nil {
		return nil, err
	}

	requestURL := url.URL{
		Scheme: "https",
		Host:   c.cfg.Host,
		Path:   c.cfg.NormalizedPath(),
	}
	pr, pw := io.Pipe()
	connCtx, cancelConn := context.WithCancel(c.ctx)
	var localAddr net.Addr
	var remoteAddr net.Addr

	conn := &Conn{writer: pw}

	req, err := stdhttp.NewRequestWithContext(connCtx, stdhttp.MethodPost, requestURL.String(), pr)
	if err != nil {
		cancelConn()
		_ = pr.Close()
		_ = pw.Close()
		closeTransport(transport)
		return nil, err
	}
	req.Host = c.cfg.Host

	if err := c.cfg.FillStreamRequest(req, ""); err != nil {
		cancelConn()
		_ = pr.Close()
		_ = pw.Close()
		closeTransport(transport)
		return nil, err
	}

	wrc := newWaitReadCloser()
	if err := c.startRoundTrip(waitCtx, req, transport, func(info stdtrace.GotConnInfo) {
		localAddr = info.Conn.LocalAddr()
		remoteAddr = info.Conn.RemoteAddr()
	}, func(resp *stdhttp.Response, err error) {
		if err != nil {
			_ = pw.CloseWithError(err)
			wrc.closeWithError(err)
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			err = fmt.Errorf("xhttp stream-one bad status: %s", resp.Status)
			_ = resp.Body.Close()
			_ = pw.CloseWithError(err)
			wrc.closeWithError(err)
			return
		}
		wrc.set(resp.Body)
	}); err != nil {
		cancelConn()
		_ = pr.Close()
		_ = pw.Close()
		_ = wrc.Close()
		closeTransport(transport)
		return nil, err
	}
	conn.reader = wrc
	httputils.SetAddrs(&conn.NetAddr, localAddr, remoteAddr)
	conn.onClose = func() {
		cancelConn()
		_ = pr.Close()
		_ = wrc.Close()
		closeTransport(transport)
	}

	return conn, nil
}

func (c *Client) dialStreamUp(waitCtx context.Context) (net.Conn, error) {
	uploadTransport, downloadTransport, err := c.getTransport()
	if err != nil {
		return nil, err
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
	connCtx, cancelConn := context.WithCancel(c.ctx)
	var downloadLocalAddr net.Addr
	var downloadRemoteAddr net.Addr
	var uploadLocalAddr net.Addr
	var uploadRemoteAddr net.Addr

	conn := &Conn{writer: pw}

	sessionID := newSessionID()

	downloadReq, err := stdhttp.NewRequestWithContext(
		connCtx,
		stdhttp.MethodGet,
		downloadURL.String(),
		nil,
	)
	if err != nil {
		cancelConn()
		closeTransport(uploadTransport)
		closeTransport(downloadTransport)
		return nil, err
	}

	if err := downloadCfg.FillDownloadRequest(downloadReq, sessionID); err != nil {
		cancelConn()
		closeTransport(uploadTransport)
		closeTransport(downloadTransport)
		return nil, err
	}
	downloadReq.Host = downloadCfg.Host

	wrc := newWaitReadCloser()
	uploadDone := make(chan struct{})
	if err := c.startRoundTrip(waitCtx, downloadReq, downloadTransport, func(info stdtrace.GotConnInfo) {
		downloadLocalAddr = info.Conn.LocalAddr()
		downloadRemoteAddr = info.Conn.RemoteAddr()
	}, func(resp *stdhttp.Response, err error) {
		if err != nil {
			wrc.closeWithError(err)
			return
		}
		if resp.StatusCode != stdhttp.StatusOK {
			_ = resp.Body.Close()
			wrc.closeWithError(fmt.Errorf("xhttp stream-up download bad status: %s", resp.Status))
			return
		}
		wrc.set(resp.Body)
	}); err != nil {
		cancelConn()
		_ = pr.Close()
		_ = pw.Close()
		_ = wrc.Close()
		closeTransport(downloadTransport)
		go func() {
			<-uploadDone
			closeTransport(uploadTransport)
		}()
		return nil, err
	}

	uploadReq, err := stdhttp.NewRequestWithContext(
		connCtx,
		stdhttp.MethodPost,
		streamURL.String(),
		pr,
	)
	if err != nil {
		cancelConn()
		_ = pr.Close()
		_ = pw.Close()
		_ = wrc.Close()
		closeTransport(uploadTransport)
		closeTransport(downloadTransport)
		return nil, err
	}

	if err := c.cfg.FillStreamRequest(uploadReq, sessionID); err != nil {
		cancelConn()
		_ = pr.Close()
		_ = pw.Close()
		_ = wrc.Close()
		closeTransport(uploadTransport)
		closeTransport(downloadTransport)
		return nil, err
	}
	uploadReq.Host = c.cfg.Host

	if err := c.startRoundTrip(waitCtx, uploadReq, uploadTransport, func(info stdtrace.GotConnInfo) {
		uploadLocalAddr = info.Conn.LocalAddr()
		uploadRemoteAddr = info.Conn.RemoteAddr()
	}, func(resp *stdhttp.Response, err error) {
		defer close(uploadDone)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			_ = pw.CloseWithError(fmt.Errorf("xhttp stream-up upload bad status: %s", resp.Status))
		}
	}); err != nil {
		cancelConn()
		_ = pr.Close()
		_ = pw.Close()
		_ = wrc.Close()
		closeTransport(uploadTransport)
		closeTransport(downloadTransport)
		return nil, err
	}

	localAddr := downloadLocalAddr
	remoteAddr := downloadRemoteAddr
	if localAddr == nil {
		localAddr = uploadLocalAddr
	}
	if remoteAddr == nil {
		remoteAddr = uploadRemoteAddr
	}

	conn.reader = wrc
	httputils.SetAddrs(&conn.NetAddr, localAddr, remoteAddr)
	conn.onClose = func() {
		cancelConn()
		_ = pr.Close()
		_ = wrc.Close()
		if _, shared := downloadTransport.(onlyRoundTripper); shared {
			go func() {
				<-uploadDone
				closeTransport(uploadTransport)
			}()
			return
		}
		closeTransport(downloadTransport)
		go func() {
			<-uploadDone
			closeTransport(uploadTransport)
		}()
	}

	return conn, nil
}

func (c *Client) dialPacketUp(waitCtx context.Context) (net.Conn, error) {
	uploadTransport, downloadTransport, err := c.getTransport()
	if err != nil {
		return nil, err
	}

	downloadCfg := c.cfg
	if ds := c.cfg.DownloadConfig; ds != nil {
		downloadCfg = ds
	}
	sessionID := newSessionID()
	connCtx, cancelConn := context.WithCancel(c.ctx)
	var localAddr net.Addr
	var remoteAddr net.Addr

	downloadURL := url.URL{
		Scheme: "https",
		Host:   downloadCfg.Host,
		Path:   downloadCfg.NormalizedPath(),
	}

	writer := &PacketUpWriter{
		ctx:       connCtx,
		cancel:    cancelConn,
		cfg:       c.cfg,
		sessionID: sessionID,
		transport: uploadTransport,
		seq:       0,
	}
	conn := &Conn{writer: writer}

	downloadReq, err := stdhttp.NewRequestWithContext(
		connCtx,
		stdhttp.MethodGet,
		downloadURL.String(),
		nil,
	)
	if err != nil {
		cancelConn()
		closeTransport(uploadTransport)
		closeTransport(downloadTransport)
		return nil, err
	}
	if err := downloadCfg.FillDownloadRequest(downloadReq, sessionID); err != nil {
		cancelConn()
		closeTransport(uploadTransport)
		closeTransport(downloadTransport)
		return nil, err
	}
	downloadReq.Host = downloadCfg.Host

	wrc := newWaitReadCloser()
	if err := c.startRoundTrip(waitCtx, downloadReq, downloadTransport, func(info stdtrace.GotConnInfo) {
		localAddr = info.Conn.LocalAddr()
		remoteAddr = info.Conn.RemoteAddr()
	}, func(resp *stdhttp.Response, err error) {
		if err != nil {
			wrc.closeWithError(err)
			return
		}
		if resp.StatusCode != stdhttp.StatusOK {
			_ = resp.Body.Close()
			wrc.closeWithError(fmt.Errorf("xhttp packet-up download bad status: %s", resp.Status))
			return
		}
		wrc.set(resp.Body)
	}); err != nil {
		cancelConn()
		_ = wrc.Close()
		closeTransport(uploadTransport)
		closeTransport(downloadTransport)
		return nil, err
	}

	conn.reader = wrc
	httputils.SetAddrs(&conn.NetAddr, localAddr, remoteAddr)
	conn.onClose = func() {
		cancelConn()
		_ = wrc.Close()
		// uploadTransport already closed by writer
		closeTransport(downloadTransport)
	}

	return conn, nil
}

func newSessionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

type waitReadCloser struct {
	mu     sync.Mutex
	ch     chan struct{}
	reader io.ReadCloser
	err    error
}

func newWaitReadCloser() *waitReadCloser {
	return &waitReadCloser{ch: make(chan struct{})}
}

func (w *waitReadCloser) set(rc io.ReadCloser) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.reader != nil || w.err != nil {
		if rc != nil {
			_ = rc.Close()
		}
		return
	}
	w.reader = rc
	close(w.ch)
}

func (w *waitReadCloser) closeWithError(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.reader != nil || w.err != nil {
		return
	}
	w.err = err
	close(w.ch)
}

func (w *waitReadCloser) Read(b []byte) (int, error) {
	<-w.ch
	w.mu.Lock()
	err := w.err
	r := w.reader
	w.mu.Unlock()
	if err != nil {
		return 0, err
	}
	return r.Read(b)
}

func (w *waitReadCloser) Close() error {
	w.mu.Lock()
	if w.reader == nil && w.err == nil {
		w.err = io.ErrClosedPipe
		close(w.ch)
		w.mu.Unlock()
		return nil
	}
	err := w.err
	r := w.reader
	w.mu.Unlock()
	if err != nil {
		return nil
	}
	return r.Close()
}

type closeIdleTransport interface {
	CloseIdleConnections()
}

func closeTransport(roundTripper stdhttp.RoundTripper) {
	if tr, ok := roundTripper.(closeIdleTransport); ok {
		tr.CloseIdleConnections()
	}
	if tr, ok := roundTripper.(io.Closer); ok {
		_ = tr.Close()
	}
}
