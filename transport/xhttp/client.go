package xhttp

import (
	"bytes"
	"context"
	cryptotls "crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptrace"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	xquic "github.com/apernet/quic-go"
	xhttp3 "github.com/apernet/quic-go/http3"
	"golang.org/x/net/http2"

	"github.com/metacubex/mihomo/common/httputils"
	xbuf "github.com/xtls/xray-core/common/buf"
	xraynet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/uuid"
	xsplithttp "github.com/xtls/xray-core/transport/internet/splithttp"
)

type DialRawFunc func(ctx context.Context) (net.Conn, error)
type WrapTLSFunc func(ctx context.Context, conn net.Conn, isH2 bool) (net.Conn, error)
type DialPacketFunc func(ctx context.Context) (net.PacketConn, net.Addr, error)

type TransportMaker func() stdhttp.RoundTripper

const (
	HTTPVersion11 = "1.1"
	HTTPVersion2  = "2"
	HTTPVersion3  = "3"
)

type TransportOption struct {
	HTTPVersion     string
	DialRaw         DialRawFunc
	WrapTLS         WrapTLSFunc
	DialPacket      DialPacketFunc
	KeepAlivePeriod time.Duration
	QUICKeepAlive   time.Duration
	QUICMaxIdle     time.Duration
	TLSClientConfig *cryptotls.Config
	PrepareTLS      func(ctx context.Context, cfg *cryptotls.Config) error
}

func NormalizeALPN(nextProtos []string) []string {
	if len(nextProtos) == 0 {
		return []string{"h2", "http/1.1"}
	}
	return slices.Clone(nextProtos)
}

func DecideHTTPVersion(hasTLS bool, nextProtos []string, hasReality bool) string {
	if hasReality {
		return HTTPVersion2
	}
	if !hasTLS {
		return HTTPVersion11
	}
	if len(nextProtos) != 1 {
		return HTTPVersion2
	}
	if nextProtos[0] == "http/1.1" {
		return HTTPVersion11
	}
	if nextProtos[0] == "h3" {
		return HTTPVersion3
	}
	return HTTPVersion2
}

type packetUpWriter struct {
	ctx        context.Context
	cancel     context.CancelFunc
	client     *dialerClient
	xmuxClient *xsplithttp.XmuxClient
	requestURL string
	sessionID  string
	writeMu    sync.Mutex
	seq        uint64
}

func (w *packetUpWriter) Write(b []byte) (int, error) {
	select {
	case <-w.ctx.Done():
		return 0, io.ErrClosedPipe
	default:
	}

	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	seqStr := strconv.FormatUint(w.seq, 10)
	w.seq++

	if w.xmuxClient != nil {
		w.xmuxClient.LeftRequests.Add(-1)
	}

	payload := xbuf.MergeBytes(nil, b)
	err := w.client.PostPacket(w.ctx, w.requestURL, w.sessionID, seqStr, payload)
	xbuf.ReleaseMulti(payload)
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

func (w *packetUpWriter) Close() error {
	w.cancel()
	return nil
}

type transportMetadata interface {
	httpVersion() string
	dialUploadConn(ctx context.Context) (net.Conn, error)
}

type managedTransport struct {
	inner              stdhttp.RoundTripper
	version            string
	dialUploadConnFunc func(ctx context.Context) (net.Conn, error)
}

func (t *managedTransport) RoundTrip(req *stdhttp.Request) (*stdhttp.Response, error) {
	return t.inner.RoundTrip(req)
}

func (t *managedTransport) CloseIdleConnections() {
	if tr, ok := t.inner.(interface{ CloseIdleConnections() }); ok {
		tr.CloseIdleConnections()
	}
}

func (t *managedTransport) Close() error {
	if tr, ok := t.inner.(io.Closer); ok {
		return tr.Close()
	}
	return nil
}

func (t *managedTransport) httpVersion() string {
	return t.version
}

func (t *managedTransport) dialUploadConn(ctx context.Context) (net.Conn, error) {
	if t.dialUploadConnFunc == nil {
		return nil, errors.New("xhttp: h1 upload dialer is not configured")
	}
	return t.dialUploadConnFunc(ctx)
}

func NewTransport(opt TransportOption) stdhttp.RoundTripper {
	var transport stdhttp.RoundTripper
	var dialUploadConn func(ctx context.Context) (net.Conn, error)

	switch opt.HTTPVersion {
	case HTTPVersion11:
		dialUploadConn = func(ctx context.Context) (net.Conn, error) {
			return dialTransportConn(ctx, opt.DialRaw, opt.WrapTLS, false)
		}
		transport = &stdhttp.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialTransportConn(ctx, opt.DialRaw, opt.WrapTLS, false)
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialTransportConn(ctx, opt.DialRaw, opt.WrapTLS, false)
			},
			ForceAttemptHTTP2: false,
			IdleConnTimeout:   xraynet.ConnIdleTimeout,
			DisableKeepAlives: true,
		}
	case HTTPVersion3:
		quicMaxIdle := opt.QUICMaxIdle
		if quicMaxIdle == 0 {
			quicMaxIdle = xraynet.ConnIdleTimeout
		}
		if quicMaxIdle < 0 {
			quicMaxIdle = 0
		}

		quicKeepAlive := opt.QUICKeepAlive
		if quicKeepAlive == 0 {
			quicKeepAlive = xraynet.QuicgoH3KeepAlivePeriod
		}
		if quicKeepAlive < 0 {
			quicKeepAlive = 0
		}

		quicConfig := &xquic.Config{
			MaxIdleTimeout:  quicMaxIdle,
			KeepAlivePeriod: quicKeepAlive,
		}
		transport = &xhttp3.Transport{
			QUICConfig:      quicConfig,
			TLSClientConfig: opt.TLSClientConfig,
			Dial: func(ctx context.Context, addr string, tlsCfg *cryptotls.Config, cfg *xquic.Config) (*xquic.Conn, error) {
				if opt.DialPacket == nil {
					return nil, errors.New("xhttp: h3 packet dialer is not configured")
				}
				if opt.PrepareTLS != nil {
					if err := opt.PrepareTLS(ctx, tlsCfg); err != nil {
						return nil, err
					}
				}
				packetConn, remoteAddr, err := opt.DialPacket(ctx)
				if err != nil {
					return nil, err
				}
				return xquic.DialEarly(ctx, packetConn, remoteAddr, tlsCfg, cfg)
			},
		}
	default:
		keepAlivePeriod := opt.KeepAlivePeriod
		if keepAlivePeriod == 0 {
			keepAlivePeriod = xraynet.ChromeH2KeepAlivePeriod
		}
		if keepAlivePeriod < 0 {
			keepAlivePeriod = 0
		}
		transport = &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, _ *cryptotls.Config) (net.Conn, error) {
				return dialTransportConn(ctx, opt.DialRaw, opt.WrapTLS, true)
			},
			IdleConnTimeout: xraynet.ConnIdleTimeout,
			ReadIdleTimeout: keepAlivePeriod,
		}
	}

	return &managedTransport{
		inner:              transport,
		version:            opt.HTTPVersion,
		dialUploadConnFunc: dialUploadConn,
	}
}

func dialTransportConn(ctx context.Context, dialRaw DialRawFunc, wrapTLS WrapTLSFunc, isH2 bool) (net.Conn, error) {
	if dialRaw == nil {
		return nil, errors.New("xhttp: transport dialer is not configured")
	}
	raw, err := dialRaw(ctx)
	if err != nil {
		return nil, err
	}
	if wrapTLS == nil {
		return raw, nil
	}
	wrapped, err := wrapTLS(ctx, raw, isH2)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return wrapped, nil
}

type endpointManager struct {
	cfg           *xsplithttp.Config
	requestURL    string
	makeTransport TransportMaker
	xmux          *xsplithttp.XmuxManager

	mu      sync.Mutex
	clients []*dialerClient
}

func newEndpointManager(cfg *Config, makeTransport TransportMaker) (*endpointManager, error) {
	xrayCfg, err := cfg.XrayConfig()
	if err != nil {
		return nil, err
	}

	requestURL := url.URL{
		Scheme:   cfg.RequestScheme(),
		Host:     xrayCfg.Host,
		Path:     xrayCfg.GetNormalizedPath(),
		RawQuery: xrayCfg.GetNormalizedQuery(),
	}

	m := &endpointManager{
		cfg:           xrayCfg,
		requestURL:    requestURL.String(),
		makeTransport: makeTransport,
	}

	if xrayCfg.Xmux != nil {
		m.xmux = xsplithttp.NewXmuxManager(*xrayCfg.Xmux, func() xsplithttp.XmuxConn {
			return m.newDialerClientLocked()
		})
	}

	return m, nil
}

func (m *endpointManager) newDialerClientLocked() *dialerClient {
	transport := m.makeTransport()
	client := &dialerClient{
		cfg:       m.cfg,
		transport: transport,
	}
	if meta, ok := transport.(transportMetadata); ok {
		client.httpVersion = meta.httpVersion()
		client.dialUploadConn = meta.dialUploadConn
		if client.httpVersion == HTTPVersion11 && client.dialUploadConn != nil {
			client.uploadRawAll = make(map[*H1Conn]struct{})
		}
	}
	client.client = &stdhttp.Client{Transport: client.transport}
	m.clients = append(m.clients, client)
	return client
}

func (m *endpointManager) acquire(ctx context.Context) acquiredSession {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.xmux == nil {
		return acquiredSession{client: m.newDialerClientLocked()}
	}

	xmuxClient := m.xmux.GetXmuxClient(ctx)
	client, _ := xmuxClient.XmuxConn.(*dialerClient)
	return acquiredSession{client: client, xmuxClient: xmuxClient}
}

func (m *endpointManager) Close() error {
	if m == nil {
		return nil
	}

	m.mu.Lock()
	clients := m.clients
	m.clients = nil
	m.mu.Unlock()

	var errs []error
	for _, client := range clients {
		if client == nil {
			continue
		}
		if err := client.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

type dialerClient struct {
	cfg            *xsplithttp.Config
	transport      stdhttp.RoundTripper
	client         *stdhttp.Client
	httpVersion    string
	dialUploadConn func(ctx context.Context) (net.Conn, error)
	uploadRawMu    sync.Mutex
	uploadRawIdle  []*H1Conn
	uploadRawAll   map[*H1Conn]struct{}
	closed         atomic.Bool
	closeOnce      sync.Once
}

func (c *dialerClient) IsClosed() bool {
	return c.closed.Load()
}

func (c *dialerClient) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		c.closeH1UploadConns()
		closeTransport(c.transport)
	})
	return nil
}

func (c *dialerClient) getH1UploadConn(ctx context.Context) (*H1Conn, bool, error) {
	c.uploadRawMu.Lock()
	if n := len(c.uploadRawIdle); n > 0 {
		conn := c.uploadRawIdle[n-1]
		c.uploadRawIdle = c.uploadRawIdle[:n-1]
		c.uploadRawMu.Unlock()
		return conn, false, nil
	}
	c.uploadRawMu.Unlock()

	if c.dialUploadConn == nil {
		return nil, false, errors.New("xhttp: h1 upload dialer is not configured")
	}

	raw, err := c.dialUploadConn(ctx)
	if err != nil {
		return nil, true, err
	}
	conn := NewH1Conn(raw)

	c.uploadRawMu.Lock()
	defer c.uploadRawMu.Unlock()
	if c.uploadRawAll == nil {
		_ = conn.Close()
		return nil, true, io.ErrClosedPipe
	}
	c.uploadRawAll[conn] = struct{}{}
	return conn, true, nil
}

func (c *dialerClient) putH1UploadConn(conn *H1Conn) {
	if conn == nil {
		return
	}

	c.uploadRawMu.Lock()
	defer c.uploadRawMu.Unlock()
	if c.uploadRawAll == nil {
		_ = conn.Close()
		return
	}
	if _, ok := c.uploadRawAll[conn]; !ok {
		_ = conn.Close()
		return
	}
	c.uploadRawIdle = append(c.uploadRawIdle, conn)
}

func (c *dialerClient) dropH1UploadConn(conn *H1Conn) {
	if conn == nil {
		return
	}

	c.uploadRawMu.Lock()
	if c.uploadRawAll != nil {
		delete(c.uploadRawAll, conn)
	}
	for i := len(c.uploadRawIdle) - 1; i >= 0; i-- {
		if c.uploadRawIdle[i] == conn {
			c.uploadRawIdle = append(c.uploadRawIdle[:i], c.uploadRawIdle[i+1:]...)
			break
		}
	}
	c.uploadRawMu.Unlock()

	_ = conn.Close()
}

func (c *dialerClient) closeH1UploadConns() {
	c.uploadRawMu.Lock()
	all := c.uploadRawAll
	c.uploadRawAll = nil
	c.uploadRawIdle = nil
	c.uploadRawMu.Unlock()

	for conn := range all {
		_ = conn.Close()
	}
}

func (c *dialerClient) OpenStream(ctx context.Context, requestURL string, sessionID string, body io.Reader, uploadOnly bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	var remoteAddr net.Addr
	var localAddr net.Addr
	var gotConn atomic.Bool

	gotConnCh := make(chan struct{})
	gotConnOnce := sync.Once{}
	readyErrCh := make(chan error, 1)

	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr = connInfo.Conn.RemoteAddr()
			localAddr = connInfo.Conn.LocalAddr()
			gotConn.Store(true)
			gotConnOnce.Do(func() {
				close(gotConnCh)
			})
		},
	})

	method := stdhttp.MethodGet
	if body != nil {
		method = c.cfg.GetNormalizedUplinkHTTPMethod()
	}

	req, err := stdhttp.NewRequestWithContext(context.WithoutCancel(ctx), method, requestURL, body)
	if err != nil {
		return nil, nil, nil, err
	}
	c.cfg.FillStreamRequest(req, sessionID, "")
	if c.cfg.Host != "" {
		req.Host = c.cfg.Host
	}

	wrc := &xsplithttp.WaitReadCloser{Wait: make(chan struct{})}
	go func() {
		resp, err := c.client.Do(req)
		if err != nil {
			if !uploadOnly {
				c.closed.Store(true)
			}
			if !gotConn.Load() {
				select {
				case readyErrCh <- err:
				default:
				}
			}
			wrc.Close()
			return
		}

		if resp.StatusCode != stdhttp.StatusOK || uploadOnly {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			wrc.Close()
			return
		}

		wrc.Set(resp.Body)
	}()

	select {
	case <-gotConnCh:
		return wrc, remoteAddr, localAddr, nil
	case err := <-readyErrCh:
		return nil, nil, nil, err
	case <-ctx.Done():
		return nil, nil, nil, ctx.Err()
	}
}

func (c *dialerClient) PostPacket(ctx context.Context, requestURL string, sessionID string, seqStr string, payload xbuf.MultiBuffer) error {
	req, err := stdhttp.NewRequestWithContext(context.WithoutCancel(ctx), c.cfg.GetNormalizedUplinkHTTPMethod(), requestURL, nil)
	if err != nil {
		return err
	}
	if err := c.cfg.FillPacketRequest(req, sessionID, seqStr, payload); err != nil {
		return err
	}
	if c.cfg.Host != "" {
		req.Host = c.cfg.Host
	}

	if c.httpVersion == HTTPVersion11 && c.dialUploadConn != nil {
		requestBuf := bytes.NewBuffer(make([]byte, 0, 512+len(payload)))
		if err := req.Write(requestBuf); err != nil {
			c.closed.Store(true)
			return err
		}

		for {
			uploadConn, newConn, err := c.getH1UploadConn(context.WithoutCancel(ctx))
			if err != nil {
				c.closed.Store(true)
				return err
			}

			if err := uploadConn.DrainResponse(req); err != nil {
				c.dropH1UploadConn(uploadConn)
				if newConn {
					c.closed.Store(true)
					return fmt.Errorf("xhttp packet-up read response: %w", err)
				}
				continue
			}

			if _, err := uploadConn.Write(requestBuf.Bytes()); err != nil {
				c.dropH1UploadConn(uploadConn)
				if newConn {
					c.closed.Store(true)
					return err
				}
				continue
			}

			uploadConn.PendingResponses++
			c.putH1UploadConn(uploadConn)
			return nil
		}
	}

	resp, err := c.client.Do(req)
	if err != nil {
		c.closed.Store(true)
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != stdhttp.StatusOK {
		return fmt.Errorf("xhttp packet-up bad status: %s", resp.Status)
	}

	return nil
}

type acquiredSession struct {
	client     *dialerClient
	xmuxClient *xsplithttp.XmuxClient
}

func holdSessions(sessions ...acquiredSession) {
	seen := map[*xsplithttp.XmuxClient]struct{}{}
	for _, session := range sessions {
		if session.xmuxClient == nil {
			continue
		}
		if _, ok := seen[session.xmuxClient]; ok {
			continue
		}
		seen[session.xmuxClient] = struct{}{}
		session.xmuxClient.OpenUsage.Add(1)
	}
}

func releaseSessions(sessions ...acquiredSession) {
	seenXmux := map[*xsplithttp.XmuxClient]struct{}{}
	seenClient := map[*dialerClient]struct{}{}
	for _, session := range sessions {
		if session.client == nil {
			continue
		}
		if session.xmuxClient != nil {
			if _, ok := seenXmux[session.xmuxClient]; ok {
				continue
			}
			seenXmux[session.xmuxClient] = struct{}{}
			session.xmuxClient.OpenUsage.Add(-1)
			continue
		}
		if _, ok := seenClient[session.client]; ok {
			continue
		}
		seenClient[session.client] = struct{}{}
		_ = session.client.Close()
	}
}

func consumeRequestBudget(session acquiredSession) {
	if session.xmuxClient != nil {
		session.xmuxClient.LeftRequests.Add(-1)
	}
}

func closeTransport(roundTripper stdhttp.RoundTripper) {
	if roundTripper == nil {
		return
	}
	if tr, ok := roundTripper.(interface{ CloseIdleConnections() }); ok {
		tr.CloseIdleConnections()
	}
	if tr, ok := roundTripper.(io.Closer); ok {
		_ = tr.Close()
	}
}

type Client struct {
	ctx              context.Context
	cancel           context.CancelFunc
	mode             string
	uploadEndpoint   *endpointManager
	downloadEndpoint *endpointManager
}

func NewClient(cfg *Config, makeTransport TransportMaker, makeDownloadTransport TransportMaker, hasReality bool) (*Client, error) {
	mode := cfg.EffectiveMode(hasReality)
	switch mode {
	case "stream-one", "stream-up", "packet-up":
	default:
		return nil, fmt.Errorf("xhttp mode %s is not implemented yet", mode)
	}

	ctx, cancel := context.WithCancel(context.Background())

	uploadEndpoint, err := newEndpointManager(cfg, makeTransport)
	if err != nil {
		cancel()
		return nil, err
	}

	downloadEndpoint := uploadEndpoint
	if cfg.DownloadConfig != nil {
		if makeDownloadTransport == nil {
			cancel()
			_ = uploadEndpoint.Close()
			return nil, fmt.Errorf("xhttp: download manager requires download transport maker")
		}

		downloadEndpoint, err = newEndpointManager(cfg.DownloadConfig, makeDownloadTransport)
		if err != nil {
			cancel()
			_ = uploadEndpoint.Close()
			return nil, err
		}
	}

	return &Client{
		ctx:              ctx,
		cancel:           cancel,
		mode:             mode,
		uploadEndpoint:   uploadEndpoint,
		downloadEndpoint: downloadEndpoint,
	}, nil
}

func (c *Client) Close() error {
	c.cancel()
	if c.downloadEndpoint == c.uploadEndpoint {
		return c.uploadEndpoint.Close()
	}
	return errors.Join(c.uploadEndpoint.Close(), c.downloadEndpoint.Close())
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

func (c *Client) dialStreamOne(waitCtx context.Context) (net.Conn, error) {
	upload := c.uploadEndpoint.acquire(waitCtx)
	holdSessions(upload)

	pr, pw := io.Pipe()
	consumeRequestBudget(upload)
	reader, remoteAddr, localAddr, err := upload.client.OpenStream(waitCtx, c.uploadEndpoint.requestURL, "", pr, false)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		releaseSessions(upload)
		return nil, err
	}

	conn := &Conn{writer: pw, reader: reader}
	httputils.SetAddrs(&conn.NetAddr, localAddr, remoteAddr)
	conn.onClose = func() {
		_ = pr.Close()
		releaseSessions(upload)
	}

	return conn, nil
}

func (c *Client) dialStreamUp(waitCtx context.Context) (net.Conn, error) {
	upload := c.uploadEndpoint.acquire(waitCtx)
	download := upload
	if c.downloadEndpoint != c.uploadEndpoint {
		download = c.downloadEndpoint.acquire(waitCtx)
	}
	holdSessions(upload, download)

	pr, pw := io.Pipe()
	sessionID := newSessionID()

	consumeRequestBudget(download)
	reader, remoteAddr, localAddr, err := download.client.OpenStream(waitCtx, c.downloadEndpoint.requestURL, sessionID, nil, false)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		releaseSessions(upload, download)
		return nil, err
	}

	consumeRequestBudget(upload)
	_, uploadRemoteAddr, uploadLocalAddr, err := upload.client.OpenStream(waitCtx, c.uploadEndpoint.requestURL, sessionID, pr, true)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		_ = reader.Close()
		releaseSessions(upload, download)
		return nil, err
	}

	if remoteAddr == nil {
		remoteAddr = uploadRemoteAddr
	}
	if localAddr == nil {
		localAddr = uploadLocalAddr
	}

	conn := &Conn{writer: pw, reader: reader}
	httputils.SetAddrs(&conn.NetAddr, localAddr, remoteAddr)
	conn.onClose = func() {
		_ = pr.Close()
		releaseSessions(upload, download)
	}

	return conn, nil
}

func (c *Client) dialPacketUp(waitCtx context.Context) (net.Conn, error) {
	upload := c.uploadEndpoint.acquire(waitCtx)
	download := upload
	if c.downloadEndpoint != c.uploadEndpoint {
		download = c.downloadEndpoint.acquire(waitCtx)
	}
	holdSessions(upload, download)

	sessionID := newSessionID()
	consumeRequestBudget(download)
	reader, remoteAddr, localAddr, err := download.client.OpenStream(waitCtx, c.downloadEndpoint.requestURL, sessionID, nil, false)
	if err != nil {
		releaseSessions(upload, download)
		return nil, err
	}

	writerCtx, cancelWriter := context.WithCancel(context.Background())
	writer := &packetUpWriter{
		ctx:        writerCtx,
		cancel:     cancelWriter,
		client:     upload.client,
		xmuxClient: upload.xmuxClient,
		requestURL: c.uploadEndpoint.requestURL,
		sessionID:  sessionID,
	}

	conn := &Conn{writer: writer, reader: reader}
	httputils.SetAddrs(&conn.NetAddr, localAddr, remoteAddr)
	conn.onClose = func() {
		cancelWriter()
		releaseSessions(upload, download)
	}

	return conn, nil
}

func newSessionID() string {
	id := uuid.New()
	return id.String()
}
