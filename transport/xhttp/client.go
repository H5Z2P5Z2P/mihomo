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

	"github.com/metacubex/mihomo/common/contextutils"
	"github.com/metacubex/mihomo/common/httputils"

	"github.com/metacubex/http"
	"github.com/metacubex/tls"
)

type DialRawFunc func(ctx context.Context) (net.Conn, error)
type WrapTLSFunc func(ctx context.Context, conn net.Conn, isH2 bool) (net.Conn, error)

type DialOptions struct {
	Config  *Config
	DialRaw DialRawFunc
	WrapTLS WrapTLSFunc
}

type PacketUpWriter struct {
	ctx       context.Context
	cfg       *Config
	sessionID string
	transport http.RoundTripper
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

	req, err := http.NewRequestWithContext(c.ctx, http.MethodPost, u.String(), nil)
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

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("xhttp packet-up bad status: %s", resp.Status)
	}

	return len(b), nil
}

func (c *PacketUpWriter) Close() error {
	httputils.CloseTransport(c.transport)
	return nil
}

func newTransport(opt DialOptions) http.RoundTripper {
	return &http.Http2Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			raw, err := opt.DialRaw(ctx)
			if err != nil {
				return nil, err
			}
			wrapped, err := opt.WrapTLS(ctx, raw, true)
			if err != nil {
				_ = raw.Close()
				return nil, err
			}
			return wrapped, nil
		},
	}
}

func newRequestURL(cfg *Config) url.URL {
	return url.URL{
		Scheme: "https",
		Host:   cfg.Host,
		Path:   cfg.NormalizedPath(),
	}
}

func DialStreamOne(
	ctx context.Context,
	opt DialOptions,
) (net.Conn, error) {
	requestURL := newRequestURL(opt.Config)
	transport := newTransport(opt)

	pr, pw := io.Pipe()

	conn := &Conn{
		writer: pw,
	}

	req, err := http.NewRequestWithContext(httputils.NewAddrContext(&conn.NetAddr, contextutils.WithoutCancel(ctx)), http.MethodPost, requestURL.String(), pr)
	if err != nil {
		_ = pr.Close()
		_ = pw.Close()
		return nil, err
	}
	req.Host = opt.Config.Host

	if err := opt.Config.FillStreamRequest(req); err != nil {
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
		_ = resp.Body.Close()
		_ = pr.Close()
		httputils.CloseTransport(transport)
	}

	return conn, nil
}

func DialPacketUp(
	ctx context.Context,
	upload DialOptions,
	download *DialOptions,
) (net.Conn, error) {
	uploadTransport := newTransport(upload)
	downloadTransport := uploadTransport
	downloadConfig := upload.Config
	if download != nil {
		downloadTransport = newTransport(*download)
		downloadConfig = download.Config
	}

	sessionID := newSessionID()
	downloadURL := newRequestURL(downloadConfig)

	ctx = contextutils.WithoutCancel(ctx)
	writer := &PacketUpWriter{
		ctx:       ctx,
		cfg:       upload.Config,
		sessionID: sessionID,
		transport: uploadTransport,
		seq:       0,
	}
	conn := &Conn{writer: writer}

	req, err := http.NewRequestWithContext(httputils.NewAddrContext(&conn.NetAddr, ctx), http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
		httputils.CloseTransport(uploadTransport)
		return nil, err
	}
	if err := downloadConfig.FillDownloadRequest(req, sessionID); err != nil {
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
		httputils.CloseTransport(uploadTransport)
		return nil, err
	}
	req.Host = downloadConfig.Host

	resp, err := downloadTransport.RoundTrip(req)
	if err != nil {
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
		httputils.CloseTransport(uploadTransport)
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
		httputils.CloseTransport(uploadTransport)
		return nil, fmt.Errorf("xhttp packet-up download bad status: %s", resp.Status)
	}
	conn.reader = resp.Body
	conn.onClose = func() {
		if downloadTransport != uploadTransport {
			httputils.CloseTransport(downloadTransport)
		}
	}

	return conn, nil
}

func DialStreamUp(
	ctx context.Context,
	upload DialOptions,
	download DialOptions,
) (net.Conn, error) {
	uploadTransport := newTransport(upload)
	downloadTransport := newTransport(download)
	sessionID := newSessionID()
	ctx = contextutils.WithoutCancel(ctx)

	conn := &Conn{}
	downloadURL := newRequestURL(download.Config)
	downloadReq, err := http.NewRequestWithContext(httputils.NewAddrContext(&conn.NetAddr, ctx), http.MethodGet, downloadURL.String(), nil)
	if err != nil {
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, err
	}
	if err := download.Config.FillDownloadRequest(downloadReq, sessionID); err != nil {
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, err
	}
	downloadReq.Host = download.Config.Host

	downloadResp, err := downloadTransport.RoundTrip(downloadReq)
	if err != nil {
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, err
	}
	if downloadResp.StatusCode != http.StatusOK {
		_ = downloadResp.Body.Close()
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, fmt.Errorf("xhttp stream-up download bad status: %s", downloadResp.Status)
	}

	pr, pw := io.Pipe()
	uploadURL := newRequestURL(upload.Config)
	uploadReq, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL.String(), pr)
	if err != nil {
		_ = downloadResp.Body.Close()
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, err
	}
	if err := upload.Config.FillStreamRequest(uploadReq); err != nil {
		_ = downloadResp.Body.Close()
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, err
	}
	upload.Config.ApplyMetaToRequest(uploadReq, sessionID, "")
	uploadReq.Host = upload.Config.Host

	uploadResp, err := uploadTransport.RoundTrip(uploadReq)
	if err != nil {
		_ = downloadResp.Body.Close()
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, err
	}
	if uploadResp.StatusCode < 200 || uploadResp.StatusCode >= 300 {
		_ = uploadResp.Body.Close()
		_ = downloadResp.Body.Close()
		_ = pr.Close()
		_ = pw.Close()
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
		return nil, fmt.Errorf("xhttp stream-up upload bad status: %s", uploadResp.Status)
	}

	conn.writer = pw
	conn.reader = downloadResp.Body
	conn.onClose = func() {
		_ = uploadResp.Body.Close()
		httputils.CloseTransport(uploadTransport)
		httputils.CloseTransport(downloadTransport)
	}

	go func() {
		_, _ = io.Copy(io.Discard, uploadResp.Body)
		_ = uploadResp.Body.Close()
	}()

	return conn, nil
}

func newSessionID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
