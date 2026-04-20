package xhttp

import (
	"context"
	"errors"
	"io"
	"net"
	stdhttp "net/http"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	xhttp3 "github.com/apernet/quic-go/http3"
	xbuf "github.com/xtls/xray-core/common/buf"
	xraynet "github.com/xtls/xray-core/common/net"
	"golang.org/x/net/http2"
)

func TestNormalizeALPN(t *testing.T) {
	got := NormalizeALPN(nil)
	want := []string{"h2", "http/1.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("NormalizeALPN(nil) = %v, want %v", got, want)
	}

	input := []string{"h3"}
	got = NormalizeALPN(input)
	if !reflect.DeepEqual(got, input) {
		t.Fatalf("NormalizeALPN(%v) = %v", input, got)
	}
	got[0] = "modified"
	if input[0] != "h3" {
		t.Fatal("NormalizeALPN should clone the input slice")
	}
}

func TestDecideHTTPVersion(t *testing.T) {
	tests := []struct {
		name       string
		hasTLS     bool
		nextProtos []string
		hasReality bool
		want       string
	}{
		{name: "default h2", hasTLS: true, nextProtos: NormalizeALPN(nil), want: HTTPVersion2},
		{name: "single h1", hasTLS: true, nextProtos: []string{"http/1.1"}, want: HTTPVersion11},
		{name: "single h3", hasTLS: true, nextProtos: []string{"h3"}, want: HTTPVersion3},
		{name: "reality forces h2", hasTLS: true, nextProtos: []string{"h3"}, hasReality: true, want: HTTPVersion2},
		{name: "plain http falls back h1", hasTLS: false, nextProtos: []string{"h3"}, want: HTTPVersion11},
		{name: "multi alpn keeps h2", hasTLS: true, nextProtos: []string{"h3", "h2"}, want: HTTPVersion2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DecideHTTPVersion(tt.hasTLS, tt.nextProtos, tt.hasReality); got != tt.want {
				t.Fatalf("DecideHTTPVersion(%v, %v, %v) = %s, want %s", tt.hasTLS, tt.nextProtos, tt.hasReality, got, tt.want)
			}
		})
	}
}

func TestRequestScheme(t *testing.T) {
	if got := (&Config{}).RequestScheme(); got != "https" {
		t.Fatalf("default request scheme = %q, want https", got)
	}
	if got := (&Config{Scheme: "http"}).RequestScheme(); got != "http" {
		t.Fatalf("custom request scheme = %q, want http", got)
	}
}

func TestReuseConfigResolveKeepAliveSeconds(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *ReuseConfig
		want    int64
		wantErr bool
	}{
		{name: "nil", cfg: nil, want: 0},
		{name: "empty", cfg: &ReuseConfig{}, want: 0},
		{name: "positive", cfg: &ReuseConfig{HKeepAlivePeriod: "45"}, want: 45},
		{name: "negative", cfg: &ReuseConfig{HKeepAlivePeriod: "-1"}, want: -1},
		{name: "invalid", cfg: &ReuseConfig{HKeepAlivePeriod: "1-2"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.ResolveKeepAliveSeconds()
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("ResolveKeepAliveSeconds() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestXrayConfigKeepsKeepAlivePeriod(t *testing.T) {
	xcfg, err := (&ReuseConfig{HKeepAlivePeriod: "45"}).XrayConfig()
	if err != nil {
		t.Fatal(err)
	}
	if xcfg.HKeepAlivePeriod != 45 {
		t.Fatalf("XrayConfig().HKeepAlivePeriod = %d, want 45", xcfg.HKeepAlivePeriod)
	}
}

func TestXrayConfigNormalizesXPaddingDefaults(t *testing.T) {
	xcfg, err := (&Config{Path: "/xhttp", XPaddingObfsMode: true}).XrayConfig()
	if err != nil {
		t.Fatal(err)
	}

	if !xcfg.XPaddingObfsMode {
		t.Fatal("XPaddingObfsMode = false, want true")
	}
	if xcfg.XPaddingKey != "x_padding" {
		t.Fatalf("XPaddingKey = %q, want x_padding", xcfg.XPaddingKey)
	}
	if xcfg.XPaddingHeader != "X-Padding" {
		t.Fatalf("XPaddingHeader = %q, want X-Padding", xcfg.XPaddingHeader)
	}
	if xcfg.XPaddingPlacement != xPaddingPlacementQueryInHeader {
		t.Fatalf("XPaddingPlacement = %q, want %q", xcfg.XPaddingPlacement, xPaddingPlacementQueryInHeader)
	}
	if xcfg.XPaddingMethod != xPaddingMethodRepeatX {
		t.Fatalf("XPaddingMethod = %q, want %q", xcfg.XPaddingMethod, xPaddingMethodRepeatX)
	}
}

func TestXrayConfigKeepsCustomXPaddingSettings(t *testing.T) {
	xcfg, err := (&Config{
		Path:              "/xhttp",
		XPaddingObfsMode:  true,
		XPaddingKey:       "pad",
		XPaddingHeader:    "X-Obfs",
		XPaddingPlacement: xPaddingPlacementCookie,
		XPaddingMethod:    xPaddingMethodTokenish,
	}).XrayConfig()
	if err != nil {
		t.Fatal(err)
	}

	if xcfg.XPaddingKey != "pad" {
		t.Fatalf("XPaddingKey = %q, want pad", xcfg.XPaddingKey)
	}
	if xcfg.XPaddingHeader != "X-Obfs" {
		t.Fatalf("XPaddingHeader = %q, want X-Obfs", xcfg.XPaddingHeader)
	}
	if xcfg.XPaddingPlacement != xPaddingPlacementCookie {
		t.Fatalf("XPaddingPlacement = %q, want %q", xcfg.XPaddingPlacement, xPaddingPlacementCookie)
	}
	if xcfg.XPaddingMethod != xPaddingMethodTokenish {
		t.Fatalf("XPaddingMethod = %q, want %q", xcfg.XPaddingMethod, xPaddingMethodTokenish)
	}
}

func TestXrayConfigRejectsInvalidXPaddingSettings(t *testing.T) {
	if _, err := (&Config{Path: "/xhttp", XPaddingPlacement: "bad"}).XrayConfig(); err == nil {
		t.Fatal("expected invalid placement error")
	}
	if _, err := (&Config{Path: "/xhttp", XPaddingMethod: "bad"}).XrayConfig(); err == nil {
		t.Fatal("expected invalid method error")
	}
}

func TestXrayConfigNormalizesUplinkAndMetaControls(t *testing.T) {
	xcfg, err := (&Config{
		Path:                "/xhttp",
		Mode:                "packet-up",
		UplinkHTTPMethod:    "get",
		SessionPlacement:    xPaddingPlacementHeader,
		SeqPlacement:        xPaddingPlacementQuery,
		UplinkDataPlacement: xPaddingPlacementAuto,
		UplinkChunkSize:     "3000-4000",
	}).XrayConfig()
	if err != nil {
		t.Fatal(err)
	}

	if xcfg.UplinkHTTPMethod != "GET" {
		t.Fatalf("UplinkHTTPMethod = %q, want GET", xcfg.UplinkHTTPMethod)
	}
	if xcfg.SessionPlacement != xPaddingPlacementHeader {
		t.Fatalf("SessionPlacement = %q, want %q", xcfg.SessionPlacement, xPaddingPlacementHeader)
	}
	if xcfg.SessionKey != "X-Session" {
		t.Fatalf("SessionKey = %q, want X-Session", xcfg.SessionKey)
	}
	if xcfg.SeqPlacement != xPaddingPlacementQuery {
		t.Fatalf("SeqPlacement = %q, want %q", xcfg.SeqPlacement, xPaddingPlacementQuery)
	}
	if xcfg.SeqKey != "x_seq" {
		t.Fatalf("SeqKey = %q, want x_seq", xcfg.SeqKey)
	}
	if xcfg.UplinkDataPlacement != xPaddingPlacementAuto {
		t.Fatalf("UplinkDataPlacement = %q, want %q", xcfg.UplinkDataPlacement, xPaddingPlacementAuto)
	}
	if xcfg.UplinkDataKey != "X-Data" {
		t.Fatalf("UplinkDataKey = %q, want X-Data", xcfg.UplinkDataKey)
	}
	if xcfg.UplinkChunkSize == nil || xcfg.UplinkChunkSize.From != 3000 || xcfg.UplinkChunkSize.To != 4000 {
		t.Fatalf("UplinkChunkSize = %#v, want 3000-4000", xcfg.UplinkChunkSize)
	}
}

func TestXrayConfigRejectsInvalidUplinkAndMetaControls(t *testing.T) {
	if _, err := (&Config{Path: "/xhttp", SessionPlacement: "bad"}).XrayConfig(); err == nil {
		t.Fatal("expected invalid session placement error")
	}
	if _, err := (&Config{Path: "/xhttp", SeqPlacement: "bad"}).XrayConfig(); err == nil {
		t.Fatal("expected invalid seq placement error")
	}
	if _, err := (&Config{Path: "/xhttp", Mode: "stream-up", UplinkHTTPMethod: "GET"}).XrayConfig(); err == nil {
		t.Fatal("expected invalid uplinkHTTPMethod error")
	}
	if _, err := (&Config{Path: "/xhttp", Mode: "stream-up", UplinkDataPlacement: xPaddingPlacementHeader}).XrayConfig(); err == nil {
		t.Fatal("expected invalid uplinkDataPlacement error")
	}
	if _, err := (&Config{Path: "/xhttp", UplinkDataPlacement: "bad"}).XrayConfig(); err == nil {
		t.Fatal("expected invalid uplinkDataPlacement value error")
	}
}

func TestNewTransportH2KeepAlivePeriod(t *testing.T) {
	tests := []struct {
		name       string
		keepAlive  time.Duration
		wantPeriod time.Duration
	}{
		{name: "default", keepAlive: 0, wantPeriod: xraynet.ChromeH2KeepAlivePeriod},
		{name: "custom", keepAlive: 30 * time.Second, wantPeriod: 30 * time.Second},
		{name: "disabled", keepAlive: -1 * time.Second, wantPeriod: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := NewTransport(TransportOption{HTTPVersion: HTTPVersion2, KeepAlivePeriod: tt.keepAlive})
			managed, ok := rt.(*managedTransport)
			if !ok {
				t.Fatalf("transport type = %T, want *managedTransport", rt)
			}
			h2Transport, ok := managed.inner.(*http2.Transport)
			if !ok {
				t.Fatalf("inner transport type = %T, want *http2.Transport", managed.inner)
			}
			if h2Transport.ReadIdleTimeout != tt.wantPeriod {
				t.Fatalf("ReadIdleTimeout = %s, want %s", h2Transport.ReadIdleTimeout, tt.wantPeriod)
			}
		})
	}
}

func TestNewTransportH3QUICSettings(t *testing.T) {
	tests := []struct {
		name          string
		keepAlive     time.Duration
		maxIdle       time.Duration
		wantKeepAlive time.Duration
		wantMaxIdle   time.Duration
	}{
		{name: "default", keepAlive: 0, maxIdle: 0, wantKeepAlive: xraynet.QuicgoH3KeepAlivePeriod, wantMaxIdle: xraynet.ConnIdleTimeout},
		{name: "custom", keepAlive: 30 * time.Second, maxIdle: 15 * time.Minute, wantKeepAlive: 30 * time.Second, wantMaxIdle: 15 * time.Minute},
		{name: "disable keepalive", keepAlive: -1 * time.Second, maxIdle: 0, wantKeepAlive: 0, wantMaxIdle: xraynet.ConnIdleTimeout},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := NewTransport(TransportOption{HTTPVersion: HTTPVersion3, QUICKeepAlive: tt.keepAlive, QUICMaxIdle: tt.maxIdle})
			managed, ok := rt.(*managedTransport)
			if !ok {
				t.Fatalf("transport type = %T, want *managedTransport", rt)
			}
			h3Transport, ok := managed.inner.(*xhttp3.Transport)
			if !ok {
				t.Fatalf("inner transport type = %T, want *http3.Transport", managed.inner)
			}
			if h3Transport.QUICConfig.KeepAlivePeriod != tt.wantKeepAlive {
				t.Fatalf("KeepAlivePeriod = %s, want %s", h3Transport.QUICConfig.KeepAlivePeriod, tt.wantKeepAlive)
			}
			if h3Transport.QUICConfig.MaxIdleTimeout != tt.wantMaxIdle {
				t.Fatalf("MaxIdleTimeout = %s, want %s", h3Transport.QUICConfig.MaxIdleTimeout, tt.wantMaxIdle)
			}
		})
	}
}

type countingListener struct {
	net.Listener
	accepted atomic.Int64
}

func (l *countingListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err == nil {
		l.accepted.Add(1)
	}
	return conn, err
}

func TestDialerClientPostPacketReusesH1Conn(t *testing.T) {
	baseCfg, err := (&Config{Path: "/xhttp"}).XrayConfig()
	if err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &countingListener{Listener: ln}

	requests := make(chan string, 2)
	server := &stdhttp.Server{Handler: stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			stdhttp.Error(w, err.Error(), stdhttp.StatusInternalServerError)
			return
		}
		_ = r.Body.Close()
		requests <- string(body)
		w.WriteHeader(stdhttp.StatusOK)
	})}

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Serve(listener)
	}()

	client := &dialerClient{
		cfg:         baseCfg,
		httpVersion: HTTPVersion11,
		dialUploadConn: func(ctx context.Context) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", listener.Addr().String())
		},
		uploadRawAll: make(map[*H1Conn]struct{}),
	}

	payload1 := xbuf.MergeBytes(nil, []byte("first"))
	defer xbuf.ReleaseMulti(payload1)
	if err := client.PostPacket(context.Background(), "http://"+listener.Addr().String()+"/xhttp/", "session", "0", payload1); err != nil {
		t.Fatal(err)
	}

	payload2 := xbuf.MergeBytes(nil, []byte("second"))
	defer xbuf.ReleaseMulti(payload2)
	if err := client.PostPacket(context.Background(), "http://"+listener.Addr().String()+"/xhttp/", "session", "1", payload2); err != nil {
		t.Fatal(err)
	}

	for _, want := range []string{"first", "second"} {
		select {
		case got := <-requests:
			if got != want {
				t.Fatalf("request body = %q, want %q", got, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for %q request", want)
		}
	}

	if got := listener.accepted.Load(); got != 1 {
		t.Fatalf("accepted connections = %d, want 1", got)
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErrCh; err != nil && !errors.Is(err, stdhttp.ErrServerClosed) {
		t.Fatal(err)
	}
}
