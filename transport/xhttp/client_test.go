package xhttp

import (
	"context"
	"io"
	"net"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptrace"
	"github.com/stretchr/testify/require"
)

type testAddr string

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return string(a) }

type testConn struct{}

func (c *testConn) Read(_ []byte) (int, error)       { return 0, io.EOF }
func (c *testConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *testConn) Close() error                     { return nil }
func (c *testConn) LocalAddr() net.Addr              { return testAddr("127.0.0.1:1") }
func (c *testConn) RemoteAddr() net.Addr             { return testAddr("127.0.0.1:2") }
func (c *testConn) SetDeadline(time.Time) error      { return nil }
func (c *testConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testConn) SetWriteDeadline(time.Time) error { return nil }

type signalingTransport struct {
	uploadStarted         chan struct{}
	allowDownloadResponse chan struct{}
	respondUpload         bool
	respondDownload       bool
}

func (t *signalingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if trace := httptrace.ContextClientTrace(req.Context()); trace != nil && trace.GotConn != nil {
		trace.GotConn(httptrace.GotConnInfo{Conn: &testConn{}})
		if trace.WroteRequest != nil {
			trace.WroteRequest(httptrace.WroteRequestInfo{})
		}
	}

	switch req.Method {
	case http.MethodGet:
		if t.allowDownloadResponse != nil {
			<-t.allowDownloadResponse
		}
		if !t.respondDownload {
			return nil, io.ErrClosedPipe
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(&neverReader{}),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	case http.MethodPost:
		if t.uploadStarted != nil {
			select {
			case <-t.uploadStarted:
			default:
				close(t.uploadStarted)
			}
		}
		if !t.respondUpload {
			return nil, io.ErrClosedPipe
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Status:     "200 OK",
			Body:       io.NopCloser(io.LimitReader(req.Body, 0)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	default:
		return nil, io.ErrUnexpectedEOF
	}
}

type neverReader struct{}

func (r *neverReader) Read(_ []byte) (int, error) {
	select {}
}

type setupBlockingTransport struct{}

func (t *setupBlockingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
}

type recordingPacketTransport struct {
	firstPostStarted chan struct{}
	allowResponse    chan struct{}

	mu     sync.Mutex
	bodies [][]byte
}

func (t *recordingPacketTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	t.mu.Lock()
	t.bodies = append(t.bodies, body)
	t.mu.Unlock()

	if t.firstPostStarted != nil {
		select {
		case <-t.firstPostStarted:
		default:
			close(t.firstPostStarted)
		}
	}

	if t.allowResponse != nil {
		<-t.allowResponse
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(io.LimitReader(req.Body, 0)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

type tracingPacketTransport struct {
	allowFirstResponse chan struct{}
	secondPostStarted  chan struct{}

	mu     sync.Mutex
	seqs   []string
	bodies [][]byte
	once   sync.Once
}

func (t *tracingPacketTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	if trace := httptrace.ContextClientTrace(req.Context()); trace != nil {
		if trace.GotConn != nil {
			trace.GotConn(httptrace.GotConnInfo{Conn: &testConn{}})
		}
		if trace.WroteRequest != nil {
			trace.WroteRequest(httptrace.WroteRequestInfo{})
		}
	}

	seq := path.Base(req.URL.Path)

	t.mu.Lock()
	index := len(t.seqs)
	t.seqs = append(t.seqs, seq)
	t.bodies = append(t.bodies, body)
	t.mu.Unlock()

	if index == 0 && t.allowFirstResponse != nil {
		<-t.allowFirstResponse
	}
	if index == 1 && t.secondPostStarted != nil {
		t.once.Do(func() {
			close(t.secondPostStarted)
		})
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(io.LimitReader(req.Body, 0)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

type contextValueTransport struct {
	key any

	mu       sync.Mutex
	values   []any
	methods  []string
	postSeen chan struct{}
	once     sync.Once
}

func (t *contextValueTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if trace := httptrace.ContextClientTrace(req.Context()); trace != nil {
		if trace.GotConn != nil {
			trace.GotConn(httptrace.GotConnInfo{Conn: &testConn{}})
		}
		if trace.WroteRequest != nil {
			trace.WroteRequest(httptrace.WroteRequestInfo{})
		}
	}

	t.mu.Lock()
	t.values = append(t.values, req.Context().Value(t.key))
	t.methods = append(t.methods, req.Method)
	t.mu.Unlock()

	if req.Method == http.MethodPost && t.postSeen != nil {
		t.once.Do(func() {
			close(t.postSeen)
		})
	}

	body := io.NopCloser(io.LimitReader(req.Body, 0))
	if req.Method == http.MethodGet {
		body = io.NopCloser(&neverReader{})
	}

	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       body,
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func (t *contextValueTransport) valuesFor(method string) []any {
	t.mu.Lock()
	defer t.mu.Unlock()

	values := make([]any, 0, len(t.values))
	for i, gotMethod := range t.methods {
		if gotMethod == method {
			values = append(values, t.values[i])
		}
	}
	return values
}

func TestDialStreamUpDoesNotWaitForDownloadResponse(t *testing.T) {
	cfg := &Config{
		Host: "upload.example.com",
		Path: "/xhttp",
		Mode: "stream-up",
		DownloadConfig: &Config{
			Host: "download.example.com",
			Path: "/xhttp",
		},
	}

	uploadStarted := make(chan struct{})
	allowDownloadResponse := make(chan struct{})
	uploadTransport := &signalingTransport{uploadStarted: uploadStarted, respondUpload: true}
	downloadTransport := &signalingTransport{allowDownloadResponse: allowDownloadResponse, respondDownload: true}

	type result struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		conn, err := DialStreamUp(cfg, uploadTransport, downloadTransport)
		resultCh <- result{conn: conn, err: err}
	}()

	select {
	case <-uploadStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("upload request was not started before timeout")
	}

	select {
	case res := <-resultCh:
		require.NoError(t, res.err)
		require.NotNil(t, res.conn)
		close(allowDownloadResponse)
		_ = res.conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("DialStreamUp waited for the download response")
	}
}

func TestDialPacketUpDoesNotWaitForDownloadResponse(t *testing.T) {
	cfg := &Config{
		Host: "upload.example.com",
		Path: "/xhttp",
		Mode: "packet-up",
		DownloadConfig: &Config{
			Host: "download.example.com",
			Path: "/xhttp",
		},
	}

	allowDownloadResponse := make(chan struct{})
	uploadTransport := &signalingTransport{respondUpload: true}
	downloadTransport := &signalingTransport{allowDownloadResponse: allowDownloadResponse, respondDownload: true}

	type result struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		conn, err := DialPacketUp(cfg, uploadTransport, downloadTransport)
		resultCh <- result{conn: conn, err: err}
	}()

	select {
	case res := <-resultCh:
		require.NoError(t, res.err)
		require.NotNil(t, res.conn)
		close(allowDownloadResponse)
		_ = res.conn.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("DialPacketUp waited for the download response")
	}
}

func TestDialPacketUpContextCancellation(t *testing.T) {
	cfg := &Config{
		Host: "upload.example.com",
		Path: "/xhttp",
		Mode: "packet-up",
		DownloadConfig: &Config{
			Host: "download.example.com",
			Path: "/xhttp",
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		_, err := DialPacketUpContext(ctx, cfg, &setupBlockingTransport{}, &setupBlockingTransport{})
		errCh <- err
	}()

	cancel()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("DialPacketUpContext did not stop after context cancellation")
	}
}

func TestPacketUpWriterBuffersWritesWhileUploadIsInFlight(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transport := &recordingPacketTransport{
		firstPostStarted: make(chan struct{}),
		allowResponse:    make(chan struct{}),
	}
	writer := newPacketUpWriter(ctx, cancel, &Config{Host: "upload.example.com", Path: "/xhttp"}, "session", transport)
	defer func() {
		close(transport.allowResponse)
		_ = writer.Close()
	}()

	_, err := writer.Write([]byte("hello"))
	require.NoError(t, err)

	select {
	case <-transport.firstPostStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("first packet upload did not start")
	}

	writeErrCh := make(chan error, 1)
	go func() {
		_, err := writer.Write([]byte("world"))
		writeErrCh <- err
	}()

	select {
	case err := <-writeErrCh:
		require.NoError(t, err)
	case <-time.After(200 * time.Millisecond):
		t.Fatal("second packet write blocked on in-flight upload")
	}
}

func TestPacketUpWriterStartsNextRequestBeforePreviousResponse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	transport := &tracingPacketTransport{
		allowFirstResponse: make(chan struct{}),
		secondPostStarted:  make(chan struct{}),
	}
	writer := newPacketUpWriter(ctx, cancel, &Config{Host: "upload.example.com", Path: "/xhttp"}, "session", transport)
	writer.maxUploadSz = 3
	defer func() {
		close(transport.allowFirstResponse)
		_ = writer.Close()
	}()

	_, err := writer.Write([]byte("abcdef"))
	require.NoError(t, err)

	select {
	case <-transport.secondPostStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("second packet request did not start before first response")
	}

	transport.mu.Lock()
	seqs := append([]string(nil), transport.seqs...)
	bodies := append([][]byte(nil), transport.bodies...)
	transport.mu.Unlock()

	require.Equal(t, []string{"0", "1"}, seqs)
	require.Equal(t, [][]byte{[]byte("abc"), []byte("def")}, bodies)
}

func TestDialPacketUpContextPreservesContextValuesAfterSetup(t *testing.T) {
	type ctxKey string
	const key ctxKey = "packet-up"

	cfg := &Config{
		Host: "upload.example.com",
		Path: "/xhttp",
		Mode: "packet-up",
		DownloadConfig: &Config{
			Host: "download.example.com",
			Path: "/xhttp",
		},
	}

	uploadTransport := &contextValueTransport{key: key, postSeen: make(chan struct{})}
	downloadTransport := &contextValueTransport{key: key}

	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), key, "marker"))
	conn, err := DialPacketUpContext(ctx, cfg, uploadTransport, downloadTransport)
	require.NoError(t, err)
	defer func() {
		_ = conn.Close()
	}()

	cancel()

	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)

	select {
	case <-uploadTransport.postSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("packet-up upload did not start after setup context cancellation")
	}

	require.Equal(t, []any{"marker"}, downloadTransport.valuesFor(http.MethodGet))
	require.Equal(t, []any{"marker"}, uploadTransport.valuesFor(http.MethodPost))
}
