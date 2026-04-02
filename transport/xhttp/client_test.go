package xhttp

import (
	"io"
	"net"
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
	if trace := httptrace.ContextClientTrace(req.Context()); trace != nil {
		if trace.GotConn != nil {
			trace.GotConn(httptrace.GotConnInfo{Conn: &testConn{}})
		}
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
	client, err := NewClient(
		cfg,
		func() http.RoundTripper { return uploadTransport },
		func() http.RoundTripper { return downloadTransport },
		false,
	)
	require.NoError(t, err)
	defer client.Close()

	type result struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		conn, err := client.DialStreamUp()
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

func TestDialStreamUpPropagatesAsyncUploadError(t *testing.T) {
	cfg := &Config{
		Host: "upload.example.com",
		Path: "/xhttp",
		Mode: "stream-up",
		DownloadConfig: &Config{
			Host: "download.example.com",
			Path: "/xhttp",
		},
	}

	uploadTransport := &signalingTransport{respondUpload: false}
	downloadTransport := &signalingTransport{respondDownload: true}
	client, err := NewClient(
		cfg,
		func() http.RoundTripper { return uploadTransport },
		func() http.RoundTripper { return downloadTransport },
		false,
	)
	require.NoError(t, err)
	defer client.Close()

	conn, err := client.DialStreamUp()
	require.NoError(t, err)
	defer conn.Close()

	type result struct {
		n   int
		err error
	}
	resultCh := make(chan result, 1)
	go func() {
		n, err := conn.Write([]byte("abc"))
		resultCh <- result{n: n, err: err}
	}()

	select {
	case res := <-resultCh:
		require.Error(t, res.err)
		require.Zero(t, res.n)
	case <-time.After(2 * time.Second):
		t.Fatal("stream-up write did not observe asynchronous upload failure")
	}
}

func TestDialPacketUpDoesNotWaitForDownloadResponse(t *testing.T) {
	cfg := &Config{
		Host: "upload.example.com",
		Path: "/xhttp",
		Mode: "packet-up",
	}

	allowDownloadResponse := make(chan struct{})
	uploadTransport := &signalingTransport{respondUpload: true}
	downloadTransport := &signalingTransport{allowDownloadResponse: allowDownloadResponse, respondDownload: true}
	client, err := NewClient(
		cfg,
		func() http.RoundTripper { return uploadTransport },
		func() http.RoundTripper { return downloadTransport },
		false,
	)
	require.NoError(t, err)
	defer client.Close()

	type result struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		conn, err := client.DialPacketUp()
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
