package xhttp

import (
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptrace"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestDialStreamUpStartsUploadWithoutWaitingForDownload(t *testing.T) {
	uploadConnected := make(chan struct{})

	client, err := NewClient(
		&Config{
			Host:          "upload.example",
			Path:          "/xhttp",
			Mode:          "stream-up",
			XPaddingBytes: "0",
			DownloadConfig: &Config{
				Host:          "download.example",
				Path:          "/xhttp-download",
				XPaddingBytes: "0",
			},
		},
		func() http.RoundTripper {
			return roundTripFunc(func(req *http.Request) (*http.Response, error) {
				trace := httptrace.ContextClientTrace(req.Context())
				if trace == nil || trace.GotConn == nil {
					return nil, errors.New("missing upload got-conn trace")
				}

				conn, peer := net.Pipe()
				defer conn.Close()
				defer peer.Close()
				trace.GotConn(httptrace.GotConnInfo{Conn: conn})
				close(uploadConnected)

				<-req.Context().Done()
				return nil, req.Context().Err()
			})
		},
		func() http.RoundTripper {
			return roundTripFunc(func(req *http.Request) (*http.Response, error) {
				select {
				case <-uploadConnected:
				case <-time.After(200 * time.Millisecond):
					return nil, errors.New("upload request did not connect before download response")
				}

				return &http.Response{
					StatusCode: http.StatusOK,
					Status:     "200 OK",
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader("")),
				}, nil
			})
		},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	dialDone := make(chan struct{})
	var conn io.Closer
	var dialErr error
	go func() {
		defer close(dialDone)
		conn, dialErr = client.DialStreamUp()
	}()

	select {
	case <-dialDone:
	case <-time.After(time.Second):
		t.Fatal("DialStreamUp blocked while waiting for download response")
	}

	if dialErr != nil {
		t.Fatal(dialErr)
	}
	if conn == nil {
		t.Fatal("expected DialStreamUp to return a connection")
	}
	defer conn.Close()
}

func TestDialStreamUpCancelsUploadWhenDownloadFails(t *testing.T) {
	uploadCanceled := make(chan struct{})

	client, err := NewClient(
		&Config{
			Host:          "upload.example",
			Path:          "/xhttp",
			Mode:          "stream-up",
			XPaddingBytes: "0",
			DownloadConfig: &Config{
				Host:          "download.example",
				Path:          "/xhttp-download",
				XPaddingBytes: "0",
			},
		},
		func() http.RoundTripper {
			return roundTripFunc(func(req *http.Request) (*http.Response, error) {
				trace := httptrace.ContextClientTrace(req.Context())
				if trace == nil || trace.GotConn == nil {
					return nil, errors.New("missing upload got-conn trace")
				}

				conn, peer := net.Pipe()
				defer conn.Close()
				defer peer.Close()
				trace.GotConn(httptrace.GotConnInfo{Conn: conn})

				<-req.Context().Done()
				close(uploadCanceled)
				return nil, req.Context().Err()
			})
		},
		func() http.RoundTripper {
			return roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return nil, errors.New("download failed")
			})
		},
		true,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	_, err = client.DialStreamUp()
	if err == nil || err.Error() != "download failed" {
		t.Fatalf("unexpected error: %v", err)
	}

	select {
	case <-uploadCanceled:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("upload request was not canceled after download failure")
	}
}
