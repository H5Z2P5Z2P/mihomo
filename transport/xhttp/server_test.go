package xhttp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
	httptest "github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/require"
)

func newTestRequestHandler() *requestHandler {
	return &requestHandler{
		path:               "/xhttp/",
		sessionReapTimeout: 25 * time.Millisecond,
		sessions:           map[string]*httpSession{},
	}
}

func TestRequestHandlerReapsUnconnectedSession(t *testing.T) {
	h := newTestRequestHandler()
	h.getOrCreateSession("session")

	require.Eventually(t, func() bool {
		return h.getSession("session") == nil
	}, time.Second, 10*time.Millisecond)
}

func TestRequestHandlerKeepsConnectedSession(t *testing.T) {
	h := newTestRequestHandler()
	session := h.getOrCreateSession("session")
	session.markConnected()

	time.Sleep(80 * time.Millisecond)
	require.Same(t, session, h.getSession("session"))

	h.deleteSession("session")
}

func TestRequestHandlerCreatesSessionForStreamUpUpload(t *testing.T) {
	h := newTestRequestHandler()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest(http.MethodPost, "http://example.com/xhttp/session", strings.NewReader("abc")).WithContext(ctx)
	w := httptest.NewRecorder()
	done := make(chan struct{})

	go func() {
		h.ServeHTTP(w, req)
		close(done)
	}()

	require.Eventually(t, func() bool {
		return w.Code == http.StatusOK && h.getSession("session") != nil
	}, time.Second, 10*time.Millisecond)

	cancel()
	require.Eventually(t, func() bool {
		select {
		case <-done:
			return true
		default:
			return false
		}
	}, time.Second, 10*time.Millisecond)
}

func TestRequestHandlerCreatesSessionForPacketUpUpload(t *testing.T) {
	h := newTestRequestHandler()

	req := httptest.NewRequest(http.MethodPost, "http://example.com/xhttp/session/0", strings.NewReader("abc"))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, h.getSession("session"))
}

func TestRequestHandlerRejectsOversizePacketUpUpload(t *testing.T) {
	h := newTestRequestHandler()

	body := strings.Repeat("a", xhttpPacketUpMaxEachPostBytes+1)
	req := httptest.NewRequest(http.MethodPost, "http://example.com/xhttp/session/0", strings.NewReader(body))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}
