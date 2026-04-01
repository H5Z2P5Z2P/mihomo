package xhttp

import (
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
	httptest "github.com/metacubex/http/httptest"
	"github.com/stretchr/testify/require"
)

func newTestRequestHandler() *requestHandler {
	return &requestHandler{
		path:                 "/xhttp/",
		sessionReapTimeout:   25 * time.Millisecond,
		maxBufferedPostBytes: 2,
		maxUploadPostBytes:   4,
		sessions:             map[string]*httpSession{},
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
	session := h.connectSession("session")

	time.Sleep(80 * time.Millisecond)
	require.Same(t, session, h.getSession("session"))

	h.deleteSession("session")
}

func TestUploadQueueRejectsTooManyBufferedPackets(t *testing.T) {
	q := NewUploadQueue(2)

	require.NoError(t, q.Push(Packet{Seq: 1, Payload: []byte("a")}))
	require.NoError(t, q.Push(Packet{Seq: 2, Payload: []byte("b")}))
	require.ErrorContains(t, q.Push(Packet{Seq: 3, Payload: []byte("c")}), "too large")
}

func TestRequestHandlerRejectsOversizedPacketUpload(t *testing.T) {
	h := newTestRequestHandler()
	req := httptest.NewRequest(http.MethodPost, "http://example.com/xhttp/session/0", strings.NewReader("12345"))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, req)

	require.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	require.Eventually(t, func() bool {
		return h.getSession("session") == nil
	}, time.Second, 10*time.Millisecond)
}
