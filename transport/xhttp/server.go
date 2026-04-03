package xhttp

import (
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/httputils"
	N "github.com/metacubex/mihomo/common/net"

	"github.com/metacubex/http"
	"github.com/metacubex/http/h2c"
)

type ServerOption struct {
	Path        string
	Host        string
	Mode        string
	ConnHandler func(net.Conn)
	HttpHandler http.Handler
}

type httpServerConn struct {
	mu      sync.Mutex
	w       http.ResponseWriter
	flusher http.Flusher
	reader  io.Reader
	closed  bool
	done    chan struct{}
	once    sync.Once
}

func newHTTPServerConn(w http.ResponseWriter, r io.Reader) *httpServerConn {
	flusher, _ := w.(http.Flusher)
	return &httpServerConn{
		w:       w,
		flusher: flusher,
		reader:  r,
		done:    make(chan struct{}),
	}
}

func (c *httpServerConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *httpServerConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, io.ErrClosedPipe
	}

	n, err := c.w.Write(b)
	if err == nil && c.flusher != nil {
		c.flusher.Flush()
	}
	return n, err
}

func (c *httpServerConn) Close() error {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		close(c.done)
	})
	return nil
}

func (c *httpServerConn) Wait() <-chan struct{} {
	return c.done
}

type httpSession struct {
	uploadQueue *uploadQueue
	connected   chan struct{}
	once        sync.Once
}

func newHTTPSession() *httpSession {
	return &httpSession{
		uploadQueue: NewUploadQueue(0),
		connected:   make(chan struct{}),
	}
}

func (s *httpSession) markConnected() bool {
	marked := false
	s.once.Do(func() {
		marked = true
		close(s.connected)
	})
	return marked
}

type requestHandler struct {
	path        string
	host        string
	mode        string
	connHandler func(net.Conn)
	httpHandler http.Handler

	sessionReapTimeout time.Duration

	mu       sync.Mutex
	sessions map[string]*httpSession
}

func NewServerHandler(opt ServerOption) http.Handler {
	path := opt.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if !strings.HasSuffix(path, "/") {
		path += "/"
	}

	// using h2c.NewHandler to ensure we can work in plain http2
	// and some tls conn is not *tls.Conn (like *reality.Conn)
	return h2c.NewHandler(&requestHandler{
		path:               path,
		host:               opt.Host,
		mode:               opt.Mode,
		connHandler:        opt.ConnHandler,
		httpHandler:        opt.HttpHandler,
		sessionReapTimeout: 30 * time.Second,
		sessions:           map[string]*httpSession{},
	}, &http.Http2Server{
		IdleTimeout: 30 * time.Second,
	})
}

func (h *requestHandler) getOrCreateSession(sessionID string) *httpSession {
	h.mu.Lock()
	s, ok := h.sessions[sessionID]
	if ok {
		h.mu.Unlock()
		return s
	}

	s = newHTTPSession()
	h.sessions[sessionID] = s
	activeSessions := len(h.sessions)
	reapTimeout := h.sessionReapTimeout
	h.mu.Unlock()

	logLifecycle("session created id=%s active=%d", sessionID, activeSessions)
	h.scheduleSessionReap(sessionID, s, reapTimeout)
	return s
}

func (h *requestHandler) scheduleSessionReap(sessionID string, session *httpSession, timeout time.Duration) {
	if timeout <= 0 {
		return
	}

	go func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()

		select {
		case <-session.connected:
			return
		case <-timer.C:
		}

		h.mu.Lock()
		current, ok := h.sessions[sessionID]
		if !ok || current != session {
			h.mu.Unlock()
			return
		}

		select {
		case <-session.connected:
			h.mu.Unlock()
			return
		default:
		}

		_ = session.uploadQueue.Close()
		delete(h.sessions, sessionID)
		activeSessions := len(h.sessions)
		h.mu.Unlock()
		logLifecycle("session reaped id=%s active=%d", sessionID, activeSessions)
	}()
}

func (h *requestHandler) deleteSession(sessionID string) {
	h.mu.Lock()
	deleted := false
	activeSessions := 0

	if s, ok := h.sessions[sessionID]; ok {
		_ = s.uploadQueue.Close()
		delete(h.sessions, sessionID)
		deleted = true
		activeSessions = len(h.sessions)
	}
	h.mu.Unlock()

	if deleted {
		logLifecycle("session deleted id=%s active=%d", sessionID, activeSessions)
	}
}

func (h *requestHandler) getSession(sessionID string) *httpSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessions[sessionID]
}

func (h *requestHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.httpHandler != nil && !strings.HasPrefix(r.URL.Path, h.path) {
		h.httpHandler.ServeHTTP(w, r)
		return
	}

	if h.host != "" && !equalHost(r.Host, h.host) {
		http.NotFound(w, r)
		return
	}

	if !strings.HasPrefix(r.URL.Path, h.path) {
		http.NotFound(w, r)
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, h.path)
	parts := splitNonEmpty(rest)

	// stream-one: POST /path
	if r.Method == http.MethodPost && len(parts) == 0 {
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}

		httpSC := newHTTPServerConn(w, r.Body)
		conn := &Conn{
			writer: httpSC,
			reader: httpSC,
		}
		httputils.SetAddrFromRequest(&conn.NetAddr, r)

		go h.connHandler(N.NewDeadlineConn(conn))

		select {
		case <-r.Context().Done():
		case <-httpSC.Wait():
		}

		_ = conn.Close()
		return
	}

	// packet-up download: GET /path/{session}
	if r.Method == http.MethodGet && len(parts) == 1 {
		sessionID := parts[0]
		session := h.getOrCreateSession(sessionID)
		if session.markConnected() {
			logLifecycle("session connected id=%s", sessionID)
		}
		logLifecycle("download stream opened session=%s remote=%s", sessionID, r.RemoteAddr)

		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}

		httpSC := newHTTPServerConn(w, r.Body)
		conn := &Conn{
			writer: httpSC,
			reader: session.uploadQueue,
			onClose: func() {
				h.deleteSession(sessionID)
			},
		}
		httputils.SetAddrFromRequest(&conn.NetAddr, r)

		go h.connHandler(N.NewDeadlineConn(conn))

		select {
		case <-r.Context().Done():
		case <-httpSC.Wait():
		}

		_ = conn.Close()
		logLifecycle("download stream closed session=%s remote=%s ctxErr=%v", sessionID, r.RemoteAddr, r.Context().Err())
		return
	}

	// stream-up upload: POST /path/{session}
	if r.Method == http.MethodPost && len(parts) == 1 {
		sessionID := parts[0]
		session := h.getOrCreateSession(sessionID)
		logLifecycle("stream-up upload opened session=%s remote=%s", sessionID, r.RemoteAddr)

		httpSC := newHTTPServerConn(w, r.Body)
		if err := session.uploadQueue.Push(Packet{Reader: httpSC}); err != nil {
			logLifecycle("stream-up upload push failed session=%s err=%v", sessionID, err)
			http.Error(w, err.Error(), http.StatusConflict)
			_ = httpSC.Close()
			return
		}

		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}

		select {
		case <-r.Context().Done():
		case <-httpSC.Wait():
		}

		_ = httpSC.Close()
		logLifecycle("stream-up upload closed session=%s remote=%s ctxErr=%v", sessionID, r.RemoteAddr, r.Context().Err())
		return
	}

	// packet-up upload: POST /path/{session}/{seq}
	if r.Method == http.MethodPost && len(parts) == 2 {
		sessionID := parts[0]
		seq, err := strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			http.Error(w, "invalid xhttp seq", http.StatusBadRequest)
			return
		}

		session := h.getOrCreateSession(sessionID)
		session.uploadQueue.SetMaxSize(xhttpPacketUpMaxBufferedPosts)

		body, err := io.ReadAll(io.LimitReader(r.Body, xhttpPacketUpMaxEachPostBytes+1))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if len(body) > xhttpPacketUpMaxEachPostBytes {
			http.Error(w, "xhttp packet-up too large", http.StatusRequestEntityTooLarge)
			return
		}

		if err := session.uploadQueue.Push(Packet{
			Seq:     seq,
			Payload: body,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if len(body) == 0 {
			w.Header().Set("Cache-Control", "no-store")
		}
		w.WriteHeader(http.StatusOK)
		return
	}

	http.NotFound(w, r)
}

func splitNonEmpty(s string) []string {
	raw := strings.Split(s, "/")
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func equalHost(a, b string) bool {
	a = strings.ToLower(a)
	b = strings.ToLower(b)

	if ah, _, err := net.SplitHostPort(a); err == nil {
		a = ah
	}
	if bh, _, err := net.SplitHostPort(b); err == nil {
		b = bh
	}

	return a == b
}
