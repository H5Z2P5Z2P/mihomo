package xhttp

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/mihomo/common/httputils"
)

type xmuxEntry struct {
	transport http.RoundTripper

	openUsage     atomic.Int32
	leftRequests  atomic.Int32
	reuseCount    atomic.Int32
	maxReuseTimes int32
	unreusableAt  time.Time

	closed atomic.Bool
}

func (e *xmuxEntry) IsClosed() bool {
	return e.closed.Load()
}

func (e *xmuxEntry) Close() {
	if !e.closed.CompareAndSwap(false, true) {
		return
	}
	httputils.CloseTransport(e.transport)
}

type XMuxProvider interface {
	GetMaxConnections() string
	GetMaxConcurrency() string
	GetCMaxReuseTimes() string
	GetHMaxRequestTimes() string
	GetHMaxReusableSecs() string
}

func (c *XMuxConfig) GetMaxConnections() string   { return c.MaxConnections }
func (c *XMuxConfig) GetMaxConcurrency() string   { return c.MaxConcurrency }
func (c *XMuxConfig) GetCMaxReuseTimes() string   { return c.CMaxReuseTimes }
func (c *XMuxConfig) GetHMaxRequestTimes() string { return c.HMaxRequestTimes }
func (c *XMuxConfig) GetHMaxReusableSecs() string { return c.HMaxReusableSecs }

func (c *XMuxDownloadConfig) GetMaxConnections() string   { return c.MaxConnections }
func (c *XMuxDownloadConfig) GetMaxConcurrency() string   { return c.MaxConcurrency }
func (c *XMuxDownloadConfig) GetCMaxReuseTimes() string   { return c.CMaxReuseTimes }
func (c *XMuxDownloadConfig) GetHMaxRequestTimes() string { return c.HMaxRequestTimes }
func (c *XMuxDownloadConfig) GetHMaxReusableSecs() string { return c.HMaxReusableSecs }

type xmuxManager struct {
	cfg XMuxProvider

	mu      sync.Mutex
	entries []*xmuxEntry
}

func newXMuxManager(cfg XMuxProvider) *xmuxManager {
	if cfg == nil {
		return nil
	}
	return &xmuxManager{
		cfg:     cfg,
		entries: make([]*xmuxEntry, 0),
	}
}

func (m *xmuxManager) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, entry := range m.entries {
		entry.Close()
	}
	m.entries = nil
}

func (m *xmuxManager) cleanupLocked(now time.Time) {
	kept := m.entries[:0]
	for _, entry := range m.entries {
		if entry.IsClosed() {
			continue
		}
		if entry.leftRequests.Load() <= 0 && entry.openUsage.Load() == 0 {
			entry.Close()
			continue
		}
		if !entry.unreusableAt.IsZero() && now.After(entry.unreusableAt) && entry.openUsage.Load() == 0 {
			entry.Close()
			continue
		}
		kept = append(kept, entry)
	}
	m.entries = kept
}

func (m *xmuxManager) release(entry *xmuxEntry) {
	if entry == nil {
		return
	}
	remaining := entry.openUsage.Add(-1)
	if remaining < 0 {
		entry.openUsage.Store(0)
		remaining = 0
	}

	if remaining == 0 {
		now := time.Now()
		if entry.leftRequests.Load() <= 0 ||
			(entry.maxReuseTimes > 0 && entry.reuseCount.Load() >= entry.maxReuseTimes) ||
			(!entry.unreusableAt.IsZero() && now.After(entry.unreusableAt)) {
			entry.Close()
		}
	}
}

func (m *xmuxManager) getResolvedConfigs() (int, int, int, int, int) {
	if m.cfg == nil {
		return 0, 0, 0, 0, 0
	}

	maxConnections, _ := resolveRangeValue(m.cfg.GetMaxConnections(), 0)
	maxConcurrency, _ := resolveRangeValue(m.cfg.GetMaxConcurrency(), 0)
	cMaxReuseTimes, _ := resolveRangeValue(m.cfg.GetCMaxReuseTimes(), 0)
	hMaxRequestTimes, _ := resolveRangeValue(m.cfg.GetHMaxRequestTimes(), 0)
	hMaxReusableSecs, _ := resolveRangeValue(m.cfg.GetHMaxReusableSecs(), 0)

	return maxConnections, maxConcurrency, cMaxReuseTimes, hMaxRequestTimes, hMaxReusableSecs
}

func (m *xmuxManager) resolvedMaxConcurrency() int {
	_, maxConcurrency, _, _, _ := m.getResolvedConfigs()
	return maxConcurrency
}

func (m *xmuxManager) resolvedMaxConnections() int {
	maxConnections, _, _, _, _ := m.getResolvedConfigs()
	return maxConnections
}

func (m *xmuxManager) pickLocked() *xmuxEntry {
	maxConcurrency := m.resolvedMaxConcurrency()

	var best *xmuxEntry
	for _, entry := range m.entries {
		if entry.IsClosed() {
			continue
		}
		if entry.leftRequests.Load() <= 0 {
			continue
		}
		if entry.maxReuseTimes > 0 && entry.reuseCount.Load() >= entry.maxReuseTimes {
			continue
		}
		if maxConcurrency > 0 && int(entry.openUsage.Load()) >= maxConcurrency {
			continue
		}
		if best == nil || entry.openUsage.Load() < best.openUsage.Load() {
			best = entry
		}
	}
	return best
}

func (m *xmuxManager) canCreateLocked() bool {
	maxConnections := m.resolvedMaxConnections()
	if maxConnections <= 0 {
		return true
	}
	return len(m.entries) < maxConnections
}

func (m *xmuxManager) newEntryLocked(
	makeTransport TransportMaker,
	now time.Time,
) *xmuxEntry {
	transport := makeTransport()

	entry := &xmuxEntry{
		transport: transport,
	}

	_, _, cMaxReuseTimes, hMaxRequestTimes, hMaxReusableSecs := m.getResolvedConfigs()

	if hMaxRequestTimes > 0 {
		entry.leftRequests.Store(int32(hMaxRequestTimes))
	} else {
		entry.leftRequests.Store(1<<30 - 1)
	}
	if hMaxReusableSecs > 0 {
		entry.unreusableAt = now.Add(time.Duration(hMaxReusableSecs) * time.Second)
	}

	if cMaxReuseTimes > 0 {
		entry.maxReuseTimes = int32(cMaxReuseTimes)
	}

	m.entries = append(m.entries, entry)
	return entry
}

func (m *xmuxManager) getOrCreate(
	makeTransport TransportMaker,
) (*xmuxEntry, error) {
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	m.cleanupLocked(now)

	entry := m.pickLocked()
	reused := entry != nil

	if entry == nil {
		if !m.canCreateLocked() {
			return nil, fmt.Errorf("xmux: no available connection")
		}
		entry = m.newEntryLocked(makeTransport, now)
	}

	if reused {
		entry.reuseCount.Add(1)
	}

	entry.openUsage.Add(1)
	if entry.leftRequests.Load() > 0 {
		entry.leftRequests.Add(-1)
	}

	return entry, nil
}
