package xhttp

import (
	"errors"
	"io"
	"sync"
)

var errPacketQueueTooLarge = errors.New("packet queue is too large")

type Packet struct {
	Seq     uint64
	Payload []byte
}

type uploadQueue struct {
	mu      sync.Mutex
	cond    *sync.Cond
	packets map[uint64][]byte
	nextSeq uint64
	buf     []byte
	maxSize int
	err     error
	closed  bool
}

func NewUploadQueue(maxSize int) *uploadQueue {
	if maxSize <= 0 {
		maxSize = 1
	}

	q := &uploadQueue{
		packets: make(map[uint64][]byte),
		maxSize: maxSize,
	}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *uploadQueue) Push(p Packet) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return io.ErrClosedPipe
	}
	if q.err != nil {
		return q.err
	}
	if p.Seq < q.nextSeq {
		return nil
	}
	if _, exists := q.packets[p.Seq]; exists {
		return nil
	}

	for len(q.packets) >= q.maxSize {
		if _, ok := q.packets[q.nextSeq]; !ok {
			q.err = errPacketQueueTooLarge
			q.cond.Broadcast()
			return q.err
		}
		q.cond.Wait()
		if q.closed {
			return io.ErrClosedPipe
		}
		if q.err != nil {
			return q.err
		}
		if p.Seq < q.nextSeq {
			return nil
		}
		if _, exists := q.packets[p.Seq]; exists {
			return nil
		}
	}

	cp := make([]byte, len(p.Payload))
	copy(cp, p.Payload)
	q.packets[p.Seq] = cp
	q.cond.Broadcast()
	return nil
}

func (q *uploadQueue) Read(b []byte) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for {
		if len(q.buf) > 0 {
			n := copy(b, q.buf)
			q.buf = q.buf[n:]
			if len(q.buf) == 0 {
				q.cond.Broadcast()
			}
			return n, nil
		}

		if payload, ok := q.packets[q.nextSeq]; ok {
			delete(q.packets, q.nextSeq)
			q.nextSeq++
			q.buf = payload
			q.cond.Broadcast()
			continue
		}

		if q.err != nil {
			return 0, q.err
		}

		if q.closed {
			return 0, io.EOF
		}

		q.cond.Wait()
	}
}

func (q *uploadQueue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.closed = true
	q.cond.Broadcast()
	return nil
}
