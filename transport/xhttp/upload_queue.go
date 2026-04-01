package xhttp

import (
	"fmt"
	"io"
	"sync"
)

type Packet struct {
	Seq     uint64
	Payload []byte
}

type uploadQueue struct {
	mu            sync.Mutex
	cond          *sync.Cond
	packets       map[uint64][]byte
	nextSeq       uint64
	buf           []byte
	closed        bool
	maxBytes      int
	bufferedBytes int
}

func NewUploadQueue(maxBytes int) *uploadQueue {
	q := &uploadQueue{
		packets:  make(map[uint64][]byte),
		maxBytes: maxBytes,
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

	oldLen := 0
	if old, ok := q.packets[p.Seq]; ok {
		oldLen = len(old)
	}

	if q.maxBytes > 0 && q.bufferedBytes-oldLen+len(p.Payload) > q.maxBytes {
		return fmt.Errorf("xhttp upload queue is too large")
	}

	q.packets[p.Seq] = p.Payload
	q.bufferedBytes += len(p.Payload) - oldLen
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
			q.bufferedBytes -= n
			return n, nil
		}

		if payload, ok := q.packets[q.nextSeq]; ok {
			delete(q.packets, q.nextSeq)
			q.nextSeq++
			q.buf = payload
			continue
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
