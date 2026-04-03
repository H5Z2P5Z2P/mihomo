package xhttp

import (
	"errors"
	"io"
	"sync"
)

var (
	errPacketQueueTooLarge = errors.New("packet queue is too large")
	errUploadReaderExists  = errors.New("upload reader already exists")
)

type Packet struct {
	Reader  io.ReadCloser
	Seq     uint64
	Payload []byte
}

type uploadQueue struct {
	mu      sync.Mutex
	cond    *sync.Cond
	reader  io.ReadCloser
	stream  bool
	packets map[uint64][]byte
	nextSeq uint64
	buf     []byte
	maxSize int
	err     error
	closed  bool
}

func NewUploadQueue(maxSize int) *uploadQueue {
	q := &uploadQueue{
		packets: make(map[uint64][]byte),
		maxSize: maxSize,
	}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *uploadQueue) SetMaxSize(maxSize int) {
	q.mu.Lock()
	q.maxSize = maxSize
	q.cond.Broadcast()
	q.mu.Unlock()
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
	if p.Reader != nil {
		if q.stream || len(q.packets) > 0 || len(q.buf) > 0 {
			return errUploadReaderExists
		}
		q.stream = true
		q.reader = p.Reader
		q.cond.Broadcast()
		return nil
	}
	if q.stream {
		return errUploadReaderExists
	}
	if p.Seq < q.nextSeq {
		return nil
	}
	if _, exists := q.packets[p.Seq]; exists {
		return nil
	}

	for q.maxSize > 0 && len(q.packets) >= q.maxSize {
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
	for {
		q.mu.Lock()

		if q.reader != nil {
			reader := q.reader
			q.mu.Unlock()
			return reader.Read(b)
		}

		if len(q.buf) > 0 {
			n := copy(b, q.buf)
			q.buf = q.buf[n:]
			if len(q.buf) == 0 {
				q.cond.Broadcast()
			}
			q.mu.Unlock()
			return n, nil
		}

		if payload, ok := q.packets[q.nextSeq]; ok {
			delete(q.packets, q.nextSeq)
			q.nextSeq++
			q.buf = payload
			q.cond.Broadcast()
			q.mu.Unlock()
			continue
		}

		if q.err != nil {
			err := q.err
			q.mu.Unlock()
			return 0, err
		}

		if q.closed {
			q.mu.Unlock()
			return 0, io.EOF
		}

		q.cond.Wait()
		q.mu.Unlock()
	}
}

func (q *uploadQueue) Close() error {
	q.mu.Lock()
	reader := q.reader
	q.closed = true
	q.reader = nil
	q.cond.Broadcast()
	q.mu.Unlock()

	if reader != nil {
		return reader.Close()
	}
	return nil
}
