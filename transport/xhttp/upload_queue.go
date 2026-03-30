package xhttp

import (
	"errors"
	"io"
	"sync"
)

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
	stream  io.Reader
	closed  bool
}

func NewUploadQueue() *uploadQueue {
	q := &uploadQueue{
		packets: make(map[uint64][]byte),
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

	cp := make([]byte, len(p.Payload))
	copy(cp, p.Payload)
	q.packets[p.Seq] = cp
	q.cond.Broadcast()
	return nil
}

func (q *uploadQueue) PushReader(r io.Reader) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return io.ErrClosedPipe
	}
	if q.stream != nil {
		return errors.New("xhttp stream already exists")
	}

	q.stream = r
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
			return n, nil
		}

		if payload, ok := q.packets[q.nextSeq]; ok {
			delete(q.packets, q.nextSeq)
			q.nextSeq++
			q.buf = payload
			continue
		}

		if stream := q.stream; stream != nil {
			q.mu.Unlock()
			n, err := stream.Read(b)
			q.mu.Lock()

			if err == io.EOF {
				if q.stream == stream {
					q.stream = nil
				}
				if n > 0 {
					return n, nil
				}
				return 0, io.EOF
			}

			return n, err
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
	if closer, ok := q.stream.(io.Closer); ok {
		_ = closer.Close()
	}
	q.cond.Broadcast()
	return nil
}
