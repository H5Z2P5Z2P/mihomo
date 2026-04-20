package xhttp

import (
	"errors"
	"io"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/httputils"
)

type Conn struct {
	writer  io.WriteCloser
	reader  io.ReadCloser
	onClose func()
	httputils.NetAddr

	closeOnce sync.Once
}

func (c *Conn) Write(b []byte) (int, error) {
	return c.writer.Write(b)
}

func (c *Conn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err1 := c.writer.Close()
		err2 := c.reader.Close()
		if c.onClose != nil {
			c.onClose()
		}
		err = errors.Join(err1, err2)
	})
	return err
}

func (c *Conn) SetReadDeadline(t time.Time) error  { return c.SetDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.SetDeadline(t) }

func (c *Conn) SetDeadline(t time.Time) error {
	// Align with Xray splitConn: xhttp does not implement transport-level
	// deadlines, and treating them as hard close timers makes idle sessions
	// disconnect under normal upper-layer deadline usage.
	return nil
}
