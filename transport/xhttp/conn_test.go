package xhttp

import (
	"io"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

type countingCloser struct {
	closed atomic.Int64
}

func (c *countingCloser) Close() error {
	c.closed.Add(1)
	return nil
}

func (c *countingCloser) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (c *countingCloser) Write(b []byte) (int, error) {
	return len(b), nil
}

func TestConnCloseIsIdempotent(t *testing.T) {
	writer := &countingCloser{}
	reader := &countingCloser{}
	var onCloseCalls atomic.Int64

	conn := &Conn{
		writer: writer,
		reader: reader,
		onClose: func() {
			onCloseCalls.Add(1)
		},
	}

	require.NoError(t, conn.Close())
	require.NoError(t, conn.Close())
	require.NoError(t, conn.Close())

	require.Equal(t, int64(1), writer.closed.Load())
	require.Equal(t, int64(1), reader.closed.Load())
	require.Equal(t, int64(1), onCloseCalls.Load())
}
