package xhttp

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUploadQueueReadsFromStreamReader(t *testing.T) {
	q := NewUploadQueue(0)
	require.NoError(t, q.Push(Packet{Reader: io.NopCloser(strings.NewReader("abc"))}))

	buf := make([]byte, 3)
	n, err := q.Read(buf)
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, "abc", string(buf[:n]))
}

func TestUploadQueueErrorsWhenMisorderedBufferExceedsLimit(t *testing.T) {
	q := NewUploadQueue(2)

	require.NoError(t, q.Push(Packet{Seq: 1, Payload: []byte("a")}))
	require.NoError(t, q.Push(Packet{Seq: 2, Payload: []byte("b")}))
	require.ErrorIs(t, q.Push(Packet{Seq: 3, Payload: []byte("c")}), errPacketQueueTooLarge)

	buf := make([]byte, 1)
	_, err := q.Read(buf)
	require.ErrorIs(t, err, errPacketQueueTooLarge)
}

func TestUploadQueueWithoutLimitAllowsBufferedPackets(t *testing.T) {
	q := NewUploadQueue(0)

	for i := 1; i <= 64; i++ {
		require.NoError(t, q.Push(Packet{Seq: uint64(i), Payload: []byte("a")}))
	}
}
