package xhttp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUploadQueueErrorsWhenMisorderedBufferExceedsLimit(t *testing.T) {
	q := NewUploadQueue(2)

	require.NoError(t, q.Push(Packet{Seq: 1, Payload: []byte("a")}))
	require.NoError(t, q.Push(Packet{Seq: 2, Payload: []byte("b")}))
	require.ErrorIs(t, q.Push(Packet{Seq: 3, Payload: []byte("c")}), errPacketQueueTooLarge)

	buf := make([]byte, 1)
	_, err := q.Read(buf)
	require.ErrorIs(t, err, errPacketQueueTooLarge)
}
