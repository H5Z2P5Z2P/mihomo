package xhttp

import "time"

const (
	xhttpPacketUpMaxEachPostBytes = 1000000
	xhttpPacketUpMaxBufferedPosts = 30
)

const xhttpPacketUpMinPostsInterval = 30 * time.Millisecond
