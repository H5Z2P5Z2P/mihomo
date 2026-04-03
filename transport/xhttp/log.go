package xhttp

import (
	"sync/atomic"

	mlog "github.com/metacubex/mihomo/log"
)

var activeStreamUpConns atomic.Int64
var activePacketUpConns atomic.Int64
var activeStreamUpUploads atomic.Int64

func logLifecycle(format string, v ...any) {
	mlog.Infoln("[xhttp] "+format, v...)
}

func addActiveConn(mode string, delta int64) int64 {
	switch mode {
	case "stream-up":
		return activeStreamUpConns.Add(delta)
	case "packet-up":
		return activePacketUpConns.Add(delta)
	default:
		return 0
	}
}

func addActiveStreamUpUploads(delta int64) int64 {
	return activeStreamUpUploads.Add(delta)
}
