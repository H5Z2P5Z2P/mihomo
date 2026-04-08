package xhttp

import (
	"bufio"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
)

type H1Conn struct {
	PendingResponses int
	RespBufReader    *bufio.Reader
	net.Conn
}

func NewH1Conn(conn net.Conn) *H1Conn {
	return &H1Conn{
		RespBufReader: bufio.NewReader(conn),
		Conn:          conn,
	}
}

func (c *H1Conn) DrainResponse(req *stdhttp.Request) error {
	for c.PendingResponses > 0 {
		resp, err := stdhttp.ReadResponse(c.RespBufReader, req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		c.PendingResponses--
		if resp.StatusCode != stdhttp.StatusOK {
			return fmt.Errorf("xhttp packet-up bad status: %s", resp.Status)
		}
	}
	return nil
}
