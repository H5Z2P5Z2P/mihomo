package snell

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
	"github.com/metacubex/mihomo/transport/socks5"
)

func TestSnellV4RoundTrip(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	client := newV4Conn(clientRaw, []byte("password"))
	server := newV4Conn(serverRaw, []byte("password"))

	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("hello"))
		writeErr <- err
	}()

	buf := make([]byte, 5)
	if _, err := io.ReadFull(server, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("unexpected plaintext: %q", buf)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}

	go func() {
		_, err := server.Write([]byte("world"))
		writeErr <- err
	}()
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "world" {
		t.Fatalf("unexpected response plaintext: %q", buf)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
}

func TestSnellV4ZeroChunk(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	client := newV4Conn(clientRaw, []byte("password"))
	server := newV4Conn(serverRaw, []byte("password"))

	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write(nil)
		writeErr <- err
	}()

	_, err := server.Read(make([]byte, 1))
	if !errors.Is(err, shadowaead.ErrZeroChunk) {
		t.Fatalf("expected zero chunk, got %v", err)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
}

func TestSnellV4FirstFrameIncludesInitialPadding(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	client := newV4Conn(clientRaw, []byte("password"))
	writeErr := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte("x"))
		writeErr <- err
	}()

	salt := make([]byte, v4SaltSize)
	if _, err := io.ReadFull(serverRaw, salt); err != nil {
		t.Fatal(err)
	}

	headerCipher := make([]byte, v4HeaderCipherSize)
	if _, err := io.ReadFull(serverRaw, headerCipher); err != nil {
		t.Fatal(err)
	}
	aead, err := v4AEAD([]byte("password"), salt)
	if err != nil {
		t.Fatal(err)
	}
	var nonce [v4NonceSize]byte
	header, err := aead.Open(nil, nonce[:], headerCipher, nil)
	if err != nil {
		t.Fatal(err)
	}
	paddingLength := int(binary.BigEndian.Uint16(header[3:5]))
	payloadLength := int(binary.BigEndian.Uint16(header[5:7]))
	if paddingLength < v4InitialPaddingMin || paddingLength >= v4InitialPaddingMin+v4InitialPaddingSpan {
		t.Fatalf("unexpected initial padding length: %d", paddingLength)
	}
	if payloadLength != 1 {
		t.Fatalf("unexpected first payload length: %d", payloadLength)
	}

	rest := make([]byte, paddingLength+payloadLength+aead.Overhead())
	if _, err := io.ReadFull(serverRaw, rest); err != nil {
		t.Fatal(err)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
}

func TestSnellV4PaddedFrame(t *testing.T) {
	var raw bytes.Buffer
	writer, err := newV4Writer(&raw, []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.writeFrame([]byte("payload"), 13); err != nil {
		t.Fatal(err)
	}

	data := raw.Bytes()
	aead, err := v4AEAD([]byte("password"), data[:v4SaltSize])
	if err != nil {
		t.Fatal(err)
	}
	reader := &v4Reader{
		Reader: bytes.NewReader(data[v4SaltSize:]),
		aead:   aead,
	}

	buf := make([]byte, 7)
	if _, err := io.ReadFull(reader, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "payload" {
		t.Fatalf("unexpected padded plaintext: %q", buf)
	}
}

func TestSnellV4BitCountPadding(t *testing.T) {
	padding, err := makeV4BitCountPadding(32, 77)
	if err != nil {
		t.Fatal(err)
	}
	if len(padding) != 32 {
		t.Fatalf("unexpected padding length: got %d want 32", len(padding))
	}

	ones := 0
	for _, b := range padding {
		for b != 0 {
			ones += int(b & 1)
			b >>= 1
		}
	}
	if ones != 77 {
		t.Fatalf("unexpected padding bit count: got %d want 77", ones)
	}
}

func TestSnellV4WriterDefersSaltUntilFirstFrame(t *testing.T) {
	raw := &recordingWriter{}
	writer, err := newV4Writer(raw, []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	if raw.Len() != 0 {
		t.Fatalf("salt was written before first frame: %d bytes", raw.Len())
	}
	if raw.writes != 0 {
		t.Fatalf("salt was written before first frame: %d writes", raw.writes)
	}

	if _, err := writer.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}

	wantLen := v4SaltSize + v4HeaderCipherSize + 1 + writer.aead.Overhead()
	paddingLength, payloadLength := decodeV4HeaderForTest(t, raw.Bytes())
	if paddingLength < v4InitialPaddingMin || paddingLength >= v4InitialPaddingMin+v4InitialPaddingSpan {
		t.Fatalf("unexpected initial padding length: %d", paddingLength)
	}
	if payloadLength != 1 {
		t.Fatalf("unexpected first payload length: %d", payloadLength)
	}
	wantLen += paddingLength
	if raw.Len() != wantLen {
		t.Fatalf("unexpected first frame length: got %d, want %d", raw.Len(), wantLen)
	}
	if raw.writes != 1 {
		t.Fatalf("first frame should be written with salt in one write, got %d writes", raw.writes)
	}
}

func TestSnellV4PayloadLimitMatchesServer(t *testing.T) {
	writer, err := newV4Writer(io.Discard, []byte("password"))
	if err != nil {
		t.Fatal(err)
	}

	initialPaddingLength := writer.initialPaddingLength
	if initialPaddingLength < v4InitialPaddingMin || initialPaddingLength >= v4InitialPaddingMin+v4InitialPaddingSpan {
		t.Fatalf("unexpected initial padding length: %d", initialPaddingLength)
	}

	if got, want := writer.nextPayloadLimit(), uint16(v4FrameSize-55-initialPaddingLength); got != want {
		t.Fatalf("initial payload limit mismatch: got %d want %d", got, want)
	}
	if got, want := writer.nextPayloadLimit(), uint16(v4FrameSize-55-initialPaddingLength+v4FrameSize-39); got != want {
		t.Fatalf("grown payload limit mismatch: got %d want %d", got, want)
	}

	writer.lastWrite = time.Now().Add(-31 * time.Second)
	if got, want := writer.nextPayloadLimit(), uint16(v4FrameSize-39); got != want {
		t.Fatalf("reset payload limit mismatch: got %d want %d", got, want)
	}
}

func TestSnellV4UDPWriteKeepsDatagramInSingleFrame(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	client := &Snell{Conn: newV4Conn(clientRaw, []byte("password"))}
	server := newV4Conn(serverRaw, []byte("password"))
	pc := PacketConn(client)
	payload := bytes.Repeat([]byte{0x42}, v4FrameSize)
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 53}

	writeErr := make(chan error, 1)
	go func() {
		_, err := pc.WriteTo(payload, addr)
		writeErr <- err
	}()

	buf := make([]byte, maxLength)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}
	if want := 1 + 2 + net.IPv4len + 2 + len(payload); n != want {
		t.Fatalf("UDP request was split or truncated: got %d want %d", n, want)
	}
	if got := buf[:9]; !bytes.Equal(got, []byte{CommondUDPForward, 0, 4, 1, 2, 3, 4, 0, 53}) {
		t.Fatalf("unexpected UDP request header: %x", got)
	}
}

func TestSnellWritePacketRejectsOversizedDatagram(t *testing.T) {
	var raw recordingWriter
	addr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 53}
	payload := bytes.Repeat([]byte{0x42}, maxLength)

	n, err := WritePacket(&raw, socks5.ParseAddrToSocksAddr(addr), payload)
	if err == nil {
		t.Fatal("expected oversized UDP payload to be rejected")
	}
	if got, want := err.Error(), "snell UDP payload too large"; got != want {
		t.Fatalf("unexpected error: got %q want %q", got, want)
	}
	if n != 0 {
		t.Fatalf("written payload length = %d, want 0", n)
	}
	if raw.Len() != 0 {
		t.Fatalf("oversized datagram should not be written, got %d bytes", raw.Len())
	}
}

func TestSnellWriteHeaderConnectCommand(t *testing.T) {
	tests := []struct {
		name    string
		version int
		reuse   bool
		want    byte
	}{
		{name: "v1", version: Version1, want: CommandConnect},
		{name: "v2", version: Version2, want: CommandConnectV2},
		{name: "v4 no reuse", version: Version4, want: CommandConnect},
		{name: "v4 reuse", version: Version4, reuse: true, want: CommandConnectV2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &bufferConn{}
			if err := WriteHeaderWithReuse(conn, "example.com", 443, tt.version, tt.reuse); err != nil {
				t.Fatal(err)
			}
			data := conn.Bytes()
			if len(data) < 2 {
				t.Fatalf("header too short: %x", data)
			}
			if data[1] != tt.want {
				t.Fatalf("unexpected command: got %#x, want %#x", data[1], tt.want)
			}
		})
	}
}

func TestSnellWriteHeaderRejectsInvalidAddress(t *testing.T) {
	tests := []struct {
		name string
		host string
		port uint
	}{
		{name: "long host", host: string(bytes.Repeat([]byte{'a'}, 256)), port: 443},
		{name: "large port", host: "example.com", port: 65536},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &bufferConn{}
			if err := WriteHeaderWithReuse(conn, tt.host, tt.port, Version4, false); err == nil {
				t.Fatal("expected invalid address error")
			}
			if conn.Len() != 0 {
				t.Fatalf("invalid header should not be written, got %d bytes", conn.Len())
			}
		})
	}
}

func TestSnellV4ConcurrentFirstWrite(t *testing.T) {
	conn := newV4Conn(&bufferConn{}, []byte("password"))

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := conn.Write([]byte("payload"))
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestSnellV4CountPayloadOnesIncludesTail(t *testing.T) {
	if got, want := countV4PayloadOnes([]byte{0, 0, 0, 0xff, 0x0f}), 12; got != want {
		t.Fatalf("ones = %d, want %d", got, want)
	}
}

func TestSnellReadReplyPreservesBufferedPayload(t *testing.T) {
	conn := &Snell{Conn: &bufferConn{}}
	conn.Conn.(*bufferConn).Write([]byte{CommandTunnel, 'o', 'k'})

	if err := conn.ReadReply(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "ok" {
		t.Fatalf("unexpected buffered payload: %q", buf)
	}
}

func TestSnellReadReplyErrorResponse(t *testing.T) {
	conn := &Snell{Conn: &bufferConn{}}
	conn.Conn.(*bufferConn).Write([]byte{CommandError, 0x65, 10})
	conn.Conn.(*bufferConn).WriteString("Remote EOF")

	err := conn.ReadReply()
	if err == nil {
		t.Fatal("expected error response")
	}
	if got, want := err.Error(), "server reported code: 101, message: Remote EOF"; got != want {
		t.Fatalf("unexpected error: got %q want %q", got, want)
	}
}

func TestEncodeQUICEnvelope(t *testing.T) {
	inner := []byte("quic initial")
	envelope, err := EncodeQUICEnvelope([]byte("password"), "example.com", 443, inner)
	if err != nil {
		t.Fatal(err)
	}
	if len(envelope) < v4SaltSize+v4HeaderCipherSize {
		t.Fatalf("envelope too short: %d", len(envelope))
	}

	aead, err := v4AEAD([]byte("password"), envelope[:v4SaltSize])
	if err != nil {
		t.Fatal(err)
	}
	headerCipher := envelope[v4SaltSize : v4SaltSize+v4HeaderCipherSize]
	header, err := aead.Open(nil, make([]byte, aead.NonceSize()), headerCipher, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(header) != v4HeaderPlainSize || header[0] != 4 {
		t.Fatalf("invalid header: %x", header)
	}
	paddingLength := int(binary.BigEndian.Uint16(header[3:5]))
	payloadLength := int(binary.BigEndian.Uint16(header[5:7]))
	if paddingLength != 0 {
		t.Fatalf("unexpected padding length: %d", paddingLength)
	}
	payloadCipher := envelope[v4SaltSize+v4HeaderCipherSize:]
	if len(payloadCipher) != payloadLength+aead.Overhead() {
		t.Fatalf("payload length mismatch: got %d want %d", len(payloadCipher), payloadLength+aead.Overhead())
	}
	nonce1 := make([]byte, aead.NonceSize())
	binary.LittleEndian.PutUint64(nonce1, 1)
	payload, err := aead.Open(nil, nonce1, payloadCipher, nil)
	if err != nil {
		t.Fatal(err)
	}
	wantPrefix := []byte{quicReqVersion, quicReqCommand, 0, byte(len("example.com"))}
	if !bytes.Equal(payload[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("unexpected payload prefix: %x", payload[:len(wantPrefix)])
	}
	offset := len(wantPrefix)
	if got := string(payload[offset : offset+len("example.com")]); got != "example.com" {
		t.Fatalf("unexpected host: %q", got)
	}
	offset += len("example.com")
	if got := binary.BigEndian.Uint16(payload[offset : offset+2]); got != 443 {
		t.Fatalf("unexpected port: %d", got)
	}
	offset += 2
	if !bytes.Equal(payload[offset:], inner) {
		t.Fatalf("unexpected inner packet: %q", payload[offset:])
	}
}

func TestEncodeQUICEnvelopeRejectsInvalidInput(t *testing.T) {
	if _, err := EncodeQUICEnvelope([]byte("password"), "example.com", 443, nil); err == nil {
		t.Fatal("expected empty inner QUIC packet error")
	}
	if _, err := EncodeQUICEnvelope([]byte("password"), string(bytes.Repeat([]byte{'a'}, 256)), 443, []byte("x")); err == nil {
		t.Fatal("expected long host error")
	}
}

func TestWritePacketResponseUsesSocksAddrParser(t *testing.T) {
	var buf bytes.Buffer
	n, err := WritePacketResponse(&buf, dummyAddr("127.0.0.1:53"), []byte("ok"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("written payload length = %d, want 2", n)
	}

	want := []byte{0x04, 127, 0, 0, 1, 0, 53, 'o', 'k'}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("packet = %x, want %x", buf.Bytes(), want)
	}
}

type bufferConn struct {
	bytes.Buffer
}

func (c *bufferConn) Close() error                     { return nil }
func (c *bufferConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *bufferConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *bufferConn) SetDeadline(time.Time) error      { return nil }
func (c *bufferConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufferConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }

type recordingWriter struct {
	bytes.Buffer
	writes int
}

func (w *recordingWriter) Write(b []byte) (int, error) {
	w.writes++
	return w.Buffer.Write(b)
}

func decodeV4HeaderForTest(t *testing.T, data []byte) (int, int) {
	t.Helper()
	if len(data) < v4SaltSize+v4HeaderCipherSize {
		t.Fatalf("frame too short: %d", len(data))
	}
	aead, err := v4AEAD([]byte("password"), data[:v4SaltSize])
	if err != nil {
		t.Fatal(err)
	}
	var nonce [v4NonceSize]byte
	header, err := aead.Open(nil, nonce[:], data[v4SaltSize:v4SaltSize+v4HeaderCipherSize], nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(header) != v4HeaderPlainSize || header[0] != 4 {
		t.Fatalf("invalid v4 header: %x", header)
	}
	return int(binary.BigEndian.Uint16(header[3:5])), int(binary.BigEndian.Uint16(header[5:7]))
}

func BenchmarkSnellV4WriteFrame(b *testing.B) {
	writer, err := newV4Writer(io.Discard, []byte("password"))
	if err != nil {
		b.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), 16*1024)

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := writer.Write(payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSnellV4BitCountPadding(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := makeV4BitCountPadding(v4InitialPaddingMin, 900); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeQUICEnvelope(b *testing.B) {
	inner := bytes.Repeat([]byte("x"), 1200)

	b.SetBytes(int64(len(inner)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := EncodeQUICEnvelope([]byte("password"), "example.com", 443, inner); err != nil {
			b.Fatal(err)
		}
	}
}
