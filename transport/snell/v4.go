package snell

import (
	"bufio"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/big"
	"math/bits"
	mrand "math/rand"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
)

const (
	v4SaltSize           = 16
	v4NonceSize          = 12
	v4HeaderPlainSize    = 7
	v4HeaderCipherSize   = v4HeaderPlainSize + 16
	v4FrameSize          = 1460
	v4InitialPaddingMin  = 0x100
	v4InitialPaddingSpan = 0x100
)

type v4Conn struct {
	net.Conn
	psk   []byte
	r     *v4Reader
	w     *v4Writer
	rOnce sync.Once
	wOnce sync.Once
	rErr  error
	wErr  error
}

func newV4Conn(conn net.Conn, psk []byte) *v4Conn {
	return &v4Conn{Conn: conn, psk: psk}
}

func (c *v4Conn) initReader() error {
	var salt [v4SaltSize]byte
	if _, err := io.ReadFull(c.Conn, salt[:]); err != nil {
		return err
	}

	aead, err := v4AEAD(c.psk, salt[:])
	if err != nil {
		return err
	}
	c.r = &v4Reader{Reader: bufio.NewReaderSize(c.Conn, 64*1024), aead: aead}
	return nil
}

func (c *v4Conn) initWriter() error {
	w, err := newV4Writer(c.Conn, c.psk)
	if err != nil {
		return err
	}
	c.w = w
	return nil
}

func (c *v4Conn) Read(b []byte) (int, error) {
	c.rOnce.Do(func() {
		c.rErr = c.initReader()
	})
	if c.rErr != nil {
		return 0, c.rErr
	}
	return c.r.Read(b)
}

func (c *v4Conn) Write(b []byte) (int, error) {
	c.wOnce.Do(func() {
		c.wErr = c.initWriter()
	})
	if c.wErr != nil {
		return 0, c.wErr
	}
	return c.w.Write(b)
}

func (c *v4Conn) WritePacketFrame(b []byte) (int, error) {
	if len(b) > maxLength {
		return 0, errors.New("snell v4 frame too large")
	}
	c.wOnce.Do(func() {
		c.wErr = c.initWriter()
	})
	if c.wErr != nil {
		return 0, c.wErr
	}

	c.w.mux.Lock()
	defer c.w.mux.Unlock()
	if err := c.w.writeFrame(b, c.w.nextFramePaddingLength(len(b))); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *v4Conn) WriteTo(w io.Writer) (int64, error) {
	c.rOnce.Do(func() {
		c.rErr = c.initReader()
	})
	if c.rErr != nil {
		return 0, c.rErr
	}

	var written int64
	buf := make([]byte, maxLength)
	for {
		n, err := c.r.Read(buf)
		if n > 0 {
			nw, ew := w.Write(buf[:n])
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
			if nw != n {
				return written, io.ErrShortWrite
			}
		}
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return written, err
		}
	}
}

func (c *v4Conn) ReadFrom(r io.Reader) (int64, error) {
	c.wOnce.Do(func() {
		c.wErr = c.initWriter()
	})
	if c.wErr != nil {
		return 0, c.wErr
	}

	var read int64
	buf := make([]byte, maxLength)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			read += int64(n)
			if _, ew := c.w.Write(buf[:n]); ew != nil {
				return read, ew
			}
		}
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return read, err
		}
	}
}

func v4AEAD(psk, salt []byte) (cipher.AEAD, error) {
	return aesGCM(snellKDF(psk, salt, 16))
}

type v4Reader struct {
	io.Reader
	aead  cipher.AEAD
	nonce [v4NonceSize]byte
	buf   []byte
	frame []byte
	mux   sync.Mutex
}

func (r *v4Reader) Read(b []byte) (int, error) {
	r.mux.Lock()
	defer r.mux.Unlock()

	if len(r.buf) == 0 {
		payload, err := r.readFrame()
		if err != nil {
			return 0, err
		}
		r.buf = payload
	}

	n := copy(b, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func (r *v4Reader) readFrame() ([]byte, error) {
	var headerCipher [v4HeaderCipherSize]byte
	if _, err := io.ReadFull(r.Reader, headerCipher[:]); err != nil {
		return nil, err
	}

	header, err := r.aead.Open(headerCipher[:0], r.nonce[:], headerCipher[:], nil)
	incrementV4Nonce(r.nonce[:])
	if err != nil {
		return nil, err
	}
	if len(header) != v4HeaderPlainSize || header[0] != 4 {
		return nil, errors.New("snell v4 invalid frame header")
	}

	paddingLength := int(binary.BigEndian.Uint16(header[3:5]))
	payloadLength := int(binary.BigEndian.Uint16(header[5:7]))
	if payloadLength == 0 {
		if paddingLength != 0 {
			return nil, errors.New("snell v4 zero chunk with padding")
		}
		return nil, shadowaead.ErrZeroChunk
	}
	if payloadLength > maxLength || paddingLength > maxLength {
		return nil, errors.New("snell v4 frame too large")
	}

	payloadCipherLength := payloadLength + r.aead.Overhead()
	frameLength := paddingLength + payloadCipherLength
	if cap(r.frame) < frameLength {
		r.frame = make([]byte, frameLength)
	}
	frame := r.frame[:frameLength]
	if _, err := io.ReadFull(r.Reader, frame); err != nil {
		return nil, err
	}
	if paddingLength > 0 {
		swapPadding(frame[:paddingLength], frame[paddingLength:])
	}

	payloadCipher := frame[paddingLength:]
	payload, err := r.aead.Open(payloadCipher[:0], r.nonce[:], payloadCipher, nil)
	incrementV4Nonce(r.nonce[:])
	if err != nil {
		return nil, err
	}
	return payload, nil
}

type v4Writer struct {
	io.Writer
	aead                 cipher.AEAD
	nonce                [v4NonceSize]byte
	salt                 [v4SaltSize]byte
	saltSent             bool
	buf                  []byte
	initialPaddingLength uint16
	payloadLimit         uint16
	lastWrite            time.Time
	mux                  sync.Mutex
}

func newV4Writer(w io.Writer, psk []byte) (*v4Writer, error) {
	var salt [v4SaltSize]byte
	if _, err := io.ReadFull(cryptorand.Reader, salt[:]); err != nil {
		return nil, err
	}

	aead, err := v4AEAD(psk, salt[:])
	if err != nil {
		return nil, err
	}
	paddingDelta, err := cryptoRandomInt(v4InitialPaddingSpan)
	if err != nil {
		return nil, err
	}
	return &v4Writer{
		Writer:               w,
		aead:                 aead,
		salt:                 salt,
		initialPaddingLength: uint16(v4InitialPaddingMin + paddingDelta),
	}, nil
}

func (w *v4Writer) Write(b []byte) (int, error) {
	w.mux.Lock()
	defer w.mux.Unlock()

	if len(b) == 0 {
		return 0, w.writeFrame(nil, 0)
	}

	written := 0
	for written < len(b) {
		payloadLimit := int(w.nextPayloadLimit())
		if payloadLimit <= 0 || payloadLimit > maxLength {
			payloadLimit = maxLength
		}
		end := written + payloadLimit
		if end > len(b) {
			end = len(b)
		}
		paddingLength := w.nextFramePaddingLength(end - written)
		if err := w.writeFrame(b[written:end], paddingLength); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

func (w *v4Writer) nextPayloadLimit() uint16 {
	now := time.Now()
	var payloadLimit uint16
	switch {
	case w.lastWrite.IsZero():
		payloadLimit = v4FrameSize - 55 - w.initialPaddingLength
	case now.Sub(w.lastWrite) > 30*time.Second:
		payloadLimit = v4FrameSize - 39
	default:
		payloadLimit = w.payloadLimit
	}
	w.lastWrite = now

	if payloadLimit <= maxLength-1 {
		next := int(payloadLimit) + v4FrameSize - 39
		if next > maxLength {
			next = maxLength
		}
		w.payloadLimit = uint16(next)
	} else {
		w.payloadLimit = maxLength
	}
	return payloadLimit
}

func (w *v4Writer) nextFramePaddingLength(payloadLength int) int {
	if w.saltSent || payloadLength == 0 {
		return 0
	}
	return int(w.initialPaddingLength)
}

func (w *v4Writer) writeFrame(payload []byte, paddingLength int) error {
	if len(payload) > maxLength || paddingLength > maxLength {
		return errors.New("snell v4 frame too large")
	}
	if len(payload) == 0 && paddingLength != 0 {
		return errors.New("snell v4 zero chunk with padding")
	}

	var header [v4HeaderPlainSize]byte
	header[0] = 4
	binary.BigEndian.PutUint16(header[3:5], uint16(paddingLength))
	binary.BigEndian.PutUint16(header[5:7], uint16(len(payload)))

	var headerCipherBuf [v4HeaderCipherSize]byte
	headerCipher := w.aead.Seal(headerCipherBuf[:0], w.nonce[:], header[:], nil)
	incrementV4Nonce(w.nonce[:])

	payloadCipherLength := 0
	if len(payload) > 0 {
		payloadCipherLength = len(payload) + w.aead.Overhead()
	}
	frameLength := len(headerCipher) + paddingLength + payloadCipherLength
	if !w.saltSent {
		frameLength += v4SaltSize
	}
	if cap(w.buf) < frameLength {
		w.buf = make([]byte, 0, frameLength)
	}
	frame := w.buf[:0]
	if !w.saltSent {
		frame = append(frame, w.salt[:]...)
		w.saltSent = true
	}
	frame = append(frame, headerCipher...)
	paddingStart := len(frame)
	if paddingLength > 0 {
		frame = frame[:len(frame)+paddingLength]
	}
	payloadCipherStart := len(frame)
	if len(payload) > 0 {
		frame = w.aead.Seal(frame, w.nonce[:], payload, nil)
		incrementV4Nonce(w.nonce[:])
	}

	if paddingLength > 0 {
		padding := frame[paddingStart:payloadCipherStart]
		payloadCipher := frame[payloadCipherStart:]
		if err := fillV4Padding(padding, payloadCipher); err != nil {
			return err
		}
		swapPadding(padding, payloadCipher)
	}

	return writeFull(w.Writer, frame)
}

func swapPadding(padding, payloadCipher []byte) {
	limit := len(padding)
	if len(payloadCipher) < limit {
		limit = len(payloadCipher)
	}
	for i := 0; i < limit; i += 2 {
		padding[i], payloadCipher[i] = payloadCipher[i], padding[i]
	}
}

func makeV4Padding(payloadCipher []byte, paddingLength int) ([]byte, error) {
	if paddingLength <= 0 {
		return nil, nil
	}
	padding := make([]byte, paddingLength)
	if err := fillV4Padding(padding, payloadCipher); err != nil {
		return nil, err
	}
	return padding, nil
}

func fillV4Padding(padding, payloadCipher []byte) error {
	paddingLength := len(padding)
	if paddingLength <= 0 {
		return nil
	}

	payloadOnes := countV4PayloadOnes(payloadCipher)
	payloadZeros := 8*len(payloadCipher) - payloadOnes
	if payloadZeros <= 0 {
		return fillV4RandomPadding(padding)
	}

	ratio := float64(payloadOnes) / float64(payloadZeros)
	if ratio <= 0.5 || ratio >= 1.6 {
		return fillV4RandomPadding(padding)
	}

	targetRatioBase := 1.6
	if payloadZeros < payloadOnes {
		targetRatioBase = 0.4
	}
	jitter, err := randomUnitFloat64()
	if err != nil {
		return err
	}
	targetRatio := targetRatioBase + jitter/10
	totalBits := 8 * (paddingLength + len(payloadCipher))
	targetOnes := int(float64(totalBits)*(targetRatio/(targetRatio+1)) - float64(payloadOnes))
	if targetOnes < 0 || targetOnes > 8*paddingLength {
		return fillV4RandomPadding(padding)
	}

	return fillV4BitCountPadding(padding, targetOnes)
}

func countV4PayloadOnes(payloadCipher []byte) int {
	ones := 0
	for _, b := range payloadCipher {
		ones += bits.OnesCount8(b)
	}
	return ones
}

func makeV4RandomPadding(length int) ([]byte, error) {
	padding := make([]byte, length)
	if err := fillV4RandomPadding(padding); err != nil {
		return nil, err
	}
	return padding, nil
}

func fillV4RandomPadding(padding []byte) error {
	_, err := io.ReadFull(cryptorand.Reader, padding)
	return err
}

func makeV4BitCountPadding(length, oneBits int) ([]byte, error) {
	padding := make([]byte, length)
	if err := fillV4BitCountPadding(padding, oneBits); err != nil {
		return nil, err
	}
	return padding, nil
}

func fillV4BitCountPadding(padding []byte, oneBits int) error {
	totalBits := 8 * len(padding)
	if oneBits < 0 || oneBits > totalBits {
		return errors.New("snell v4 invalid padding bit count")
	}
	if oneBits == 0 {
		for i := range padding {
			padding[i] = 0
		}
		return nil
	}

	var seed int64
	if err := binary.Read(cryptorand.Reader, binary.LittleEndian, &seed); err != nil {
		return err
	}
	rng := mrand.New(mrand.NewSource(seed))

	positions := make([]uint32, totalBits)
	for i := range positions {
		positions[i] = uint32(i)
	}
	for i := range padding {
		padding[i] = 0
	}
	for i := 0; i < oneBits; i++ {
		j := i + rng.Intn(totalBits-i)
		positions[i], positions[j] = positions[j], positions[i]
		pos := positions[i]
		padding[pos/8] |= byte(1 << (pos % 8))
	}
	return nil
}

func cryptoRandomInt(max int) (int, error) {
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

func randomUnitFloat64() (float64, error) {
	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(1<<53))
	if err != nil {
		return 0, err
	}
	return float64(n.Int64()) / math.Exp2(53), nil
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func incrementV4Nonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}
