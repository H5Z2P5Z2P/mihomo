package snell

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

const (
	quicReqVersion byte = 1
	quicReqCommand byte = 1
)

// EncodeQUICEnvelope wraps the first QUIC packet for Snell v5 UDP proxy mode.
// After the server accepts this encrypted envelope, following packets on the
// same UDP 5-tuple are forwarded as raw QUIC packets.
func EncodeQUICEnvelope(psk []byte, host string, port uint16, innerQUIC []byte) ([]byte, error) {
	if len(host) > 255 {
		return nil, errors.New("hostname too long")
	}
	if len(innerQUIC) == 0 {
		return nil, errors.New("inner QUIC packet missing")
	}

	payload := make([]byte, 0, 5+len(host)+len(innerQUIC))
	payload = append(payload, quicReqVersion, quicReqCommand, 0, byte(len(host)))
	payload = append(payload, host...)
	payload = binary.BigEndian.AppendUint16(payload, port)
	payload = append(payload, innerQUIC...)
	if len(payload) > 0xffff {
		return nil, errors.New("envelope payload too large")
	}

	salt := make([]byte, v4SaltSize)
	if _, err := io.ReadFull(cryptorand.Reader, salt); err != nil {
		return nil, err
	}
	aead, err := v4AEAD(psk, salt)
	if err != nil {
		return nil, err
	}

	header := make([]byte, v4HeaderPlainSize)
	header[0] = 4
	binary.BigEndian.PutUint16(header[5:7], uint16(len(payload)))

	nonce0 := make([]byte, aead.NonceSize())
	headerCipher := aead.Seal(nil, nonce0, header, nil)

	nonce1 := make([]byte, aead.NonceSize())
	binary.LittleEndian.PutUint64(nonce1, 1)
	payloadCipher := aead.Seal(nil, nonce1, payload, nil)

	out := make([]byte, 0, v4SaltSize+len(headerCipher)+len(payloadCipher))
	out = append(out, salt...)
	out = append(out, headerCipher...)
	out = append(out, payloadCipher...)
	return out, nil
}
