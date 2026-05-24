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

	payloadLength := 6 + len(host) + len(innerQUIC)
	if payloadLength > 0xffff {
		return nil, errors.New("envelope payload too large")
	}

	var salt [v4SaltSize]byte
	if _, err := io.ReadFull(cryptorand.Reader, salt[:]); err != nil {
		return nil, err
	}
	aead, err := v4AEAD(psk, salt[:])
	if err != nil {
		return nil, err
	}

	out := make([]byte, v4SaltSize+v4HeaderCipherSize+payloadLength+aead.Overhead())
	copy(out, salt[:])

	var header [v4HeaderPlainSize]byte
	header[0] = 4
	binary.BigEndian.PutUint16(header[5:7], uint16(payloadLength))

	var nonce0 [v4NonceSize]byte
	headerCipher := aead.Seal(out[v4SaltSize:v4SaltSize], nonce0[:], header[:], nil)

	var nonce1 [v4NonceSize]byte
	binary.LittleEndian.PutUint64(nonce1[:], 1)

	payloadStart := v4SaltSize + len(headerCipher)
	payload := out[payloadStart : payloadStart+payloadLength]
	payload[0] = quicReqVersion
	payload[1] = quicReqCommand
	payload[2] = 0
	payload[3] = byte(len(host))
	copy(payload[4:], host)
	portStart := 4 + len(host)
	binary.BigEndian.PutUint16(payload[portStart:portStart+2], port)
	copy(payload[portStart+2:], innerQUIC)

	payloadCipher := aead.Seal(payload[:0], nonce1[:], payload, nil)
	return out[:payloadStart+len(payloadCipher)], nil
}
