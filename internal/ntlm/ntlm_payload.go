// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

package ntlm

import (
	"encoding/binary"
	"errors"
)

// Payload represents a NTLM payload
type Payload struct {
	payloadType int
	len         uint16
	maxLen      uint16
	offset      uint32
	payload     []byte
}

const (
	// payloadEncodingUnicode represents the Unicode payload encoding
	payloadEncodingUnicode = iota

	// payloadEncodingOEM represents the OEM payload encoding
	payloadEncodingOEM

	// payloadEncodingByte represents the byte payload encoding
	payloadEncodingByte
)

var (
	// ErrNTLMInvalidPayload is returned when the payload is invalid
	ErrNTLMInvalidPayload = errors.New("invalid NTLM payload")
)

// createBytePayload creates a Payload from the given byte slice.
func createBytePayload(payload []byte) *Payload {
	return &Payload{
		payloadType: payloadEncodingByte,
		len:         uint16(len(payload)),
		maxLen:      uint16(len(payload)),
		payload:     payload,
	}
}

// createStringPayload creates a Payload from the given string.
func createStringPayload(payload string) *Payload {
	b := utf16FromString(payload)
	return &Payload{
		payloadType: payloadEncodingUnicode,
		len:         uint16(len(b)),
		maxLen:      uint16(len(b)),
		payload:     b,
	}
}

// readPayload reads a payload from the given byte slice starting at startByte of type payloadType.
func readPayload(startByte int, payload []byte, payloadType int) (*Payload, error) {
	if startByte < 0 || len(payload) < startByte+8 {
		return nil, ErrNTLMInvalidPayload
	}

	p := &Payload{
		payloadType: payloadType,
		len:         binary.LittleEndian.Uint16(payload[startByte : startByte+2]),
		maxLen:      binary.LittleEndian.Uint16(payload[startByte+2 : startByte+4]),
		offset:      binary.LittleEndian.Uint32(payload[startByte+4 : startByte+8]),
	}

	if p.len > 0 {
		end := uint64(p.offset) + uint64(p.len)
		if uint64(p.offset) > uint64(len(payload)) || end > uint64(len(payload)) {
			return nil, ErrNTLMInvalidPayload
		}
		p.payload = payload[p.offset:end]
	}
	return p, nil
}

// bytes returns the payload as a byte slice.
func (p *Payload) bytes() []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint16(b[0:2], p.len)
	binary.LittleEndian.PutUint16(b[2:4], p.maxLen)
	binary.LittleEndian.PutUint32(b[4:8], p.offset)
	return b
}
