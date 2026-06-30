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
	Type    int
	Len     uint16
	MaxLen  uint16
	Offset  uint32
	Payload []byte
}

const (
	// PayloadEncodingUnicode represents the Unicode payload encoding
	PayloadEncodingUnicode = iota

	// PayloadEncodingOEM represents the OEM payload encoding
	PayloadEncodingOEM

	// PayloadEncodingByte represents the byte payload encoding
	PayloadEncodingByte
)

var (
	// ErrNTLMInvalidPayload is returned when the payload is invalid
	ErrNTLMInvalidPayload = errors.New("invalid payload")
)

// CreateBytePayload creates a Payload from the given byte slice.
func CreateBytePayload(payload []byte) *Payload {
	return &Payload{
		Type:    PayloadEncodingByte,
		Len:     uint16(len(payload)),
		MaxLen:  uint16(len(payload)),
		Payload: payload,
	}
}

// CreateStringPayload creates a Payload from the given string.
func CreateStringPayload(payload string) *Payload {
	b := utf16FromString(payload)
	return &Payload{
		Type:    PayloadEncodingUnicode,
		Len:     uint16(len(b)),
		MaxLen:  uint16(len(b)),
		Payload: b,
	}
}

// ReadPayload reads a payload from the given byte slice starting at startByte of type payloadType.
func ReadPayload(startByte int, payload []byte, payloadType int) (*Payload, error) {
	if startByte < 0 || len(payload) < startByte+8 {
		return nil, ErrNTLMInvalidPayload
	}

	p := &Payload{
		Type:   payloadType,
		Len:    binary.LittleEndian.Uint16(payload[startByte : startByte+2]),
		MaxLen: binary.LittleEndian.Uint16(payload[startByte+2 : startByte+4]),
		Offset: binary.LittleEndian.Uint32(payload[startByte+4 : startByte+8]),
	}

	if p.Len > 0 {
		end := uint64(p.Offset) + uint64(p.Len)
		if uint64(p.Offset) > uint64(len(payload)) || end > uint64(len(payload)) {
			return nil, ErrNTLMInvalidPayload
		}
		p.Payload = payload[p.Offset:end]
	}
	return p, nil
}

// Bytes returns the payload as a byte slice.
func (p *Payload) Bytes() []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint16(b[0:2], p.Len)
	binary.LittleEndian.PutUint16(b[2:4], p.MaxLen)
	binary.LittleEndian.PutUint32(b[4:8], p.Offset)
	return b
}
