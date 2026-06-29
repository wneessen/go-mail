package ntlm

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type Payload struct {
	Type    int
	Len     uint16
	MaxLen  uint16
	Offset  uint32
	Payload []byte
}

const (
	PayloadEncodingUnicode = iota
	PayloadEncodingOEM
	PayloadEncodingByte
)

var (
	ErrNTLMInvalidPayload = errors.New("invalid payload")
)

func CreateBytePayload(payload []byte) *Payload {
	return &Payload{
		Type:    PayloadEncodingByte,
		Len:     uint16(len(payload)),
		MaxLen:  uint16(len(payload)),
		Payload: payload,
	}
}

func CreateStringPayload(payload string) *Payload {
	b := utf16FromString(payload)
	return &Payload{
		Type:    PayloadEncodingUnicode,
		Len:     uint16(len(b)),
		MaxLen:  uint16(len(b)),
		Payload: b,
	}
}

func ReadPayload(startByte int, payload []byte, payloadType int) (*Payload, error) {
	if len(payload) < startByte+8 {
		return nil, ErrNTLMInvalidPayload
	}
	p := new(Payload)
	p.Type = payloadType
	p.Len = binary.LittleEndian.Uint16(payload[startByte : startByte+2])
	p.MaxLen = binary.LittleEndian.Uint16(payload[startByte+2 : startByte+4])
	p.Offset = binary.LittleEndian.Uint32(payload[startByte+4 : startByte+8])
	if p.Len > 0 {
		end := p.Offset + uint32(p.Len)
		if uint32(len(payload)) < end {
			return nil, ErrNTLMInvalidPayload
		}
		p.Payload = payload[p.Offset:end]
	}
	return p, nil
}

func (p *Payload) Bytes() []byte {
	buffer := bytes.NewBuffer(nil)
	binary.Write(buffer, binary.LittleEndian, p.Len)
	binary.Write(buffer, binary.LittleEndian, p.MaxLen)
	binary.Write(buffer, binary.LittleEndian, p.Offset)
	return buffer.Bytes()
}
