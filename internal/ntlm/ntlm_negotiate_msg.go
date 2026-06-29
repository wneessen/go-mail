package ntlm

import (
	"bytes"
	"encoding/binary"
)

type NegotiateFlags uint32
type NegotiateFlag uint32

type NegotiateMessage struct {
	Signature         []byte
	MessageType       uint32
	NegotiateFlags    NegotiateFlags
	DomainNameFields  *Payload
	WorkstationFields *Payload
	/*
		Payload           []byte
	*/
}

const (
	NTLMSSP_NEGOTIATE_UNICODE                  NegotiateFlag = 0x00000001
	NTLM_NEGOTIATE_OEM                         NegotiateFlag = 0x00000002
	NTLMSSP_REQUEST_TARGET                     NegotiateFlag = 0x00000004
	NTLMSSP_NEGOTIATE_LM_KEY                   NegotiateFlag = 0x00000080
	NTLMSSP_NEGOTIATE_NTLM                     NegotiateFlag = 0x00000200
	NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY NegotiateFlag = 0x00080000
	NTLMSSP_NEGOTIATE_VERSION                  NegotiateFlag = 0x02000000
	NTLMSSP_NEGOTIATE_KEY_EXCH                 NegotiateFlag = 0x40000000
)

func (n *NTLMv2Session) GenerateNegotiateMessage() (*NegotiateMessage, error) {
	message := &NegotiateMessage{
		Signature:   []byte("NTLMSSP\x00"),
		MessageType: 1,
		NegotiateFlags: NegotiateFlags(NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_REQUEST_TARGET |
			NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY),
		DomainNameFields:  new(Payload),
		WorkstationFields: new(Payload),
	}
	n.negotiateMessage = message

	return message, nil
}

func (f NegotiateFlags) Bytes() []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(f))
	return b
}

func ReadNegotiateFlags(flags []byte) NegotiateFlags {
	return NegotiateFlags(binary.LittleEndian.Uint32(flags))
}

func (nm *NegotiateMessage) Bytes() []byte {
	payloadLength := nm.DomainNameFields.Len + nm.WorkstationFields.Len
	messageLength := uint16(40)
	payloadOffset := messageLength

	buffer := bytes.NewBuffer(make([]byte, 0, messageLength+payloadLength))
	buffer.Write(nm.Signature)
	binary.Write(buffer, binary.LittleEndian, nm.MessageType)
	buffer.Write(nm.NegotiateFlags.Bytes())

	nm.DomainNameFields.Offset = uint32(payloadOffset)
	payloadOffset += nm.DomainNameFields.Len
	buffer.Write(nm.DomainNameFields.Bytes())

	nm.WorkstationFields.Offset = uint32(payloadOffset)
	payloadOffset += nm.WorkstationFields.Len
	buffer.Write(nm.WorkstationFields.Bytes())

	buffer.Write(nm.DomainNameFields.Payload)
	buffer.Write(nm.WorkstationFields.Payload)
	return buffer.Bytes()
}
