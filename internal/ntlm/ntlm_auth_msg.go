package ntlm

import (
	"bytes"
	"encoding/binary"
)

type AuthenticateMessage struct {
	Signature   []byte
	MessageType uint32

	LmChallengeResponse       *Payload
	NtChallengeResponseFields *Payload

	DomainName  *Payload
	UserName    *Payload
	Workstation *Payload

	EncryptedRandomSessionKey *Payload

	NegotiateFlags NegotiateFlags

	Payload []byte
}

func (a *AuthenticateMessage) Bytes() []byte {
	payloadLen := int(a.LmChallengeResponse.Len + a.NtChallengeResponseFields.Len + a.DomainName.Len + a.UserName.Len + a.Workstation.Len + a.EncryptedRandomSessionKey.Len)
	messageLen := 8 + 4 + 6*8 + 4 + 8 + 16
	payloadOffset := uint32(messageLen)

	buf := bytes.NewBuffer(make([]byte, 0, messageLen+payloadLen))
	buf.Write(a.Signature)
	binary.Write(buf, binary.LittleEndian, a.MessageType)

	a.LmChallengeResponse.Offset = payloadOffset + uint32(a.DomainName.Len+a.UserName.Len+a.Workstation.Len)
	buf.Write(a.LmChallengeResponse.Bytes())

	a.NtChallengeResponseFields.Offset = a.LmChallengeResponse.Offset + uint32(a.LmChallengeResponse.Len)
	buf.Write(a.NtChallengeResponseFields.Bytes())

	a.DomainName.Offset = payloadOffset
	payloadOffset += uint32(a.DomainName.Len)
	buf.Write(a.DomainName.Bytes())

	a.UserName.Offset = payloadOffset
	payloadOffset += uint32(a.UserName.Len)
	buf.Write(a.UserName.Bytes())

	a.Workstation.Offset = payloadOffset
	payloadOffset += uint32(a.Workstation.Len)
	buf.Write(a.Workstation.Bytes())

	a.EncryptedRandomSessionKey.Offset = a.NtChallengeResponseFields.Offset + uint32(a.NtChallengeResponseFields.Len)
	payloadOffset += uint32(a.EncryptedRandomSessionKey.Len)
	buf.Write(a.EncryptedRandomSessionKey.Bytes())

	buf.Write(a.NegotiateFlags.Bytes())

	buf.Write(make([]byte, 8))
	buf.Write(make([]byte, 16))

	buf.Write(a.DomainName.Payload)
	buf.Write(a.UserName.Payload)
	buf.Write(a.Workstation.Payload)
	buf.Write(a.LmChallengeResponse.Payload)
	buf.Write(a.NtChallengeResponseFields.Payload)
	buf.Write(a.EncryptedRandomSessionKey.Payload)
	return buf.Bytes()
}
