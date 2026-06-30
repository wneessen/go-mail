package ntlm

import (
	"bytes"
	"encoding/binary"
)

// AuthenticateMessage represents the Type 3 message in the NTLM authentication process.
type AuthenticateMessage struct {
	Signature   []byte
	MessageType uint32

	NegotiateFlags NegotiateFlags

	LmChallengeResponse       *Payload
	NtChallengeResponseFields *Payload
	DomainName                *Payload
	UserName                  *Payload
	Workstation               *Payload
	EncryptedRandomSessionKey *Payload

	Payload []byte
}

// Bytes returns the byte representation of the AuthenticateMessage type (Type 3 message)
//
// See: https://curl.se/rfc/ntlm.html#theType3Message
func (a *AuthenticateMessage) Bytes() []byte {
	// sig + type + 6 descriptors + flags + version
	//
	// See: https://curl.se/rfc/ntlm.html#theType3Message
	const headerLen = 8 + 4 + 6*8 + 4 + 8

	payloadLen := int(a.DomainName.Len) + int(a.UserName.Len) + int(a.Workstation.Len) +
		int(a.LmChallengeResponse.Len) + int(a.NtChallengeResponseFields.Len) +
		int(a.EncryptedRandomSessionKey.Len)

	offset := uint32(headerLen)
	for _, p := range []*Payload{
		a.DomainName, a.UserName, a.Workstation, a.LmChallengeResponse,
		a.NtChallengeResponseFields, a.EncryptedRandomSessionKey,
	} {
		p.Offset = offset
		offset += uint32(p.Len)
	}

	buf := bytes.NewBuffer(make([]byte, 0, headerLen+payloadLen))

	buf.Write(a.Signature)

	var msgType [4]byte
	binary.LittleEndian.PutUint32(msgType[:], a.MessageType)
	buf.Write(msgType[:])

	buf.Write(a.LmChallengeResponse.Bytes())
	buf.Write(a.NtChallengeResponseFields.Bytes())
	buf.Write(a.DomainName.Bytes())
	buf.Write(a.UserName.Bytes())
	buf.Write(a.Workstation.Bytes())
	buf.Write(a.EncryptedRandomSessionKey.Bytes())
	buf.Write(a.NegotiateFlags.Bytes())

	// Even if NTLMSSP_NEGOTIATE_VERSION is set, we'll send a zero version byte, due
	// to improved privacy. The version field is purely cosmetic and only useful for
	// debugging purposes on the server end.
	buf.Write(make([]byte, 8))

	buf.Write(a.DomainName.Payload)
	buf.Write(a.UserName.Payload)
	buf.Write(a.Workstation.Payload)
	buf.Write(a.LmChallengeResponse.Payload)
	buf.Write(a.NtChallengeResponseFields.Payload)
	buf.Write(a.EncryptedRandomSessionKey.Payload)

	return buf.Bytes()
}
