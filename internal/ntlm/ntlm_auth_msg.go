package ntlm

import (
	"bytes"
	"encoding/binary"
)

// AuthenticateMessage represents the Type 3 message in the NTLM authentication process.
type AuthenticateMessage struct {
	signature   []byte
	messageType uint32

	negotiateFlags NegotiateFlags

	lmChallengeResponse       *Payload
	ntChallengeResponseFields *Payload
	domainname                *Payload
	username                  *Payload
	workstation               *Payload
	encryptedRandomSessionKey *Payload
}

// Bytes returns the byte representation of the AuthenticateMessage type (Type 3 message)
//
// See: https://curl.se/rfc/ntlm.html#theType3Message
func (a *AuthenticateMessage) Bytes() []byte {
	// sig + type + 6 descriptors + flags + version
	//
	// See: https://curl.se/rfc/ntlm.html#theType3Message
	const headerLen = 8 + 4 + 6*8 + 4 + 8

	payloadLen := int(a.domainname.Len) + int(a.username.Len) + int(a.workstation.Len) +
		int(a.lmChallengeResponse.Len) + int(a.ntChallengeResponseFields.Len) +
		int(a.encryptedRandomSessionKey.Len)

	offset := uint32(headerLen)
	for _, p := range []*Payload{
		a.domainname, a.username, a.workstation, a.lmChallengeResponse,
		a.ntChallengeResponseFields, a.encryptedRandomSessionKey,
	} {
		p.Offset = offset
		offset += uint32(p.Len)
	}

	buf := bytes.NewBuffer(make([]byte, 0, headerLen+payloadLen))

	buf.Write(a.signature)

	var msgType [4]byte
	binary.LittleEndian.PutUint32(msgType[:], a.messageType)
	buf.Write(msgType[:])

	buf.Write(a.lmChallengeResponse.Bytes())
	buf.Write(a.ntChallengeResponseFields.Bytes())
	buf.Write(a.domainname.Bytes())
	buf.Write(a.username.Bytes())
	buf.Write(a.workstation.Bytes())
	buf.Write(a.encryptedRandomSessionKey.Bytes())
	buf.Write(a.negotiateFlags.Bytes())

	// Even if NTLMSSP_NEGOTIATE_VERSION is set, we'll send a zero version byte, due
	// to improved privacy. The version field is purely cosmetic and only useful for
	// debugging purposes on the server end.
	buf.Write(make([]byte, 8))

	buf.Write(a.domainname.Payload)
	buf.Write(a.username.Payload)
	buf.Write(a.workstation.Payload)
	buf.Write(a.lmChallengeResponse.Payload)
	buf.Write(a.ntChallengeResponseFields.Payload)
	buf.Write(a.encryptedRandomSessionKey.Payload)

	return buf.Bytes()
}
