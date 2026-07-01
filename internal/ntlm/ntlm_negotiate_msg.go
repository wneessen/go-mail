// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

package ntlm

import (
	"bytes"
	"encoding/binary"
)

type (
	// negotiateFlag holds the individual flags for the NTLMv2 negotiate message (Type 1 message).
	negotiateFlag uint32

	// negotiateFlagSet holds the flags for the NTLMv2 negotiate message (Type 1 message).
	negotiateFlagSet uint32
)

// NegotiateMessage represents a NTLMv2 negotiate message (Type 1 message).
type NegotiateMessage struct {
	signature      []byte
	messageType    uint32
	negotiateFlags negotiateFlagSet
	domainname     *Payload
	workstation    *Payload
}

// List of required NTLM flags. This list only holds the flags that are required for
// this package to work. Check the reference for a comprehensive list.
//
// See: https://curl.se/rfc/ntlm.html#theNtlmFlags
const (
	// NTLMSSP_NEGOTIATE_UNICODE indicates that Unicode strings are supported for use
	// in security buffer data.
	NTLMSSP_NEGOTIATE_UNICODE negotiateFlag = 0x00000001

	// NTLMSSP_NEGOTIATE_OEM indicates that OEM strings are supported for use in
	// security buffer data.
	NTLMSSP_NEGOTIATE_OEM negotiateFlag = 0x00000002

	// NTLMSSP_REQUEST_TARGET requests that the server's authentication realm be included
	// in the Type 2 message.
	NTLMSSP_REQUEST_TARGET negotiateFlag = 0x00000004

	// NTLMSSP_NEGOTIATE_LM_KEY indicates that the Lan Manager Session Key should be used
	// for signing and sealing authenticated communications.
	NTLMSSP_NEGOTIATE_LM_KEY negotiateFlag = 0x00000080

	// NTLMSSP_NEGOTIATE_NTLM indicates that NTLM authentication is being used.
	NTLMSSP_NEGOTIATE_NTLM negotiateFlag = 0x00000200

	// NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED is sent by the client in the Type 1 message to indicate that
	// the name of the domain in which the client workstation has membership is included in the message.
	// This is used by the server to determine whether the client is eligible for local authentication.
	NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED negotiateFlag = 0x00001000

	// NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY indicates that the NTLM2 signing and sealing scheme
	// should be used for protecting authenticated communications.
	//
	// Note that this refers to a particular session security scheme, and is not related to the use of
	// NTLMv2 authentication. This flag can, however, have an effect on the response calculations.
	//
	// See: https://curl.se/rfc/ntlm.html#theNtlm2SessionResponse
	NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY negotiateFlag = 0x00080000

	// NTLMSSP_NEGOTIATE_VERSION indicates the OS version (purley cosmetic and for debugging purposes)
	// We ignore this
	NTLMSSP_NEGOTIATE_VERSION negotiateFlag = 0x02000000

	// NTLMSSP_NEGOTIATE_128 indicates that 128-bit encryption is supported.
	NTLMSSP_NEGOTIATE_128 negotiateFlag = 0x20000000

	// NTLMSSP_NEGOTIATE_KEY_EXCH indicates that the client will provide an encrypted master key in
	// the "Session Key" field of the Type 3 message.
	NTLMSSP_NEGOTIATE_KEY_EXCH negotiateFlag = 0x40000000
)

// GenerateNegotiateMessage generates a NTLMv2 negotiation message (Type 1 message).
//
// See: https://curl.se/rfc/ntlm.html#theType1Message
func (n *NTLMv2Session) GenerateNegotiateMessage() (*NegotiateMessage, error) {
	message := &NegotiateMessage{
		signature:   []byte("NTLMSSP\x00"),
		messageType: 1,
		negotiateFlags: negotiateFlagSet(NTLMSSP_NEGOTIATE_UNICODE | NTLMSSP_NEGOTIATE_OEM |
			NTLMSSP_REQUEST_TARGET | NTLMSSP_NEGOTIATE_NTLM | NTLMSSP_NEGOTIATE_DOMAIN_SUPPLIED |
			NTLMSSP_NEGOTIATE_128 | NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY),
		domainname:  new(Payload),
		workstation: new(Payload),
	}
	n.negotiateMessage = message

	return message, nil
}

// ReadNegotiateFlags reads the negotiate flags from the given byte slice and returns them as
// NegotiateFlags type.
func ReadNegotiateFlags(flags []byte) negotiateFlagSet {
	return negotiateFlagSet(binary.LittleEndian.Uint32(flags))
}

// Bytes returns the byte representation of the negotiate flags.
func (f negotiateFlagSet) Bytes() []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(f))
	return b
}

// Bytes returns the byte representation of the NTLMv2 negotiate message (Type 1 message).
func (nm *NegotiateMessage) Bytes() []byte {
	const headerLen = 32

	payloadLen := int(nm.domainname.len) + int(nm.workstation.len)
	buffer := bytes.NewBuffer(make([]byte, 0, headerLen+payloadLen))

	buffer.Write(nm.signature)
	binary.Write(buffer, binary.LittleEndian, nm.messageType)
	buffer.Write(nm.negotiateFlags.Bytes())

	payloadOffset := uint16(headerLen)

	nm.domainname.offset = uint32(payloadOffset)
	payloadOffset += nm.domainname.len
	buffer.Write(nm.domainname.Bytes())

	nm.workstation.offset = uint32(payloadOffset)
	payloadOffset += nm.workstation.len
	buffer.Write(nm.workstation.Bytes())

	buffer.Write(nm.domainname.payload)
	buffer.Write(nm.workstation.payload)

	return buffer.Bytes()
}
