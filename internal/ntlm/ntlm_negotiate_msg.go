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
	// ntlmsspNegotiateUnicode indicates that Unicode strings are supported for use
	// in security buffer data.
	ntlmsspNegotiateUnicode negotiateFlag = 0x00000001

	// ntlmsspNegotiateOEM indicates that OEM strings are supported for use in
	// security buffer data.
	ntlmsspNegotiateOEM negotiateFlag = 0x00000002

	// ntlmsspRequestTarget requests that the server's authentication realm be included
	// in the Type 2 message.
	ntlmsspRequestTarget negotiateFlag = 0x00000004

	// ntlmsspNegotiateLMKey indicates that the Lan Manager Session Key should be used
	// for signing and sealing authenticated communications.
	ntlmsspNegotiateLMKey negotiateFlag = 0x00000080

	// ntlmsspNegotiateNTLM indicates that NTLM authentication is being used.
	ntlmsspNegotiateNTLM negotiateFlag = 0x00000200

	// ntlmsspNegotiateDomainSupplied is sent by the client in the Type 1 message to indicate that
	// the name of the domain in which the client workstation has membership is included in the message.
	// This is used by the server to determine whether the client is eligible for local authentication.
	ntlmsspNegotiateDomainSupplied negotiateFlag = 0x00001000

	// ntlmsspNegotiateExtendedSessionSecurity indicates that the NTLM2 signing and sealing scheme
	// should be used for protecting authenticated communications.
	//
	// Note that this refers to a particular session security scheme, and is not related to the use of
	// NTLMv2 authentication. This flag can, however, have an effect on the response calculations.
	//
	// See: https://curl.se/rfc/ntlm.html#theNtlm2SessionResponse
	ntlmsspNegotiateExtendedSessionSecurity negotiateFlag = 0x00080000

	// ntlmsspNegotiateVersion indicates the OS version (purley cosmetic and for debugging purposes)
	// We ignore this
	ntlmsspNegotiateVersion negotiateFlag = 0x02000000

	// ntlmsspNegotiate128Bit indicates that 128-bit encryption is supported.
	ntlmsspNegotiate128Bit negotiateFlag = 0x20000000

	// ntlmsspNegotiateKeyExchange indicates that the client will provide an encrypted master key in
	// the "Session Key" field of the Type 3 message.
	ntlmsspNegotiateKeyExchange negotiateFlag = 0x40000000
)

// GenerateNegotiateMessage generates a NTLMv2 negotiation message (Type 1 message).
//
// See: https://curl.se/rfc/ntlm.html#theType1Message
func (n *NTLMv2Session) GenerateNegotiateMessage() (*NegotiateMessage, error) {
	message := &NegotiateMessage{
		signature:   []byte("NTLMSSP\x00"),
		messageType: 1,
		negotiateFlags: negotiateFlagSet(ntlmsspNegotiateUnicode | ntlmsspNegotiateOEM |
			ntlmsspRequestTarget | ntlmsspNegotiateNTLM | ntlmsspNegotiateDomainSupplied |
			ntlmsspNegotiate128Bit | ntlmsspNegotiateExtendedSessionSecurity),
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
