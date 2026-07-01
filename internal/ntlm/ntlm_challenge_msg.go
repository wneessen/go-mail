// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

package ntlm

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// ChallengeMessage represents an NTLM challenge message (Type 2 message)
type ChallengeMessage struct {
	signature       []byte
	messageType     uint32
	targetName      *Payload
	negotiateFlags  NegotiateFlags
	serverChallenge []byte
	reserved        []byte
	targetInfo      *avPairs
	payload         []byte
}

var (
	// ErrNTLMInvalidChallengeMessage is returned when the challenge message is invalid
	ErrNTLMInvalidChallengeMessage = errors.New("invalid challenge message")

	// ErrNTLMInvalidSignatureMessage is returned when the NTLM message signature is invalid
	ErrNTLMInvalidSignatureMessage = errors.New("invalid NTLM message signature")

	// ErrNTLMInvalidSignatureType is returned when the NTLM message type is invalid
	ErrNTLMInvalidSignatureType = errors.New("invalid NTLM message type")
)

// ParseChallengeMessage parses an NTLM challenge message (Type 2 message) from the given body
//
// See: https://curl.se/rfc/ntlm.html#theType2Message
func ParseChallengeMessage(body []byte) (*ChallengeMessage, error) {
	if len(body) < 48 {
		return nil, ErrNTLMInvalidChallengeMessage
	}

	var err error
	challenge := new(ChallengeMessage)

	challenge.signature = body[0:8]
	if !bytes.Equal(challenge.signature, []byte("NTLMSSP\x00")) {
		return nil, ErrNTLMInvalidSignatureMessage
	}

	challenge.messageType = binary.LittleEndian.Uint32(body[8:12])
	if challenge.messageType != 2 {
		return nil, ErrNTLMInvalidSignatureType
	}

	challenge.negotiateFlags = ReadNegotiateFlags(body[20:24])

	if challenge.targetName, err = challenge.readStringPayload(12, body); err != nil {
		return nil, err
	}
	challenge.serverChallenge = body[24:32]
	challenge.reserved = body[32:40]

	targetInfo, err := ReadPayload(40, body, payloadEncodingByte)
	if err != nil {
		return nil, err
	}
	if challenge.targetInfo, err = ReadAvPairs(targetInfo.payload); err != nil {
		return nil, err
	}

	offset := 48
	if uint32(challenge.negotiateFlags)&uint32(NTLMSSP_NEGOTIATE_VERSION) != 0 {
		if len(body) < offset+8 {
			return nil, ErrNTLMInvalidChallengeMessage
		}
		offset += 8
	}

	challenge.payload = body[offset:]
	return challenge, nil
}

// readStringPayload reads a string payload from the given body, using the negotiated encoding.
func (c *ChallengeMessage) readStringPayload(startByte int, payload []byte) (*Payload, error) {
	// MS-NLMP: Unicode takes precedence, OEM is only used when UNICODE is not negotiated
	encoding := payloadEncodingOEM
	if uint32(c.negotiateFlags)&uint32(NTLMSSP_NEGOTIATE_UNICODE) != 0 {
		encoding = payloadEncodingUnicode
	}
	return ReadPayload(startByte, payload, encoding)
}
