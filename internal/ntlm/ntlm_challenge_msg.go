// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

package ntlm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// messageType represents the type of NTLM message
type messageType int

// ChallengeMessage represents an NTLM challenge message (Type 2 message)
type ChallengeMessage struct {
	signature       []byte
	messageType     uint32
	targetName      *Payload
	negotiateFlags  negotiateFlagset
	serverChallenge []byte
	reserved        []byte
	targetInfo      *avPairs
	payload         []byte
}

const (
	messageTypeNegotiate messageType = iota + 1
	messageTypeChallenge
	messageTypeAuthenticate
)

var (
	// ErrNTLMInvalidChallengeMessage is returned when the challenge message is invalid
	ErrNTLMInvalidChallengeMessage = errors.New("invalid challenge message")

	// ErrNTLMInvalidSignatureMessage is returned when the NTLM message signature is invalid
	ErrNTLMInvalidSignatureMessage = errors.New("invalid NTLM message signature")

	// ErrNTLMInvalidSignatureType is returned when the NTLM message type is invalid
	ErrNTLMInvalidSignatureType = errors.New("invalid NTLM message type")
)

// CreateChallengeMessage creates an NTLM challenge message (Type 2 message) for the
// given target name and domain
func CreateChallengeMessage(clientFlags uint32, challenge []byte, targetName, domain string) ([]byte, error) {
	const headerLen = 48
	const versionLen = 8

	target := utf16FromString(targetName)
	targetInfo := new(avPairs)
	if err := targetInfo.appendAVPair(msvAVNbDomainName, utf16FromString(domain)); err != nil {
		return nil, fmt.Errorf("failed to append netbios domain name to targetinfo: %w", err)
	}
	if err := targetInfo.appendAVPair(msvAVNbComputerName, target); err != nil {
		return nil, fmt.Errorf("failed to append netbios computer name to targetinfo: %w", err)
	}
	if err := targetInfo.appendAVPair(msvAVDNSDomainName, utf16FromString(domain)); err != nil {
		return nil, fmt.Errorf("failed to append dns domain name to targetinfo: %w", err)
	}
	if err := targetInfo.appendAVPair(msvAVDNSComputerName, target); err != nil {
		return nil, fmt.Errorf("failed to append dns computer name to targetinfo: %w", err)
	}
	if err := targetInfo.appendAVPair(msvAVTimestamp, timeToWindowsFileTime(time.Now())); err != nil {
		return nil, fmt.Errorf("failed to append timestamp to targetinfo: %w", err)
	}
	if err := targetInfo.appendAVPair(msvAVEOL, nil); err != nil {
		return nil, fmt.Errorf("failed to append EOL to targetinfo: %w", err)
	}
	tiBytes := targetInfo.bytes() // compute once

	flags := negotiateFlagset(ntlmsspNegotiateUnicode | ntlmsspNegotiateNTLM | ntlmsspRequestTarget |
		ntlmsspNegotiateAlwaysSign | ntlmsspNegotiateTargetTypeServer |
		ntlmsspNegotiateTargetInfo | ntlmsspNegotiateVersion)
	if clientFlags&uint32(ntlmsspNegotiateExtendedSessionSecurity) != 0 {
		flags |= negotiateFlagset(ntlmsspNegotiateExtendedSessionSecurity)
	}

	payloadStart := uint32(headerLen + versionLen) // 56
	buffer := bytes.NewBuffer(make([]byte, 0, int(payloadStart)+len(target)+len(tiBytes)))

	// Signature + type
	buffer.Write([]byte(signature))
	if err := binary.Write(buffer, binary.LittleEndian, uint32(messageTypeChallenge)); err != nil {
		return nil, fmt.Errorf("failed to write message type: %w", err)
	}

	// TargetName security buffer  (len uint16, maxlen uint16, offset uint32)
	targetOff := payloadStart
	targetLength, err := toUint16(len(target))
	if err != nil {
		return nil, fmt.Errorf("failed to convert target name length: %w", err)
	}
	if err := binary.Write(buffer, binary.LittleEndian, targetLength); err != nil {
		return nil, fmt.Errorf("failed to write target name length: %w", err)
	}
	if err := binary.Write(buffer, binary.LittleEndian, targetLength); err != nil {
		return nil, fmt.Errorf("failed to write target name max length: %w", err)
	}
	if err := binary.Write(buffer, binary.LittleEndian, targetOff); err != nil {
		return nil, fmt.Errorf("failed to write target name offset: %w", err)
	}

	// Negotiate flags
	buffer.Write(flags.bytes())

	// Server challenge (8 bytes)
	buffer.Write(challenge)

	// Reserved (8 bytes)  <-- was missing
	buffer.Write(make([]byte, 8))

	// TargetInfo security buffer
	targetLength32, err := toUint32(len(target))
	if err != nil {
		return nil, fmt.Errorf("failed to convert target name length: %w", err)
	}
	tiOff := targetOff + targetLength32
	tiByteLength, err := toUint16(len(tiBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to convert target info length: %w", err)
	}
	if err := binary.Write(buffer, binary.LittleEndian, tiByteLength); err != nil {
		return nil, fmt.Errorf("failed to write target info length: %w", err)
	}
	if err := binary.Write(buffer, binary.LittleEndian, tiByteLength); err != nil {
		return nil, fmt.Errorf("failed to write target info max length: %w", err)
	}
	if err := binary.Write(buffer, binary.LittleEndian, tiOff); err != nil {
		return nil, fmt.Errorf("failed to write target info offset: %w", err)
	}

	// Version (8 bytes)
	buffer.Write(make([]byte, 8))

	// Payload
	buffer.Write(target)
	buffer.Write(tiBytes)

	return buffer.Bytes(), nil
}

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

	challenge.negotiateFlags = readNegotiateFlagset(body[20:24])

	if challenge.targetName, err = challenge.readStringPayload(12, body); err != nil {
		return nil, err
	}
	challenge.serverChallenge = body[24:32]
	challenge.reserved = body[32:40]

	targetInfo, err := readPayload(40, body, payloadEncodingByte)
	if err != nil {
		return nil, err
	}
	if challenge.targetInfo, err = readAVPairs(targetInfo.payload); err != nil {
		return nil, err
	}

	offset := 48
	if uint32(challenge.negotiateFlags)&uint32(ntlmsspNegotiateVersion) != 0 {
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
	if uint32(c.negotiateFlags)&uint32(ntlmsspNegotiateUnicode) != 0 {
		encoding = payloadEncodingUnicode
	}
	return readPayload(startByte, payload, encoding)
}
