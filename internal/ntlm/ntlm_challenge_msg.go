package ntlm

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type ChallengeMessage struct {
	Signature       []byte
	MessageType     uint32
	TargetName      *Payload
	NegotiateFlags  NegotiateFlags
	ServerChallenge []byte
	Reserved        []byte
	TargetInfo      *AVPairs
	Payload         []byte
}

var (
	ErrNTLMInvalidChallengeMessage = errors.New("invalid challenge message")
	ErrNTLMInvalidSignatureMessage = errors.New("invalid NTLM message signature")
	ErrNTLMInvalidSignatureType    = errors.New("invalid NTLM message type")
	ErrNTLMUnknownEncoding         = errors.New("unknown payload encoding")
)

func ParseChallengeMessage(body []byte) (*ChallengeMessage, error) {
	if len(body) < 40 {
		return nil, ErrNTLMInvalidChallengeMessage
	}

	challenge := new(ChallengeMessage)
	challenge.Signature = body[0:8]
	if !bytes.Equal(challenge.Signature, []byte("NTLMSSP\x00")) {
		return challenge, ErrNTLMInvalidSignatureMessage
	}

	challenge.MessageType = binary.LittleEndian.Uint32(body[8:12])
	if challenge.MessageType != 2 {
		return challenge, ErrNTLMInvalidSignatureType
	}

	challenge.NegotiateFlags = ReadNegotiateFlags(body[20:24])

	var err error
	if challenge.TargetName, err = challenge.readStringPayload(12, body); err != nil {
		return nil, err
	}
	challenge.ServerChallenge = body[24:32]
	challenge.Reserved = body[32:40]

	targetInfo, err := ReadPayload(40, body, PayloadEncodingByte)
	if err != nil {
		return nil, err
	}
	if challenge.TargetInfo, err = ReadAvPairs(targetInfo.Payload); err != nil {
		return nil, err
	}

	offset := 48
	if uint32(challenge.NegotiateFlags)&uint32(NTLMSSP_NEGOTIATE_VERSION) != 0 {
		if len(body) < offset+8 {
			return nil, errors.New("invalid challenge message")
		}
		offset += 8
	}

	if len(body) < offset {
		return nil, errors.New("invalid challenge message")
	}
	challenge.Payload = body[offset:]
	return challenge, nil
}

func (c *ChallengeMessage) readStringPayload(startByte int, payload []byte) (*Payload, error) {
	payloadType := PayloadEncodingUnicode
	if uint32(c.NegotiateFlags)&uint32(NTLM_NEGOTIATE_OEM) != 0 {
		payloadType = PayloadEncodingOEM
	}

	switch payloadType {
	case PayloadEncodingUnicode, PayloadEncodingOEM:
		return ReadPayload(startByte, payload, payloadType)
	default:
		return nil, ErrNTLMUnknownEncoding
	}
}
