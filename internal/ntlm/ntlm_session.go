package ntlm

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"fmt"
	"slices"
	"time"
)

// NTLMv2Session represents a session using the NTLMv2 protocol.
type NTLMv2Session struct {
	user       string
	password   string
	userDomain string

	negotiateFlags NegotiateFlags

	negotiateMessage *NegotiateMessage
	challengeMessage *ChallengeMessage
	serverChallenge  []byte
	clientChallenge  []byte

	responseKeyNT       []byte
	ntChallengeResponse []byte
	lmChallengeResponse []byte

	sessionBaseKey            []byte
	keyExchangeKey            []byte
	exportedSessionKey        []byte
	encryptedRandomSessionKey []byte

	sequenceNumber uint32
}

// CreateClientSession returns a new NTLMv2Session.
func CreateClientSession() *NTLMv2Session {
	return &NTLMv2Session{}
}

// SetUserInfo sets the user information for the NTLMv2Session.
func (n *NTLMv2Session) SetUserInfo(username, password, domain string) {
	n.user = username
	n.password = password
	n.userDomain = domain
}

// ProcessChallengeMessage processes the challenge message from the server.
func (n *NTLMv2Session) ProcessChallengeMessage(message *ChallengeMessage) error {
	// Fill session with required data
	n.challengeMessage = message
	n.serverChallenge = message.ServerChallenge
	n.clientChallenge = randomBytes(8)
	n.negotiateFlags = message.NegotiateFlags
	n.responseKeyNT = ntlmv2Hash(n.user, n.password, n.userDomain)
	timestamp := timeToWindowsFileTime(time.Now())
	n.keyExchangeKey = n.sessionBaseKey

	// Compute the expected response
	n.computeExpectedResponses(timestamp, message.TargetInfo)

	// Return the encrypted session key
	return n.computeEncryptedSessionKey()
}

// GenerateAuthenticateMessage generates an NTLMv2 AuthenticateMessage (Type 3 message).
//
// See: https://curl.se/rfc/ntlm.html#theType3Message
func (n *NTLMv2Session) GenerateAuthenticateMessage() *AuthenticateMessage {
	return &AuthenticateMessage{
		Signature:                 []byte("NTLMSSP\x00"),
		MessageType:               3,
		LmChallengeResponse:       CreateBytePayload(n.lmChallengeResponse),
		NtChallengeResponseFields: CreateBytePayload(n.ntChallengeResponse),
		DomainName:                CreateStringPayload(n.userDomain),
		UserName:                  CreateStringPayload(n.user),
		Workstation:               CreateStringPayload(""),
		EncryptedRandomSessionKey: CreateBytePayload(n.encryptedRandomSessionKey),
		NegotiateFlags:            n.negotiateFlags,
	}
}

// computeExpectedResponses computes the expected NTLMv2 challenge responses (LMv2 and NTLMv2).
func (n *NTLMv2Session) computeExpectedResponses(timestamp []byte, avPairs *AVPairs) {
	// temp = RespType || HiRespType || ZeroByte(6) || Timestamp || ClientChallenge ||
	// ZeroByte(4) || TargetInfo || ZeroByte(4)
	//
	// See: https://curl.se/rfc/ntlm.html#theNtlmv2Response
	temp := slices.Concat(
		[]byte{0x01, 0x01, 0, 0, 0, 0, 0, 0},
		timestamp,
		n.clientChallenge,
		make([]byte, 4),
		avPairs.Bytes(),
		make([]byte, 4),
	)

	// NTLMv2: both the NTLMv2 and LMv2 responses are keyed by the same
	// 16-byte "NTLMv2 hash", so one keyed HMAC-MD5 instance suffices.
	//
	// See: https://curl.se/rfc/ntlm.html#theNtlmv2Response
	mac := hmac.New(md5.New, n.responseKeyNT)
	mac.Write(n.serverChallenge)
	mac.Write(temp)
	ntProofStr := mac.Sum(nil)

	n.ntChallengeResponse = slices.Concat(ntProofStr, temp)

	mac.Reset()
	mac.Write(n.serverChallenge)
	mac.Write(n.clientChallenge)
	n.lmChallengeResponse = slices.Concat(mac.Sum(nil), n.clientChallenge)

	mac.Reset()
	mac.Write(ntProofStr)
	n.sessionBaseKey = mac.Sum(nil)

	if avPairs.Find(MsvAvTimestamp) != nil {
		n.lmChallengeResponse = make([]byte, 24)
	}
}

// computeEncryptedSessionKey computes the encrypted session key for NTLMv2 key exchange.
func (n *NTLMv2Session) computeEncryptedSessionKey() error {
	if uint32(n.negotiateFlags)&uint32(NTLMSSP_NEGOTIATE_KEY_EXCH) == 0 {
		n.exportedSessionKey = n.keyExchangeKey
		n.encryptedRandomSessionKey = nil
		return nil
	}

	n.exportedSessionKey = randomBytes(16)
	cipher, err := rc4.NewCipher(n.keyExchangeKey)
	if err != nil {
		return fmt.Errorf("failed to create RC4 cipher: %w", err)
	}

	encrypted := make([]byte, len(n.exportedSessionKey))
	cipher.XORKeyStream(encrypted, n.exportedSessionKey)
	n.encryptedRandomSessionKey = encrypted

	return nil
}
