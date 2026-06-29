package ntlm

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"fmt"
	"time"
)

const (
	WindowsFileTime = 116444736000000000
)

// NTLMv2Session holds the state of an NTLMv2 session.
type NTLMv2Session struct {
	user       string
	password   string
	userDomain string

	NegotiateFlags NegotiateFlags

	negotiateMessage *NegotiateMessage
	challengeMessage *ChallengeMessage
	serverChallenge  []byte
	clientChallenge  []byte

	responseKeyLM       []byte
	responseKeyNT       []byte
	ntChallengeResponse []byte
	lmChallengeResponse []byte

	sessionBaseKey            []byte
	keyExchangeKey            []byte
	exportedSessionKey        []byte
	encryptedRandomSessionKey []byte

	sequenceNumber uint32
}

// CreateClientSession creates a new NTLMv2Session.
func CreateClientSession() *NTLMv2Session {
	return &NTLMv2Session{}
}

func (n *NTLMv2Session) SetUserInfo(username, password, domain string) {
	n.user = username
	n.password = password
	n.userDomain = domain
	n.sequenceNumber = 0
}

func (n *NTLMv2Session) ProcessChallengeMessage(message *ChallengeMessage) (err error) {
	n.challengeMessage = message
	n.serverChallenge = message.ServerChallenge
	n.clientChallenge = randomBytes(8)
	n.NegotiateFlags = message.NegotiateFlags

	if err = n.fetchResponseKeys(); err != nil {
		return err
	}

	timestamp := timeToWindowsFileTime(time.Now())
	n.computeExpectedResponses(timestamp, message.TargetInfo)
	n.keyExchangeKey = n.sessionBaseKey

	if err = n.computeEncryptedSessionKey(); err != nil {
		return err
	}

	return nil
}

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
		NegotiateFlags:            n.NegotiateFlags,
		Mic:                       make([]byte, 16),
	}
}

func (n *NTLMv2Session) fetchResponseKeys() (err error) {
	if len(n.responseKeyNT) > 0 {
		return
	}
	n.responseKeyLM = ntowfv2(n.user, n.password, n.userDomain)
	n.responseKeyNT = ntowfv2(n.user, n.password, n.userDomain)
	return
}

func (n *NTLMv2Session) computeExpectedResponses(timestamp []byte, avPairs *AVPairs) {
	avPairBytes := avPairs.Bytes()
	temp := concatBytes([]byte{0x01}, []byte{0x01}, zeroBytes(6), timestamp, n.clientChallenge,
		zeroBytes(4), avPairBytes, zeroBytes(4))

	mac := hmac.New(md5.New, n.responseKeyNT)
	mac.Write(concatBytes(n.serverChallenge, temp))
	ntProofStr := mac.Sum(nil)

	n.ntChallengeResponse = concatBytes(ntProofStr, temp)

	mac.Reset()
	mac.Write(concatBytes(n.serverChallenge, n.clientChallenge))
	n.lmChallengeResponse = concatBytes(mac.Sum(nil), n.clientChallenge)

	mac.Reset()
	mac.Write(ntProofStr)
	n.sessionBaseKey = mac.Sum(nil)

	if avPairs.Find(MsvAvTimestamp) != nil {
		n.lmChallengeResponse = make([]byte, 24)
	}
}

func (n *NTLMv2Session) computeEncryptedSessionKey() error {
	if uint32(n.NegotiateFlags)&uint32(NTLMSSP_NEGOTIATE_KEY_EXCH) != 0 {
		cipher, err := rc4.NewCipher(n.keyExchangeKey)
		if err != nil {
			return fmt.Errorf("failed create new RC4 cipher: %w", err)
		}
		result := make([]byte, len(n.exportedSessionKey))
		cipher.XORKeyStream(result, n.exportedSessionKey)

		n.exportedSessionKey = randomBytes(16)
		n.encryptedRandomSessionKey = result
		return nil
	}

	n.encryptedRandomSessionKey = make([]byte, 0)
	n.exportedSessionKey = n.keyExchangeKey
	return nil
}
