// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

package ntlm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

const (
	testChallenge = "S3creT!1"
	testUser      = "testuser"
	testPassword  = "Passw0rd!."
	testHost      = "localhost"
	testDomain    = "EXAMPLE.COM"
)

func Test_ntlmv2Hash(t *testing.T) {
	want := []byte{0xea, 0x13, 0x64, 0x57, 0x17, 0xa0, 0x62, 0xcf, 0xf6, 0x65, 0x74, 0x7b, 0xb4, 0x51, 0x2a, 0x43}
	hash := ntlmv2Hash(testUser, testPassword, testDomain)
	if !bytes.Equal(hash, want) {
		t.Errorf("ntlmv2 hash mismatch, got: %x, want: %x", hash, want)
	}
}

func Test_timeToWindowsFileTime(t *testing.T) {
	want := []byte{0x00, 0x00, 0x81, 0x92, 0xb1, 0x7a, 0xdc, 0x01}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	filetime := timeToWindowsFileTime(now)
	if !bytes.Equal(filetime, want) {
		t.Errorf("timeToWindowsFileTime mismatch, got: %x, want: %x", filetime, want)
	}
}

func Test_utf16FromString(t *testing.T) {
	value := "teststring"
	want := []byte{0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x73, 0x00, 0x74, 0x00, 0x72, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x67, 0x00}
	got := utf16FromString(value)
	if !bytes.Equal(got, want) {
		t.Errorf("utf16FromString mismatch, got: %x, want: %x", got, want)
	}
}

func Test_randomBytes(t *testing.T) {
	lengths := []int{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47}
	for _, length := range lengths {
		t.Run(fmt.Sprintf("generating %d random bytes", length), func(t *testing.T) {
			val := randomBytes(length)
			if len(val) != length {
				t.Errorf("randomBytes length mismatch, got: %d, want: %d", len(val), length)
			}
		})
	}
}

func Test_toUint16(t *testing.T) {
	tests := []struct {
		name    string
		input   int
		want    uint16
		wantErr bool
	}{
		{"int fits into uint16", 1, 1, false},
		{"negative int fails", -1, 0, true},
		{"max uint16 fits", 65535, 65535, false},
		{"max uint16 + 1 overflows and fails", 65536, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toUint16(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("failed to convert int to uint16, got: %s", err)
			}
			if got != tt.want {
				t.Errorf("failed to convert int to uint16, got: %d, want: %d", got, tt.want)
			}
		})
	}
}

func Test_toUint32(t *testing.T) {
	tests := []struct {
		name    string
		input   int
		want    uint32
		wantErr bool
	}{
		{"int fits into uint32", 1, 1, false},
		{"negative int fails", -1, 0, true},
		{"max uint32 fits", 4294967295, 4294967295, false},
		{"max uint32 + 1 overflows and fails", 4294967296, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toUint32(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("failed to convert int to uint16, got: %s", err)
			}
			if got != tt.want {
				t.Errorf("failed to convert int to uint16, got: %d, want: %d", got, tt.want)
			}
		})
	}
}

func TestCreateClientSession(t *testing.T) {
	session := NewNTLMv2Session()
	if session == nil {
		t.Fatal("failed to create client session. session is nil")
	}
}

func TestCreateBytePayload(t *testing.T) {
	has := []byte("testpayload")
	payload, err := createBytePayload(has)
	if err != nil {
		t.Fatalf("failed to create payload: %s", err)
	}
	payloadLength, err := toUint16(len(has))
	if err != nil {
		t.Fatalf("failed to convert payload length to uint16: %s", err)
	}

	if payload == nil {
		t.Fatal("createBytePayload returned nil")
	}
	if payload.encoding != payloadEncodingByte {
		t.Errorf("expected byte payload encoding to be: %d, got: %d", payloadEncodingByte, payload.encoding)
	}
	if payload.maxLen != payloadLength {
		t.Errorf("expected payload maximum length to be: %d, got: %d", payloadLength, payload.maxLen)
	}
	if payload.len != payloadLength {
		t.Errorf("expected payload length to be: %d, got: %d", payloadLength, payload.len)
	}
	if payload.offset != 0 {
		t.Errorf("expected payload offset to be: 0, got: %d", payload.offset)
	}
	if !bytes.Equal(payload.payload, has) {
		t.Errorf("expected payload to be: %s, got: %s", has, payload.payload)
	}
}

func TestCreateStringPayload(t *testing.T) {
	has := "testpayload"
	want := utf16FromString(has)
	payload, err := createStringPayload(has)
	if err != nil {
		t.Fatalf("failed to create payload: %s", err)
	}
	payloadLength, err := toUint16(len(want))
	if err != nil {
		t.Fatalf("failed to convert payload length to uint16: %s", err)
	}

	if payload == nil {
		t.Fatal("createStringPayload returned nil")
	}
	if payload.encoding != payloadEncodingUnicode {
		t.Errorf("expected string payload encoding to be: %d, got: %d", payloadEncodingUnicode, payload.encoding)
	}
	if payload.maxLen != payloadLength {
		t.Errorf("expected payload maximum length to be: %d, got: %d", payloadLength, payload.maxLen)
	}
	if payload.len != payloadLength {
		t.Errorf("expected payload length to be: %d, got: %d", payloadLength, payload.len)
	}
	if payload.offset != 0 {
		t.Errorf("expected payload offset to be: 0, got: %d", payload.offset)
	}
	if !bytes.Equal(payload.payload, want) {
		t.Errorf("expected payload to be: %s, got: %s", want, payload.payload)
	}
}

func TestNTLMv2Session_SetUserInfo(t *testing.T) {
	t.Run("set all values", func(t *testing.T) {
		session := NewNTLMv2Session()
		if session == nil {
			t.Fatal("failed to create client session. session is nil")
		}
		session.SetUserInfo(testUser, testPassword, testDomain)
		if session.user != testUser || session.password != testPassword || session.domain != testDomain {
			t.Errorf("failed to set user info, got: user=%s, password=%s, domain=%s, want: user=%s, password=%s, domain=%s",
				session.user, session.password, session.domain, testUser, testPassword, testDomain)
		}
	})
	t.Run("username only", func(t *testing.T) {
		session := NewNTLMv2Session()
		if session == nil {
			t.Fatal("failed to create client session. session is nil")
		}
		session.SetUserInfo(testUser, "", "")
		if session.user != testUser {
			t.Errorf("failed to set userinfo, got: user=%s, want: user=%s", session.user, testUser)
		}
		if session.password != "" || session.domain != "" {
			t.Errorf("failed to set userinfo, got: password=%s, domain=%s, want: password=empty, domain=empty",
				session.password, session.domain)
		}
	})
	t.Run("password only", func(t *testing.T) {
		session := NewNTLMv2Session()
		if session == nil {
			t.Fatal("failed to create client session. session is nil")
		}
		session.SetUserInfo("", testPassword, "")
		if session.password != testPassword {
			t.Errorf("failed to set userinfo, got: pass=%s, want: pass=%s", session.password, testPassword)
		}
		if session.user != "" || session.domain != "" {
			t.Errorf("failed to set userinfo, got: user=%s, domain=%s, want: user=empty, domain=empty",
				session.user, session.domain)
		}
	})
	t.Run("domain only", func(t *testing.T) {
		session := NewNTLMv2Session()
		if session == nil {
			t.Fatal("failed to create client session. session is nil")
		}
		session.SetUserInfo("", "", testDomain)
		if session.domain != testDomain {
			t.Errorf("failed to set userinfo, got: domain=%s, want: domain=%s", session.domain, testDomain)
		}
		if session.user != "" || session.password != "" {
			t.Errorf("failed to set userinfo, got: user=%s, password=%s, want: user=empty, password=empty",
				session.user, session.password)
		}
	})
}

func TestNTLMv2Session_ParseChallengeMessage(t *testing.T) {
	t.Run("processing challenge message succeeds", func(t *testing.T) {
		session := NewNTLMv2Session()
		if session == nil {
			t.Fatal("failed to create client session. session is nil")
		}
		session.SetUserInfo(testUser, testPassword, testDomain)
		message, err := CreateChallengeMessage(
			uint32(ntlmsspNegotiateUnicode|ntlmsspNegotiateAlwaysSign|ntlmsspNegotiateKeyExchange),
			[]byte(testChallenge), testHost, testDomain)
		if err != nil {
			t.Fatalf("failed to create challenge message: %s", err)
		}
		err = session.ParseChallengeMessage(message)
		if err != nil {
			t.Fatalf("failed to parse challenge message: %s", err)
		}
		if session.negotiateMessage != nil {
			t.Errorf("didn't expect a negotiateMessage in the session, got: %+v", session.negotiateMessage)
		}
		if session.challengeMessage == nil {
			t.Errorf("expected challengeMessage in the session, got nil")
		}
		want := []byte{0xea, 0x13, 0x64, 0x57, 0x17, 0xa0, 0x62, 0xcf, 0xf6, 0x65, 0x74, 0x7b, 0xb4, 0x51, 0x2a, 0x43}
		if !bytes.EqualFold(session.responseKeyNT, want) {
			t.Errorf("expected responseKeyNT to be: %x, got: %x", want, session.responseKeyNT)
		}
	})
	t.Run("processing nil byte challenge message fails", func(t *testing.T) {
		session := NewNTLMv2Session()
		if session == nil {
			t.Fatal("failed to create client session. session is nil")
		}
		if err := session.ParseChallengeMessage(nil); err == nil {
			t.Errorf("expected error, got nil")
		}
	})
	t.Run("processing message with broken signature fails", func(t *testing.T) {
		session := NewNTLMv2Session()
		if session == nil {
			t.Fatal("failed to create client session. session is nil")
		}

		buffer := bytes.NewBuffer(nil)
		buffer.Write([]byte("INVALID"))
		if err := binary.Write(buffer, binary.LittleEndian, uint32(messageTypeChallenge)); err != nil {
			t.Fatalf("failed to write to buffer: %s", err)
		}
		buffer.Write([]byte(strings.Repeat("x", 60)))
		err := session.ParseChallengeMessage(buffer.Bytes())
		if err == nil {
			t.Error("expected an error parsing an invalid message, got nil")
		}
		if !errors.Is(err, ErrNTLMInvalidSignature) {
			t.Errorf("expected error %s, got %s", ErrNTLMInvalidSignature, err)
		}
	})
	t.Run("processing message with wrong message type fails", func(t *testing.T) {
		session := NewNTLMv2Session()
		if session == nil {
			t.Fatal("failed to create client session. session is nil")
		}

		buffer := bytes.NewBuffer(nil)
		buffer.Write([]byte(signature))
		if err := binary.Write(buffer, binary.LittleEndian, uint32(messageTypeNegotiate)); err != nil {
			t.Fatalf("failed to write to buffer: %s", err)
		}
		buffer.Write([]byte(strings.Repeat("x", 60)))
		err := session.ParseChallengeMessage(buffer.Bytes())
		if err == nil {
			t.Error("expected an error parsing an invalid message, got nil")
		}
		if !errors.Is(err, ErrNTLMInvalidMessageType) {
			t.Errorf("expected error %s, got %s", ErrNTLMInvalidMessageType, err)
		}
	})
	t.Run("processing message with broken payload fails", func(t *testing.T) {
		session := NewNTLMv2Session()
		if session == nil {
			t.Fatal("failed to create client session. session is nil")
		}

		buffer := bytes.NewBuffer(nil)
		buffer.Write([]byte(signature))
		if err := binary.Write(buffer, binary.LittleEndian, uint32(messageTypeChallenge)); err != nil {
			t.Fatalf("failed to write to buffer: %s", err)
		}
		buffer.Write([]byte(strings.Repeat("x", 60)))
		err := session.ParseChallengeMessage(buffer.Bytes())
		if err == nil {
			t.Error("expected an error parsing an invalid message, got nil")
		}
		if !errors.Is(err, ErrNTLMInvalidPayload) {
			t.Errorf("expected error %s, got %s", ErrNTLMInvalidPayload, err)
		}
	})
}

func TestNTLMv2Session_GenerateAuthenticateMessage(t *testing.T) {
	t.Run("generates authenticate message successfully", func(t *testing.T) {
		session := NewNTLMv2Session()
		if session == nil {
			t.Fatal("failed to create client session. session is nil")
		}
		session.SetUserInfo(testUser, testPassword, testDomain)
		message, err := CreateChallengeMessage(
			uint32(ntlmsspNegotiateUnicode|ntlmsspNegotiateAlwaysSign|ntlmsspNegotiateKeyExchange),
			[]byte(testChallenge), testHost, testDomain)
		if err != nil {
			t.Fatalf("failed to create challenge message: %s", err)
		}
		err = session.ParseChallengeMessage(message)
		if err != nil {
			t.Fatalf("failed to parse challenge message: %s", err)
		}
		authMsg, err := session.GenerateAuthenticateMessage()
		if err != nil {
			t.Errorf("failed to generate authenticate message: %s", err)
		}
		data := authMsg.Bytes()
		if data == nil {
			t.Error("expected authenticate message, but got nil")
		}
		if len(data) != 310 {
			t.Errorf("expected %d bytes, but got %d", 310, len(data))
		}
	})
	t.Run("generates authenticate message without negotiate key exchange successfully", func(t *testing.T) {
		session := NewNTLMv2Session()
		if session == nil {
			t.Fatal("failed to create client session. session is nil")
		}
		session.SetUserInfo(testUser, testPassword, testDomain)
		message, err := CreateChallengeMessage(uint32(ntlmsspNegotiateUnicode), []byte(testChallenge), testHost, testDomain)
		if err != nil {
			t.Fatalf("failed to create challenge message: %s", err)
		}
		err = session.ParseChallengeMessage(message)
		if err != nil {
			t.Fatalf("failed to parse challenge message: %s", err)
		}
		if _, err = session.GenerateAuthenticateMessage(); err != nil {
			t.Errorf("failed to generate authenticate message: %s", err)
		}
	})
	t.Run("broken session fields fails the authenticate message generation", func(t *testing.T) {
		tests := []struct {
			name       string
			sessionFun func(s *NTLMv2Session)
		}{
			{
				"broken lmChallengeResponse", func(s *NTLMv2Session) {
					s.lmChallengeResponse = []byte(strings.Repeat("x", math.MaxUint16+1))
				},
			},
			{
				"broken ntChallengeResponse", func(s *NTLMv2Session) {
					s.ntChallengeResponse = []byte(strings.Repeat("x", math.MaxUint16+1))
				},
			},
			{
				"broken encryptedRandomSessionKey", func(s *NTLMv2Session) {
					s.encryptedRandomSessionKey = []byte(strings.Repeat("x", math.MaxUint16+1))
				},
			},
			{
				"broken domain", func(s *NTLMv2Session) {
					s.domain = strings.Repeat("x", math.MaxUint16+1)
				},
			},
			{
				"broken user", func(s *NTLMv2Session) {
					s.user = strings.Repeat("x", math.MaxUint16+1)
				},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				session := NewNTLMv2Session()
				if session == nil {
					t.Fatal("failed to create client session. session is nil")
				}
				session.SetUserInfo(testUser, testPassword, testDomain)
				message, err := CreateChallengeMessage(
					uint32(ntlmsspNegotiateUnicode|ntlmsspNegotiateAlwaysSign|ntlmsspNegotiateKeyExchange),
					[]byte(testChallenge), testHost, testDomain)
				if err != nil {
					t.Fatalf("failed to create challenge message: %s", err)
				}
				if err = session.ParseChallengeMessage(message); err != nil {
					t.Errorf("failed to parse challenge message: %s", err)
				}
				tt.sessionFun(session)
				if _, err = session.GenerateAuthenticateMessage(); err == nil {
					t.Error("expected authentication message generation to fail, but got nil")
				}
			})
		}
	})
}

func TestNTLMv2Session_GenerateNegotiateMessage(t *testing.T) {
	t.Run("generates negotiate message successfully", func(t *testing.T) {
		session := NewNTLMv2Session()
		if session == nil {
			t.Fatal("failed to create client session. session is nil")
		}
		session.SetUserInfo(testUser, testPassword, testDomain)
		message, err := session.GenerateNegotiateMessage()
		if err != nil {
			t.Errorf("failed to generate negotiate message: %s", err)
		}
		if message == nil {
			t.Error("expected negotiate message, but got nil")
		}
	})
	t.Run("generating negotiate message fails on invalid domain", func(t *testing.T) {
		session := NewNTLMv2Session()
		if session == nil {
			t.Fatal("failed to create client session. session is nil")
		}
		session.SetUserInfo(testUser, testPassword, strings.Repeat("x", math.MaxInt16+1))
		_, err := session.GenerateNegotiateMessage()
		if err == nil {
			t.Error("expected negotiate message generation to fail, but got nil")
		}
	})
}

func TestNegotiateMessage_Bytes(t *testing.T) {
	t.Run("bytes returns the correct message bytes", func(t *testing.T) {
		session := NewNTLMv2Session()
		if session == nil {
			t.Fatal("failed to create client session. session is nil")
		}
		session.SetUserInfo(testUser, testPassword, testDomain)
		message, err := session.GenerateNegotiateMessage()
		if err != nil {
			t.Errorf("failed to generate negotiate message: %s", err)
		}
		if message == nil {
			t.Error("expected negotiate message, but got nil")
		}
		date, err := message.Bytes()
		if err != nil {
			t.Errorf("failed to get message bytes: %s", err)
		}
		if len(date) != 54 {
			t.Errorf("expected %d bytes, but got %d", 54, len(date))
		}
	})
}

func TestNTLMv2Session_computeEncryptedSessionKey(t *testing.T) {
	t.Run("computes encrypted session key successfully", func(t *testing.T) {
		session := NewNTLMv2Session()
		if session == nil {
			t.Fatal("failed to create client session. session is nil")
		}
		session.SetUserInfo(testUser, testPassword, testDomain)
		message, err := CreateChallengeMessage(
			uint32(ntlmsspNegotiateUnicode|ntlmsspNegotiateAlwaysSign|ntlmsspNegotiateKeyExchange),
			[]byte(testChallenge), testHost, testDomain)
		if err != nil {
			t.Fatalf("failed to create challenge message: %s", err)
		}
		if err = session.ParseChallengeMessage(message); err != nil {
			t.Errorf("failed to parse challenge message: %s", err)
		}
		session.sessionBaseKey = []byte(strings.Repeat("x", 257))
		if err := session.computeEncryptedSessionKey(); err == nil {
			t.Error("expected computeEncryptedSessionKey to fail, but got nil")
		}
	})
}

func TestCreateChallengeMessage(t *testing.T) {
	t.Run("creates challenge message successfully", func(t *testing.T) {
		_, err := CreateChallengeMessage(
			uint32(ntlmsspNegotiateUnicode|ntlmsspNegotiateAlwaysSign|ntlmsspNegotiateKeyExchange),
			[]byte(testChallenge), testHost, testDomain)
		if err != nil {
			t.Fatalf("failed to create challenge message: %s", err)
		}
	})
	t.Run("creates challenge message with extended session security successfully", func(t *testing.T) {
		_, err := CreateChallengeMessage(
			uint32(ntlmsspNegotiateUnicode|ntlmsspNegotiateAlwaysSign|ntlmsspNegotiateKeyExchange|
				ntlmsspNegotiateExtendedSessionSecurity),
			[]byte(testChallenge), testHost, testDomain)
		if err != nil {
			t.Fatalf("failed to create challenge message: %s", err)
		}
	})
	t.Run("challenge message creation with overly long domain fails", func(t *testing.T) {
		_, err := CreateChallengeMessage(
			uint32(ntlmsspNegotiateUnicode|ntlmsspNegotiateAlwaysSign|ntlmsspNegotiateKeyExchange),
			[]byte(testChallenge), testHost, strings.Repeat("x", math.MaxInt16+1))
		if err == nil {
			t.Error("expected challenge message creation to fail, but got nil")
		}
	})
	t.Run("challenge message creation with overly long target fails", func(t *testing.T) {
		_, err := CreateChallengeMessage(
			uint32(ntlmsspNegotiateUnicode|ntlmsspNegotiateAlwaysSign|ntlmsspNegotiateKeyExchange),
			[]byte(testChallenge), strings.Repeat("x", math.MaxInt16+1), testDomain)
		if err == nil {
			t.Error("expected challenge message creation to fail, but got nil")
		}
	})
}
