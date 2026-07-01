// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

package ntlm

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func Test_ntlmv2Hash(t *testing.T) {
	want := []byte{23, 76, 33, 13, 99, 39, 31, 213, 150, 111, 98, 90, 105, 122, 255, 91}
	hash := ntlmv2Hash("user", "password", "domain")
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

func TestCreateClientSession(t *testing.T) {
	session := CreateClientSession()
	if session == nil {
		t.Fatal("failed to create client session. session is nil")
	}
}

func TestCreateBytePayload(t *testing.T) {
	has := []byte("testpayload")
	payload := createBytePayload(has)

	if payload == nil {
		t.Fatal("createBytePayload returned nil")
	}
	if payload.encoding != payloadEncodingByte {
		t.Errorf("expected byte payload encoding to be: %d, got: %d", payloadEncodingByte, payload.encoding)
	}
	if payload.maxLen != uint16(len(has)) {
		t.Errorf("expected payload maximum length to be: %d, got: %d", uint16(len(has)), payload.maxLen)
	}
	if payload.len != uint16(len(has)) {
		t.Errorf("expected payload length to be: %d, got: %d", uint16(len(has)), payload.len)
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
	payload := createStringPayload(has)
	want := utf16FromString(has)

	if payload == nil {
		t.Fatal("createStringPayload returned nil")
	}
	if payload.encoding != payloadEncodingUnicode {
		t.Errorf("expected string payload encoding to be: %d, got: %d", payloadEncodingUnicode, payload.encoding)
	}
	if payload.maxLen != uint16(len(want)) {
		t.Errorf("expected payload maximum length to be: %d, got: %d", uint16(len(want)), payload.maxLen)
	}
	if payload.len != uint16(len(want)) {
		t.Errorf("expected payload length to be: %d, got: %d", uint16(len(want)), payload.len)
	}
	if payload.offset != 0 {
		t.Errorf("expected payload offset to be: 0, got: %d", payload.offset)
	}
	if !bytes.Equal(payload.payload, want) {
		t.Errorf("expected payload to be: %s, got: %s", want, payload.payload)
	}
}

func TestNTLMv2Session_SetUserInfo(t *testing.T) {
	testUser, testPass, testDomain := "testuser", "passw0rd!", "DOMAIN"

	t.Run("set all values", func(t *testing.T) {
		session := CreateClientSession()
		if session == nil {
			t.Fatal("failed to create client session. session is nil")
		}
		session.SetUserInfo(testUser, testPass, testDomain)
		if session.user != testUser || session.password != testPass || session.domain != testDomain {
			t.Errorf("failed to set user info, got: user=%s, password=%s, domain=%s, want: user=%s, password=%s, domain=%s",
				session.user, session.password, session.domain, testUser, testPass, testDomain)
		}
	})
	t.Run("username only", func(t *testing.T) {
		session := CreateClientSession()
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
		session := CreateClientSession()
		if session == nil {
			t.Fatal("failed to create client session. session is nil")
		}
		session.SetUserInfo("", testPass, "")
		if session.password != testPass {
			t.Errorf("failed to set userinfo, got: pass=%s, want: pass=%s", session.password, testPass)
		}
		if session.user != "" || session.domain != "" {
			t.Errorf("failed to set userinfo, got: user=%s, domain=%s, want: user=empty, domain=empty",
				session.user, session.domain)
		}
	})
	t.Run("domain only", func(t *testing.T) {
		session := CreateClientSession()
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
