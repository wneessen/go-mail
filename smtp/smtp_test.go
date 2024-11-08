// SPDX-FileCopyrightText: Copyright 2010 The Go Authors. All rights reserved.
// SPDX-FileCopyrightText: Copyright (c) 2022-2023 The go-mail Authors
//
// Original net/smtp code from the Go stdlib by the Go Authors.
// Use of this source code is governed by a BSD-style
// LICENSE file that can be found in this directory.
//
// go-mail specific modifications by the go-mail Authors.
// Licensed under the MIT License.
// See [PROJECT ROOT]/LICENSES directory for more information.
//
// SPDX-License-Identifier: BSD-3-Clause AND MIT

package smtp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// TestServerProto is the protocol used for the simple SMTP test server
	TestServerProto = "tcp"
	// TestServerAddr is the address the simple SMTP test server listens on
	TestServerAddr = "127.0.0.1"
	// TestServerPortBase is the base port for the simple SMTP test server
	TestServerPortBase = 12025
)

// PortAdder is an atomic counter used to increment port numbers for the test SMTP server instances.
var PortAdder atomic.Int32

// localhostCert is a PEM-encoded TLS cert generated from src/crypto/tls:
//
//	go run generate_cert.go --rsa-bits 1024 --host 127.0.0.1,::1,example.com \
//		--ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
var localhostCert = []byte(`
-----BEGIN CERTIFICATE-----
MIICFDCCAX2gAwIBAgIRAK0xjnaPuNDSreeXb+z+0u4wDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAgFw03MDAxMDEwMDAwMDBaGA8yMDg0MDEyOTE2
MDAwMFowEjEQMA4GA1UEChMHQWNtZSBDbzCBnzANBgkqhkiG9w0BAQEFAAOBjQAw
gYkCgYEA0nFbQQuOWsjbGtejcpWz153OlziZM4bVjJ9jYruNw5n2Ry6uYQAffhqa
JOInCmmcVe2siJglsyH9aRh6vKiobBbIUXXUU1ABd56ebAzlt0LobLlx7pZEMy30
LqIi9E6zmL3YvdGzpYlkFRnRrqwEtWYbGBf3znO250S56CCWH2UCAwEAAaNoMGYw
DgYDVR0PAQH/BAQDAgKkMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1UdEwEB/wQF
MAMBAf8wLgYDVR0RBCcwJYILZXhhbXBsZS5jb22HBH8AAAGHEAAAAAAAAAAAAAAA
AAAAAAEwDQYJKoZIhvcNAQELBQADgYEAbZtDS2dVuBYvb+MnolWnCNqvw1w5Gtgi
NmvQQPOMgM3m+oQSCPRTNGSg25e1Qbo7bgQDv8ZTnq8FgOJ/rbkyERw2JckkHpD4
n4qcK27WkEDBtQFlPihIM8hLIuzWoi/9wygiElTy/tVL3y7fGCvY2/k1KBthtZGF
tN8URjVmyEo=
-----END CERTIFICATE-----`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
MIICXgIBAAKBgQDScVtBC45ayNsa16NylbPXnc6XOJkzhtWMn2Niu43DmfZHLq5h
AB9+Gpok4icKaZxV7ayImCWzIf1pGHq8qKhsFshRddRTUAF3np5sDOW3QuhsuXHu
lkQzLfQuoiL0TrOYvdi90bOliWQVGdGurAS1ZhsYF/fOc7bnRLnoIJYfZQIDAQAB
AoGBAMst7OgpKyFV6c3JwyI/jWqxDySL3caU+RuTTBaodKAUx2ZEmNJIlx9eudLA
kucHvoxsM/eRxlxkhdFxdBcwU6J+zqooTnhu/FE3jhrT1lPrbhfGhyKnUrB0KKMM
VY3IQZyiehpxaeXAwoAou6TbWoTpl9t8ImAqAMY8hlULCUqlAkEA+9+Ry5FSYK/m
542LujIcCaIGoG1/Te6Sxr3hsPagKC2rH20rDLqXwEedSFOpSS0vpzlPAzy/6Rbb
PHTJUhNdwwJBANXkA+TkMdbJI5do9/mn//U0LfrCR9NkcoYohxfKz8JuhgRQxzF2
6jpo3q7CdTuuRixLWVfeJzcrAyNrVcBq87cCQFkTCtOMNC7fZnCTPUv+9q1tcJyB
vNjJu3yvoEZeIeuzouX9TJE21/33FaeDdsXbRhQEj23cqR38qFHsF1qAYNMCQQDP
QXLEiJoClkR2orAmqjPLVhR3t2oB3INcnEjLNSq8LHyQEfXyaFfu4U9l5+fRPL2i
jiC0k/9L5dHUsF0XZothAkEA23ddgRs+Id/HxtojqqUT27B8MT/IGNrYsp4DvS/c
qgkeluku4GjxRlDMBuXk94xOBEinUs+p/hwP1Alll80Tpg==
-----END RSA TESTING KEY-----`))

type authTest struct {
	auth       Auth
	challenges []string
	name       string
	responses  []string
	sf         []bool
	hasNonce   bool
}

var authTests = []authTest{
	{
		PlainAuth("", "user", "pass", "testserver", false),
		[]string{},
		"PLAIN",
		[]string{"\x00user\x00pass"},
		[]bool{false, false},
		false,
	},
	{
		PlainAuth("", "user", "pass", "testserver", true),
		[]string{},
		"PLAIN",
		[]string{"\x00user\x00pass"},
		[]bool{false, false},
		false,
	},
	{
		PlainAuth("foo", "bar", "baz", "testserver", false),
		[]string{},
		"PLAIN",
		[]string{"foo\x00bar\x00baz"},
		[]bool{false, false},
		false,
	},
	{
		PlainAuth("foo", "bar", "baz", "testserver", false),
		[]string{"foo"},
		"PLAIN",
		[]string{"foo\x00bar\x00baz", ""},
		[]bool{true},
		false,
	},
	{
		LoginAuth("user", "pass", "testserver", false),
		[]string{"Username:", "Password:"},
		"LOGIN",
		[]string{"", "user", "pass"},
		[]bool{false, false},
		false,
	},
	{
		LoginAuth("user", "pass", "testserver", true),
		[]string{"Username:", "Password:"},
		"LOGIN",
		[]string{"", "user", "pass"},
		[]bool{false, false},
		false,
	},
	{
		LoginAuth("user", "pass", "testserver", false),
		[]string{"User Name\x00", "Password\x00"},
		"LOGIN",
		[]string{"", "user", "pass"},
		[]bool{false, false},
		false,
	},
	{
		LoginAuth("user", "pass", "testserver", false),
		[]string{"Invalid", "Invalid:"},
		"LOGIN",
		[]string{"", "user", "pass"},
		[]bool{false, false},
		false,
	},
	{
		LoginAuth("user", "pass", "testserver", false),
		[]string{"Invalid", "Invalid:", "Too many"},
		"LOGIN",
		[]string{"", "user", "pass", ""},
		[]bool{false, false, true},
		false,
	},
	{
		CRAMMD5Auth("user", "pass"),
		[]string{"<123456.1322876914@testserver>"},
		"CRAM-MD5",
		[]string{"", "user 287eb355114cf5c471c26a875f1ca4ae"},
		[]bool{false, false},
		false,
	},
	{
		XOAuth2Auth("username", "token"),
		[]string{""},
		"XOAUTH2",
		[]string{"user=username\x01auth=Bearer token\x01\x01", ""},
		[]bool{false},
		false,
	},
	{
		ScramSHA1Auth("username", "password"),
		[]string{"", "r=foo"},
		"SCRAM-SHA-1",
		[]string{"", "n,,n=username,r=", ""},
		[]bool{false, true},
		true,
	},
	{
		ScramSHA1Auth("username", "password"),
		[]string{"", "v=foo"},
		"SCRAM-SHA-1",
		[]string{"", "n,,n=username,r=", ""},
		[]bool{false, true},
		true,
	},
	{
		ScramSHA256Auth("username", "password"),
		[]string{""},
		"SCRAM-SHA-256",
		[]string{"", "n,,n=username,r=", ""},
		[]bool{false},
		true,
	},
	{
		ScramSHA1PlusAuth("username", "password", nil),
		[]string{""},
		"SCRAM-SHA-1-PLUS",
		[]string{"", "", ""},
		[]bool{true},
		true,
	},
	{
		ScramSHA256PlusAuth("username", "password", nil),
		[]string{""},
		"SCRAM-SHA-256-PLUS",
		[]string{"", "", ""},
		[]bool{true},
		true,
	},
}

func TestAuth(t *testing.T) {
	t.Run("Auth for all supported auth methods", func(t *testing.T) {
		for i, tt := range authTests {
			t.Run(tt.name, func(t *testing.T) {
				name, resp, err := tt.auth.Start(&ServerInfo{"testserver", true, nil})
				if name != tt.name {
					t.Errorf("test #%d got name %s, expected %s", i, name, tt.name)
				}
				if len(tt.responses) <= 0 {
					t.Fatalf("test #%d got no responses, expected at least one", i)
				}
				if !bytes.Equal(resp, []byte(tt.responses[0])) {
					t.Errorf("#%d got response %s, expected %s", i, resp, tt.responses[0])
				}
				if err != nil {
					t.Errorf("#%d error: %s", i, err)
				}
			testLoop:
				for j := range tt.challenges {
					challenge := []byte(tt.challenges[j])
					expected := []byte(tt.responses[j+1])
					sf := tt.sf[j]
					resp, err := tt.auth.Next(challenge, true)
					if err != nil && !sf {
						t.Errorf("#%d error: %s", i, err)
						continue testLoop
					}
					if tt.hasNonce {
						if !bytes.HasPrefix(resp, expected) {
							t.Errorf("#%d got response: %s, expected response to start with: %s", i, resp, expected)
						}
						continue testLoop
					}
					if !bytes.Equal(resp, expected) {
						t.Errorf("#%d got %s, expected %s", i, resp, expected)
						continue testLoop
					}
					_, err = tt.auth.Next([]byte("2.7.0 Authentication successful"), false)
					if err != nil {
						t.Errorf("#%d success message error: %s", i, err)
					}
				}
			})
		}
	})
}

func TestPlainAuth(t *testing.T) {
	tests := []struct {
		name       string
		authName   string
		server     *ServerInfo
		shouldFail bool
		wantErr    error
	}{
		{
			name:       "PLAIN auth succeeds",
			authName:   "servername",
			server:     &ServerInfo{Name: "servername", TLS: true},
			shouldFail: false,
		},
		{
			// OK to use PlainAuth on localhost without TLS
			name:       "PLAIN on localhost is allowed to go unencrypted",
			authName:   "localhost",
			server:     &ServerInfo{Name: "localhost", TLS: false},
			shouldFail: false,
		},
		{
			// NOT OK on non-localhost, even if server says PLAIN is OK.
			// (We don't know that the server is the real server.)
			name:       "PLAIN on non-localhost is not allowed to go unencrypted",
			authName:   "servername",
			server:     &ServerInfo{Name: "servername", Auth: []string{"PLAIN"}},
			shouldFail: true,
			wantErr:    ErrUnencrypted,
		},
		{
			name:       "PLAIN on non-localhost with no PLAIN announcement, is not allowed to go unencrypted",
			authName:   "servername",
			server:     &ServerInfo{Name: "servername", Auth: []string{"CRAM-MD5"}},
			shouldFail: true,
			wantErr:    ErrUnencrypted,
		},
		{
			name:       "PLAIN with wrong hostname",
			authName:   "servername",
			server:     &ServerInfo{Name: "attacker", TLS: true},
			shouldFail: true,
			wantErr:    ErrWrongHostname,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := "foo"
			user := "toni.tester@example.com"
			pass := "v3ryS3Cur3P4ssw0rd"
			auth := PlainAuth(identity, user, pass, tt.authName, false)
			method, resp, err := auth.Start(tt.server)
			if err != nil && !tt.shouldFail {
				t.Errorf("plain authentication failed: %s", err)
			}
			if err == nil && tt.shouldFail {
				t.Error("plain authentication was expected to fail")
			}
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error to be: %s, got: %s", tt.wantErr, err)
				}
				return
			}
			if method != "PLAIN" {
				t.Errorf("expected method return to be: %q, got: %q", "PLAIN", method)
			}
			if !bytes.Equal([]byte(identity+"\x00"+user+"\x00"+pass), resp) {
				t.Errorf("expected response to be: %q, got: %q", identity+"\x00"+user+"\x00"+pass, resp)
			}
		})
	}
	t.Run("PLAIN sends second server response should fail", func(t *testing.T) {
		identity := "foo"
		user := "toni.tester@example.com"
		pass := "v3ryS3Cur3P4ssw0rd"
		server := &ServerInfo{Name: "servername", TLS: true}
		auth := PlainAuth(identity, user, pass, "servername", false)
		method, resp, err := auth.Start(server)
		if err != nil {
			t.Fatalf("plain authentication failed: %s", err)
		}
		if method != "PLAIN" {
			t.Errorf("expected method return to be: %q, got: %q", "PLAIN", method)
		}
		if !bytes.Equal([]byte(identity+"\x00"+user+"\x00"+pass), resp) {
			t.Errorf("expected response to be: %q, got: %q", identity+"\x00"+user+"\x00"+pass, resp)
		}
		_, err = auth.Next([]byte("nonsense"), true)
		if err == nil {
			t.Fatal("expected second server challange to fail")
		}
		if !errors.Is(err, ErrUnexpectedServerChallange) {
			t.Errorf("expected error to be: %s, got: %s", ErrUnexpectedServerChallange, err)
		}
	})
	t.Run("PLAIN authentication on test server", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		auth := PlainAuth("", "user", "pass", TestServerAddr, false)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client connection: %s", err)
			}
		})
		if err = client.Auth(auth); err != nil {
			t.Errorf("failed to authenticate to test server: %s", err)
		}
	})
	t.Run("PLAIN authentication on test server should fail", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnAuth: true,
				FeatureSet: featureSet,
				ListenPort: serverPort},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		auth := PlainAuth("", "user", "pass", TestServerAddr, false)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to connect to test server: %s", err)
		}
		if err = client.Auth(auth); err == nil {
			t.Errorf("expected authentication to fail")
		}
	})
}

func TestPlainAuth_noEnc(t *testing.T) {
	tests := []struct {
		name       string
		authName   string
		server     *ServerInfo
		shouldFail bool
		wantErr    error
	}{
		{
			name:       "PLAIN-NOENC auth succeeds",
			authName:   "servername",
			server:     &ServerInfo{Name: "servername", TLS: true},
			shouldFail: false,
		},
		{
			// OK to use PlainAuth on localhost without TLS
			name:       "PLAIN-NOENC on localhost is allowed to go unencrypted",
			authName:   "localhost",
			server:     &ServerInfo{Name: "localhost", TLS: false},
			shouldFail: false,
		},
		{
			// ALSO OK on non-localhost. This auth mode is specificly for that.
			name:       "PLAIN-NOENC on non-localhost is allowed to go unencrypted",
			authName:   "servername",
			server:     &ServerInfo{Name: "servername", Auth: []string{"PLAIN"}},
			shouldFail: false,
		},
		{
			name:       "PLAIN-NOENC on non-localhost with no PLAIN announcement, is allowed to go unencrypted",
			authName:   "servername",
			server:     &ServerInfo{Name: "servername", Auth: []string{"CRAM-MD5"}},
			shouldFail: false,
		},
		{
			name:       "PLAIN-NOENC with wrong hostname",
			authName:   "servername",
			server:     &ServerInfo{Name: "attacker", TLS: true},
			shouldFail: true,
			wantErr:    ErrWrongHostname,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := "foo"
			user := "toni.tester@example.com"
			pass := "v3ryS3Cur3P4ssw0rd"
			auth := PlainAuth(identity, user, pass, tt.authName, true)
			method, resp, err := auth.Start(tt.server)
			if err != nil && !tt.shouldFail {
				t.Errorf("plain authentication failed: %s", err)
			}
			if err == nil && tt.shouldFail {
				t.Error("plain authentication was expected to fail")
			}
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error to be: %s, got: %s", tt.wantErr, err)
				}
				return
			}
			if method != "PLAIN" {
				t.Errorf("expected method return to be: %q, got: %q", "PLAIN", method)
			}
			if !bytes.Equal([]byte(identity+"\x00"+user+"\x00"+pass), resp) {
				t.Errorf("expected response to be: %q, got: %q", identity+"\x00"+user+"\x00"+pass, resp)
			}
		})
	}
	t.Run("PLAIN-NOENC sends second server response should fail", func(t *testing.T) {
		identity := "foo"
		user := "toni.tester@example.com"
		pass := "v3ryS3Cur3P4ssw0rd"
		server := &ServerInfo{Name: "servername", TLS: true}
		auth := PlainAuth(identity, user, pass, "servername", true)
		method, resp, err := auth.Start(server)
		if err != nil {
			t.Fatalf("plain authentication failed: %s", err)
		}
		if method != "PLAIN" {
			t.Errorf("expected method return to be: %q, got: %q", "PLAIN", method)
		}
		if !bytes.Equal([]byte(identity+"\x00"+user+"\x00"+pass), resp) {
			t.Errorf("expected response to be: %q, got: %q", identity+"\x00"+user+"\x00"+pass, resp)
		}
		_, err = auth.Next([]byte("nonsense"), true)
		if err == nil {
			t.Fatal("expected second server challange to fail")
		}
		if !errors.Is(err, ErrUnexpectedServerChallange) {
			t.Errorf("expected error to be: %s, got: %s", ErrUnexpectedServerChallange, err)
		}
	})
	t.Run("PLAIN-NOENC authentication on test server", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		auth := PlainAuth("", "user", "pass", TestServerAddr, true)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client connection: %s", err)
			}
		})
		if err = client.Auth(auth); err != nil {
			t.Errorf("failed to authenticate to test server: %s", err)
		}
	})
	t.Run("PLAIN-NOENC authentication on test server should fail", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnAuth: true,
				FeatureSet: featureSet,
				ListenPort: serverPort},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		auth := PlainAuth("", "user", "pass", TestServerAddr, true)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to connect to test server: %s", err)
		}
		if err = client.Auth(auth); err == nil {
			t.Errorf("expected authentication to fail")
		}
	})
}

func TestLoginAuth(t *testing.T) {
	tests := []struct {
		name       string
		authName   string
		server     *ServerInfo
		shouldFail bool
		wantErr    error
	}{
		{
			name:       "LOGIN auth succeeds",
			authName:   "servername",
			server:     &ServerInfo{Name: "servername", TLS: true},
			shouldFail: false,
		},
		{
			// OK to use PlainAuth on localhost without TLS
			name:       "LOGIN on localhost is allowed to go unencrypted",
			authName:   "localhost",
			server:     &ServerInfo{Name: "localhost", TLS: false},
			shouldFail: false,
		},
		{
			// NOT OK on non-localhost, even if server says LOGIN is OK.
			// (We don't know that the server is the real server.)
			name:       "LOGIN on non-localhost is not allowed to go unencrypted",
			authName:   "servername",
			server:     &ServerInfo{Name: "servername", Auth: []string{"LOGIN"}},
			shouldFail: true,
			wantErr:    ErrUnencrypted,
		},
		{
			name:       "LOGIN on non-localhost with no LOGIN announcement, is not allowed to go unencrypted",
			authName:   "servername",
			server:     &ServerInfo{Name: "servername", Auth: []string{"CRAM-MD5"}},
			shouldFail: true,
			wantErr:    ErrUnencrypted,
		},
		{
			name:       "LOGIN with wrong hostname",
			authName:   "servername",
			server:     &ServerInfo{Name: "attacker", TLS: true},
			shouldFail: true,
			wantErr:    ErrWrongHostname,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := "toni.tester@example.com"
			pass := "v3ryS3Cur3P4ssw0rd"
			auth := LoginAuth(user, pass, tt.authName, false)
			method, _, err := auth.Start(tt.server)
			if err != nil && !tt.shouldFail {
				t.Errorf("login authentication failed: %s", err)
			}
			if err == nil && tt.shouldFail {
				t.Error("login authentication was expected to fail")
			}
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error to be: %s, got: %s", tt.wantErr, err)
				}
				return
			}
			if method != "LOGIN" {
				t.Errorf("expected method return to be: %q, got: %q", "LOGIN", method)
			}
			resp, err := auth.Next([]byte(user), true)
			if err != nil {
				t.Errorf("failed on first server challange: %s", err)
			}
			if !bytes.Equal([]byte(user), resp) {
				t.Errorf("expected response to first challange to be: %q, got: %q", user, resp)
			}
			resp, err = auth.Next([]byte(pass), true)
			if err != nil {
				t.Errorf("failed on second server challange: %s", err)
			}
			if !bytes.Equal([]byte(pass), resp) {
				t.Errorf("expected response to second challange to be: %q, got: %q", pass, resp)
			}
			resp, err = auth.Next([]byte("nonsense"), true)
			if err == nil {
				t.Error("expected third server challange to fail, but didn't")
			}
			if !errors.Is(err, ErrUnexpectedServerResponse) {
				t.Errorf("expected error to be: %s, got: %s", ErrUnexpectedServerResponse, err)
			}
		})
	}
	t.Run("LOGIN authentication on test server", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH LOGIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		auth := LoginAuth("user", "pass", TestServerAddr, false)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client connection: %s", err)
			}
		})
		if err = client.Auth(auth); err != nil {
			t.Errorf("failed to authenticate to test server: %s", err)
		}
	})
	t.Run("LOGIN authentication on test server should fail", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH LOGIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnAuth: true,
				FeatureSet: featureSet,
				ListenPort: serverPort},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		auth := LoginAuth("user", "pass", TestServerAddr, false)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to connect to test server: %s", err)
		}
		if err = client.Auth(auth); err == nil {
			t.Errorf("expected authentication to fail")
		}
	})
}

func TestLoginAuth_noEnc(t *testing.T) {
	tests := []struct {
		name       string
		authName   string
		server     *ServerInfo
		shouldFail bool
		wantErr    error
	}{
		{
			name:       "LOGIN-NOENC auth succeeds",
			authName:   "servername",
			server:     &ServerInfo{Name: "servername", TLS: true},
			shouldFail: false,
		},
		{
			// OK to use PlainAuth on localhost without TLS
			name:       "LOGIN-NOENC on localhost is allowed to go unencrypted",
			authName:   "localhost",
			server:     &ServerInfo{Name: "localhost", TLS: false},
			shouldFail: false,
		},
		{
			// ALSO OK on non-localhost. This auth mode is specificly for that.
			name:       "LOGIN-NOENC on non-localhost is allowed to go unencrypted",
			authName:   "servername",
			server:     &ServerInfo{Name: "servername", Auth: []string{"LOGIN"}},
			shouldFail: false,
		},
		{
			name:       "LOGIN-NOENC on non-localhost with no LOGIN announcement, is not allowed to go unencrypted",
			authName:   "servername",
			server:     &ServerInfo{Name: "servername", Auth: []string{"CRAM-MD5"}},
			shouldFail: false,
		},
		{
			name:       "LOGIN-NOENC with wrong hostname",
			authName:   "servername",
			server:     &ServerInfo{Name: "attacker", TLS: true},
			shouldFail: true,
			wantErr:    ErrWrongHostname,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := "toni.tester@example.com"
			pass := "v3ryS3Cur3P4ssw0rd"
			auth := LoginAuth(user, pass, tt.authName, true)
			method, _, err := auth.Start(tt.server)
			if err != nil && !tt.shouldFail {
				t.Errorf("login authentication failed: %s", err)
			}
			if err == nil && tt.shouldFail {
				t.Error("login authentication was expected to fail")
			}
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("expected error to be: %s, got: %s", tt.wantErr, err)
				}
				return
			}
			if method != "LOGIN" {
				t.Errorf("expected method return to be: %q, got: %q", "LOGIN", method)
			}
			resp, err := auth.Next([]byte(user), true)
			if err != nil {
				t.Errorf("failed on first server challange: %s", err)
			}
			if !bytes.Equal([]byte(user), resp) {
				t.Errorf("expected response to first challange to be: %q, got: %q", user, resp)
			}
			resp, err = auth.Next([]byte(pass), true)
			if err != nil {
				t.Errorf("failed on second server challange: %s", err)
			}
			if !bytes.Equal([]byte(pass), resp) {
				t.Errorf("expected response to second challange to be: %q, got: %q", pass, resp)
			}
			resp, err = auth.Next([]byte("nonsense"), true)
			if err == nil {
				t.Error("expected third server challange to fail, but didn't")
			}
			if !errors.Is(err, ErrUnexpectedServerResponse) {
				t.Errorf("expected error to be: %s, got: %s", ErrUnexpectedServerResponse, err)
			}
		})
	}
	t.Run("LOGIN-NOENC authentication on test server", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH LOGIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		auth := LoginAuth("user", "pass", TestServerAddr, true)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client connection: %s", err)
			}
		})
		if err = client.Auth(auth); err != nil {
			t.Errorf("failed to authenticate to test server: %s", err)
		}
	})
	t.Run("LOGIN-NOENC authentication on test server should fail", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH LOGIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnAuth: true,
				FeatureSet: featureSet,
				ListenPort: serverPort},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		auth := LoginAuth("user", "pass", TestServerAddr, true)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to connect to test server: %s", err)
		}
		if err = client.Auth(auth); err == nil {
			t.Errorf("expected authentication to fail")
		}
	})
}

func TestXOAuth2Auth(t *testing.T) {
	t.Run("XOAuth2 authentication all steps", func(t *testing.T) {
		auth := XOAuth2Auth("user", "token")
		proto, toserver, err := auth.Start(&ServerInfo{Name: "servername", TLS: true})
		if err != nil {
			t.Fatalf("failed to start XOAuth2 authentication: %s", err)
		}
		if proto != "XOAUTH2" {
			t.Errorf("expected protocol to be XOAUTH2, got: %q", proto)
		}
		expected := []byte("user=user\x01auth=Bearer token\x01\x01")
		if !bytes.Equal(expected, toserver) {
			t.Errorf("expected server response to be: %q, got: %q", expected, toserver)
		}
		resp, err := auth.Next([]byte("nonsense"), true)
		if err != nil {
			t.Errorf("failed on first server challange: %s", err)
		}
		if !bytes.Equal([]byte(""), resp) {
			t.Errorf("expected server response to be empty, got: %q", resp)
		}
		resp, err = auth.Next([]byte("nonsense"), false)
		if err != nil {
			t.Errorf("failed on first server challange: %s", err)
		}
	})
	t.Run("XOAuth2 succeeds with faker", func(t *testing.T) {
		server := []string{
			"220 Fake server ready ESMTP",
			"250-fake.server",
			"250-AUTH XOAUTH2",
			"250 8BITMIME",
			"235 2.7.0 Accepted",
		}
		var wrote strings.Builder
		var fake faker
		fake.ReadWriter = struct {
			io.Reader
			io.Writer
		}{
			strings.NewReader(strings.Join(server, "\r\n")),
			&wrote,
		}
		client, err := NewClient(fake, "fake.host")
		if err != nil {
			t.Fatalf("failed to create client on faker server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client connection: %s", err)
			}
		})

		auth := XOAuth2Auth("user", "token")
		if err = client.Auth(auth); err != nil {
			t.Errorf("failed to authenticate to faker server: %s", err)
		}

		// the Next method returns a nil response. It must not be sent.
		// The client request must end with the authentication.
		if !strings.HasSuffix(wrote.String(), "AUTH XOAUTH2 dXNlcj11c2VyAWF1dGg9QmVhcmVyIHRva2VuAQE=\r\n") {
			t.Fatalf("got %q; want AUTH XOAUTH2 dXNlcj11c2VyAWF1dGg9QmVhcmVyIHRva2VuAQE=\r\n", wrote.String())
		}
	})
	t.Run("XOAuth2 fails with faker", func(t *testing.T) {
		serverResp := []string{
			"220 Fake server ready ESMTP",
			"250-fake.server",
			"250-AUTH XOAUTH2",
			"250 8BITMIME",
			"334 eyJzdGF0dXMiOiI0MDAiLCJzY2hlbWVzIjoiQmVhcmVyIiwic2NvcGUiOiJodHRwczovL21haWwuZ29vZ2xlLmNvbS8ifQ==",
			"535 5.7.8 Username and Password not accepted",
			"221 2.0.0 closing connection",
		}
		var wrote strings.Builder
		var fake faker
		fake.ReadWriter = struct {
			io.Reader
			io.Writer
		}{
			strings.NewReader(strings.Join(serverResp, "\r\n")),
			&wrote,
		}
		client, err := NewClient(fake, "fake.host")
		if err != nil {
			t.Fatalf("failed to create client on faker server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client connection: %s", err)
			}
		})

		auth := XOAuth2Auth("user", "token")
		if err = client.Auth(auth); err == nil {
			t.Errorf("expected authentication to fail")
		}
		resp := strings.Split(wrote.String(), "\r\n")
		if len(resp) != 5 {
			t.Fatalf("unexpected number of client requests got %d; want 5", len(resp))
		}
		if resp[1] != "AUTH XOAUTH2 dXNlcj11c2VyAWF1dGg9QmVhcmVyIHRva2VuAQE=" {
			t.Fatalf("got %q; want AUTH XOAUTH2 dXNlcj11c2VyAWF1dGg9QmVhcmVyIHRva2VuAQE=", resp[1])
		}
		// the Next method returns an empty response. It must be sent
		if resp[2] != "" {
			t.Fatalf("got %q; want empty response", resp[2])
		}
	})
	t.Run("XOAuth2 authentication on test server succeeds", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH XOAUTH2\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		auth := XOAuth2Auth("user", "token")
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client connection: %s", err)
			}
		})
		if err = client.Auth(auth); err != nil {
			t.Errorf("failed to authenticate to test server: %s", err)
		}
	})
	t.Run("XOAuth2 authentication on test server fails", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH XOAUTH2\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnAuth: true,
				FeatureSet: featureSet,
				ListenPort: serverPort},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		auth := XOAuth2Auth("user", "token")
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to connect to test server: %s", err)
		}
		if err = client.Auth(auth); err == nil {
			t.Errorf("expected authentication to fail")
		}
	})
}

func TestScramAuth(t *testing.T) {
	tests := []struct {
		name       string
		tls        bool
		authString string
		hash       func() hash.Hash
		isPlus     bool
	}{
		{"SCRAM-SHA-1 (no TLS)", false, "SCRAM-SHA-1", sha1.New, false},
		{"SCRAM-SHA-256 (no TLS)", false, "SCRAM-SHA-256", sha256.New, false},
		{"SCRAM-SHA-1 (with TLS)", true, "SCRAM-SHA-1", sha1.New, false},
		{"SCRAM-SHA-256 (with TLS)", true, "SCRAM-SHA-256", sha256.New, false},
		{"SCRAM-SHA-1-PLUS", true, "SCRAM-SHA-1-PLUS", sha1.New, true},
		{"SCRAM-SHA-256-PLUS", true, "SCRAM-SHA-256-PLUS", sha256.New, true},
	}
	for _, tt := range tests {
		t.Run(tt.name+" succeeds on test server", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			PortAdder.Add(1)
			serverPort := int(TestServerPortBase + PortAdder.Load())
			featureSet := fmt.Sprintf("250-AUTH %s\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8", tt.authString)
			go func() {
				if err := simpleSMTPServer(ctx, t, &serverProps{
					TestSCRAM:   true,
					HashFunc:    tt.hash,
					FeatureSet:  featureSet,
					ListenPort:  serverPort,
					SSLListener: tt.tls,
					IsSCRAMPlus: tt.isPlus,
				},
				); err != nil {
					t.Errorf("failed to start test server: %s", err)
					return
				}
			}()
			time.Sleep(time.Millisecond * 30)

			var client *Client
			switch tt.tls {
			case true:
				cert, err := tls.X509KeyPair(localhostCert, localhostKey)
				if err != nil {
					fmt.Printf("error creating TLS cert: %s", err)
					return
				}
				tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
				conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", TestServerAddr, serverPort), &tlsConfig)
				if err != nil {
					t.Fatalf("failed to dial TLS server: %v", err)
				}
				client, err = NewClient(conn, TestServerAddr)
			case false:
				var err error
				client, err = Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
				if err != nil {
					t.Fatalf("failed to connect to test server: %s", err)
				}
			}
			t.Cleanup(func() {
				if err := client.Close(); err != nil {
					t.Errorf("failed to close client connection: %s", err)
				}
			})

			var auth Auth
			switch tt.authString {
			case "SCRAM-SHA-1":
				auth = ScramSHA1Auth("username", "password")
			case "SCRAM-SHA-256":
				auth = ScramSHA256Auth("username", "password")
			case "SCRAM-SHA-1-PLUS":
				tlsConnState, err := client.GetTLSConnectionState()
				if err != nil {
					t.Fatalf("failed to get TLS connection state: %s", err)
				}
				auth = ScramSHA1PlusAuth("username", "password", tlsConnState)
			case "SCRAM-SHA-256-PLUS":
				tlsConnState, err := client.GetTLSConnectionState()
				if err != nil {
					t.Fatalf("failed to get TLS connection state: %s", err)
				}
				auth = ScramSHA256PlusAuth("username", "password", tlsConnState)
			default:
				t.Fatalf("unexpected auth string: %s", tt.authString)
			}
			if err := client.Auth(auth); err != nil {
				t.Errorf("failed to authenticate to test server: %s", err)
			}
		})
		t.Run(tt.name+" fails on test server", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			PortAdder.Add(1)
			serverPort := int(TestServerPortBase + PortAdder.Load())
			featureSet := fmt.Sprintf("250-AUTH %s\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8", tt.authString)
			go func() {
				if err := simpleSMTPServer(ctx, t, &serverProps{
					TestSCRAM:   true,
					HashFunc:    tt.hash,
					FeatureSet:  featureSet,
					ListenPort:  serverPort,
					SSLListener: tt.tls,
					IsSCRAMPlus: tt.isPlus,
				},
				); err != nil {
					t.Errorf("failed to start test server: %s", err)
					return
				}
			}()
			time.Sleep(time.Millisecond * 30)

			var client *Client
			switch tt.tls {
			case true:
				cert, err := tls.X509KeyPair(localhostCert, localhostKey)
				if err != nil {
					fmt.Printf("error creating TLS cert: %s", err)
					return
				}
				tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
				conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", TestServerAddr, serverPort), &tlsConfig)
				if err != nil {
					t.Fatalf("failed to dial TLS server: %v", err)
				}
				client, err = NewClient(conn, TestServerAddr)
			case false:
				var err error
				client, err = Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
				if err != nil {
					t.Fatalf("failed to connect to test server: %s", err)
				}
			}

			var auth Auth
			switch tt.authString {
			case "SCRAM-SHA-1":
				auth = ScramSHA1Auth("invalid", "password")
			case "SCRAM-SHA-256":
				auth = ScramSHA256Auth("invalid", "password")
			case "SCRAM-SHA-1-PLUS":
				tlsConnState, err := client.GetTLSConnectionState()
				if err != nil {
					t.Fatalf("failed to get TLS connection state: %s", err)
				}
				auth = ScramSHA1PlusAuth("invalid", "password", tlsConnState)
			case "SCRAM-SHA-256-PLUS":
				tlsConnState, err := client.GetTLSConnectionState()
				if err != nil {
					t.Fatalf("failed to get TLS connection state: %s", err)
				}
				auth = ScramSHA256PlusAuth("invalid", "password", tlsConnState)
			default:
				t.Fatalf("unexpected auth string: %s", tt.authString)
			}
			if err := client.Auth(auth); err == nil {
				t.Error("expected authentication to fail")
			}
		})
	}
	t.Run("ScramAuth_Next with nonsense parameter", func(t *testing.T) {
		auth := ScramSHA1Auth("username", "password")
		_, err := auth.Next([]byte("x=nonsense"), true)
		if err == nil {
			t.Fatal("expected authentication to fail")
		}
		if !errors.Is(err, ErrUnexpectedServerResponse) {
			t.Errorf("expected ErrUnexpectedServerResponse, got %s", err)
		}
	})
}

/*






func TestAuthSCRAMSHA1_OK(t *testing.T) {
	hostname := "127.0.0.1"
	port := "2585"

	go func() {
		startSMTPServer(false, hostname, port, sha1.New)
	}()
	time.Sleep(time.Millisecond * 500)

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", hostname, port))
	if err != nil {
		t.Errorf("failed to dial server: %v", err)
	}
	client, err := NewClient(conn, hostname)
	if err != nil {
		t.Errorf("failed to create client: %v", err)
	}
	if err = client.Hello(hostname); err != nil {
		t.Errorf("failed to send HELO: %v", err)
	}
	if err = client.Auth(ScramSHA1Auth("username", "password")); err != nil {
		t.Errorf("failed to authenticate: %v", err)
	}
}

func TestAuthSCRAMSHA256_OK(t *testing.T) {
	hostname := "127.0.0.1"
	port := "2586"

	go func() {
		startSMTPServer(false, hostname, port, sha256.New)
	}()
	time.Sleep(time.Millisecond * 500)

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", hostname, port))
	if err != nil {
		t.Errorf("failed to dial server: %v", err)
	}
	client, err := NewClient(conn, hostname)
	if err != nil {
		t.Errorf("failed to create client: %v", err)
	}
	if err = client.Hello(hostname); err != nil {
		t.Errorf("failed to send HELO: %v", err)
	}
	if err = client.Auth(ScramSHA256Auth("username", "password")); err != nil {
		t.Errorf("failed to authenticate: %v", err)
	}
}

func TestAuthSCRAMSHA1PLUS_OK(t *testing.T) {
	hostname := "127.0.0.1"
	port := "2590"

	go func() {
		startSMTPServer(true, hostname, port, sha1.New)
	}()
	time.Sleep(time.Millisecond * 500)

	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		fmt.Printf("error creating TLS cert: %s", err)
		return
	}
	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%s", hostname, port), &tlsConfig)
	if err != nil {
		t.Errorf("failed to dial server: %v", err)
	}
	client, err := NewClient(conn, hostname)
	if err != nil {
		t.Errorf("failed to create client: %v", err)
	}
	if err = client.Hello(hostname); err != nil {
		t.Errorf("failed to send HELO: %v", err)
	}

	tlsConnState := conn.ConnectionState()
	if err = client.Auth(ScramSHA1PlusAuth("username", "password", &tlsConnState)); err != nil {
		t.Errorf("failed to authenticate: %v", err)
	}
}

func TestAuthSCRAMSHA256PLUS_OK(t *testing.T) {
	hostname := "127.0.0.1"
	port := "2591"

	go func() {
		startSMTPServer(true, hostname, port, sha256.New)
	}()
	time.Sleep(time.Millisecond * 500)

	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		fmt.Printf("error creating TLS cert: %s", err)
		return
	}
	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%s", hostname, port), &tlsConfig)
	if err != nil {
		t.Errorf("failed to dial server: %v", err)
	}
	client, err := NewClient(conn, hostname)
	if err != nil {
		t.Errorf("failed to create client: %v", err)
	}
	if err = client.Hello(hostname); err != nil {
		t.Errorf("failed to send HELO: %v", err)
	}

	tlsConnState := conn.ConnectionState()
	if err = client.Auth(ScramSHA256PlusAuth("username", "password", &tlsConnState)); err != nil {
		t.Errorf("failed to authenticate: %v", err)
	}
}

func TestAuthSCRAMSHA1_fail(t *testing.T) {
	hostname := "127.0.0.1"
	port := "2587"

	go func() {
		startSMTPServer(false, hostname, port, sha1.New)
	}()
	time.Sleep(time.Millisecond * 500)

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", hostname, port))
	if err != nil {
		t.Errorf("failed to dial server: %v", err)
	}
	client, err := NewClient(conn, hostname)
	if err != nil {
		t.Errorf("failed to create client: %v", err)
	}
	if err = client.Hello(hostname); err != nil {
		t.Errorf("failed to send HELO: %v", err)
	}
	if err = client.Auth(ScramSHA1Auth("username", "invalid")); err == nil {
		t.Errorf("expected auth error, got nil")
	}
}

func TestAuthSCRAMSHA256_fail(t *testing.T) {
	hostname := "127.0.0.1"
	port := "2588"

	go func() {
		startSMTPServer(false, hostname, port, sha256.New)
	}()
	time.Sleep(time.Millisecond * 500)

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", hostname, port))
	if err != nil {
		t.Errorf("failed to dial server: %v", err)
	}
	client, err := NewClient(conn, hostname)
	if err != nil {
		t.Errorf("failed to create client: %v", err)
	}
	if err = client.Hello(hostname); err != nil {
		t.Errorf("failed to send HELO: %v", err)
	}
	if err = client.Auth(ScramSHA256Auth("username", "invalid")); err == nil {
		t.Errorf("expected auth error, got nil")
	}
}

func TestAuthSCRAMSHA1PLUS_fail(t *testing.T) {
	hostname := "127.0.0.1"
	port := "2592"

	go func() {
		startSMTPServer(true, hostname, port, sha1.New)
	}()
	time.Sleep(time.Millisecond * 500)

	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		fmt.Printf("error creating TLS cert: %s", err)
		return
	}
	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%s", hostname, port), &tlsConfig)
	if err != nil {
		t.Errorf("failed to dial server: %v", err)
	}
	client, err := NewClient(conn, hostname)
	if err != nil {
		t.Errorf("failed to create client: %v", err)
	}
	if err = client.Hello(hostname); err != nil {
		t.Errorf("failed to send HELO: %v", err)
	}
	tlsConnState := conn.ConnectionState()
	if err = client.Auth(ScramSHA1PlusAuth("username", "invalid", &tlsConnState)); err == nil {
		t.Errorf("expected auth error, got nil")
	}
}

func TestAuthSCRAMSHA256PLUS_fail(t *testing.T) {
	hostname := "127.0.0.1"
	port := "2593"

	go func() {
		startSMTPServer(true, hostname, port, sha1.New)
	}()
	time.Sleep(time.Millisecond * 500)

	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		fmt.Printf("error creating TLS cert: %s", err)
		return
	}
	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%s", hostname, port), &tlsConfig)
	if err != nil {
		t.Errorf("failed to dial server: %v", err)
	}
	client, err := NewClient(conn, hostname)
	if err != nil {
		t.Errorf("failed to create client: %v", err)
	}
	if err = client.Hello(hostname); err != nil {
		t.Errorf("failed to send HELO: %v", err)
	}
	tlsConnState := conn.ConnectionState()
	if err = client.Auth(ScramSHA256PlusAuth("username", "invalid", &tlsConnState)); err == nil {
		t.Errorf("expected auth error, got nil")
	}
}

// Issue 17794: don't send a trailing space on AUTH command when there's no password.
func TestClientAuthTrimSpace(t *testing.T) {
	server := "220 hello world\r\n" +
		"200 some more"
	var wrote strings.Builder
	var fake faker
	fake.ReadWriter = struct {
		io.Reader
		io.Writer
	}{
		strings.NewReader(server),
		&wrote,
	}
	c, err := NewClient(fake, "fake.host")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	c.tls = true
	c.didHello = true
	_ = c.Auth(toServerEmptyAuth{})
	if err := c.Close(); err != nil {
		t.Errorf("close failed: %s", err)
	}
	if got, want := wrote.String(), "AUTH FOOAUTH\r\n*\r\nQUIT\r\n"; got != want {
		t.Errorf("wrote %q; want %q", got, want)
	}
}

// toServerEmptyAuth is an implementation of Auth that only implements
// the Start method, and returns "FOOAUTH", nil, nil. Notably, it returns
// zero bytes for "toServer" so we can test that we don't send spaces at
// the end of the line. See TestClientAuthTrimSpace.
type toServerEmptyAuth struct{}

func (toServerEmptyAuth) Start(_ *ServerInfo) (proto string, toServer []byte, err error) {
	return "FOOAUTH", nil, nil
}

func (toServerEmptyAuth) Next(_ []byte, _ bool) (toServer []byte, err error) {
	panic("unexpected call")
}

func TestBasic(t *testing.T) {
	server := strings.Join(strings.Split(basicServer, "\n"), "\r\n")
	client := strings.Join(strings.Split(basicClient, "\n"), "\r\n")

	var cmdbuf strings.Builder
	bcmdbuf := bufio.NewWriter(&cmdbuf)
	var fake faker
	fake.ReadWriter = bufio.NewReadWriter(bufio.NewReader(strings.NewReader(server)), bcmdbuf)
	c := &Client{Text: textproto.NewConn(fake), localName: "localhost"}

	if err := c.helo(); err != nil {
		t.Fatalf("HELO failed: %s", err)
	}
	if err := c.ehlo(); err == nil {
		t.Fatalf("Expected first EHLO to fail")
	}
	if err := c.ehlo(); err != nil {
		t.Fatalf("Second EHLO failed: %s", err)
	}

	c.didHello = true
	if ok, args := c.Extension("aUtH"); !ok || args != "LOGIN PLAIN" {
		t.Fatalf("Expected AUTH supported")
	}
	if ok, _ := c.Extension("DSN"); ok {
		t.Fatalf("Shouldn't support DSN")
	}

	if err := c.Mail("user@gmail.com"); err == nil {
		t.Fatalf("MAIL should require authentication")
	}

	if err := c.Verify("user1@gmail.com"); err == nil {
		t.Fatalf("First VRFY: expected no verification")
	}
	if err := c.Verify("user2@gmail.com>\r\nDATA\r\nAnother injected message body\r\n.\r\nQUIT\r\n"); err == nil {
		t.Fatalf("VRFY should have failed due to a message injection attempt")
	}
	if err := c.Verify("user2@gmail.com"); err != nil {
		t.Fatalf("Second VRFY: expected verification, got %s", err)
	}

	// fake TLS so authentication won't complain
	c.tls = true
	c.serverName = "smtp.google.com"
	if err := c.Auth(PlainAuth("", "user", "pass", "smtp.google.com", false)); err != nil {
		t.Fatalf("AUTH failed: %s", err)
	}

	if err := c.Rcpt("golang-nuts@googlegroups.com>\r\nDATA\r\nInjected message body\r\n.\r\nQUIT\r\n"); err == nil {
		t.Fatalf("RCPT should have failed due to a message injection attempt")
	}
	if err := c.Mail("user@gmail.com>\r\nDATA\r\nAnother injected message body\r\n.\r\nQUIT\r\n"); err == nil {
		t.Fatalf("MAIL should have failed due to a message injection attempt")
	}
	if err := c.Mail("user@gmail.com"); err != nil {
		t.Fatalf("MAIL failed: %s", err)
	}
	if err := c.Rcpt("golang-nuts@googlegroups.com"); err != nil {
		t.Fatalf("RCPT failed: %s", err)
	}
	msg := `From: user@gmail.com
To: golang-nuts@googlegroups.com
Subject: Hooray for Go

Line 1
.Leading dot line .
Goodbye.`
	w, err := c.Data()
	if err != nil {
		t.Fatalf("DATA failed: %s", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		t.Fatalf("Data write failed: %s", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Bad data response: %s", err)
	}

	if err := c.Quit(); err != nil {
		t.Fatalf("QUIT failed: %s", err)
	}

	if err := bcmdbuf.Flush(); err != nil {
		t.Errorf("flush failed: %s", err)
	}
	actualcmds := cmdbuf.String()
	if client != actualcmds {
		t.Fatalf("Got:\n%s\nExpected:\n%s", actualcmds, client)
	}
}

var basicServer = `250 mx.google.com at your service
502 Unrecognized command.
250-mx.google.com at your service
250-SIZE 35651584
250-AUTH LOGIN PLAIN
250 8BITMIME
530 Authentication required
252 Send some mail, I'll try my best
250 User is valid
235 Accepted
250 Sender OK
250 Receiver OK
354 Go ahead
250 Data OK
221 OK
`

var basicClient = `HELO localhost
EHLO localhost
EHLO localhost
MAIL FROM:<user@gmail.com> BODY=8BITMIME
VRFY user1@gmail.com
VRFY user2@gmail.com
AUTH PLAIN AHVzZXIAcGFzcw==
MAIL FROM:<user@gmail.com> BODY=8BITMIME
RCPT TO:<golang-nuts@googlegroups.com>
DATA
From: user@gmail.com
To: golang-nuts@googlegroups.com
Subject: Hooray for Go

Line 1
..Leading dot line .
Goodbye.
.
QUIT
`

func TestHELOFailed(t *testing.T) {
	serverLines := `502 EH?
502 EH?
221 OK
`
	clientLines := `EHLO localhost
HELO localhost
QUIT
`
	server := strings.Join(strings.Split(serverLines, "\n"), "\r\n")
	client := strings.Join(strings.Split(clientLines, "\n"), "\r\n")
	var cmdbuf strings.Builder
	bcmdbuf := bufio.NewWriter(&cmdbuf)
	var fake faker
	fake.ReadWriter = bufio.NewReadWriter(bufio.NewReader(strings.NewReader(server)), bcmdbuf)
	c := &Client{Text: textproto.NewConn(fake), localName: "localhost"}
	if err := c.Hello("localhost"); err == nil {
		t.Fatal("expected EHLO to fail")
	}
	if err := c.Quit(); err != nil {
		t.Errorf("QUIT failed: %s", err)
	}
	_ = bcmdbuf.Flush()
	actual := cmdbuf.String()
	if client != actual {
		t.Errorf("Got:\n%s\nWant:\n%s", actual, client)
	}
}

func TestExtensions(t *testing.T) {
	fake := func(server string) (c *Client, bcmdbuf *bufio.Writer, cmdbuf *strings.Builder) {
		server = strings.Join(strings.Split(server, "\n"), "\r\n")

		cmdbuf = &strings.Builder{}
		bcmdbuf = bufio.NewWriter(cmdbuf)
		var fake faker
		fake.ReadWriter = bufio.NewReadWriter(bufio.NewReader(strings.NewReader(server)), bcmdbuf)
		c = &Client{Text: textproto.NewConn(fake), localName: "localhost"}

		return c, bcmdbuf, cmdbuf
	}

	t.Run("helo", func(t *testing.T) {
		const (
			basicServer = `250 mx.google.com at your service
250 Sender OK
221 Goodbye
`

			basicClient = `HELO localhost
MAIL FROM:<user@gmail.com>
QUIT
`
		)

		c, bcmdbuf, cmdbuf := fake(basicServer)

		if err := c.helo(); err != nil {
			t.Fatalf("HELO failed: %s", err)
		}
		c.didHello = true
		if err := c.Mail("user@gmail.com"); err != nil {
			t.Fatalf("MAIL FROM failed: %s", err)
		}
		if err := c.Quit(); err != nil {
			t.Fatalf("QUIT failed: %s", err)
		}

		if err := bcmdbuf.Flush(); err != nil {
			t.Errorf("flush failed: %s", err)
		}
		actualcmds := cmdbuf.String()
		client := strings.Join(strings.Split(basicClient, "\n"), "\r\n")
		if client != actualcmds {
			t.Fatalf("Got:\n%s\nExpected:\n%s", actualcmds, client)
		}
	})

	t.Run("ehlo", func(t *testing.T) {
		const (
			basicServer = `250-mx.google.com at your service
250 SIZE 35651584
250 Sender OK
221 Goodbye
`

			basicClient = `EHLO localhost
MAIL FROM:<user@gmail.com>
QUIT
`
		)

		c, bcmdbuf, cmdbuf := fake(basicServer)

		if err := c.Hello("localhost"); err != nil {
			t.Fatalf("EHLO failed: %s", err)
		}
		if ok, _ := c.Extension("8BITMIME"); ok {
			t.Fatalf("Shouldn't support 8BITMIME")
		}
		if ok, _ := c.Extension("SMTPUTF8"); ok {
			t.Fatalf("Shouldn't support SMTPUTF8")
		}
		if err := c.Mail("user@gmail.com"); err != nil {
			t.Fatalf("MAIL FROM failed: %s", err)
		}
		if err := c.Quit(); err != nil {
			t.Fatalf("QUIT failed: %s", err)
		}

		if err := bcmdbuf.Flush(); err != nil {
			t.Errorf("flush failed: %s", err)
		}
		actualcmds := cmdbuf.String()
		client := strings.Join(strings.Split(basicClient, "\n"), "\r\n")
		if client != actualcmds {
			t.Fatalf("Got:\n%s\nExpected:\n%s", actualcmds, client)
		}
	})

	t.Run("ehlo 8bitmime", func(t *testing.T) {
		const (
			basicServer = `250-mx.google.com at your service
250-SIZE 35651584
250 8BITMIME
250 Sender OK
221 Goodbye
`

			basicClient = `EHLO localhost
MAIL FROM:<user@gmail.com> BODY=8BITMIME
QUIT
`
		)

		c, bcmdbuf, cmdbuf := fake(basicServer)

		if err := c.Hello("localhost"); err != nil {
			t.Fatalf("EHLO failed: %s", err)
		}
		if ok, _ := c.Extension("8BITMIME"); !ok {
			t.Fatalf("Should support 8BITMIME")
		}
		if ok, _ := c.Extension("SMTPUTF8"); ok {
			t.Fatalf("Shouldn't support SMTPUTF8")
		}
		if err := c.Mail("user@gmail.com"); err != nil {
			t.Fatalf("MAIL FROM failed: %s", err)
		}
		if err := c.Quit(); err != nil {
			t.Fatalf("QUIT failed: %s", err)
		}

		if err := bcmdbuf.Flush(); err != nil {
			t.Errorf("failed to flush: %s", err)
		}
		actualcmds := cmdbuf.String()
		client := strings.Join(strings.Split(basicClient, "\n"), "\r\n")
		if client != actualcmds {
			t.Fatalf("Got:\n%s\nExpected:\n%s", actualcmds, client)
		}
	})

	t.Run("ehlo smtputf8", func(t *testing.T) {
		const (
			basicServer = `250-mx.google.com at your service
250-SIZE 35651584
250 SMTPUTF8
250 Sender OK
221 Goodbye
`

			basicClient = `EHLO localhost
MAIL FROM:<user+📧@gmail.com> SMTPUTF8
QUIT
`
		)

		c, bcmdbuf, cmdbuf := fake(basicServer)

		if err := c.Hello("localhost"); err != nil {
			t.Fatalf("EHLO failed: %s", err)
		}
		if ok, _ := c.Extension("8BITMIME"); ok {
			t.Fatalf("Shouldn't support 8BITMIME")
		}
		if ok, _ := c.Extension("SMTPUTF8"); !ok {
			t.Fatalf("Should support SMTPUTF8")
		}
		if err := c.Mail("user+📧@gmail.com"); err != nil {
			t.Fatalf("MAIL FROM failed: %s", err)
		}
		if err := c.Quit(); err != nil {
			t.Fatalf("QUIT failed: %s", err)
		}

		if err := bcmdbuf.Flush(); err != nil {
			t.Errorf("failed to flush: %s", err)
		}
		actualcmds := cmdbuf.String()
		client := strings.Join(strings.Split(basicClient, "\n"), "\r\n")
		if client != actualcmds {
			t.Fatalf("Got:\n%s\nExpected:\n%s", actualcmds, client)
		}
	})

	t.Run("ehlo 8bitmime smtputf8", func(t *testing.T) {
		const (
			basicServer = `250-mx.google.com at your service
250-SIZE 35651584
250-8BITMIME
250 SMTPUTF8
250 Sender OK
221 Goodbye
	`

			basicClient = `EHLO localhost
MAIL FROM:<user+📧@gmail.com> BODY=8BITMIME SMTPUTF8
QUIT
`
		)

		c, bcmdbuf, cmdbuf := fake(basicServer)

		if err := c.Hello("localhost"); err != nil {
			t.Fatalf("EHLO failed: %s", err)
		}
		c.didHello = true
		if ok, _ := c.Extension("8BITMIME"); !ok {
			t.Fatalf("Should support 8BITMIME")
		}
		if ok, _ := c.Extension("SMTPUTF8"); !ok {
			t.Fatalf("Should support SMTPUTF8")
		}
		if err := c.Mail("user+📧@gmail.com"); err != nil {
			t.Fatalf("MAIL FROM failed: %s", err)
		}
		if err := c.Quit(); err != nil {
			t.Fatalf("QUIT failed: %s", err)
		}

		if err := bcmdbuf.Flush(); err != nil {
			t.Errorf("failed to flush: %s", err)
		}
		actualcmds := cmdbuf.String()
		client := strings.Join(strings.Split(basicClient, "\n"), "\r\n")
		if client != actualcmds {
			t.Fatalf("Got:\n%s\nExpected:\n%s", actualcmds, client)
		}
	})
}

func TestNewClient(t *testing.T) {
	server := strings.Join(strings.Split(newClientServer, "\n"), "\r\n")
	client := strings.Join(strings.Split(newClientClient, "\n"), "\r\n")

	var cmdbuf strings.Builder
	bcmdbuf := bufio.NewWriter(&cmdbuf)
	out := func() string {
		if err := bcmdbuf.Flush(); err != nil {
			t.Errorf("failed to flush: %s", err)
		}
		return cmdbuf.String()
	}
	var fake faker
	fake.ReadWriter = bufio.NewReadWriter(bufio.NewReader(strings.NewReader(server)), bcmdbuf)
	c, err := NewClient(fake, "fake.host")
	if err != nil {
		t.Fatalf("NewClient: %v\n(after %v)", err, out())
	}
	defer func() {
		_ = c.Close()
	}()
	if ok, args := c.Extension("aUtH"); !ok || args != "LOGIN PLAIN" {
		t.Fatalf("Expected AUTH supported")
	}
	if ok, _ := c.Extension("DSN"); ok {
		t.Fatalf("Shouldn't support DSN")
	}
	if err := c.Quit(); err != nil {
		t.Fatalf("QUIT failed: %s", err)
	}

	actualcmds := out()
	if client != actualcmds {
		t.Fatalf("Got:\n%s\nExpected:\n%s", actualcmds, client)
	}
}

// TestClient_SetDebugLog tests the Client method with the Client.SetDebugLog method
// to enable debug logging
func TestClient_SetDebugLog(t *testing.T) {
	server := strings.Join(strings.Split(newClientServer, "\n"), "\r\n")

	var cmdbuf strings.Builder
	bcmdbuf := bufio.NewWriter(&cmdbuf)
	out := func() string {
		if err := bcmdbuf.Flush(); err != nil {
			t.Errorf("failed to flush: %s", err)
		}
		return cmdbuf.String()
	}
	var fake faker
	fake.ReadWriter = bufio.NewReadWriter(bufio.NewReader(strings.NewReader(server)), bcmdbuf)
	c, err := NewClient(fake, "fake.host")
	if err != nil {
		t.Fatalf("NewClient: %v\n(after %v)", err, out())
	}
	defer func() {
		_ = c.Close()
	}()
	c.SetDebugLog(true)
	if !c.debug {
		t.Errorf("Expected DebugLog flag to be true but received false")
	}
}

// TestClient_SetLogger tests the Client method with the Client.SetLogger method
// to provide a custom logger
func TestClient_SetLogger(t *testing.T) {
	server := strings.Join(strings.Split(newClientServer, "\n"), "\r\n")

	var cmdbuf strings.Builder
	bcmdbuf := bufio.NewWriter(&cmdbuf)
	out := func() string {
		if err := bcmdbuf.Flush(); err != nil {
			t.Errorf("failed to flush: %s", err)
		}
		return cmdbuf.String()
	}
	var fake faker
	fake.ReadWriter = bufio.NewReadWriter(bufio.NewReader(strings.NewReader(server)), bcmdbuf)
	c, err := NewClient(fake, "fake.host")
	if err != nil {
		t.Fatalf("NewClient: %v\n(after %v)", err, out())
	}
	defer func() {
		_ = c.Close()
	}()
	c.SetLogger(log.New(os.Stderr, log.LevelDebug))
	if c.logger == nil {
		t.Errorf("Expected Logger to be set but received nil")
	}
	c.logger.Debugf(log.Log{Direction: log.DirServerToClient, Format: "%s", Messages: []interface{}{"test"}})
	c.SetLogger(nil)
	c.logger.Debugf(log.Log{Direction: log.DirServerToClient, Format: "%s", Messages: []interface{}{"test"}})
}

func TestClient_SetLogAuthData(t *testing.T) {
	server := strings.Join(strings.Split(newClientServer, "\n"), "\r\n")

	var cmdbuf strings.Builder
	bcmdbuf := bufio.NewWriter(&cmdbuf)
	out := func() string {
		if err := bcmdbuf.Flush(); err != nil {
			t.Errorf("failed to flush: %s", err)
		}
		return cmdbuf.String()
	}
	var fake faker
	fake.ReadWriter = bufio.NewReadWriter(bufio.NewReader(strings.NewReader(server)), bcmdbuf)
	c, err := NewClient(fake, "fake.host")
	if err != nil {
		t.Fatalf("NewClient: %v\n(after %v)", err, out())
	}
	defer func() {
		_ = c.Close()
	}()
	c.SetLogAuthData()
	if !c.logAuthData {
		t.Error("Expected logAuthData to be true but received false")
	}
}

var newClientServer = `220 hello world
250-mx.google.com at your service
250-SIZE 35651584
250-AUTH LOGIN PLAIN
250 8BITMIME
221 OK
`

var newClientClient = `EHLO localhost
QUIT
`

func TestNewClient2(t *testing.T) {
	server := strings.Join(strings.Split(newClient2Server, "\n"), "\r\n")
	client := strings.Join(strings.Split(newClient2Client, "\n"), "\r\n")

	var cmdbuf strings.Builder
	bcmdbuf := bufio.NewWriter(&cmdbuf)
	var fake faker
	fake.ReadWriter = bufio.NewReadWriter(bufio.NewReader(strings.NewReader(server)), bcmdbuf)
	c, err := NewClient(fake, "fake.host")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() {
		_ = c.Close()
	}()
	if ok, _ := c.Extension("DSN"); ok {
		t.Fatalf("Shouldn't support DSN")
	}
	if err := c.Quit(); err != nil {
		t.Fatalf("QUIT failed: %s", err)
	}

	if err := bcmdbuf.Flush(); err != nil {
		t.Errorf("flush failed: %s", err)
	}
	actualcmds := cmdbuf.String()
	if client != actualcmds {
		t.Fatalf("Got:\n%s\nExpected:\n%s", actualcmds, client)
	}
}

var newClient2Server = `220 hello world
502 EH?
250-mx.google.com at your service
250-SIZE 35651584
250-AUTH LOGIN PLAIN
250 8BITMIME
221 OK
`

var newClient2Client = `EHLO localhost
HELO localhost
QUIT
`

func TestNewClientWithTLS(t *testing.T) {
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatalf("loadcert: %v", err)
	}

	config := tls.Config{Certificates: []tls.Certificate{cert}}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &config)
	if err != nil {
		ln, err = tls.Listen("tcp", "[::1]:0", &config)
		if err != nil {
			t.Fatalf("server: listen: %v", err)
		}
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			t.Errorf("server: accept: %v", err)
			return
		}
		defer func() {
			_ = conn.Close()
		}()

		_, err = conn.Write([]byte("220 SIGNS\r\n"))
		if err != nil {
			t.Errorf("server: write: %v", err)
			return
		}
	}()

	config.InsecureSkipVerify = true
	conn, err := tls.Dial("tcp", ln.Addr().String(), &config)
	if err != nil {
		t.Fatalf("client: dial: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	client, err := NewClient(conn, ln.Addr().String())
	if err != nil {
		t.Fatalf("smtp: newclient: %v", err)
	}
	if !client.tls {
		t.Errorf("client.tls Got: %t Expected: %t", client.tls, true)
	}
}

func TestHello(t *testing.T) {
	if len(helloServer) != len(helloClient) {
		t.Fatalf("Hello server and client size mismatch")
	}

	tf := func(fake faker, i int) error {
		c, err := NewClient(fake, "fake.host")
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		defer func() {
			_ = c.Close()
		}()
		c.localName = "customhost"
		err = nil

		switch i {
		case 0:
			err = c.Hello("hostinjection>\n\rDATA\r\nInjected message body\r\n.\r\nQUIT\r\n")
			if err == nil {
				t.Errorf("Expected Hello to be rejected due to a message injection attempt")
			}
			err = c.Hello("customhost")
		case 1:
			err = c.StartTLS(nil)
			if err.Error() == "502 Not implemented" {
				err = nil
			}
		case 2:
			err = c.Verify("test@example.com")
		case 3:
			c.tls = true
			c.serverName = "smtp.google.com"
			err = c.Auth(PlainAuth("", "user", "pass", "smtp.google.com", false))
		case 4:
			err = c.Mail("test@example.com")
		case 5:
			ok, _ := c.Extension("feature")
			if ok {
				t.Errorf("Expected FEATURE not to be supported")
			}
		case 6:
			err = c.Reset()
		case 7:
			err = c.Quit()
		case 8:
			err = c.Verify("test@example.com")
			if err != nil {
				err = c.Hello("customhost")
				if err != nil {
					t.Errorf("Want error, got none")
				}
			}
		case 9:
			err = c.Noop()
		default:
			t.Fatalf("Unhandled command")
		}

		if err != nil {
			t.Errorf("Command %d failed: %v", i, err)
		}
		return nil
	}

	for i := 0; i < len(helloServer); i++ {
		server := strings.Join(strings.Split(baseHelloServer+helloServer[i], "\n"), "\r\n")
		client := strings.Join(strings.Split(baseHelloClient+helloClient[i], "\n"), "\r\n")
		var cmdbuf strings.Builder
		bcmdbuf := bufio.NewWriter(&cmdbuf)
		var fake faker
		fake.ReadWriter = bufio.NewReadWriter(bufio.NewReader(strings.NewReader(server)), bcmdbuf)

		if err := tf(fake, i); err != nil {
			t.Error(err)
		}

		if err := bcmdbuf.Flush(); err != nil {
			t.Errorf("flush failed: %s", err)
		}
		actualcmds := cmdbuf.String()
		if client != actualcmds {
			t.Errorf("Got:\n%s\nExpected:\n%s", actualcmds, client)
		}
	}
}

var baseHelloServer = `220 hello world
502 EH?
250-mx.google.com at your service
250 FEATURE
`

var helloServer = []string{
	"",
	"502 Not implemented\n",
	"250 User is valid\n",
	"235 Accepted\n",
	"250 Sender ok\n",
	"",
	"250 Reset ok\n",
	"221 Goodbye\n",
	"250 Sender ok\n",
	"250 ok\n",
}

var baseHelloClient = `EHLO customhost
HELO customhost
`

var helloClient = []string{
	"",
	"STARTTLS\n",
	"VRFY test@example.com\n",
	"AUTH PLAIN AHVzZXIAcGFzcw==\n",
	"MAIL FROM:<test@example.com>\n",
	"",
	"RSET\n",
	"QUIT\n",
	"VRFY test@example.com\n",
	"NOOP\n",
}

func TestSendMail(t *testing.T) {
	server := strings.Join(strings.Split(sendMailServer, "\n"), "\r\n")
	client := strings.Join(strings.Split(sendMailClient, "\n"), "\r\n")
	var cmdbuf strings.Builder
	bcmdbuf := bufio.NewWriter(&cmdbuf)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Unable to create listener: %v", err)
	}
	defer func() {
		_ = l.Close()
	}()

	// prevent data race on bcmdbuf
	done := make(chan struct{})
	go func(data []string) {
		defer close(done)

		conn, err := l.Accept()
		if err != nil {
			t.Errorf("Accept error: %v", err)
			return
		}
		defer func() {
			_ = conn.Close()
		}()

		tc := textproto.NewConn(conn)
		for i := 0; i < len(data) && data[i] != ""; i++ {
			if err := tc.PrintfLine("%s", data[i]); err != nil {
				t.Errorf("printing to textproto failed: %s", err)
			}
			for len(data[i]) >= 4 && data[i][3] == '-' {
				i++
				if err := tc.PrintfLine("%s", data[i]); err != nil {
					t.Errorf("printing to textproto failed: %s", err)
				}
			}
			if data[i] == "221 Goodbye" {
				return
			}
			read := false
			for !read || data[i] == "354 Go ahead" {
				msg, err := tc.ReadLine()
				if _, err := bcmdbuf.Write([]byte(msg + "\r\n")); err != nil {
					t.Errorf("write failed: %s", err)
				}
				read = true
				if err != nil {
					t.Errorf("Read error: %v", err)
					return
				}
				if data[i] == "354 Go ahead" && msg == "." {
					break
				}
			}
		}
	}(strings.Split(server, "\r\n"))

	err = SendMail(l.Addr().String(), nil, "test@example.com", []string{"other@example.com>\n\rDATA\r\nInjected message body\r\n.\r\nQUIT\r\n"}, []byte(strings.Replace(`From: test@example.com
To: other@example.com
Subject: SendMail test

SendMail is working for me.
`, "\n", "\r\n", -1)))
	if err == nil {
		t.Errorf("Expected SendMail to be rejected due to a message injection attempt")
	}

	err = SendMail(l.Addr().String(), nil, "test@example.com", []string{"other@example.com"}, []byte(strings.Replace(`From: test@example.com
To: other@example.com
Subject: SendMail test

SendMail is working for me.
`, "\n", "\r\n", -1)))
	if err != nil {
		t.Errorf("%v", err)
	}

	<-done
	if err := bcmdbuf.Flush(); err != nil {
		t.Errorf("flush failed: %s", err)
	}
	actualcmds := cmdbuf.String()
	if client != actualcmds {
		t.Errorf("Got:\n%s\nExpected:\n%s", actualcmds, client)
	}
}

var sendMailServer = `220 hello world
502 EH?
250 mx.google.com at your service
250 Sender ok
250 Receiver ok
354 Go ahead
250 Data ok
221 Goodbye
`

var sendMailClient = `EHLO localhost
HELO localhost
MAIL FROM:<test@example.com>
RCPT TO:<other@example.com>
DATA
From: test@example.com
To: other@example.com
Subject: SendMail test

SendMail is working for me.
.
QUIT
`

func TestSendMailWithAuth(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Unable to create listener: %v", err)
	}
	defer func() {
		_ = l.Close()
	}()

	errCh := make(chan error)
	go func() {
		defer close(errCh)
		conn, err := l.Accept()
		if err != nil {
			errCh <- fmt.Errorf("listener Accept: %w", err)
			return
		}
		defer func() {
			_ = conn.Close()
		}()

		tc := textproto.NewConn(conn)
		if err := tc.PrintfLine("220 hello world"); err != nil {
			t.Errorf("textproto connetion print failed: %s", err)
		}
		msg, err := tc.ReadLine()
		if err != nil {
			errCh <- fmt.Errorf("textproto connection ReadLine error: %w", err)
			return
		}
		const wantMsg = "EHLO localhost"
		if msg != wantMsg {
			errCh <- fmt.Errorf("unexpected response %q; want %q", msg, wantMsg)
			return
		}
		err = tc.PrintfLine("250 mx.google.com at your service")
		if err != nil {
			errCh <- fmt.Errorf("textproto connection PrintfLine: %w", err)
			return
		}
	}()

	err = SendMail(l.Addr().String(), PlainAuth("", "user", "pass", "smtp.google.com", false), "test@example.com", []string{"other@example.com"}, []byte(strings.Replace(`From: test@example.com
To: other@example.com
Subject: SendMail test

SendMail is working for me.
`, "\n", "\r\n", -1)))
	if err == nil {
		t.Error("SendMail: Server doesn't support AUTH, expected to get an error, but got none ")
		return
	}
	if err.Error() != "smtp: server doesn't support AUTH" {
		t.Errorf("Expected: smtp: server doesn't support AUTH, got: %s", err)
	}
	err = <-errCh
	if err != nil {
		t.Fatalf("server error: %v", err)
	}
}

func TestAuthFailed(t *testing.T) {
	server := strings.Join(strings.Split(authFailedServer, "\n"), "\r\n")
	client := strings.Join(strings.Split(authFailedClient, "\n"), "\r\n")
	var cmdbuf strings.Builder
	bcmdbuf := bufio.NewWriter(&cmdbuf)
	var fake faker
	fake.ReadWriter = bufio.NewReadWriter(bufio.NewReader(strings.NewReader(server)), bcmdbuf)
	c, err := NewClient(fake, "fake.host")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer func() {
		_ = c.Close()
	}()

	c.tls = true
	c.serverName = "smtp.google.com"
	err = c.Auth(PlainAuth("", "user", "pass", "smtp.google.com", false))

	if err == nil {
		t.Error("Auth: expected error; got none")
	} else if err.Error() != "535 Invalid credentials\nplease see www.example.com" {
		t.Errorf("Auth: got error: %v, want: %s", err, "535 Invalid credentials\nplease see www.example.com")
	}

	if err := bcmdbuf.Flush(); err != nil {
		t.Errorf("flush failed: %s", err)
	}
	actualcmds := cmdbuf.String()
	if client != actualcmds {
		t.Errorf("Got:\n%s\nExpected:\n%s", actualcmds, client)
	}
}

var authFailedServer = `220 hello world
250-mx.google.com at your service
250 AUTH LOGIN PLAIN
535-Invalid credentials
535 please see www.example.com
221 Goodbye
`

var authFailedClient = `EHLO localhost
AUTH PLAIN AHVzZXIAcGFzcw==
*
QUIT
`

func TestTLSClient(t *testing.T) {
	if runtime.GOOS == "freebsd" || runtime.GOOS == "js" || runtime.GOOS == "wasip1" {
		SkipFlaky(t, 19229)
	}
	ln := newLocalListener(t)
	defer func() {
		_ = ln.Close()
	}()
	errc := make(chan error)
	go func() {
		errc <- sendMail(ln.Addr().String())
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("failed to accept connection: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()
	if err := serverHandle(conn, t); err != nil {
		t.Fatalf("failed to handle connection: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("client error: %v", err)
	}
}

func TestTLSConnState(t *testing.T) {
	ln := newLocalListener(t)
	defer func() {
		_ = ln.Close()
	}()
	clientDone := make(chan bool)
	serverDone := make(chan bool)
	go func() {
		defer close(serverDone)
		c, err := ln.Accept()
		if err != nil {
			t.Errorf("Server accept: %v", err)
			return
		}
		defer func() {
			_ = c.Close()
		}()
		if err := serverHandle(c, t); err != nil {
			t.Errorf("server error: %v", err)
		}
	}()
	go func() {
		defer close(clientDone)
		c, err := Dial(ln.Addr().String())
		if err != nil {
			t.Errorf("Client dial: %v", err)
			return
		}
		defer func() {
			_ = c.Quit()
		}()
		cfg := &tls.Config{ServerName: "example.com"}
		testHookStartTLS(cfg) // set the RootCAs
		if err := c.StartTLS(cfg); err != nil {
			t.Errorf("StartTLS: %v", err)
			return
		}
		cs, ok := c.TLSConnectionState()
		if !ok {
			t.Errorf("TLSConnectionState returned ok == false; want true")
			return
		}
		if cs.Version == 0 || !cs.HandshakeComplete {
			t.Errorf("ConnectionState = %#v; expect non-zero Version and HandshakeComplete", cs)
		}
	}()
	<-clientDone
	<-serverDone
}

func TestClient_GetTLSConnectionState(t *testing.T) {
	ln := newLocalListener(t)
	defer func() {
		_ = ln.Close()
	}()
	clientDone := make(chan bool)
	serverDone := make(chan bool)
	go func() {
		defer close(serverDone)
		c, err := ln.Accept()
		if err != nil {
			t.Errorf("Server accept: %v", err)
			return
		}
		defer func() {
			_ = c.Close()
		}()
		if err := serverHandle(c, t); err != nil {
			t.Errorf("server error: %v", err)
		}
	}()
	go func() {
		defer close(clientDone)
		c, err := Dial(ln.Addr().String())
		if err != nil {
			t.Errorf("Client dial: %v", err)
			return
		}
		defer func() {
			_ = c.Quit()
		}()
		cfg := &tls.Config{ServerName: "example.com"}
		testHookStartTLS(cfg) // set the RootCAs
		if err := c.StartTLS(cfg); err != nil {
			t.Errorf("StartTLS: %v", err)
			return
		}
		cs, err := c.GetTLSConnectionState()
		if err != nil {
			t.Errorf("failed to get TLSConnectionState: %s", err)
			return
		}
		if cs.Version == 0 || !cs.HandshakeComplete {
			t.Errorf("ConnectionState = %#v; expect non-zero Version and HandshakeComplete", cs)
		}
	}()
	<-clientDone
	<-serverDone
}

func TestClient_GetTLSConnectionState_noTLS(t *testing.T) {
	ln := newLocalListener(t)
	defer func() {
		_ = ln.Close()
	}()
	clientDone := make(chan bool)
	serverDone := make(chan bool)
	go func() {
		defer close(serverDone)
		c, err := ln.Accept()
		if err != nil {
			t.Errorf("Server accept: %v", err)
			return
		}
		defer func() {
			_ = c.Close()
		}()
		if err := serverHandle(c, t); err != nil {
			t.Errorf("server error: %v", err)
		}
	}()
	go func() {
		defer close(clientDone)
		c, err := Dial(ln.Addr().String())
		if err != nil {
			t.Errorf("Client dial: %v", err)
			return
		}
		defer func() {
			_ = c.Quit()
		}()
		_, err = c.GetTLSConnectionState()
		if err == nil {
			t.Error("GetTLSConnectionState: expected error; got nil")
			return
		}
	}()
	<-clientDone
	<-serverDone
}

func TestClient_GetTLSConnectionState_noConn(t *testing.T) {
	ln := newLocalListener(t)
	defer func() {
		_ = ln.Close()
	}()
	clientDone := make(chan bool)
	serverDone := make(chan bool)
	go func() {
		defer close(serverDone)
		c, err := ln.Accept()
		if err != nil {
			t.Errorf("Server accept: %v", err)
			return
		}
		defer func() {
			_ = c.Close()
		}()
		if err := serverHandle(c, t); err != nil {
			t.Errorf("server error: %v", err)
		}
	}()
	go func() {
		defer close(clientDone)
		c, err := Dial(ln.Addr().String())
		if err != nil {
			t.Errorf("Client dial: %v", err)
			return
		}
		_ = c.Close()
		_, err = c.GetTLSConnectionState()
		if err == nil {
			t.Error("GetTLSConnectionState: expected error; got nil")
			return
		}
	}()
	<-clientDone
	<-serverDone
}

func TestClient_GetTLSConnectionState_unableErr(t *testing.T) {
	ln := newLocalListener(t)
	defer func() {
		_ = ln.Close()
	}()
	clientDone := make(chan bool)
	serverDone := make(chan bool)
	go func() {
		defer close(serverDone)
		c, err := ln.Accept()
		if err != nil {
			t.Errorf("Server accept: %v", err)
			return
		}
		defer func() {
			_ = c.Close()
		}()
		if err := serverHandle(c, t); err != nil {
			t.Errorf("server error: %v", err)
		}
	}()
	go func() {
		defer close(clientDone)
		c, err := Dial(ln.Addr().String())
		if err != nil {
			t.Errorf("Client dial: %v", err)
			return
		}
		defer func() {
			_ = c.Quit()
		}()
		c.tls = true
		_, err = c.GetTLSConnectionState()
		if err == nil {
			t.Error("GetTLSConnectionState: expected error; got nil")
			return
		}
	}()
	<-clientDone
	<-serverDone
}

func TestClient_HasConnection(t *testing.T) {
	ln := newLocalListener(t)
	defer func() {
		_ = ln.Close()
	}()
	clientDone := make(chan bool)
	serverDone := make(chan bool)
	go func() {
		defer close(serverDone)
		c, err := ln.Accept()
		if err != nil {
			t.Errorf("Server accept: %v", err)
			return
		}
		defer func() {
			_ = c.Close()
		}()
		if err := serverHandle(c, t); err != nil {
			t.Errorf("server error: %v", err)
		}
	}()
	go func() {
		defer close(clientDone)
		c, err := Dial(ln.Addr().String())
		if err != nil {
			t.Errorf("Client dial: %v", err)
			return
		}
		cfg := &tls.Config{ServerName: "example.com"}
		testHookStartTLS(cfg) // set the RootCAs
		if err := c.StartTLS(cfg); err != nil {
			t.Errorf("StartTLS: %v", err)
			return
		}
		if !c.HasConnection() {
			t.Error("HasConnection: expected true; got false")
			return
		}
		if err = c.Quit(); err != nil {
			t.Errorf("closing connection failed: %s", err)
			return
		}
		if c.HasConnection() {
			t.Error("HasConnection: expected false; got true")
		}
	}()
	<-clientDone
	<-serverDone
}

func TestClient_SetDSNMailReturnOption(t *testing.T) {
	ln := newLocalListener(t)
	defer func() {
		_ = ln.Close()
	}()
	clientDone := make(chan bool)
	serverDone := make(chan bool)
	go func() {
		defer close(serverDone)
		c, err := ln.Accept()
		if err != nil {
			t.Errorf("Server accept: %v", err)
			return
		}
		defer func() {
			_ = c.Close()
		}()
		if err := serverHandle(c, t); err != nil {
			t.Errorf("server error: %v", err)
		}
	}()
	go func() {
		defer close(clientDone)
		c, err := Dial(ln.Addr().String())
		if err != nil {
			t.Errorf("Client dial: %v", err)
			return
		}
		defer func() {
			_ = c.Quit()
		}()
		c.SetDSNMailReturnOption("foo")
		if c.dsnmrtype != "foo" {
			t.Errorf("SetDSNMailReturnOption: expected %s; got %s", "foo", c.dsnrntype)
		}
	}()
	<-clientDone
	<-serverDone
}

func TestClient_SetDSNRcptNotifyOption(t *testing.T) {
	ln := newLocalListener(t)
	defer func() {
		_ = ln.Close()
	}()
	clientDone := make(chan bool)
	serverDone := make(chan bool)
	go func() {
		defer close(serverDone)
		c, err := ln.Accept()
		if err != nil {
			t.Errorf("Server accept: %v", err)
			return
		}
		defer func() {
			_ = c.Close()
		}()
		if err := serverHandle(c, t); err != nil {
			t.Errorf("server error: %v", err)
		}
	}()
	go func() {
		defer close(clientDone)
		c, err := Dial(ln.Addr().String())
		if err != nil {
			t.Errorf("Client dial: %v", err)
			return
		}
		defer func() {
			_ = c.Quit()
		}()
		c.SetDSNRcptNotifyOption("foo")
		if c.dsnrntype != "foo" {
			t.Errorf("SetDSNMailReturnOption: expected %s; got %s", "foo", c.dsnrntype)
		}
	}()
	<-clientDone
	<-serverDone
}

func TestClient_UpdateDeadline(t *testing.T) {
	ln := newLocalListener(t)
	defer func() {
		_ = ln.Close()
	}()
	clientDone := make(chan bool)
	serverDone := make(chan bool)
	go func() {
		defer close(serverDone)
		c, err := ln.Accept()
		if err != nil {
			t.Errorf("Server accept: %v", err)
			return
		}
		defer func() {
			_ = c.Close()
		}()
		if err = serverHandle(c, t); err != nil {
			t.Errorf("server error: %v", err)
		}
	}()
	go func() {
		defer close(clientDone)
		c, err := Dial(ln.Addr().String())
		if err != nil {
			t.Errorf("Client dial: %v", err)
			return
		}
		defer func() {
			_ = c.Close()
		}()
		if !c.HasConnection() {
			t.Error("HasConnection: expected true; got false")
			return
		}
		if err = c.UpdateDeadline(time.Millisecond * 20); err != nil {
			t.Errorf("failed to update deadline: %s", err)
			return
		}
		time.Sleep(time.Millisecond * 50)
		if !c.HasConnection() {
			t.Error("HasConnection: expected true; got false")
			return
		}
	}()
	<-clientDone
	<-serverDone
}

func newLocalListener(t *testing.T) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		ln, err = net.Listen("tcp6", "[::1]:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

type smtpSender struct {
	w io.Writer
}

func (s smtpSender) send(f string) {
	_, _ = s.w.Write([]byte(f + "\r\n"))
}

// smtp server, finely tailored to deal with our own client only!
func serverHandle(c net.Conn, t *testing.T) error {
	send := smtpSender{c}.send
	send("220 127.0.0.1 ESMTP service ready")
	s := bufio.NewScanner(c)
	tf := func(config *tls.Config) error {
		c = tls.Server(c, config)
		defer func() {
			_ = c.Close()
		}()
		return serverHandleTLS(c, t)
	}
	for s.Scan() {
		switch s.Text() {
		case "EHLO localhost":
			send("250-127.0.0.1 ESMTP offers a warm hug of welcome")
			send("250-STARTTLS")
			send("250 Ok")
		case "STARTTLS":
			send("220 Go ahead")
			keypair, err := tls.X509KeyPair(localhostCert, localhostKey)
			if err != nil {
				return err
			}
			config := &tls.Config{Certificates: []tls.Certificate{keypair}}
			return tf(config)
		case "QUIT":
			return nil
		default:
			t.Fatalf("unrecognized command: %q", s.Text())
		}
	}
	return s.Err()
}

func serverHandleTLS(c net.Conn, t *testing.T) error {
	send := smtpSender{c}.send
	s := bufio.NewScanner(c)
	for s.Scan() {
		switch s.Text() {
		case "EHLO localhost":
			send("250 Ok")
		case "MAIL FROM:<joe1@example.com>":
			send("250 Ok")
		case "RCPT TO:<joe2@example.com>":
			send("250 Ok")
		case "DATA":
			send("354 send the mail data, end with .")
			send("250 Ok")
		case "Subject: test":
		case "":
		case "howdy!":
		case ".":
		case "QUIT":
			send("221 127.0.0.1 Service closing transmission channel")
			return nil
		default:
			t.Fatalf("unrecognized command during TLS: %q", s.Text())
		}
	}
	return s.Err()
}

func init() {
	testRootCAs := x509.NewCertPool()
	testRootCAs.AppendCertsFromPEM(localhostCert)
	testHookStartTLS = func(config *tls.Config) {
		config.RootCAs = testRootCAs
	}
}

func sendMail(hostPort string) error {
	from := "joe1@example.com"
	to := []string{"joe2@example.com"}
	return SendMail(hostPort, nil, from, to, []byte("Subject: test\n\nhowdy!"))
}

// localhostCert is a PEM-encoded TLS cert generated from src/crypto/tls:
//
//	go run generate_cert.go --rsa-bits 1024 --host 127.0.0.1,::1,example.com \
//		--ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
var localhostCert = []byte(`
-----BEGIN CERTIFICATE-----
MIICFDCCAX2gAwIBAgIRAK0xjnaPuNDSreeXb+z+0u4wDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAgFw03MDAxMDEwMDAwMDBaGA8yMDg0MDEyOTE2
MDAwMFowEjEQMA4GA1UEChMHQWNtZSBDbzCBnzANBgkqhkiG9w0BAQEFAAOBjQAw
gYkCgYEA0nFbQQuOWsjbGtejcpWz153OlziZM4bVjJ9jYruNw5n2Ry6uYQAffhqa
JOInCmmcVe2siJglsyH9aRh6vKiobBbIUXXUU1ABd56ebAzlt0LobLlx7pZEMy30
LqIi9E6zmL3YvdGzpYlkFRnRrqwEtWYbGBf3znO250S56CCWH2UCAwEAAaNoMGYw
DgYDVR0PAQH/BAQDAgKkMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1UdEwEB/wQF
MAMBAf8wLgYDVR0RBCcwJYILZXhhbXBsZS5jb22HBH8AAAGHEAAAAAAAAAAAAAAA
AAAAAAEwDQYJKoZIhvcNAQELBQADgYEAbZtDS2dVuBYvb+MnolWnCNqvw1w5Gtgi
NmvQQPOMgM3m+oQSCPRTNGSg25e1Qbo7bgQDv8ZTnq8FgOJ/rbkyERw2JckkHpD4
n4qcK27WkEDBtQFlPihIM8hLIuzWoi/9wygiElTy/tVL3y7fGCvY2/k1KBthtZGF
tN8URjVmyEo=
-----END CERTIFICATE-----`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
MIICXgIBAAKBgQDScVtBC45ayNsa16NylbPXnc6XOJkzhtWMn2Niu43DmfZHLq5h
AB9+Gpok4icKaZxV7ayImCWzIf1pGHq8qKhsFshRddRTUAF3np5sDOW3QuhsuXHu
lkQzLfQuoiL0TrOYvdi90bOliWQVGdGurAS1ZhsYF/fOc7bnRLnoIJYfZQIDAQAB
AoGBAMst7OgpKyFV6c3JwyI/jWqxDySL3caU+RuTTBaodKAUx2ZEmNJIlx9eudLA
kucHvoxsM/eRxlxkhdFxdBcwU6J+zqooTnhu/FE3jhrT1lPrbhfGhyKnUrB0KKMM
VY3IQZyiehpxaeXAwoAou6TbWoTpl9t8ImAqAMY8hlULCUqlAkEA+9+Ry5FSYK/m
542LujIcCaIGoG1/Te6Sxr3hsPagKC2rH20rDLqXwEedSFOpSS0vpzlPAzy/6Rbb
PHTJUhNdwwJBANXkA+TkMdbJI5do9/mn//U0LfrCR9NkcoYohxfKz8JuhgRQxzF2
6jpo3q7CdTuuRixLWVfeJzcrAyNrVcBq87cCQFkTCtOMNC7fZnCTPUv+9q1tcJyB
vNjJu3yvoEZeIeuzouX9TJE21/33FaeDdsXbRhQEj23cqR38qFHsF1qAYNMCQQDP
QXLEiJoClkR2orAmqjPLVhR3t2oB3INcnEjLNSq8LHyQEfXyaFfu4U9l5+fRPL2i
jiC0k/9L5dHUsF0XZothAkEA23ddgRs+Id/HxtojqqUT27B8MT/IGNrYsp4DvS/c
qgkeluku4GjxRlDMBuXk94xOBEinUs+p/hwP1Alll80Tpg==
-----END RSA TESTING KEY-----`))

func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }

var flaky = flag.Bool("flaky", false, "run known-flaky tests too")

func SkipFlaky(t testing.TB, issue int) {
	t.Helper()
	if !*flaky {
		t.Skipf("skipping known flaky test without the -flaky flag; see golang.org/issue/%d", issue)
	}
}

// testSCRAMSMTPServer represents a test server for SCRAM-based SMTP authentication.
// It does not do any acutal computation of the challenges but verifies that the expected
// fields are present. We have actual real authentication tests for all SCRAM modes in the
// go-mail client_test.go
type testSCRAMSMTPServer struct {
	authMechanism string
	nonce         string
	hostname      string
	port          string
	tlsServer     bool
	h             func() hash.Hash
}

func (s *testSCRAMSMTPServer) handleConnection(conn net.Conn) {
	defer func() {
		_ = conn.Close()
	}()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	writeLine := func(data string) error {
		_, err := writer.WriteString(data + "\r\n")
		if err != nil {
			return fmt.Errorf("unable to write line: %w", err)
		}
		return writer.Flush()
	}
	writeOK := func() {
		_ = writeLine("250 2.0.0 OK")
	}

	if err := writeLine("220 go-mail test server ready ESMTP"); err != nil {
		return
	}

	data, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	data = strings.TrimSpace(data)
	if strings.HasPrefix(data, "EHLO") {
		_ = writeLine(fmt.Sprintf("250-%s", s.hostname))
		_ = writeLine("250-AUTH SCRAM-SHA-1 SCRAM-SHA-256")
		writeOK()
	} else {
		_ = writeLine("500 Invalid command")
		return
	}

	for {
		data, err = reader.ReadString('\n')
		if err != nil {
			fmt.Printf("failed to read data: %v", err)
		}
		data = strings.TrimSpace(data)
		if strings.HasPrefix(data, "AUTH") {
			parts := strings.Split(data, " ")
			if len(parts) < 2 {
				_ = writeLine("500 Syntax error")
				return
			}

			authMechanism := parts[1]
			if authMechanism != "SCRAM-SHA-1" && authMechanism != "SCRAM-SHA-256" &&
				authMechanism != "SCRAM-SHA-1-PLUS" && authMechanism != "SCRAM-SHA-256-PLUS" {
				_ = writeLine("504 Unrecognized authentication mechanism")
				return
			}
			s.authMechanism = authMechanism
			_ = writeLine("334 ")
			s.handleSCRAMAuth(conn)
			return
		} else {
			_ = writeLine("500 Invalid command")
		}
	}
}

func (s *testSCRAMSMTPServer) handleSCRAMAuth(conn net.Conn) {
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	writeLine := func(data string) error {
		_, err := writer.WriteString(data + "\r\n")
		if err != nil {
			return fmt.Errorf("unable to write line: %w", err)
		}
		return writer.Flush()
	}
	var authMsg string

	data, err := reader.ReadString('\n')
	if err != nil {
		_ = writeLine("535 Authentication failed")
		return
	}
	data = strings.TrimSpace(data)
	decodedMessage, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		_ = writeLine("535 Authentication failed")
		return
	}
	splits := strings.Split(string(decodedMessage), ",")
	if len(splits) != 4 {
		_ = writeLine("535 Authentication failed - expected 4 parts")
		return
	}
	if !s.tlsServer && splits[0] != "n" {
		_ = writeLine("535 Authentication failed - expected n to be in the first part")
		return
	}
	if s.tlsServer && !strings.HasPrefix(splits[0], "p=") {
		_ = writeLine("535 Authentication failed - expected p= to be in the first part")
		return
	}
	if splits[2] != "n=username" {
		_ = writeLine("535 Authentication failed - expected n=username to be in the third part")
		return
	}
	if !strings.HasPrefix(splits[3], "r=") {
		_ = writeLine("535 Authentication failed - expected r= to be in the fourth part")
		return
	}
	authMsg = splits[2] + "," + splits[3]

	clientNonce := s.extractNonce(string(decodedMessage))
	if clientNonce == "" {
		_ = writeLine("535 Authentication failed")
		return
	}

	s.nonce = clientNonce + "server_nonce"
	serverFirstMessage := fmt.Sprintf("r=%s,s=%s,i=4096", s.nonce,
		base64.StdEncoding.EncodeToString([]byte("salt")))
	_ = writeLine(fmt.Sprintf("334 %s", base64.StdEncoding.EncodeToString([]byte(serverFirstMessage))))
	authMsg = authMsg + "," + serverFirstMessage

	data, err = reader.ReadString('\n')
	if err != nil {
		_ = writeLine("535 Authentication failed")
		return
	}
	data = strings.TrimSpace(data)
	decodedFinalMessage, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		_ = writeLine("535 Authentication failed")
		return
	}
	splits = strings.Split(string(decodedFinalMessage), ",")

	if !s.tlsServer && splits[0] != "c=biws" {
		_ = writeLine("535 Authentication failed - expected c=biws to be in the first part")
		return
	}
	if s.tlsServer {
		if !strings.HasPrefix(splits[0], "c=") {
			_ = writeLine("535 Authentication failed - expected c= to be in the first part")
			return
		}
		channelBind, err := base64.StdEncoding.DecodeString(splits[0][2:])
		if err != nil {
			_ = writeLine("535 Authentication failed - base64 channel bind is not valid - " + err.Error())
			return
		}
		if !strings.HasPrefix(string(channelBind), "p=") {
			_ = writeLine("535 Authentication failed - expected channel binding to start with p=-")
			return
		}
		cbType := string(channelBind[2:])
		if !strings.HasPrefix(cbType, "tls-unique") && !strings.HasPrefix(cbType, "tls-exporter") {
			_ = writeLine("535 Authentication failed - expected channel binding type tls-unique or tls-exporter")
			return
		}
	}

	if !strings.HasPrefix(splits[1], "r=") {
		_ = writeLine("535 Authentication failed - expected r to be in the second part")
		return
	}
	if !strings.Contains(splits[1], "server_nonce") {
		_ = writeLine("535 Authentication failed - expected server_nonce to be in the second part")
		return
	}
	if !strings.HasPrefix(splits[2], "p=") {
		_ = writeLine("535 Authentication failed - expected p to be in the third part")
		return
	}

	authMsg = authMsg + "," + splits[0] + "," + splits[1]
	saltedPwd := pbkdf2.Key([]byte("password"), []byte("salt"), 4096, s.h().Size(), s.h)
	mac := hmac.New(s.h, saltedPwd)
	mac.Write([]byte("Server Key"))
	skey := mac.Sum(nil)
	mac.Reset()

	mac = hmac.New(s.h, skey)
	mac.Write([]byte(authMsg))
	ssig := mac.Sum(nil)
	mac.Reset()

	serverFinalMessage := fmt.Sprintf("v=%s", base64.StdEncoding.EncodeToString(ssig))
	_ = writeLine(fmt.Sprintf("334 %s", base64.StdEncoding.EncodeToString([]byte(serverFinalMessage))))

	_, err = reader.ReadString('\n')
	if err != nil {
		_ = writeLine("535 Authentication failed")
		return
	}

	_ = writeLine("235 Authentication successful")
}

func (s *testSCRAMSMTPServer) extractNonce(message string) string {
	parts := strings.Split(message, ",")
	for _, part := range parts {
		if strings.HasPrefix(part, "r=") {
			return part[2:]
		}
	}
	return ""
}

func startSMTPServer(tlsServer bool, hostname, port string, h func() hash.Hash) {
	server := &testSCRAMSMTPServer{
		hostname:  hostname,
		port:      port,
		tlsServer: tlsServer,
		h:         h,
	}
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%s", hostname, port))
	if err != nil {
		fmt.Printf("Failed to start SMTP server: %v", err)
	}
	defer func() {
		_ = listener.Close()
	}()

	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		fmt.Printf("error creating TLS cert: %s", err)
		return
	}
	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Failed to accept connection: %v", err)
			continue
		}
		if server.tlsServer {
			conn = tls.Server(conn, &tlsConfig)
		}
		go server.handleConnection(conn)
	}
}


*/

// faker is a struct embedding io.ReadWriter to simulate network connections for testing purposes.
type faker struct {
	io.ReadWriter
}

func (f faker) Close() error                     { return nil }
func (f faker) LocalAddr() net.Addr              { return nil }
func (f faker) RemoteAddr() net.Addr             { return nil }
func (f faker) SetDeadline(time.Time) error      { return nil }
func (f faker) SetReadDeadline(time.Time) error  { return nil }
func (f faker) SetWriteDeadline(time.Time) error { return nil }

// testingKey replaces the substring "TESTING KEY" with "PRIVATE KEY" in the given string s.
func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }

// serverProps represents the configuration properties for the SMTP server.
type serverProps struct {
	FailOnAuth      bool
	FailOnDataInit  bool
	FailOnDataClose bool
	FailOnHelo      bool
	FailOnMailFrom  bool
	FailOnNoop      bool
	FailOnQuit      bool
	FailOnReset     bool
	FailOnSTARTTLS  bool
	FailTemp        bool
	FeatureSet      string
	ListenPort      int
	SSLListener     bool
	IsSCRAMPlus     bool
	IsTLS           bool
	SupportDSN      bool
	TestSCRAM       bool
	HashFunc        func() hash.Hash
}

// simpleSMTPServer starts a simple TCP server that resonds to SMTP commands.
// The provided featureSet represents in what the server responds to EHLO command
// failReset controls if a RSET succeeds
func simpleSMTPServer(ctx context.Context, t *testing.T, props *serverProps) error {
	t.Helper()
	if props == nil {
		return fmt.Errorf("no server properties provided")
	}

	var listener net.Listener
	var err error
	if props.SSLListener {
		keypair, err := tls.X509KeyPair(localhostCert, localhostKey)
		if err != nil {
			return fmt.Errorf("failed to read TLS keypair: %w", err)
		}
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{keypair}}
		listener, err = tls.Listen(TestServerProto, fmt.Sprintf("%s:%d", TestServerAddr, props.ListenPort),
			tlsConfig)
		if err != nil {
			t.Fatalf("failed to create TLS listener: %s", err)
		}
	} else {
		listener, err = net.Listen(TestServerProto, fmt.Sprintf("%s:%d", TestServerAddr, props.ListenPort))
	}
	if err != nil {
		return fmt.Errorf("unable to listen on %s://%s: %w (SSL: %t)", TestServerProto, TestServerAddr, err,
			props.SSLListener)
	}

	defer func() {
		if err := listener.Close(); err != nil {
			t.Logf("failed to close listener: %s", err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			connection, err := listener.Accept()
			var opErr *net.OpError
			if err != nil {
				if errors.As(err, &opErr) && opErr.Temporary() {
					continue
				}
				return fmt.Errorf("unable to accept connection: %w", err)
			}
			handleTestServerConnection(connection, t, props)
		}
	}
}

func handleTestServerConnection(connection net.Conn, t *testing.T, props *serverProps) {
	t.Helper()
	if !props.IsTLS {
		t.Cleanup(func() {
			if err := connection.Close(); err != nil {
				t.Logf("failed to close connection: %s", err)
			}
		})
	}

	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)

	writeLine := func(data string) {
		_, err := writer.WriteString(data + "\r\n")
		if err != nil {
			t.Logf("failed to write line: %s", err)
		}
		_ = writer.Flush()
	}
	writeOK := func() {
		writeLine("250 2.0.0 OK")
	}

	if !props.IsTLS {
		writeLine("220 go-mail test server ready ESMTP")
	}

	for {
		data, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		time.Sleep(time.Millisecond)

		var datastring string
		data = strings.TrimSpace(data)
		switch {
		case strings.HasPrefix(data, "EHLO"), strings.HasPrefix(data, "HELO"):
			if len(strings.Split(data, " ")) != 2 {
				writeLine("501 Syntax: EHLO hostname")
				break
			}
			if props.FailOnHelo {
				writeLine("500 5.5.2 Error: fail on HELO")
				break
			}
			writeLine("250-localhost.localdomain\r\n" + props.FeatureSet)
		case strings.HasPrefix(data, "MAIL FROM:"):
			if props.FailOnMailFrom {
				writeLine("500 5.5.2 Error: fail on MAIL FROM")
				break
			}
			from := strings.TrimPrefix(data, "MAIL FROM:")
			from = strings.ReplaceAll(from, "BODY=8BITMIME", "")
			from = strings.ReplaceAll(from, "SMTPUTF8", "")
			if props.SupportDSN {
				from = strings.ReplaceAll(from, "RET=FULL", "")
			}
			from = strings.TrimSpace(from)
			if !strings.EqualFold(from, "<valid-from@domain.tld>") {
				writeLine(fmt.Sprintf("503 5.1.2 Invalid from: %s", from))
				break
			}
			writeOK()
		case strings.HasPrefix(data, "RCPT TO:"):
			to := strings.TrimPrefix(data, "RCPT TO:")
			if props.SupportDSN {
				to = strings.ReplaceAll(to, "NOTIFY=FAILURE,SUCCESS", "")
			}
			to = strings.TrimSpace(to)
			if !strings.EqualFold(to, "<valid-to@domain.tld>") {
				writeLine(fmt.Sprintf("500 5.1.2 Invalid to: %s", to))
				break
			}
			writeOK()
		case strings.HasPrefix(data, "AUTH"):
			if props.FailOnAuth {
				writeLine("535 5.7.8 Error: authentication failed")
				break
			}
			if props.TestSCRAM {
				parts := strings.Split(data, " ")
				authMechanism := parts[1]
				if authMechanism != "SCRAM-SHA-1" && authMechanism != "SCRAM-SHA-256" &&
					authMechanism != "SCRAM-SHA-1-PLUS" && authMechanism != "SCRAM-SHA-256-PLUS" {
					writeLine("504 Unrecognized authentication mechanism")
					break
				}
				scram := &testSCRAMSMTP{
					tlsServer: props.IsSCRAMPlus,
					h:         props.HashFunc,
				}
				writeLine("334 ")
				scram.handleSCRAMAuth(connection)
				break
			}
			writeLine("235 2.7.0 Authentication successful")
		case strings.EqualFold(data, "DATA"):
			if props.FailOnDataInit {
				writeLine("503 5.5.1 Error: fail on DATA init")
				break
			}
			writeLine("354 End data with <CR><LF>.<CR><LF>")
			for {
				ddata, derr := reader.ReadString('\n')
				if derr != nil {
					t.Logf("failed to read data from connection: %s", derr)
					break
				}
				ddata = strings.TrimSpace(ddata)
				if ddata == "." {
					if props.FailOnDataClose {
						writeLine("500 5.0.0 Error during DATA transmission")
						break
					}
					if props.FailTemp {
						writeLine("451 4.3.0 Error: fail on DATA close")
						break
					}
					writeLine("250 2.0.0 Ok: queued as 1234567890")
					break
				}
				datastring += ddata + "\n"
			}
		case strings.EqualFold(data, "noop"):
			if props.FailOnNoop {
				writeLine("500 5.0.0 Error: fail on NOOP")
				break
			}
			writeOK()
		case strings.EqualFold(data, "vrfy"):
			writeOK()
		case strings.EqualFold(data, "rset"):
			if props.FailOnReset {
				writeLine("500 5.1.2 Error: reset failed")
				break
			}
			writeOK()
		case strings.EqualFold(data, "quit"):
			if props.FailOnQuit {
				writeLine("500 5.1.2 Error: quit failed")
				break
			}
			writeLine("221 2.0.0 Bye")
			return
		case strings.EqualFold(data, "starttls"):
			if props.FailOnSTARTTLS {
				writeLine("500 5.1.2 Error: starttls failed")
				break
			}
			keypair, err := tls.X509KeyPair(localhostCert, localhostKey)
			if err != nil {
				writeLine("500 5.1.2 Error: starttls failed - " + err.Error())
				break
			}
			writeLine("220 Ready to start TLS")
			tlsConfig := &tls.Config{Certificates: []tls.Certificate{keypair}}
			connection = tls.Server(connection, tlsConfig)
			props.IsTLS = true
			handleTestServerConnection(connection, t, props)
		default:
			writeLine("500 5.5.2 Error: bad syntax")
		}
	}
}

// testSCRAMSMTP represents a part of the test server for SCRAM-based SMTP authentication.
// It does not do any acutal computation of the challenges but verifies that the expected
// fields are present. We have actual real authentication tests for all SCRAM modes in the
// go-mail client_test.go
type testSCRAMSMTP struct {
	authMechanism string
	nonce         string
	h             func() hash.Hash
	tlsServer     bool
}

func (s *testSCRAMSMTP) handleSCRAMAuth(conn net.Conn) {
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	writeLine := func(data string) error {
		_, err := writer.WriteString(data + "\r\n")
		if err != nil {
			return fmt.Errorf("unable to write line: %w", err)
		}
		return writer.Flush()
	}
	var authMsg string

	data, err := reader.ReadString('\n')
	if err != nil {
		_ = writeLine("535 Authentication failed")
		return
	}
	data = strings.TrimSpace(data)
	decodedMessage, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		_ = writeLine("535 Authentication failed")
		return
	}
	splits := strings.Split(string(decodedMessage), ",")
	if len(splits) != 4 {
		_ = writeLine("535 Authentication failed - expected 4 parts")
		return
	}
	if !s.tlsServer && splits[0] != "n" {
		_ = writeLine("535 Authentication failed - expected n to be in the first part")
		return
	}
	if s.tlsServer && !strings.HasPrefix(splits[0], "p=") {
		_ = writeLine("535 Authentication failed - expected p= to be in the first part")
		return
	}
	if splits[2] != "n=username" {
		_ = writeLine("535 Authentication failed - expected n=username to be in the third part")
		return
	}
	if !strings.HasPrefix(splits[3], "r=") {
		_ = writeLine("535 Authentication failed - expected r= to be in the fourth part")
		return
	}
	authMsg = splits[2] + "," + splits[3]

	clientNonce := s.extractNonce(string(decodedMessage))
	if clientNonce == "" {
		_ = writeLine("535 Authentication failed")
		return
	}

	s.nonce = clientNonce + "server_nonce"
	serverFirstMessage := fmt.Sprintf("r=%s,s=%s,i=4096", s.nonce,
		base64.StdEncoding.EncodeToString([]byte("salt")))
	_ = writeLine(fmt.Sprintf("334 %s", base64.StdEncoding.EncodeToString([]byte(serverFirstMessage))))
	authMsg = authMsg + "," + serverFirstMessage

	data, err = reader.ReadString('\n')
	if err != nil {
		_ = writeLine("535 Authentication failed")
		return
	}
	data = strings.TrimSpace(data)
	decodedFinalMessage, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		_ = writeLine("535 Authentication failed")
		return
	}
	splits = strings.Split(string(decodedFinalMessage), ",")

	if !s.tlsServer && splits[0] != "c=biws" {
		_ = writeLine("535 Authentication failed - expected c=biws to be in the first part")
		return
	}
	if s.tlsServer {
		if !strings.HasPrefix(splits[0], "c=") {
			_ = writeLine("535 Authentication failed - expected c= to be in the first part")
			return
		}
		channelBind, err := base64.StdEncoding.DecodeString(splits[0][2:])
		if err != nil {
			_ = writeLine("535 Authentication failed - base64 channel bind is not valid - " + err.Error())
			return
		}
		if !strings.HasPrefix(string(channelBind), "p=") {
			_ = writeLine("535 Authentication failed - expected channel binding to start with p=-")
			return
		}
		cbType := string(channelBind[2:])
		if !strings.HasPrefix(cbType, "tls-unique") && !strings.HasPrefix(cbType, "tls-exporter") {
			_ = writeLine("535 Authentication failed - expected channel binding type tls-unique or tls-exporter")
			return
		}
	}

	if !strings.HasPrefix(splits[1], "r=") {
		_ = writeLine("535 Authentication failed - expected r to be in the second part")
		return
	}
	if !strings.Contains(splits[1], "server_nonce") {
		_ = writeLine("535 Authentication failed - expected server_nonce to be in the second part")
		return
	}
	if !strings.HasPrefix(splits[2], "p=") {
		_ = writeLine("535 Authentication failed - expected p to be in the third part")
		return
	}

	authMsg = authMsg + "," + splits[0] + "," + splits[1]
	saltedPwd := pbkdf2.Key([]byte("password"), []byte("salt"), 4096, s.h().Size(), s.h)
	mac := hmac.New(s.h, saltedPwd)
	mac.Write([]byte("Server Key"))
	skey := mac.Sum(nil)
	mac.Reset()

	mac = hmac.New(s.h, skey)
	mac.Write([]byte(authMsg))
	ssig := mac.Sum(nil)
	mac.Reset()

	serverFinalMessage := fmt.Sprintf("v=%s", base64.StdEncoding.EncodeToString(ssig))
	_ = writeLine(fmt.Sprintf("334 %s", base64.StdEncoding.EncodeToString([]byte(serverFinalMessage))))

	_, err = reader.ReadString('\n')
	if err != nil {
		_ = writeLine("535 Authentication failed")
		return
	}

	_ = writeLine("235 Authentication successful")
}

func (s *testSCRAMSMTP) extractNonce(message string) string {
	parts := strings.Split(message, ",")
	for _, part := range parts {
		if strings.HasPrefix(part, "r=") {
			return part[2:]
		}
	}
	return ""
}
