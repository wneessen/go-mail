// SPDX-FileCopyrightText: Copyright 2010 The Go Authors. All rights reserved.
// SPDX-FileCopyrightText: Copyright (c) The go-mail Authors
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
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	netmail "net/mail"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wneessen/go-mail/log"
)

const (
	// TestServerProto is the protocol used for the simple SMTP test server
	TestServerProto = "tcp"
	// TestServerAddr is the address the simple SMTP test server listens on
	TestServerAddr = "127.0.0.1"
)

// PortAdder is an atomic counter used to increment port numbers for the test SMTP server instances.
var PortAdder atomic.Int32

// TestServerPortBase is the base port for the simple SMTP test server
var TestServerPortBase int32 = 20025

// localhostCert is a PEM-encoded TLS cert generated from src/crypto/tls:
//
//	go run generate_cert.go --rsa-bits 2048 --host 127.0.0.1,::1,example.com \
//		--ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
var localhostCert = []byte(`
-----BEGIN CERTIFICATE-----
MIIDFDCCAfygAwIBAgIRAPV4ktbcY/mn0oRRjnGAGJgwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0yNTAzMTgxOTI3NTRaFw0yNjAzMTgxOTI3
NTRaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDbsEfk1bK7ozwZlcQM8rBUikC4gwnnw0J1PUlGDGu1Y84dKtulbdWj
yrh88D4fSdtmxFbXE7fhYUJTBmEHSUk9OLHh/Tr+nSC3SfH0I/9y6l9j9vVVYhYJ
C07Z1mZZKVb+gmbbB7LEavGMNaFHjvRJAwBX2TMDbXJceZ9jU/iihILkZbrbG40r
n1mctYVmcR3YqOzI/ynLje97FEvxtsg99OUjzzXyFMqfAl0J3Gc6tzvAER3N+ovK
nudsnMB5Y+InQHHmPeizG4mFyeBYesXNwX6cmI30c8KFiAlKHcsxjJsuoBZ3bSwv
vFdK2hnuCO05HEgCzAQKUlY6Q2F0xJblAgMBAAGjZTBjMA4GA1UdDwEB/wQEAwIF
oDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMC4GA1UdEQQnMCWC
C2V4YW1wbGUuY29thwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMA0GCSqGSIb3DQEB
CwUAA4IBAQBnfO4lYRXR9AdMidpgdITqMEKJik8MvCkpQ+EKQLq3CIGXPt5lkHLs
ysbF9f3VxioKNYzkakJGVGyu51hqyhGqGQ4M7IpOBQkmY24IExWPVEk2wkIV+HTU
+oQVZOIrHF+s9IIFOIh3SIPIsXNvx7rUc5sgF4P+eAnAcv3o1zL7YjGJZ8e27Ai2
uF8iG/po/0Vd93OSB8Tj/Nvg99SSucy7nBYTreSdhUjZWRI0W1oYJX49/fhWljR9
8+f2GqUfLc7iCjcV3wxlfBqEKCdpjXsiqtsb1KrAx7AEOj7XfDjJjyCL4bshLp9x
PbV+kBFCN151iWYtfzhKEplrZFYNXlX2
-----END CERTIFICATE-----`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDbsEfk1bK7ozwZ
lcQM8rBUikC4gwnnw0J1PUlGDGu1Y84dKtulbdWjyrh88D4fSdtmxFbXE7fhYUJT
BmEHSUk9OLHh/Tr+nSC3SfH0I/9y6l9j9vVVYhYJC07Z1mZZKVb+gmbbB7LEavGM
NaFHjvRJAwBX2TMDbXJceZ9jU/iihILkZbrbG40rn1mctYVmcR3YqOzI/ynLje97
FEvxtsg99OUjzzXyFMqfAl0J3Gc6tzvAER3N+ovKnudsnMB5Y+InQHHmPeizG4mF
yeBYesXNwX6cmI30c8KFiAlKHcsxjJsuoBZ3bSwvvFdK2hnuCO05HEgCzAQKUlY6
Q2F0xJblAgMBAAECggEACzZIOQraBB8M3G5rEtEZBDuJGZGgggpSXDrsQC22mouV
M6JiEuOT5Xfdagz10rF5h9lp6DCqsA8/bA7ViWJpYT1BQNwkdGWvC4Oz3EaxDRue
kjLCqyCmKMCBvfbmAtNsC/G6T5/pNQKTQNlk2YrXd1l2nUUpyBlAHq2bX52jwSGD
bFy5hyzSrzjeLpLUNZ56W/uXCvP0l6PAEvXRn/KG89XLZCtMBvVDMCfjIe77Q1U9
/XzIrnb67RzQwiDelvX+biMkBrjeYw/Gvdo9hNCOfbOZ+SpnfDOLEfAha/XPmr3+
5EeF4emeEhCODvfe7wy/4h1gHEG2N435S61DcV3gQQKBgQD92EJidwriPGDTUSM8
nJrPQ5xwPMKz5hWpfI0zxIYZyqA37eRC5Q9WD3rDbrEZiLCInFh+Ci899iLzEpFZ
dFQAUiRam+zFpDCQcGHr/uytRoTH/nxh2MrYPq8cA5ZGU6oMH+Yl4TynqJm2KN7e
0ocE07QjyK/9nIvEtdibEiFEwQKBgQDdjcgoqHaM49YJ4yxGpjuRdc5a3iuKzZU6
BON4GKqYQ9u/o8/NPaOSQ3vKhwzTjiEoOZImn+eX1cRP0ZskmQ+LyzsdVAHMDydz
9I23dbIywtCXGhKOJRwt9O++8ataWIxi1frjj6BcI+TzGl8LM2lYIfUHzVzfswwE
1EK8ikxnJQKBgBqPKvr0a54aJSNXBPHNjOEMuOyBXvnFpBSUpI17DXDbY4IWkOBy
6PTfL8AM79i1FYtlmFivphu8ihGWqsCKTFOwRH96ev5+3FnweD5h8M98Zl4qgUcX
kLmpbVboBSwcitkz6TejZl5AZLzLb+4uZtQZdmqcD9XgMDuHrz8iWXrBAoGBAMJO
Z34pCRfVddFkGF+5yMJw5FLTSLLKTJb+1JRuZad21BIF0+i3p25OmxHrUXd0zmWd
4CzZzt5eD3bFaOA3EOhUi/rTw2O44qwSjfuZUHiuXQw4RI+/wjAYAe+fud1ZjX3d
FtVfEI/etxvyQ+rp4vj1hxWZqVtThzXxBrqePBW1AoGBAOTC19rFQXtVf9A+8c/w
2ryAY2W9qNKe0xMivTAqau0Kdy2/2toJekR/5qOy3tOF7JasOgG+y3m3gLF47EFF
v75eW4FkiCFvsyl/qv4CO1eKnHlvkRoDsnMb+dA5czst58rO6BK40QvPqwXaSxj1
ee8ReNCDhC0Zidczajm63O1G
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

func init() {
	testPort := os.Getenv("TEST_BASEPORT_SMTP")
	if testPort == "" {
		return
	}
	if port, err := strconv.Atoi(testPort); err == nil {
		if port <= 65000 && port > 1023 {
			TestServerPortBase = int32(port)
		}
	}
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
			t.Fatal("expected second server challenge to fail")
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
				ListenPort: serverPort,
			},
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
				ListenPort: serverPort,
			},
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
			t.Fatal("expected second server challenge to fail")
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
				ListenPort: serverPort,
			},
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
				ListenPort: serverPort,
			},
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
				t.Errorf("failed on first server challenge: %s", err)
			}
			if !bytes.Equal([]byte(user), resp) {
				t.Errorf("expected response to first challenge to be: %q, got: %q", user, resp)
			}
			resp, err = auth.Next([]byte(pass), true)
			if err != nil {
				t.Errorf("failed on second server challenge: %s", err)
			}
			if !bytes.Equal([]byte(pass), resp) {
				t.Errorf("expected response to second challenge to be: %q, got: %q", pass, resp)
			}
			_, err = auth.Next([]byte("nonsense"), true)
			if err == nil {
				t.Error("expected third server challenge to fail, but didn't")
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
				ListenPort: serverPort,
			},
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
				ListenPort: serverPort,
			},
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
				t.Errorf("failed on first server challenge: %s", err)
			}
			if !bytes.Equal([]byte(user), resp) {
				t.Errorf("expected response to first challenge to be: %q, got: %q", user, resp)
			}
			resp, err = auth.Next([]byte(pass), true)
			if err != nil {
				t.Errorf("failed on second server challenge: %s", err)
			}
			if !bytes.Equal([]byte(pass), resp) {
				t.Errorf("expected response to second challenge to be: %q, got: %q", pass, resp)
			}
			_, err = auth.Next([]byte("nonsense"), true)
			if err == nil {
				t.Error("expected third server challenge to fail, but didn't")
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
				ListenPort: serverPort,
			},
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
				ListenPort: serverPort,
			},
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
			t.Errorf("failed on first server challenge: %s", err)
		}
		if !bytes.Equal([]byte(""), resp) {
			t.Errorf("expected server response to be empty, got: %q", resp)
		}
		_, err = auth.Next([]byte("nonsense"), false)
		if err != nil {
			t.Errorf("failed on first server challenge: %s", err)
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
				ListenPort: serverPort,
			},
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
				ListenPort: serverPort,
			},
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
				tlsConfig := getTLSConfig(t)
				conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", TestServerAddr, serverPort), tlsConfig)
				if err != nil {
					t.Fatalf("failed to dial TLS server: %v", err)
				}
				client, err = NewClient(conn, TestServerAddr)
				if err != nil {
					t.Fatalf("failed to connect to test server: %s", err)
				}
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
				tlsConfig := getTLSConfig(t)
				conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", TestServerAddr, serverPort), tlsConfig)
				if err != nil {
					t.Fatalf("failed to dial TLS server: %v", err)
				}
				client, err = NewClient(conn, TestServerAddr)
				if err != nil {
					t.Fatalf("failed to connect to test server: %s", err)
				}
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

func TestScramAuth_normalizeString(t *testing.T) {
	t.Run("normalizeString with invalid input should fail", func(t *testing.T) {
		auth := scramAuth{}
		value := "\u0000example\uFFFEstring\u001F"
		_, err := auth.normalizeString(value)
		if err == nil {
			t.Fatal("normalizeString should fail on disallowed runes")
		}
		if !strings.Contains(err.Error(), "precis: disallowed rune encountered") {
			t.Errorf("expected error to be %q, got %q", "precis: disallowed rune encountered", err)
		}
	})
	t.Run("normalizeString on empty string should fail", func(t *testing.T) {
		auth := scramAuth{}
		_, err := auth.normalizeString("")
		if err == nil {
			t.Error("normalizeString should fail on disallowed runes")
		}
		if !strings.Contains(err.Error(), "precis: transformation resulted in empty string") {
			t.Errorf("expected error to be %q, got %q", "precis: transformation resulted in empty string", err)
		}
	})
	t.Run("normalizeUsername with invalid input should fail", func(t *testing.T) {
		auth := scramAuth{username: "\u0000example\uFFFEstring\u001F"}
		_, err := auth.normalizeUsername()
		if err == nil {
			t.Error("normalizeUsername should fail on disallowed runes")
		}
		if !strings.Contains(err.Error(), "precis: disallowed rune encountered") {
			t.Errorf("expected error to be %q, got %q", "precis: disallowed rune encountered", err)
		}
	})
	t.Run("normalizeUsername with empty input should fail", func(t *testing.T) {
		auth := scramAuth{username: ""}
		_, err := auth.normalizeUsername()
		if err == nil {
			t.Error("normalizeUsername should fail on empty input")
		}
		if !strings.Contains(err.Error(), "precis: transformation resulted in empty string") {
			t.Errorf("expected error to be %q, got %q", "precis: transformation resulted in empty string", err)
		}
	})
}

func TestScramAuth_initialClientMessage(t *testing.T) {
	t.Run("initialClientMessage with invalid username should fail", func(t *testing.T) {
		auth := scramAuth{username: "\u0000example\uFFFEstring\u001F"}
		_, err := auth.initialClientMessage()
		if err == nil {
			t.Error("initialClientMessage should fail on disallowed runes")
		}
		if !strings.Contains(err.Error(), "precis: disallowed rune encountered") {
			t.Errorf("expected error to be %q, got %q", "precis: disallowed rune encountered", err)
		}
	})
	t.Run("initialClientMessage with empty username should fail", func(t *testing.T) {
		auth := scramAuth{username: ""}
		_, err := auth.initialClientMessage()
		if err == nil {
			t.Error("initialClientMessage should fail on empty username")
		}
		if !strings.Contains(err.Error(), "precis: transformation resulted in empty string") {
			t.Errorf("expected error to be %q, got %q", "precis: transformation resulted in empty string", err)
		}
	})
	t.Run("initialClientMessage fails on broken rand.Reader", func(t *testing.T) {
		defaultRandReader := rand.Reader
		t.Cleanup(func() { rand.Reader = defaultRandReader })
		rand.Reader = &randReader{}
		auth := scramAuth{username: "username"}
		_, err := auth.initialClientMessage()
		if err == nil {
			t.Error("initialClientMessage should fail with broken rand.Reader")
		}
		if !strings.Contains(err.Error(), "unable to generate client secret: broken reader") {
			t.Errorf("expected error to be %q, got %q", "unable to generate client secret: broken reader", err)
		}
	})
}

func TestScramAuth_handleServerFirstResponse(t *testing.T) {
	t.Run("handleServerFirstResponse fails if not at least 3 parts", func(t *testing.T) {
		auth := scramAuth{}
		_, err := auth.handleServerFirstResponse([]byte("r=0"))
		if err == nil {
			t.Error("handleServerFirstResponse should fail on invalid response")
		}
		expectedErr := "not enough fields in the first server response"
		if !strings.EqualFold(err.Error(), expectedErr) {
			t.Errorf("expected error to be %q, got %q", expectedErr, err)
		}
	})
	t.Run("handleServerFirstResponse fails with first part does not start with r=", func(t *testing.T) {
		auth := scramAuth{}
		_, err := auth.handleServerFirstResponse([]byte("x=0,y=0,z=0,r=0"))
		if err == nil {
			t.Error("handleServerFirstResponse should fail on invalid response")
		}
		expectedErr := "first part of the server response does not start with r="
		if !strings.EqualFold(err.Error(), expectedErr) {
			t.Errorf("expected error to be %q, got %q", expectedErr, err)
		}
	})
	t.Run("handleServerFirstResponse fails with second part does not start with s=", func(t *testing.T) {
		auth := scramAuth{}
		_, err := auth.handleServerFirstResponse([]byte("r=0,x=0,y=0,z=0"))
		if err == nil {
			t.Error("handleServerFirstResponse should fail on invalid response")
		}
		expectedErr := "second part of the server response does not start with s="
		if !strings.EqualFold(err.Error(), expectedErr) {
			t.Errorf("expected error to be %q, got %q", expectedErr, err)
		}
	})
	t.Run("handleServerFirstResponse fails with third part does not start with i=", func(t *testing.T) {
		auth := scramAuth{}
		_, err := auth.handleServerFirstResponse([]byte("r=0,s=0,y=0,z=0"))
		if err == nil {
			t.Error("handleServerFirstResponse should fail on invalid response")
		}
		expectedErr := "third part of the server response does not start with i="
		if !strings.EqualFold(err.Error(), expectedErr) {
			t.Errorf("expected error to be %q, got %q", expectedErr, err)
		}
	})
	t.Run("handleServerFirstResponse fails with empty nonce", func(t *testing.T) {
		auth := scramAuth{}
		_, err := auth.handleServerFirstResponse([]byte("r=,s=0,i=0"))
		if err == nil {
			t.Error("handleServerFirstResponse should fail on invalid response")
		}
		expectedErr := "server nonce does not start with our nonce"
		if !strings.EqualFold(err.Error(), expectedErr) {
			t.Errorf("expected error to be %q, got %q", expectedErr, err)
		}
	})
	t.Run("handleServerFirstResponse fails with non-base64 nonce", func(t *testing.T) {
		auth := scramAuth{nonce: []byte("Test123")}
		_, err := auth.handleServerFirstResponse([]byte("r=Test123,s=0,i=0"))
		if err == nil {
			t.Error("handleServerFirstResponse should fail on invalid response")
		}
		expectedErr := "illegal base64 data at input byte 0"
		if !strings.Contains(err.Error(), expectedErr) {
			t.Errorf("expected error to be %q, got %q", expectedErr, err)
		}
	})
	t.Run("handleServerFirstResponse fails with non-number iterations", func(t *testing.T) {
		auth := scramAuth{nonce: []byte("VGVzdDEyMw==")}
		_, err := auth.handleServerFirstResponse([]byte("r=VGVzdDEyMw==,s=VGVzdDEyMw==,i=abc"))
		if err == nil {
			t.Error("handleServerFirstResponse should fail on invalid response")
		}
		expectedErr := `invalid iterations: strconv.Atoi: parsing "abc": invalid syntax`
		if !strings.Contains(err.Error(), expectedErr) {
			t.Errorf("expected error to be %q, got %q", expectedErr, err)
		}
	})
	t.Run("handleServerFirstResponse fails with invalid password runes", func(t *testing.T) {
		auth := scramAuth{
			nonce:    []byte("VGVzdDEyMw=="),
			username: "username",
			password: "\u0000example\uFFFEstring\u001F",
		}
		_, err := auth.handleServerFirstResponse([]byte("r=VGVzdDEyMw==,s=VGVzdDEyMw==,i=0"))
		if err == nil {
			t.Error("handleServerFirstResponse should fail on invalid response")
		}
		expectedErr := `unable to normalize password: failed to normalize string: precis: disallowed rune encountered`
		if !strings.Contains(err.Error(), expectedErr) {
			t.Errorf("expected error to be %q, got %q", expectedErr, err)
		}
	})
}

func TestCRAMMD5Auth(t *testing.T) {
	t.Run("CRAM-MD5 on test server succeeds", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH CRAM-MD5\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		auth := CRAMMD5Auth("username", "password")
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		if err = client.Auth(auth); err != nil {
			t.Errorf("failed to auth to test server: %s", err)
		}
	})
	t.Run("CRAM-MD5 on test server fails", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH CRAM-MD5\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnAuth: true,
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		auth := CRAMMD5Auth("username", "password")
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		if err = client.Auth(auth); err == nil {
			t.Error("auth should fail on test server")
		}
	})
}

func TestNewClient(t *testing.T) {
	t.Run("new client via Dial succeeds", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to create client: %s", err)
		}
		if err := client.Close(); err != nil {
			t.Errorf("failed to close client: %s", err)
		}
	})
	t.Run("new client via Dial fails on server not started", func(t *testing.T) {
		_, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, 64000))
		if err == nil {
			t.Error("dial on non-existent server should fail")
		}
	})
	t.Run("new client fails on server not available", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnDial: true,
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		_, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err == nil {
			t.Error("connection to non-available server should fail")
		}
	})
	t.Run("new client fails on faker that fails on close", func(t *testing.T) {
		server := "442 service not available\r\n"
		var wrote strings.Builder
		var fake faker
		fake.failOnClose = true
		fake.ReadWriter = struct {
			io.Reader
			io.Writer
		}{
			strings.NewReader(server),
			&wrote,
		}
		_, err := NewClient(fake, "faker.host")
		if err == nil {
			t.Error("connection to non-available server should fail on close")
		}
	})
}

func TestClient_hello(t *testing.T) {
	t.Run("client fails on EHLO but not on HELO", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnEhlo: true,
				FailOnHelo: true,
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		if err = client.hello(); err == nil {
			t.Error("helo should fail on test server")
		}
	})
}

func TestClient_Hello(t *testing.T) {
	t.Run("normal client HELO/EHLO", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		if err = client.Hello(TestServerAddr); err != nil {
			t.Errorf("failed to send HELO/EHLO to test server: %s", err)
		}
	})
	t.Run("client HELO/EHLO with empty name should fail", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		if err = client.Hello(""); err == nil {
			t.Error("HELO/EHLO with empty name should fail")
		}
	})
	t.Run("client HELO/EHLO with newline in name should fail", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Errorf("failed to dial to test server: %s", err)
		}
		if err = client.Hello(TestServerAddr + "\r\n"); err == nil {
			t.Error("HELO/EHLO with newline should fail")
		}
	})
	t.Run("client double HELO/EHLO should fail", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		if err = client.Hello(TestServerAddr); err != nil {
			t.Errorf("failed to send HELO/EHLO to test server: %s", err)
		}
		if err = client.Hello(TestServerAddr); err == nil {
			t.Error("double HELO/EHLO should fail")
		}
	})
}

func TestClient_cmd(t *testing.T) {
	t.Run("cmd fails on textproto cmd", func(t *testing.T) {
		server := "220 server ready\r\n"
		var fake faker
		fake.failOnClose = true
		fake.ReadWriter = struct {
			io.Reader
			io.Writer
		}{
			strings.NewReader(server),
			&failWriter{},
		}
		client, err := NewClient(fake, "faker.host")
		if err != nil {
			t.Errorf("failed to create client: %s", err)
		}
		_, _, err = client.cmd(250, "HELO faker.host")
		if err == nil {
			t.Error("cmd should fail on textproto cmd with broken writer")
		}
	})
}

func TestClient_StartTLS(t *testing.T) {
	t.Run("normal STARTTLS should succeed", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-STARTTLS\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		tlsConfig := getTLSConfig(t)
		if err = client.StartTLS(tlsConfig); err != nil {
			t.Errorf("failed to initialize STARTTLS session: %s", err)
		}
	})
	t.Run("STARTTLS fails on EHLO/HELO", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-STARTTLS\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnEhlo: true,
				FailOnHelo: true,
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		tlsConfig := getTLSConfig(t)
		if err = client.StartTLS(tlsConfig); err == nil {
			t.Error("STARTTLS should fail on EHLO")
		}
	})
	t.Run("STARTTLS fails on server not supporting STARTTLS", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnSTARTTLS: true,
				FeatureSet:     featureSet,
				ListenPort:     serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		tlsConfig := getTLSConfig(t)
		if err = client.StartTLS(tlsConfig); err == nil {
			t.Error("STARTTLS should fail for server not supporting it")
		}
	})
}

func TestClient_TLSConnectionState(t *testing.T) {
	t.Run("normal TLS connection should return a state", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-STARTTLS\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		tlsConfig := getTLSConfig(t)
		tlsConfig.MinVersion = tls.VersionTLS12
		if err = client.StartTLS(tlsConfig); err != nil {
			t.Errorf("failed to initialize STARTTLS session: %s", err)
		}
		state, ok := client.TLSConnectionState()
		if !ok {
			t.Errorf("failed to get TLS connection state")
		}
		if state.Version < tls.VersionTLS12 {
			t.Errorf("TLS connection state version is %d, should be >= %d", state.Version, tls.VersionTLS12)
		}
	})
	t.Run("no TLS state on non-TLS connection", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-STARTTLS\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		_, ok := client.TLSConnectionState()
		if ok {
			t.Error("non-TLS connection should not have TLS connection state")
		}
	})
}

func TestClient_Verify(t *testing.T) {
	t.Run("Verify on existing user succeeds", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-STARTTLS\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.Verify("toni.tester@example.com"); err != nil {
			t.Errorf("failed to verify user: %s", err)
		}
	})
	t.Run("Verify on non-existing user fails", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-STARTTLS\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet:      featureSet,
				ListenPort:      serverPort,
				VRFYUserUnknown: true,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.Verify("toni.tester@example.com"); err == nil {
			t.Error("verify on non-existing user should fail")
		}
	})
	t.Run("Verify with newlines should fails", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-STARTTLS\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.Verify("toni.tester@example.com\r\n"); err == nil {
			t.Error("verify with new lines should fail")
		}
	})
	t.Run("Verify should fail on HELO/EHLO", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-STARTTLS\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnEhlo: true,
				FailOnHelo: true,
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.Verify("toni.tester@example.com"); err == nil {
			t.Error("verify with new lines should fail")
		}
	})
}

func TestClient_Auth(t *testing.T) {
	t.Run("Auth fails on EHLO/HELO", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-STARTTLS\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnEhlo: true,
				FailOnHelo: true,
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		auth := LoginAuth("username", "password", TestServerAddr, false)
		if err = client.Auth(auth); err == nil {
			t.Error("auth should fail on EHLO/HELO")
		}
	})
	t.Run("Auth fails on auth-start", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-STARTTLS\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnAuth: true,
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		auth := LoginAuth("username", "password", "not.localhost.com", false)
		if err = client.Auth(auth); err == nil {
			t.Error("auth should fail on auth-start, then on quit")
		}
		expErr := "wrong host name"
		if !strings.EqualFold(expErr, err.Error()) {
			t.Errorf("expected error: %q, got: %q", expErr, err.Error())
		}
	})
	t.Run("Auth fails on auth-start and then on quit", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-STARTTLS\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnAuth: true,
				FailOnQuit: true,
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		auth := LoginAuth("username", "password", "not.localhost.com", false)
		if err = client.Auth(auth); err == nil {
			t.Error("auth should fail on auth-start, then on quit")
		}
		expErr := "wrong host name, 500 5.1.2 Error: quit failed"
		if !strings.EqualFold(expErr, err.Error()) {
			t.Errorf("expected error: %q, got: %q", expErr, err.Error())
		}
	})
	// Issue 17794: don't send a trailing space on AUTH command when there's no password.
	t.Run("No trailing space on AUTH when there is no password (Issue 17794)", func(t *testing.T) {
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
		if err = c.Close(); err != nil {
			t.Errorf("close failed: %s", err)
		}
		if got, want := wrote.String(), "AUTH FOOAUTH\r\n*\r\nQUIT\r\n"; got != want {
			t.Errorf("wrote %q; want %q", got, want)
		}
	})
}

func TestClient_errorRegistryHandler(t *testing.T) {
	t.Run("quit fails on short response (simulate qq.com behaviour)", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet:            featureSet,
				ListenPort:            serverPort,
				SimulateShortResponse: true,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.Hello("test.domain.tld"); err != nil {
			t.Errorf("SMTP hello failed: %s", err)
		}
		if err = client.Quit(); err == nil {
			t.Error("expected short response error on quit, but got nothing")
		}
	})
	t.Run("error registry handles short response (simulate qq.com behaviour)", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet:            featureSet,
				ListenPort:            serverPort,
				SimulateShortResponse: true,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		client.ErrorHandlerRegistry.RegisterHandler(TestServerAddr, "quit", &testRegistryErrorHandler{})
		if err = client.Hello("test.domain.tld"); err != nil {
			t.Errorf("SMTP hello failed: %s", err)
		}
		if err = client.Quit(); err != nil {
			t.Errorf("SMTP quit failed: %s", err)
		}
	})
}

func TestClient_Mail(t *testing.T) {
	t.Run("normal from address succeeds", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		fromAddr, err := netmail.ParseAddress("valid-from@domain.tld")
		if err != nil {
			t.Fatalf("failed to parse from address: %s", err)
		}
		if err = client.Mail(fromAddr.String()); err != nil {
			t.Errorf("failed to set mail from address: %s", err)
		}
	})
	t.Run("from address with new lines fails", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.Mail("valid-from@domain.tld\r\n"); err == nil {
			t.Error("mail from address with new lines should fail")
		}
	})
	t.Run("from address fails on EHLO/HELO", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnEhlo: true,
				FailOnHelo: true,
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.Mail("valid-from@domain.tld"); err == nil {
			t.Error("mail from address should fail on EHLO/HELO")
		}
	})
	t.Run("from address and server supports 8BITMIME", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250 STARTTLS"
		echoBuffer := bytes.NewBuffer(nil)
		props := &serverProps{
			EchoBuffer: echoBuffer,
			FeatureSet: featureSet,
			ListenPort: serverPort,
		}
		go func() {
			if err := simpleSMTPServer(ctx, t, props); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		fromAddr, err := netmail.ParseAddress("valid-from@domain.tld")
		if err != nil {
			t.Fatalf("failed to parse from address: %s", err)
		}
		if err = client.Mail(fromAddr.String()); err != nil {
			t.Errorf("failed to set mail from address: %s", err)
		}
		expected := "MAIL FROM:<valid-from@domain.tld> BODY=8BITMIME"
		props.BufferMutex.RLock()
		resp := strings.Split(echoBuffer.String(), "\r\n")
		props.BufferMutex.RUnlock()
		if !strings.EqualFold(resp[5], expected) {
			t.Errorf("expected mail from command to be %q, but sent %q", expected, resp[5])
		}
	})
	t.Run("from address and server supports SMTPUTF8", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-SMTPUTF8\r\n250 STARTTLS"
		echoBuffer := bytes.NewBuffer(nil)
		props := &serverProps{
			EchoBuffer: echoBuffer,
			FeatureSet: featureSet,
			ListenPort: serverPort,
		}
		go func() {
			if err := simpleSMTPServer(ctx, t, props); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		fromAddr, err := netmail.ParseAddress("valid-from@domain.tld")
		if err != nil {
			t.Fatalf("failed to parse from address: %s", err)
		}
		if err = client.Mail(fromAddr.String()); err != nil {
			t.Errorf("failed to set mail from address: %s", err)
		}
		expected := "MAIL FROM:<valid-from@domain.tld> SMTPUTF8"
		props.BufferMutex.RLock()
		resp := strings.Split(echoBuffer.String(), "\r\n")
		props.BufferMutex.RUnlock()
		if !strings.EqualFold(resp[5], expected) {
			t.Errorf("expected mail from command to be %q, but sent %q", expected, resp[5])
		}
	})
	t.Run("from address and server supports SMTPUTF8 with unicode address", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-SMTPUTF8\r\n250 STARTTLS"
		echoBuffer := bytes.NewBuffer(nil)
		props := &serverProps{
			EchoBuffer: echoBuffer,
			FeatureSet: featureSet,
			ListenPort: serverPort,
		}
		go func() {
			if err := simpleSMTPServer(ctx, t, props); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		fromAddr, err := netmail.ParseAddress("valid-from+📧@domain.tld")
		if err != nil {
			t.Fatalf("failed to parse from address: %s", err)
		}
		if err = client.Mail(fromAddr.String()); err != nil {
			t.Errorf("failed to set mail from address: %s", err)
		}
		expected := "MAIL FROM:<valid-from+📧@domain.tld> SMTPUTF8"
		props.BufferMutex.RLock()
		resp := strings.Split(echoBuffer.String(), "\r\n")
		props.BufferMutex.RUnlock()
		if !strings.EqualFold(resp[5], expected) {
			t.Errorf("expected mail from command to be %q, but sent %q", expected, resp[5])
		}
	})
	t.Run("from address and server supports DSN", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250 STARTTLS"
		echoBuffer := bytes.NewBuffer(nil)
		props := &serverProps{
			EchoBuffer: echoBuffer,
			FeatureSet: featureSet,
			ListenPort: serverPort,
		}
		go func() {
			if err := simpleSMTPServer(ctx, t, props); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		client.dsnmrtype = "FULL"
		fromAddr, err := netmail.ParseAddress("valid-from@domain.tld")
		if err != nil {
			t.Fatalf("failed to parse from address: %s", err)
		}
		if err = client.Mail(fromAddr.String()); err != nil {
			t.Errorf("failed to set mail from address: %s", err)
		}
		expected := "MAIL FROM:<valid-from@domain.tld> RET=FULL"
		props.BufferMutex.RLock()
		resp := strings.Split(echoBuffer.String(), "\r\n")
		props.BufferMutex.RUnlock()
		if !strings.EqualFold(resp[5], expected) {
			t.Errorf("expected mail from command to be %q, but sent %q", expected, resp[5])
		}
	})
	t.Run("from address and server supports DSN, SMTPUTF8 and 8BITMIME", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250-8BITMIME\r\n250-SMTPUTF8\r\n250 STARTTLS"
		echoBuffer := bytes.NewBuffer(nil)
		props := &serverProps{
			EchoBuffer: echoBuffer,
			FeatureSet: featureSet,
			ListenPort: serverPort,
		}
		go func() {
			if err := simpleSMTPServer(ctx, t, props); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		client.dsnmrtype = "FULL"
		fromAddr, err := netmail.ParseAddress("valid-from@domain.tld")
		if err != nil {
			t.Fatalf("failed to parse from address: %s", err)
		}
		if err = client.Mail(fromAddr.String()); err != nil {
			t.Errorf("failed to set mail from address: %s", err)
		}
		expected := "MAIL FROM:<valid-from@domain.tld> BODY=8BITMIME SMTPUTF8 RET=FULL"
		props.BufferMutex.RLock()
		resp := strings.Split(echoBuffer.String(), "\r\n")
		props.BufferMutex.RUnlock()
		if !strings.EqualFold(resp[7], expected) {
			t.Errorf("expected mail from command to be %q, but sent %q", expected, resp[7])
		}
	})
}

func TestClient_Rcpt(t *testing.T) {
	t.Run("normal recipient address succeeds", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250-8BITMIME\r\n250-SMTPUTF8\r\n250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		addr, err := netmail.ParseAddress("valid-to@domain.tld")
		if err != nil {
			t.Fatalf("failed to parse recipient address: %s", err)
		}
		if err = client.Rcpt(addr.String()); err != nil {
			t.Errorf("failed to set recipient address: %s", err)
		}
	})
	t.Run("recipient address with newlines fails", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.Rcpt("valid-to@domain.tld\r\n"); err == nil {
			t.Error("recpient address with newlines should fail")
		}
	})
	t.Run("recipient address with DSN", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250 STARTTLS"
		echoBuffer := bytes.NewBuffer(nil)
		props := &serverProps{
			EchoBuffer: echoBuffer,
			FeatureSet: featureSet,
			ListenPort: serverPort,
		}
		go func() {
			if err := simpleSMTPServer(ctx, t, props); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.Hello(TestServerAddr); err != nil {
			t.Fatalf("failed to send hello to test server: %s", err)
		}
		client.dsnrntype = "SUCCESS"
		addr, err := netmail.ParseAddress("valid-to@domain.tld")
		if err != nil {
			t.Fatalf("failed to parse recipient address: %s", err)
		}
		if err = client.Rcpt(addr.String()); err == nil {
			t.Error("recpient address with newlines should fail")
		}
		expected := "RCPT TO:<valid-to@domain.tld> NOTIFY=SUCCESS"
		props.BufferMutex.RLock()
		resp := strings.Split(echoBuffer.String(), "\r\n")
		props.BufferMutex.RUnlock()
		if !strings.EqualFold(resp[5], expected) {
			t.Errorf("expected rcpt to command to be %q, but sent %q", expected, resp[5])
		}
	})
}

func TestClient_Data(t *testing.T) {
	t.Run("normal mail data transmission succeeds", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		writer, err := client.Data()
		if err != nil {
			t.Fatalf("failed to create data writer: %s", err)
		}
		t.Cleanup(func() {
			if err = writer.Close(); err != nil {
				t.Errorf("failed to close data writer: %s", err)
			}
		})
		if _, err = writer.Write([]byte("test message")); err != nil {
			t.Errorf("failed to write data to test server: %s", err)
		}
	})
	t.Run("mail data transmission fails on DATA command", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnDataInit: true,
				FeatureSet:     featureSet,
				ListenPort:     serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if _, err = client.Data(); err == nil {
			t.Error("expected data writer to fail")
		}
	})
}

func TestDataCloser_ServerResponse(t *testing.T) {
	t.Run("successful delivery returns server response", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		writer, err := client.Data()
		if err != nil {
			t.Fatalf("failed to create data writer: %s", err)
		}
		if _, err = writer.Write([]byte("test message")); err != nil {
			t.Errorf("failed to write data to test server: %s", err)
		}
		if err = writer.Close(); err != nil {
			t.Errorf("failed to close data writer: %s", err)
		}
		dataCloser, ok := writer.(*DataCloser)
		if !ok {
			t.Fatalf("failed to cast writer to DataCloser")
		}
		exp := "2.0.0 Ok: queued as 1234567890"
		if !strings.EqualFold(dataCloser.ServerResponse(), exp) {
			t.Errorf("expected server response to be %q, but got %q", exp, dataCloser.ServerResponse())
		}
	})
	t.Run("unclosed datacloser returns empty server response", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		writer, err := client.Data()
		if err != nil {
			t.Fatalf("failed to create data writer: %s", err)
		}
		if _, err = writer.Write([]byte("test message")); err != nil {
			t.Errorf("failed to write data to test server: %s", err)
		}
		dataCloser, ok := writer.(*DataCloser)
		if !ok {
			t.Fatalf("failed to cast writer to DataCloser")
		}
		if dataCloser.ServerResponse() != "" {
			t.Errorf("expected empty server response but got %q", dataCloser.ServerResponse())
		}
		if err = writer.Close(); err != nil {
			t.Errorf("failed to close data writer: %s", err)
		}
	})
}

func TestSendMail(t *testing.T) {
	tests := []struct {
		name       string
		featureSet string
		hostname   string
		tlsConfig  *tls.Config
		props      *serverProps
		fromAddr   string
		toAddr     string
		message    []byte
	}{
		{
			"fail on newline in MAIL FROM address",
			"250-AUTH LOGIN\r\n250-DSN\r\n250 STARTTLS",
			TestServerAddr,
			getTLSConfig(t),
			&serverProps{},
			"valid-from@domain.tld\r\n",
			"valid-to@domain.tld",
			[]byte("test message"),
		},
		{
			"fail on newline in RCPT TO address",
			"250-AUTH LOGIN\r\n250-DSN\r\n250 STARTTLS",
			TestServerAddr,
			getTLSConfig(t),
			&serverProps{},
			"valid-from@domain.tld",
			"valid-to@domain.tld\r\n",
			[]byte("test message"),
		},
		{
			"fail on invalid host address",
			"250-AUTH LOGIN\r\n250-DSN\r\n250 STARTTLS",
			"invalid.invalid-host@domain.tld",
			getTLSConfig(t),
			&serverProps{},
			"valid-from@domain.tld",
			"valid-to@domain.tld",
			[]byte("test message"),
		},
		{
			"fail on EHLO/HELO",
			"250-AUTH LOGIN\r\n250-DSN\r\n250 STARTTLS",
			TestServerAddr,
			getTLSConfig(t),
			&serverProps{FailOnEhlo: true, FailOnHelo: true},
			"valid-from@domain.tld",
			"valid-to@domain.tld",
			[]byte("test message"),
		},
		{
			"fail on STARTTLS",
			"250-AUTH LOGIN\r\n250-DSN\r\n250 STARTTLS",
			TestServerAddr,
			&tls.Config{ServerName: "invalid.invalid-host@domain.tld"},
			&serverProps{},
			"valid-from@domain.tld",
			"valid-to@domain.tld",
			[]byte("test message"),
		},
		{
			"fail on no server AUTH support",
			"250-DSN\r\n250 STARTTLS",
			TestServerAddr,
			getTLSConfig(t),
			&serverProps{},
			"valid-from@domain.tld",
			"valid-to@domain.tld",
			[]byte("test message"),
		},
		{
			"fail on AUTH",
			"250-AUTH LOGIN\r\n250-DSN\r\n250 STARTTLS",
			TestServerAddr,
			getTLSConfig(t),
			&serverProps{FailOnAuth: true},
			"valid-from@domain.tld",
			"valid-to@domain.tld",
			[]byte("test message"),
		},
		{
			"fail on MAIL FROM",
			"250-AUTH LOGIN\r\n250-DSN\r\n250 STARTTLS",
			TestServerAddr,
			getTLSConfig(t),
			&serverProps{FailOnMailFrom: true},
			"valid-from@domain.tld",
			"valid-to@domain.tld",
			[]byte("test message"),
		},
		{
			"fail on RCPT TO",
			"250-AUTH LOGIN\r\n250-DSN\r\n250 STARTTLS",
			TestServerAddr,
			getTLSConfig(t),
			&serverProps{FailOnRcptTo: true},
			"valid-from@domain.tld",
			"valid-to@domain.tld",
			[]byte("test message"),
		},
		{
			"fail on DATA (init phase)",
			"250-AUTH LOGIN\r\n250-DSN\r\n250 STARTTLS",
			TestServerAddr,
			getTLSConfig(t),
			&serverProps{FailOnDataInit: true},
			"valid-from@domain.tld",
			"valid-to@domain.tld",
			[]byte("test message"),
		},
		{
			"fail on DATA (closing phase)",
			"250-AUTH LOGIN\r\n250-DSN\r\n250 STARTTLS",
			TestServerAddr,
			getTLSConfig(t),
			&serverProps{FailOnDataClose: true},
			"valid-from@domain.tld",
			"valid-to@domain.tld",
			[]byte("test message"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			PortAdder.Add(1)
			tt.props.ListenPort = int(TestServerPortBase + PortAdder.Load())
			tt.props.FeatureSet = tt.featureSet
			go func() {
				if err := simpleSMTPServer(ctx, t, tt.props); err != nil {
					t.Errorf("failed to start test server: %s", err)
					return
				}
			}()
			time.Sleep(time.Millisecond * 30)
			addr := fmt.Sprintf("%s:%d", tt.hostname, tt.props.ListenPort)
			testHookStartTLS = func(config *tls.Config) {
				config.ServerName = tt.tlsConfig.ServerName
				config.RootCAs = tt.tlsConfig.RootCAs
				config.Certificates = tt.tlsConfig.Certificates
			}
			auth := LoginAuth("username", "password", TestServerAddr, false)
			if err := SendMail(addr, auth, tt.fromAddr, []string{tt.toAddr}, tt.message); err == nil {
				t.Error("expected SendMail to " + tt.name)
			}
		})
	}
	t.Run("full SendMail transaction with TLS and auth", func(t *testing.T) {
		want := []string{
			"220 go-mail test server ready ESMTP",
			"EHLO localhost",
			"250-localhost.localdomain",
			"250-AUTH LOGIN",
			"250-DSN",
			"250 STARTTLS",
			"STARTTLS",
			"220 Ready to start TLS",
			"EHLO localhost",
			"250-localhost.localdomain",
			"250-AUTH LOGIN",
			"250-DSN",
			"250 STARTTLS",
			"AUTH LOGIN",
			"235 2.7.0 Authentication successful",
			"MAIL FROM:<valid-from@domain.tld>",
			"250 2.0.0 OK",
			"RCPT TO:<valid-to@domain.tld>",
			"250 2.0.0 OK",
			"DATA",
			"354 End data with <CR><LF>.<CR><LF>",
			"test message",
			".",
			"250 2.0.0 Ok: queued as 1234567890",
			"QUIT",
			"221 2.0.0 Bye",
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH LOGIN\r\n250-DSN\r\n250 STARTTLS"
		echoBuffer := bytes.NewBuffer(nil)
		props := &serverProps{
			EchoBuffer: echoBuffer,
			FeatureSet: featureSet,
			ListenPort: serverPort,
		}
		go func() {
			if err := simpleSMTPServer(ctx, t, props); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		addr := fmt.Sprintf("%s:%d", TestServerAddr, serverPort)
		testHookStartTLS = func(config *tls.Config) {
			testConfig := getTLSConfig(t)
			config.ServerName = testConfig.ServerName
			config.RootCAs = testConfig.RootCAs
			config.Certificates = testConfig.Certificates
		}
		fromAddr, err := netmail.ParseAddress("valid-from@domain.tld")
		if err != nil {
			t.Fatalf("failed to parse from address: %s", err)
		}
		auth := LoginAuth("username", "password", TestServerAddr, false)
		toAddr, err := netmail.ParseAddress("valid-to@domain.tld")
		if err != nil {
			t.Fatalf("failed to parse recipient address: %s", err)
		}
		if err := SendMail(addr, auth, fromAddr.String(), []string{toAddr.String()},
			[]byte("test message")); err != nil {
			t.Fatalf("failed to send mail: %s", err)
		}
		props.BufferMutex.RLock()
		resp := strings.Split(echoBuffer.String(), "\r\n")
		props.BufferMutex.RUnlock()
		if len(resp)-1 != len(want) {
			t.Fatalf("expected %d lines, but got %d", len(want), len(resp))
		}
		for i := 0; i < len(want); i++ {
			if !strings.EqualFold(resp[i], want[i]) {
				t.Errorf("expected line %d to be %q, but got %q", i, resp[i], want[i])
			}
		}
	})
	t.Run("full SendMail transaction with leading dots", func(t *testing.T) {
		want := []string{
			"220 go-mail test server ready ESMTP",
			"EHLO localhost",
			"250-localhost.localdomain",
			"250-AUTH LOGIN",
			"250-DSN",
			"250 STARTTLS",
			"STARTTLS",
			"220 Ready to start TLS",
			"EHLO localhost",
			"250-localhost.localdomain",
			"250-AUTH LOGIN",
			"250-DSN",
			"250 STARTTLS",
			"AUTH LOGIN",
			"235 2.7.0 Authentication successful",
			"MAIL FROM:<valid-from@domain.tld>",
			"250 2.0.0 OK",
			"RCPT TO:<valid-to@domain.tld>",
			"250 2.0.0 OK",
			"DATA",
			"354 End data with <CR><LF>.<CR><LF>",
			"From: user@gmail.com",
			"To: golang-nuts@googlegroups.com",
			"Subject: Hooray for Go",
			"",
			"Line 1",
			"..Leading dot line .",
			"Goodbye.",
			".",
			"250 2.0.0 Ok: queued as 1234567890",
			"QUIT",
			"221 2.0.0 Bye",
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH LOGIN\r\n250-DSN\r\n250 STARTTLS"
		echoBuffer := bytes.NewBuffer(nil)
		props := &serverProps{
			EchoBuffer: echoBuffer,
			FeatureSet: featureSet,
			ListenPort: serverPort,
		}
		go func() {
			if err := simpleSMTPServer(ctx, t, props); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		addr := fmt.Sprintf("%s:%d", TestServerAddr, serverPort)
		testHookStartTLS = func(config *tls.Config) {
			testConfig := getTLSConfig(t)
			config.ServerName = testConfig.ServerName
			config.RootCAs = testConfig.RootCAs
			config.Certificates = testConfig.Certificates
		}
		message := []byte(`From: user@gmail.com
To: golang-nuts@googlegroups.com
Subject: Hooray for Go

Line 1
.Leading dot line .
Goodbye.`)
		fromAddr, err := netmail.ParseAddress("valid-from@domain.tld")
		if err != nil {
			t.Fatalf("failed to parse from address: %s", err)
		}
		toAddr, err := netmail.ParseAddress("valid-to@domain.tld")
		if err != nil {
			t.Fatalf("failed to parse recipient address: %s", err)
		}
		auth := LoginAuth("username", "password", TestServerAddr, false)
		if err = SendMail(addr, auth, fromAddr.String(), []string{toAddr.String()}, message); err != nil {
			t.Fatalf("failed to send mail: %s", err)
		}
		props.BufferMutex.RLock()
		resp := strings.Split(echoBuffer.String(), "\r\n")
		props.BufferMutex.RUnlock()
		if len(resp)-1 != len(want) {
			t.Errorf("expected %d lines, but got %d", len(want), len(resp))
		}
		for i := 0; i < len(want); i++ {
			if !strings.EqualFold(resp[i], want[i]) {
				t.Errorf("expected line %d to be %q, but got %q", i, resp[i], want[i])
			}
		}
	})
}

func TestClient_Extension(t *testing.T) {
	t.Run("extension check fails on EHLO/HELO", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnEhlo: true,
				FailOnHelo: true,
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if ok, _ := client.Extension("DSN"); ok {
			t.Error("expected client extension check to fail on EHLO/HELO")
		}
	})
}

func TestClient_Reset(t *testing.T) {
	t.Run("reset on functioning client conneciton", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.Reset(); err != nil {
			t.Errorf("failed to reset client: %s", err)
		}
	})
	t.Run("reset fails on RSET", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnReset: true,
				FeatureSet:  featureSet,
				ListenPort:  serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.Reset(); err == nil {
			t.Error("expected client reset to fail")
		}
	})
	t.Run("reset fails on EHLO/HELO", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnEhlo: true,
				FailOnHelo: true,
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.Reset(); err == nil {
			t.Error("expected client reset to fail")
		}
	})
}

func TestClient_Noop(t *testing.T) {
	t.Run("noop on functioning client conneciton", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.Noop(); err != nil {
			t.Errorf("failed client no-operation: %s", err)
		}
	})
	t.Run("noop fails on EHLO/HELO", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnEhlo: true,
				FailOnHelo: true,
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.Noop(); err == nil {
			t.Error("expected client no-operation to fail")
		}
	})
	t.Run("noop fails on NOOP", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnNoop: true,
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.Noop(); err == nil {
			t.Error("expected client no-operation to fail")
		}
	})
}

func TestClient_SetDebugLog(t *testing.T) {
	t.Run("set debug loggging to on with no logger defined", func(t *testing.T) {
		client := &Client{}
		client.SetDebugLog(true)
		if !client.debug {
			t.Fatalf("expected debug log to be true")
		}
		if client.logger == nil {
			t.Fatalf("expected logger to be defined")
		}
		if !strings.EqualFold(fmt.Sprintf("%T", client.logger), "*log.Stdlog") {
			t.Errorf("expected logger to be of type *log.Stdlog, got: %T", client.logger)
		}
	})
	t.Run("set debug loggging to off with no logger defined", func(t *testing.T) {
		client := &Client{}
		client.SetDebugLog(false)
		if client.debug {
			t.Fatalf("expected debug log to be false")
		}
		if client.logger != nil {
			t.Fatalf("expected logger to be nil")
		}
	})
	t.Run("set active logging to off should cancel out logger", func(t *testing.T) {
		client := &Client{debug: true, logger: log.New(os.Stderr, log.LevelDebug)}
		client.SetDebugLog(false)
		if client.debug {
			t.Fatalf("expected debug log to be false")
		}
		if client.logger != nil {
			t.Fatalf("expected logger to be nil")
		}
	})
}

func TestClient_SetDebugLog_JSON(t *testing.T) {
	t.Run("set debug loggging to on should not override logger", func(t *testing.T) {
		client := &Client{logger: log.NewJSON(os.Stderr, log.LevelDebug)}
		client.SetDebugLog(true)
		if !client.debug {
			t.Fatalf("expected debug log to be true")
		}
		if client.logger == nil {
			t.Fatalf("expected logger to be defined")
		}
		if !strings.EqualFold(fmt.Sprintf("%T", client.logger), "*log.JSONlog") {
			t.Errorf("expected logger to be of type *log.JSONlog, got: %T", client.logger)
		}
	})
}

func TestClient_SetLogger_JSON(t *testing.T) {
	t.Run("set logger to JSONlog logger", func(t *testing.T) {
		client := &Client{}
		client.SetLogger(log.NewJSON(os.Stderr, log.LevelDebug))
		if !strings.EqualFold(fmt.Sprintf("%T", client.logger), "*log.JSONlog") {
			t.Errorf("expected logger to be of type *log.JSONlog, got: %T", client.logger)
		}
	})
	t.Run("nil logger should just return and not set/override", func(t *testing.T) {
		client := &Client{logger: log.NewJSON(os.Stderr, log.LevelDebug)}
		client.SetLogger(nil)
		if !strings.EqualFold(fmt.Sprintf("%T", client.logger), "*log.JSONlog") {
			t.Errorf("expected logger to be of type *log.JSONlog, got: %T", client.logger)
		}
	})
}

func TestClient_SetLogger(t *testing.T) {
	t.Run("set logger to Stdlog logger", func(t *testing.T) {
		client := &Client{}
		client.SetLogger(log.New(os.Stderr, log.LevelDebug))
		if !strings.EqualFold(fmt.Sprintf("%T", client.logger), "*log.Stdlog") {
			t.Errorf("expected logger to be of type *log.Stdlog, got: %T", client.logger)
		}
	})
}

func TestClient_SetLogAuthData(t *testing.T) {
	t.Run("set log auth data to true", func(t *testing.T) {
		client := &Client{}
		client.SetLogAuthData()
		if !client.logAuthData {
			t.Fatalf("expected log auth data to be true")
		}
	})
}

func TestClient_SetDSNRcptNotifyOption(t *testing.T) {
	tests := []string{"NEVER", "SUCCESS", "FAILURE", "DELAY"}
	for _, test := range tests {
		t.Run("set dsn rcpt notify option to "+test, func(t *testing.T) {
			client := &Client{}
			client.SetDSNRcptNotifyOption(test)
			if !strings.EqualFold(client.dsnrntype, test) {
				t.Errorf("expected dsn rcpt notify option to be %s, got %s", test, client.dsnrntype)
			}
		})
	}
}

func TestClient_SetDSNMailReturnOption(t *testing.T) {
	tests := []string{"HDRS", "FULL"}
	for _, test := range tests {
		t.Run("set dsn mail return option to "+test, func(t *testing.T) {
			client := &Client{}
			client.SetDSNMailReturnOption(test)
			if !strings.EqualFold(client.dsnmrtype, test) {
				t.Errorf("expected dsn mail return option to be %s, got %s", test, client.dsnmrtype)
			}
		})
	}
}

func TestClient_HasConnection(t *testing.T) {
	t.Run("client has connection", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if !client.HasConnection() {
			t.Error("expected client to have a connection")
		}
	})
	t.Run("client has no connection", func(t *testing.T) {
		client := &Client{}
		if client.HasConnection() {
			t.Error("expected client to have no connection")
		}
	})
	t.Run("client has no connection after close", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		if err = client.Close(); err != nil {
			t.Errorf("failed to close client: %s", err)
		}
		if client.HasConnection() {
			t.Error("expected client to have no connection after close")
		}
	})
	t.Run("client has no connection after quit", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		if err = client.Quit(); err != nil {
			t.Errorf("failed to quit client: %s", err)
		}
		if client.HasConnection() {
			t.Error("expected client to have no connection after quit")
		}
	})
}

func TestClient_UpdateDeadline(t *testing.T) {
	t.Run("update deadline on sane client succeeds", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.UpdateDeadline(time.Millisecond * 500); err != nil {
			t.Errorf("failed to update connection deadline: %s", err)
		}
	})
	t.Run("update deadline on no connection should fail", func(t *testing.T) {
		client := &Client{}
		var err error
		if err = client.UpdateDeadline(time.Millisecond * 500); err == nil {
			t.Error("expected client deadline update to fail on no connection")
		}
		expError := "smtp: client has no connection"
		if !strings.EqualFold(err.Error(), expError) {
			t.Errorf("expected error to be %q, got: %q", expError, err)
		}
	})
	t.Run("update deadline on closed client should fail", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		if err = client.Close(); err != nil {
			t.Errorf("failed to close client: %s", err)
		}
		if err = client.UpdateDeadline(time.Millisecond * 500); err == nil {
			t.Error("expected client deadline update to fail on closed client")
		}
	})
}

func TestClient_GetTLSConnectionState(t *testing.T) {
	t.Run("get state on sane client connection", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250 STARTTLS"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		tlsConfig := getTLSConfig(t)
		tlsConfig.MinVersion = tls.VersionTLS12
		tlsConfig.MaxVersion = tls.VersionTLS12
		if err = client.StartTLS(tlsConfig); err != nil {
			t.Fatalf("failed to start TLS on client: %s", err)
		}
		state, err := client.GetTLSConnectionState()
		if err != nil {
			t.Fatalf("failed to get TLS connection state: %s", err)
		}
		if state == nil {
			t.Fatal("expected TLS connection state to be non-nil")
		}
		if state.Version != tls.VersionTLS12 {
			t.Errorf("expected TLS connection state version to be %d, got: %d", tls.VersionTLS12, state.Version)
		}
	})
	t.Run("get state on no connection", func(t *testing.T) {
		client := &Client{}
		_, err := client.GetTLSConnectionState()
		if err == nil {
			t.Fatal("expected client to have no tls connection state")
		}
	})
	t.Run("get state on non-tls client connection", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250 DSN"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		_, err = client.GetTLSConnectionState()
		if err == nil {
			t.Error("expected client to have no tls connection state")
		}
	})
	t.Run("fail to get state on non-tls connection with tls flag set", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250 DSN"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			},
			); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		client, err := Dial(fmt.Sprintf("%s:%d", TestServerAddr, serverPort))
		if err != nil {
			t.Fatalf("failed to dial to test server: %s", err)
		}
		client.tls = true
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		_, err = client.GetTLSConnectionState()
		if err == nil {
			t.Error("expected client to have no tls connection state")
		}
	})
}

func TestClient_debugLog(t *testing.T) {
	t.Run("debug log is enabled", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		logger := log.New(buffer, log.LevelDebug)
		client := &Client{logger: logger, debug: true}
		client.debugLog(log.DirClientToServer, "%s", "simple string")
		client.debugLog(log.DirServerToClient, "%d", 1234)
		want := "DEBUG: C --> S: simple string"
		if !strings.Contains(buffer.String(), want) {
			t.Errorf("expected debug log to contain %q, got: %q", want, buffer.String())
		}
		want = "DEBUG: C <-- S: 1234"
		if !strings.Contains(buffer.String(), want) {
			t.Errorf("expected debug log to contain %q, got: %q", want, buffer.String())
		}
	})
	t.Run("debug log is disable", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		logger := log.New(buffer, log.LevelDebug)
		client := &Client{logger: logger, debug: false}
		client.debugLog(log.DirClientToServer, "%s", "simple string")
		client.debugLog(log.DirServerToClient, "%d", 1234)
		if buffer.Len() > 0 {
			t.Errorf("expected debug log to be empty, got: %q", buffer.String())
		}
	})
}

// faker is a struct embedding io.ReadWriter to simulate network connections for testing purposes.
type faker struct {
	io.ReadWriter
	failOnClose bool
}

func (f faker) Close() error {
	if f.failOnClose {
		return fmt.Errorf("faker: failed to close connection")
	}
	return nil
}
func (f faker) LocalAddr() net.Addr              { return nil }
func (f faker) RemoteAddr() net.Addr             { return nil }
func (f faker) SetDeadline(time.Time) error      { return nil }
func (f faker) SetReadDeadline(time.Time) error  { return nil }
func (f faker) SetWriteDeadline(time.Time) error { return nil }

// testingKey replaces the substring "TESTING KEY" with "PRIVATE KEY" in the given string s.
func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }

// serverProps represents the configuration properties for the SMTP server.
type serverProps struct {
	BufferMutex           sync.RWMutex
	EchoBuffer            io.Writer
	FailOnAuth            bool
	FailOnDataInit        bool
	FailOnDataClose       bool
	FailOnDial            bool
	FailOnEhlo            bool
	FailOnHelo            bool
	FailOnMailFrom        bool
	FailOnNoop            bool
	FailOnQuit            bool
	FailOnReset           bool
	FailOnRcptTo          bool
	FailOnSTARTTLS        bool
	FailTemp              bool
	SimulateShortResponse bool
	FeatureSet            string
	ListenPort            int
	HashFunc              func() hash.Hash
	IsSCRAMPlus           bool
	IsTLS                 bool
	SupportDSN            bool
	SSLListener           bool
	TestSCRAM             bool
	VRFYUserUnknown       bool
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
		if props.EchoBuffer != nil {
			props.BufferMutex.Lock()
			if _, berr := props.EchoBuffer.Write([]byte(data + "\r\n")); berr != nil {
				t.Errorf("failed write to echo buffer: %s", berr)
			}
			props.BufferMutex.Unlock()
		}
		_ = writer.Flush()
	}
	writeOK := func() {
		writeLine("250 2.0.0 OK")
	}

	if !props.IsTLS {
		if props.FailOnDial {
			writeLine("421 4.4.1 Service not available")
			return
		}
		writeLine("220 go-mail test server ready ESMTP")
	}

	for {
		data, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		time.Sleep(time.Millisecond)
		if props.EchoBuffer != nil {
			props.BufferMutex.Lock()
			if _, berr := props.EchoBuffer.Write([]byte(data)); berr != nil {
				t.Errorf("failed write to echo buffer: %s", berr)
			}
			props.BufferMutex.Unlock()
		}

		var datastring string
		data = strings.TrimSpace(data)
		switch {
		case strings.HasPrefix(data, "HELO"):
			if len(strings.Split(data, " ")) != 2 {
				writeLine("501 Syntax: HELO hostname")
				break
			}
			if props.FailOnHelo {
				writeLine("500 5.5.2 Error: fail on HELO")
				break
			}
			if props.FeatureSet != "" {
				writeLine("250-localhost.localdomain\r\n" + props.FeatureSet)
				break
			}
			writeLine("250 localhost.localdomain\r\n")
		case strings.HasPrefix(data, "EHLO"):
			if len(strings.Split(data, " ")) != 2 {
				writeLine("501 Syntax: EHLO hostname")
				break
			}
			if props.FailOnEhlo {
				writeLine("500 5.5.2 Error: fail on EHLO")
				break
			}
			if props.FeatureSet != "" {
				writeLine("250-localhost.localdomain\r\n" + props.FeatureSet)
				break
			}
			writeLine("250 localhost.localdomain\r\n")
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
			if !strings.HasPrefix(from, "<valid-from") && !strings.HasSuffix(from, "@domain.tld>") {
				writeLine(fmt.Sprintf("503 5.1.2 Invalid from: %s", from))
				break
			}
			writeOK()
		case strings.HasPrefix(data, "RCPT TO:"):
			if props.FailOnRcptTo {
				writeLine("500 5.5.2 Error: fail on RCPT TO")
				break
			}
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
				if props.EchoBuffer != nil {
					props.BufferMutex.Lock()
					if _, berr := props.EchoBuffer.Write([]byte(ddata)); berr != nil {
						t.Errorf("failed write to echo buffer: %s", berr)
					}
					props.BufferMutex.Unlock()
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
		case strings.HasPrefix(data, "VRFY"):
			if props.VRFYUserUnknown {
				writeLine("550 5.1.1 User unknown")
				break
			}
			parts := strings.SplitN(data, " ", 2)
			if len(parts) != 2 {
				writeLine("500 5.0.0 Error: invalid syntax for VRFY")
				break
			}
			writeLine(fmt.Sprintf("250 2.0.0 Ok: %s OK", parts[1]))
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
			if props.SimulateShortResponse {
				_, _ = writer.Write([]byte("\x00\x00\x00\x1a\x00\x00\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00"))
				_, _ = writer.WriteString("221 Bye.\r\n")
				_ = writer.Flush()
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
			tlsConfig := &tls.Config{Certificates: []tls.Certificate{keypair}, ServerName: "example.com"}
			connection = tls.Server(connection, tlsConfig)
			props.IsTLS = true
			handleTestServerConnection(connection, t, props)
		default:
			writeLine("500 5.5.2 Error: bad syntax - " + data)
		}
	}
}

// testSCRAMSMTP represents a part of the test server for SCRAM-based SMTP authentication.
// It does not do any acutal computation of the challenges but verifies that the expected
// fields are present. We have actual real authentication tests for all SCRAM modes in the
// go-mail client_test.go
type testSCRAMSMTP struct {
	nonce     string
	h         func() hash.Hash
	tlsServer bool
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
	saltedPwd, err := pbkdf2.Key(s.h, "password", []byte("salt"), 4096, s.h().Size())
	if err != nil {
		_ = writeLine("535 Authentication failed")
		return
	}
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

// randReader is type that satisfies the io.Reader interface. It can fail on a specific read
// operations and is therefore useful to test consecutive reads with errors
type randReader struct{}

// Read implements the io.Reader interface for the randReader type
func (r *randReader) Read([]byte) (int, error) {
	return 0, errors.New("broken reader")
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
	return nil, fmt.Errorf("unexpected call")
}

// failWriter is a struct type that implements the io.Writer interface, but always returns an error on Write.
type failWriter struct{}

func (w *failWriter) Write([]byte) (int, error) {
	return 0, errors.New("broken writer")
}

func getTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		t.Fatalf("unable to load host certifcate: %s", err)
	}
	testRootCAs := x509.NewCertPool()
	testRootCAs.AppendCertsFromPEM(localhostCert)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      testRootCAs,
		ServerName:   "example.com",
	}
}
