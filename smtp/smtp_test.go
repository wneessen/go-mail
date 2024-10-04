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
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"hash"
	"io"
	"net"
	"net/textproto"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"github.com/wneessen/go-mail/log"
)

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
		PlainAuth("", "user", "pass", "testserver"),
		[]string{},
		"PLAIN",
		[]string{"\x00user\x00pass"},
		[]bool{false, false},
		false,
	},
	{
		PlainAuth("foo", "bar", "baz", "testserver"),
		[]string{},
		"PLAIN",
		[]string{"foo\x00bar\x00baz"},
		[]bool{false, false},
		false,
	},
	{
		PlainAuth("foo", "bar", "baz", "testserver"),
		[]string{"foo"},
		"PLAIN",
		[]string{"foo\x00bar\x00baz", ""},
		[]bool{true},
		false,
	},
	{
		LoginAuth("user", "pass", "testserver"),
		[]string{"Username:", "Password:"},
		"LOGIN",
		[]string{"", "user", "pass"},
		[]bool{false, false},
		false,
	},
	{
		LoginAuth("user", "pass", "testserver"),
		[]string{"User Name\x00", "Password\x00"},
		"LOGIN",
		[]string{"", "user", "pass"},
		[]bool{false, false},
		false,
	},
	{
		LoginAuth("user", "pass", "testserver"),
		[]string{"Invalid", "Invalid:"},
		"LOGIN",
		[]string{"", "user", "pass"},
		[]bool{false, false},
		false,
	},
	{
		LoginAuth("user", "pass", "testserver"),
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
testLoop:
	for i, test := range authTests {
		name, resp, err := test.auth.Start(&ServerInfo{"testserver", true, nil})
		if name != test.name {
			t.Errorf("#%d got name %s, expected %s", i, name, test.name)
		}
		if !bytes.Equal(resp, []byte(test.responses[0])) {
			t.Errorf("#%d got response %s, expected %s", i, resp, test.responses[0])
		}
		if err != nil {
			t.Errorf("#%d error: %s", i, err)
		}
		for j := range test.challenges {
			challenge := []byte(test.challenges[j])
			expected := []byte(test.responses[j+1])
			sf := test.sf[j]
			resp, err := test.auth.Next(challenge, true)
			if err != nil && !sf {
				t.Errorf("#%d error: %s", i, err)
				continue testLoop
			}
			if test.hasNonce {
				if !bytes.HasPrefix(resp, expected) {
					t.Errorf("#%d got response: %s, expected response to start with: %s", i, resp, expected)
				}
				continue testLoop
			}
			if !bytes.Equal(resp, expected) {
				t.Errorf("#%d got %s, expected %s", i, resp, expected)
				continue testLoop
			}
			_, err = test.auth.Next([]byte("2.7.0 Authentication successful"), false)
			if err != nil {
				t.Errorf("#%d success message error: %s", i, err)
			}
		}
	}
}

func TestAuthPlain(t *testing.T) {
	tests := []struct {
		authName string
		server   *ServerInfo
		err      string
	}{
		{
			authName: "servername",
			server:   &ServerInfo{Name: "servername", TLS: true},
		},
		{
			// OK to use PlainAuth on localhost without TLS
			authName: "localhost",
			server:   &ServerInfo{Name: "localhost", TLS: false},
		},
		{
			// NOT OK on non-localhost, even if server says PLAIN is OK.
			// (We don't know that the server is the real server.)
			authName: "servername",
			server:   &ServerInfo{Name: "servername", Auth: []string{"PLAIN"}},
			err:      "unencrypted connection",
		},
		{
			authName: "servername",
			server:   &ServerInfo{Name: "servername", Auth: []string{"CRAM-MD5"}},
			err:      "unencrypted connection",
		},
		{
			authName: "servername",
			server:   &ServerInfo{Name: "attacker", TLS: true},
			err:      "wrong host name",
		},
	}
	for i, tt := range tests {
		auth := PlainAuth("foo", "bar", "baz", tt.authName)
		_, _, err := auth.Start(tt.server)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != tt.err {
			t.Errorf("%d. got error = %q; want %q", i, got, tt.err)
		}
	}
}

func TestAuthLogin(t *testing.T) {
	tests := []struct {
		authName string
		server   *ServerInfo
		err      string
	}{
		{
			authName: "servername",
			server:   &ServerInfo{Name: "servername", TLS: true},
		},
		{
			// OK to use LoginAuth on localhost without TLS
			authName: "localhost",
			server:   &ServerInfo{Name: "localhost", TLS: false},
		},
		{
			// NOT OK on non-localhost, even if server says PLAIN is OK.
			// (We don't know that the server is the real server.)
			authName: "servername",
			server:   &ServerInfo{Name: "servername", Auth: []string{"LOGIN"}},
			err:      "unencrypted connection",
		},
		{
			authName: "servername",
			server:   &ServerInfo{Name: "servername", Auth: []string{"CRAM-MD5"}},
			err:      "unencrypted connection",
		},
		{
			authName: "servername",
			server:   &ServerInfo{Name: "attacker", TLS: true},
			err:      "wrong host name",
		},
	}
	for i, tt := range tests {
		auth := LoginAuth("foo", "bar", tt.authName)
		_, _, err := auth.Start(tt.server)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != tt.err {
			t.Errorf("%d. got error = %q; want %q", i, got, tt.err)
		}
	}
}

func TestXOAuth2OK(t *testing.T) {
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

	c, err := NewClient(fake, "fake.host")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	auth := XOAuth2Auth("user", "token")
	err = c.Auth(auth)
	if err != nil {
		t.Fatalf("XOAuth2 error: %v", err)
	}
	// the Next method returns a nil response. It must not be sent.
	// The client request must end with the authentication.
	if !strings.HasSuffix(wrote.String(), "AUTH XOAUTH2 dXNlcj11c2VyAWF1dGg9QmVhcmVyIHRva2VuAQE=\r\n") {
		t.Fatalf("got %q; want AUTH XOAUTH2 dXNlcj11c2VyAWF1dGg9QmVhcmVyIHRva2VuAQE=\r\n", wrote.String())
	}
}

func TestXOAuth2Error(t *testing.T) {
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

	c, err := NewClient(fake, "fake.host")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer c.Close()

	auth := XOAuth2Auth("user", "token")
	err = c.Auth(auth)
	if err == nil {
		t.Fatal("expected auth error, got nil")
	}
	client := strings.Split(wrote.String(), "\r\n")
	if len(client) != 5 {
		t.Fatalf("unexpected number of client requests got %d; want 5", len(client))
	}
	if client[1] != "AUTH XOAUTH2 dXNlcj11c2VyAWF1dGg9QmVhcmVyIHRva2VuAQE=" {
		t.Fatalf("got %q; want AUTH XOAUTH2 dXNlcj11c2VyAWF1dGg9QmVhcmVyIHRva2VuAQE=", client[1])
	}
	// the Next method returns an empty response. It must be sent
	if client[2] != "" {
		t.Fatalf("got %q; want empty response", client[2])
	}
}

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

type faker struct {
	io.ReadWriter
}

func (f faker) Close() error                     { return nil }
func (f faker) LocalAddr() net.Addr              { return nil }
func (f faker) RemoteAddr() net.Addr             { return nil }
func (f faker) SetDeadline(time.Time) error      { return nil }
func (f faker) SetReadDeadline(time.Time) error  { return nil }
func (f faker) SetWriteDeadline(time.Time) error { return nil }

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
	if err := c.Auth(PlainAuth("", "user", "pass", "smtp.google.com")); err != nil {
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
			err = c.Auth(PlainAuth("", "user", "pass", "smtp.google.com"))
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

	err = SendMail(l.Addr().String(), PlainAuth("", "user", "pass", "smtp.google.com"), "test@example.com", []string{"other@example.com"}, []byte(strings.Replace(`From: test@example.com
To: other@example.com
Subject: SendMail test

SendMail is working for me.
`, "\n", "\r\n", -1)))
	if err == nil {
		t.Error("SendMail: Server doesn't support AUTH, expected to get an error, but got none ")
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
	err = c.Auth(PlainAuth("", "user", "pass", "smtp.google.com"))

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
// It does not do any acutal computation of the challanges but verifies that the expected
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
