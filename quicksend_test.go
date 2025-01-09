// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestNewAuthData(t *testing.T) {
	t.Run("AuthData with username and password", func(t *testing.T) {
		auth := NewAuthData("username", "password")
		if !auth.Auth {
			t.Fatal("expected auth to be true")
		}
		if auth.Username != "username" {
			t.Fatalf("expected username to be %s, got %s", "username", auth.Username)
		}
		if auth.Password != "password" {
			t.Fatalf("expected password to be %s, got %s", "password", auth.Password)
		}
	})
	t.Run("AuthData with username and empty password", func(t *testing.T) {
		auth := NewAuthData("username", "")
		if !auth.Auth {
			t.Fatal("expected auth to be true")
		}
		if auth.Username != "username" {
			t.Fatalf("expected username to be %s, got %s", "username", auth.Username)
		}
		if auth.Password != "" {
			t.Fatalf("expected password to be %s, got %s", "", auth.Password)
		}
	})
	t.Run("AuthData with empty username and set password", func(t *testing.T) {
		auth := NewAuthData("", "password")
		if !auth.Auth {
			t.Fatal("expected auth to be true")
		}
		if auth.Username != "" {
			t.Fatalf("expected username to be %s, got %s", "", auth.Username)
		}
		if auth.Password != "password" {
			t.Fatalf("expected password to be %s, got %s", "password", auth.Password)
		}
	})
	t.Run("AuthData with empty data", func(t *testing.T) {
		auth := NewAuthData("", "")
		if !auth.Auth {
			t.Fatal("expected auth to be true")
		}
		if auth.Username != "" {
			t.Fatalf("expected username to be %s, got %s", "", auth.Username)
		}
		if auth.Password != "" {
			t.Fatalf("expected password to be %s, got %s", "", auth.Password)
		}
	})
}

func TestQuickSend(t *testing.T) {
	subject := "This is a test subject"
	body := []byte("This is a test body\r\nWith multiple lines\r\n\r\nBest,\r\n  The go-mail team")
	sender := TestSenderValid
	rcpts := []string{TestRcptValid}
	t.Run("QuickSend with authentication and TLS", func(t *testing.T) {
		ctxAuth, cancelAuth := context.WithCancel(context.Background())
		defer cancelAuth()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250-STARTTLS\r\n250 SMTPUTF8"
		echoBuffer := bytes.NewBuffer(nil)
		props := &serverProps{
			EchoBuffer: echoBuffer,
			FeatureSet: featureSet,
			ListenPort: serverPort,
		}
		go func() {
			if err := simpleSMTPServer(ctxAuth, t, props); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		addr := TestServerAddr + ":" + fmt.Sprint(serverPort)
		testHookTLSConfig = func() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }

		_, err := QuickSend(addr, NewAuthData("username", "password"), sender, rcpts, subject, body)
		if err != nil {
			t.Fatalf("failed to send email: %s", err)
		}

		props.BufferMutex.RLock()
		resp := strings.Split(echoBuffer.String(), "\r\n")
		props.BufferMutex.RUnlock()

		expects := []struct {
			line int
			data string
		}{
			{8, "STARTTLS"},
			{17, "AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk"},
			{21, "MAIL FROM:<valid-from@domain.tld> BODY=8BITMIME SMTPUTF8"},
			{23, "RCPT TO:<valid-to@domain.tld>"},
			{30, "Subject: " + subject},
			{33, "From: <valid-from@domain.tld>"},
			{34, "To: <valid-to@domain.tld>"},
			{35, "Content-Transfer-Encoding: quoted-printable"},
			{36, "Content-Type: text/plain; charset=UTF-8"},
			{38, "This is a test body"},
			{39, "With multiple lines"},
			{40, ""},
			{41, "Best,"},
			{42, "  The go-mail team"},
		}
		for _, expect := range expects {
			if !strings.EqualFold(resp[expect.line], expect.data) {
				t.Errorf("expected %q at line %d, got: %q", expect.data, expect.line, resp[expect.line])
			}
		}
	})
	t.Run("QuickSend with authentication and TLS and multiple receipients", func(t *testing.T) {
		ctxAuth, cancelAuth := context.WithCancel(context.Background())
		defer cancelAuth()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250-STARTTLS\r\n250 SMTPUTF8"
		echoBuffer := bytes.NewBuffer(nil)
		props := &serverProps{
			EchoBuffer: echoBuffer,
			FeatureSet: featureSet,
			ListenPort: serverPort,
		}
		go func() {
			if err := simpleSMTPServer(ctxAuth, t, props); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		addr := TestServerAddr + ":" + fmt.Sprint(serverPort)
		testHookTLSConfig = func() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }

		multiRcpts := []string{TestRcptValid, TestRcptValid, TestRcptValid}
		_, err := QuickSend(addr, NewAuthData("username", "password"), sender, multiRcpts, subject, body)
		if err != nil {
			t.Fatalf("failed to send email: %s", err)
		}

		props.BufferMutex.RLock()
		resp := strings.Split(echoBuffer.String(), "\r\n")
		props.BufferMutex.RUnlock()

		expects := []struct {
			line int
			data string
		}{
			{8, "STARTTLS"},
			{17, "AUTH PLAIN AHVzZXJuYW1lAHBhc3N3b3Jk"},
			{21, "MAIL FROM:<valid-from@domain.tld> BODY=8BITMIME SMTPUTF8"},
			{23, "RCPT TO:<valid-to@domain.tld>"},
			{25, "RCPT TO:<valid-to@domain.tld>"},
			{27, "RCPT TO:<valid-to@domain.tld>"},
			{34, "Subject: " + subject},
			{37, "From: <valid-from@domain.tld>"},
			{38, "To: <valid-to@domain.tld>, <valid-to@domain.tld>, <valid-to@domain.tld>"},
			{39, "Content-Transfer-Encoding: quoted-printable"},
			{40, "Content-Type: text/plain; charset=UTF-8"},
			{42, "This is a test body"},
			{43, "With multiple lines"},
			{44, ""},
			{45, "Best,"},
			{46, "  The go-mail team"},
		}
		for _, expect := range expects {
			if !strings.EqualFold(resp[expect.line], expect.data) {
				t.Errorf("expected %q at line %d, got: %q", expect.data, expect.line, resp[expect.line])
			}
		}
	})
	t.Run("QuickSend uses stronged authentication method", func(t *testing.T) {
		ctxAuth, cancelAuth := context.WithCancel(context.Background())
		defer cancelAuth()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH PLAIN CRAM-MD5 SCRAM-SHA-256-PLUS SCRAM-SHA-256\r\n250-8BITMIME\r\n250-DSN\r\n250-STARTTLS\r\n250 SMTPUTF8"
		echoBuffer := bytes.NewBuffer(nil)
		props := &serverProps{
			EchoBuffer: echoBuffer,
			FeatureSet: featureSet,
			ListenPort: serverPort,
		}
		go func() {
			if err := simpleSMTPServer(ctxAuth, t, props); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		addr := TestServerAddr + ":" + fmt.Sprint(serverPort)
		testHookTLSConfig = func() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }

		_, err := QuickSend(addr, NewAuthData("username", "password"), sender, rcpts, subject, body)
		if err != nil {
			t.Fatalf("failed to send email: %s", err)
		}

		props.BufferMutex.RLock()
		resp := strings.Split(echoBuffer.String(), "\r\n")
		props.BufferMutex.RUnlock()

		expects := []struct {
			line int
			data string
		}{
			{17, "AUTH SCRAM-SHA-256-PLUS"},
		}
		for _, expect := range expects {
			if !strings.EqualFold(resp[expect.line], expect.data) {
				t.Errorf("expected %q at line %d, got: %q", expect.data, expect.line, resp[expect.line])
			}
		}
	})
	t.Run("QuickSend uses stronged authentication method without TLS", func(t *testing.T) {
		ctxAuth, cancelAuth := context.WithCancel(context.Background())
		defer cancelAuth()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH PLAIN CRAM-MD5 SCRAM-SHA-256-PLUS SCRAM-SHA-256\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		echoBuffer := bytes.NewBuffer(nil)
		props := &serverProps{
			EchoBuffer: echoBuffer,
			FeatureSet: featureSet,
			ListenPort: serverPort,
		}
		go func() {
			if err := simpleSMTPServer(ctxAuth, t, props); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		addr := TestServerAddr + ":" + fmt.Sprint(serverPort)
		testHookTLSConfig = func() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }

		_, err := QuickSend(addr, NewAuthData("username", "password"), sender, rcpts, subject, body)
		if err != nil {
			t.Fatalf("failed to send email: %s", err)
		}

		props.BufferMutex.RLock()
		resp := strings.Split(echoBuffer.String(), "\r\n")
		props.BufferMutex.RUnlock()

		expects := []struct {
			line int
			data string
		}{
			{7, "AUTH SCRAM-SHA-256"},
		}
		for _, expect := range expects {
			if !strings.EqualFold(resp[expect.line], expect.data) {
				t.Errorf("expected %q at line %d, got: %q", expect.data, expect.line, resp[expect.line])
			}
		}
	})
	t.Run("QuickSend fails during DialAndSned", func(t *testing.T) {
		ctxAuth, cancelAuth := context.WithCancel(context.Background())
		defer cancelAuth()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH PLAIN CRAM-MD5 SCRAM-SHA-256-PLUS SCRAM-SHA-256\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		props := &serverProps{
			FailOnMailFrom: true,
			FeatureSet:     featureSet,
			ListenPort:     serverPort,
		}
		go func() {
			if err := simpleSMTPServer(ctxAuth, t, props); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		addr := TestServerAddr + ":" + fmt.Sprint(serverPort)
		testHookTLSConfig = func() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }

		_, err := QuickSend(addr, NewAuthData("username", "password"), sender, rcpts, subject, body)
		if err == nil {
			t.Error("expected QuickSend to fail during DialAndSend")
		}
		expect := `failed to dial and send message: send failed: sending SMTP MAIL FROM command: 500 ` +
			`5.5.2 Error: fail on MAIL FROM`
		if !strings.EqualFold(err.Error(), expect) {
			t.Errorf("expected error to contain %s, got %s", expect, err)
		}
	})
	t.Run("QuickSend fails on server address without port", func(t *testing.T) {
		addr := TestServerAddr
		_, err := QuickSend(addr, NewAuthData("username", "password"), sender, rcpts, subject, body)
		if err == nil {
			t.Error("expected QuickSend to fail with invalid server address")
		}
		expect := "failed to split host and port from address: address 127.0.0.1: missing port in address"
		if !strings.Contains(err.Error(), expect) {
			t.Errorf("expected error to contain %s, got %s", expect, err)
		}
	})
	t.Run("QuickSend fails on server address with invalid port", func(t *testing.T) {
		addr := TestServerAddr + ":invalid"
		_, err := QuickSend(addr, NewAuthData("username", "password"), sender, rcpts, subject, body)
		if err == nil {
			t.Error("expected QuickSend to fail with invalid server port")
		}
		expect := `failed to convert port to int: strconv.Atoi: parsing "invalid": invalid syntax`
		if !strings.Contains(err.Error(), expect) {
			t.Errorf("expected error to contain %s, got %s", expect, err)
		}
	})
	t.Run("QuickSend fails on nil TLS config (test hook only)", func(t *testing.T) {
		addr := TestServerAddr + ":587"
		testHookTLSConfig = func() *tls.Config { return nil }
		defer func() {
			testHookTLSConfig = nil
		}()
		_, err := QuickSend(addr, NewAuthData("username", "password"), sender, rcpts, subject, body)
		if err == nil {
			t.Error("expected QuickSend to fail with nil-tlsConfig")
		}
		expect := `failed to set TLS config: invalid TLS config`
		if !strings.Contains(err.Error(), expect) {
			t.Errorf("expected error to contain %s, got %s", expect, err)
		}
	})
	t.Run("QuickSend fails with invalid from address", func(t *testing.T) {
		addr := TestServerAddr + ":587"
		invalid := "invalid-fromdomain.tld"
		_, err := QuickSend(addr, NewAuthData("username", "password"), invalid, rcpts, subject, body)
		if err == nil {
			t.Error("expected QuickSend to fail with invalid from address")
		}
		expect := `failed to set MAIL FROM address: failed to parse mail address "invalid-fromdomain.tld": ` +
			`mail: missing '@' or angle-addr`
		if !strings.Contains(err.Error(), expect) {
			t.Errorf("expected error to contain %s, got %s", expect, err)
		}
	})
	t.Run("QuickSend fails with invalid from address", func(t *testing.T) {
		addr := TestServerAddr + ":587"
		invalid := []string{"invalid-todomain.tld"}
		_, err := QuickSend(addr, NewAuthData("username", "password"), sender, invalid, subject, body)
		if err == nil {
			t.Error("expected QuickSend to fail with invalid to address")
		}
		expect := `failed to set RCPT TO address: failed to parse mail address "invalid-todomain.tld": ` +
			`mail: missing '@' or angle-add`
		if !strings.Contains(err.Error(), expect) {
			t.Errorf("expected error to contain %s, got %s", expect, err)
		}
	})
}
