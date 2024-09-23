// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wneessen/go-mail/log"
	"github.com/wneessen/go-mail/smtp"
)

const (
	// DefaultHost is used as default hostname for the Client
	DefaultHost = "localhost"
	// TestRcpt is a trash mail address to send test mails to
	TestRcpt = "go-mail@mytrashmailer.com"
	// TestServerProto is the protocol used for the simple SMTP test server
	TestServerProto = "tcp"
	// TestServerAddr is the address the simple SMTP test server listens on
	TestServerAddr = "127.0.0.1"
	// TestServerPortBase is the base port for the simple SMTP test server
	TestServerPortBase = 2025
)

// TestNewClient tests the NewClient() method with its default options
func TestNewClient(t *testing.T) {
	host := "mail.example.com"
	tests := []struct {
		name       string
		host       string
		shouldfail bool
	}{
		{"Default", "mail.example.com", false},
		{"Empty host should fail", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(tt.host)
			if err != nil && !tt.shouldfail {
				t.Errorf("failed to create new client: %s", err)
				return
			}
			if c.host != tt.host {
				t.Errorf("failed to create new client. Host expected: %s, got: %s", host, c.host)
			}
			if c.connTimeout != DefaultTimeout {
				t.Errorf("failed to create new client. Timeout expected: %s, got: %s", DefaultTimeout.String(),
					c.connTimeout.String())
			}
			if c.port != DefaultPort {
				t.Errorf("failed to create new client. Port expected: %d, got: %d", DefaultPort, c.port)
			}
			if c.tlspolicy != TLSMandatory {
				t.Errorf("failed to create new client. TLS policy expected: %d, got: %d", TLSMandatory, c.tlspolicy)
			}
			if c.tlsconfig.ServerName != tt.host {
				t.Errorf("failed to create new client. TLS config host expected: %s, got: %s",
					host, c.tlsconfig.ServerName)
			}
			if c.tlsconfig.MinVersion != DefaultTLSMinVersion {
				t.Errorf("failed to create new client. TLS config min versino expected: %d, got: %d",
					DefaultTLSMinVersion, c.tlsconfig.MinVersion)
			}
			if c.ServerAddr() != fmt.Sprintf("%s:%d", tt.host, c.port) {
				t.Errorf("failed to create new client. c.ServerAddr() expected: %s, got: %s",
					fmt.Sprintf("%s:%d", tt.host, c.port), c.ServerAddr())
			}
		})
	}
}

// TestNewClient tests the NewClient() method with its custom options
func TestNewClientWithOptions(t *testing.T) {
	host := "mail.example.com"
	tests := []struct {
		name       string
		option     Option
		shouldfail bool
	}{
		{"nil option", nil, true},
		{"WithPort()", WithPort(465), false},
		{"WithPort(); port is too high", WithPort(100000), true},
		{"WithTimeout()", WithTimeout(time.Second * 5), false},
		{"WithTimeout()", WithTimeout(-10), true},
		{"WithSSL()", WithSSL(), false},
		{"WithSSLPort(false)", WithSSLPort(false), false},
		{"WithSSLPort(true)", WithSSLPort(true), false},
		{"WithHELO()", WithHELO(host), false},
		{"WithHELO(); helo is empty", WithHELO(""), true},
		{"WithTLSPolicy()", WithTLSPolicy(TLSOpportunistic), false},
		{"WithTLSPortPolicy()", WithTLSPortPolicy(TLSOpportunistic), false},
		{"WithTLSConfig()", WithTLSConfig(&tls.Config{}), false},
		{"WithTLSConfig(); config is nil", WithTLSConfig(nil), true},
		{"WithSMTPAuth(NoAuth)", WithSMTPAuth(SMTPAuthNoAuth), false},
		{"WithSMTPAuth()", WithSMTPAuth(SMTPAuthLogin), false},
		{
			"WithSMTPAuthCustom()",
			WithSMTPAuthCustom(smtp.PlainAuth("", "", "", "")),
			false,
		},
		{"WithUsername()", WithUsername("test"), false},
		{"WithPassword()", WithPassword("test"), false},
		{"WithDSN()", WithDSN(), false},
		{"WithDSNMailReturnType()", WithDSNMailReturnType(DSNMailReturnFull), false},
		{"WithDSNMailReturnType() wrong option", WithDSNMailReturnType("FAIL"), true},
		{"WithDSNRcptNotifyType()", WithDSNRcptNotifyType(DSNRcptNotifySuccess), false},
		{"WithDSNRcptNotifyType() wrong option", WithDSNRcptNotifyType("FAIL"), true},
		{"WithoutNoop()", WithoutNoop(), false},
		{"WithDebugLog()", WithDebugLog(), false},
		{"WithLogger()", WithLogger(log.New(os.Stderr, log.LevelDebug)), false},
		{"WithDialContextFunc()", WithDialContextFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, nil
		}), false},

		{
			"WithDSNRcptNotifyType() NEVER combination",
			WithDSNRcptNotifyType(DSNRcptNotifySuccess, DSNRcptNotifyNever), true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(DefaultHost, tt.option, nil)
			if err != nil && !tt.shouldfail {
				t.Errorf("failed to create new client: %s", err)
				return
			}
			_ = c
		})
	}
}

// TestWithHELO tests the WithHELO() option for the NewClient() method
func TestWithHELO(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"HELO test.de", "test.de", "test.de"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(DefaultHost, WithHELO(tt.value))
			if err != nil {
				t.Errorf("failed to create new client: %s", err)
				return
			}
			if c.helo != tt.want {
				t.Errorf("failed to set custom HELO. Want: %s, got: %s", tt.want, c.helo)
			}
		})
	}
}

// TestWithPort tests the WithPort() option for the NewClient() method
func TestWithPort(t *testing.T) {
	tests := []struct {
		name  string
		value int
		want  int
		sf    bool
	}{
		{"set port to 25", 25, 25, false},
		{"set port to 465", 465, 465, false},
		{"set port to 100000", 100000, 25, true},
		{"set port to -10", -10, 25, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(DefaultHost, WithPort(tt.value))
			if err != nil && !tt.sf {
				t.Errorf("failed to create new client: %s", err)
				return
			}
			if c.port != tt.want {
				t.Errorf("failed to set custom port. Want: %d, got: %d", tt.want, c.port)
			}
		})
	}
}

// TestWithTimeout tests the WithTimeout() option for the NewClient() method
func TestWithTimeout(t *testing.T) {
	tests := []struct {
		name  string
		value time.Duration
		want  time.Duration
		sf    bool
	}{
		{"set timeout to 5s", time.Second * 5, time.Second * 5, false},
		{"set timeout to 30s", time.Second * 30, time.Second * 30, false},
		{"set timeout to 1m", time.Minute, time.Minute, false},
		{"set timeout to 0", 0, DefaultTimeout, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(DefaultHost, WithTimeout(tt.value))
			if err != nil && !tt.sf {
				t.Errorf("failed to create new client: %s", err)
				return
			}
			if c.connTimeout != tt.want {
				t.Errorf("failed to set custom timeout. Want: %d, got: %d", tt.want, c.connTimeout)
			}
		})
	}
}

// TestWithTLSPolicy tests the WithTLSPolicy() option for the NewClient() method
func TestWithTLSPolicy(t *testing.T) {
	tests := []struct {
		name  string
		value TLSPolicy
		want  string
		sf    bool
	}{
		{"Policy: TLSMandatory", TLSMandatory, TLSMandatory.String(), false},
		{"Policy: TLSOpportunistic", TLSOpportunistic, TLSOpportunistic.String(), false},
		{"Policy: NoTLS", NoTLS, NoTLS.String(), false},
		{"Policy: Invalid", -1, "UnknownPolicy", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(DefaultHost, WithTLSPolicy(tt.value))
			if err != nil && !tt.sf {
				t.Errorf("failed to create new client: %s", err)
				return
			}
			if c.tlspolicy.String() != tt.want {
				t.Errorf("failed to set TLSPolicy. Want: %s, got: %s", tt.want, c.tlspolicy)
			}
		})
	}
}

// TestWithTLSPortPolicy tests the WithTLSPortPolicy() option for the NewClient() method
func TestWithTLSPortPolicy(t *testing.T) {
	tests := []struct {
		name     string
		value    TLSPolicy
		want     string
		wantPort int
		fbPort   int
		sf       bool
	}{
		{"Policy: TLSMandatory", TLSMandatory, TLSMandatory.String(), 587, 0, false},
		{"Policy: TLSOpportunistic", TLSOpportunistic, TLSOpportunistic.String(), 587, 25, false},
		{"Policy: NoTLS", NoTLS, NoTLS.String(), 25, 0, false},
		{"Policy: Invalid", -1, "UnknownPolicy", 587, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(DefaultHost, WithTLSPortPolicy(tt.value))
			if err != nil && !tt.sf {
				t.Errorf("failed to create new client: %s", err)
				return
			}
			if c.tlspolicy.String() != tt.want {
				t.Errorf("failed to set TLSPortPolicy. Want: %s, got: %s", tt.want, c.tlspolicy)
			}
			if c.port != tt.wantPort {
				t.Errorf("failed to set TLSPortPolicy, wanted port: %d, got: %d", tt.wantPort, c.port)
			}
			if c.fallbackPort != tt.fbPort {
				t.Errorf("failed to set TLSPortPolicy, wanted fallbakc port: %d, got: %d", tt.fbPort,
					c.fallbackPort)
			}
		})
	}
}

// TestSetTLSPolicy tests the SetTLSPolicy() method for the Client object
func TestSetTLSPolicy(t *testing.T) {
	tests := []struct {
		name  string
		value TLSPolicy
		want  string
		sf    bool
	}{
		{"Policy: TLSMandatory", TLSMandatory, TLSMandatory.String(), false},
		{"Policy: TLSOpportunistic", TLSOpportunistic, TLSOpportunistic.String(), false},
		{"Policy: NoTLS", NoTLS, NoTLS.String(), false},
		{"Policy: Invalid", -1, "UnknownPolicy", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(DefaultHost, WithTLSPolicy(NoTLS))
			if err != nil {
				t.Errorf("failed to create new client: %s", err)
				return
			}
			c.SetTLSPolicy(tt.value)
			if c.tlspolicy.String() != tt.want {
				t.Errorf("failed to set TLSPolicy. Want: %s, got: %s", tt.want, c.tlspolicy)
			}
		})
	}
}

// TestSetTLSConfig tests the SetTLSConfig() method for the Client object
func TestSetTLSConfig(t *testing.T) {
	tests := []struct {
		name  string
		value *tls.Config
		sf    bool
	}{
		{"default config", &tls.Config{}, false},
		{"nil config", nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(DefaultHost)
			if err != nil {
				t.Errorf("failed to create new client: %s", err)
				return
			}
			if err := c.SetTLSConfig(tt.value); err != nil && !tt.sf {
				t.Errorf("failed to set TLSConfig: %s", err)
				return
			}
		})
	}
}

// TestSetSSL tests the SetSSL() method for the Client object
func TestSetSSL(t *testing.T) {
	tests := []struct {
		name  string
		value bool
	}{
		{"SSL: on", true},
		{"SSL: off", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(DefaultHost)
			if err != nil {
				t.Errorf("failed to create new client: %s", err)
				return
			}
			c.SetSSL(tt.value)
			if c.useSSL != tt.value {
				t.Errorf("failed to set SSL setting. Got: %t, want: %t", c.useSSL, tt.value)
			}
		})
	}
}

// TestSetSSLPort tests the Client.SetSSLPort method
func TestClient_SetSSLPort(t *testing.T) {
	tests := []struct {
		name   string
		value  bool
		fb     bool
		port   int
		fbPort int
	}{
		{"SSL: on, fb: off", true, false, 465, 0},
		{"SSL: on, fb: on", true, true, 465, 25},
		{"SSL: off, fb: off", false, false, 25, 0},
		{"SSL: off, fb: on", false, true, 25, 25},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(DefaultHost)
			if err != nil {
				t.Errorf("failed to create new client: %s", err)
				return
			}
			c.SetSSLPort(tt.value, tt.fb)
			if c.useSSL != tt.value {
				t.Errorf("failed to set SSL setting. Got: %t, want: %t", c.useSSL, tt.value)
			}
			if c.port != tt.port {
				t.Errorf("failed to set SSLPort, wanted port: %d, got: %d", c.port, tt.port)
			}
			if c.fallbackPort != tt.fbPort {
				t.Errorf("failed to set SSLPort, wanted fallback port: %d, got: %d", c.fallbackPort,
					tt.fbPort)
			}
		})
	}
}

// TestSetUsername tests the SetUsername method for the Client object
func TestSetUsername(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
		sf    bool
	}{
		{"normal username", "testuser", "testuser", false},
		{"empty username", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(DefaultHost)
			if err != nil {
				t.Errorf("failed to create new client: %s", err)
				return
			}
			c.SetUsername(tt.value)
			if c.user != tt.want {
				t.Errorf("failed to set username. Expected %s, got: %s", tt.want, c.user)
			}
		})
	}
}

// TestSetPassword tests the SetPassword method for the Client object
func TestSetPassword(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
		sf    bool
	}{
		{"normal password", "testpass", "testpass", false},
		{"empty password", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(DefaultHost)
			if err != nil {
				t.Errorf("failed to create new client: %s", err)
				return
			}
			c.SetPassword(tt.value)
			if c.pass != tt.want {
				t.Errorf("failed to set password. Expected %s, got: %s", tt.want, c.pass)
			}
		})
	}
}

// TestSetSMTPAuth tests the SetSMTPAuth method for the Client object
func TestSetSMTPAuth(t *testing.T) {
	tests := []struct {
		name  string
		value SMTPAuthType
		want  string
		sf    bool
	}{
		{"SMTPAuth: LOGIN", SMTPAuthLogin, "LOGIN", false},
		{"SMTPAuth: PLAIN", SMTPAuthPlain, "PLAIN", false},
		{"SMTPAuth: CRAM-MD5", SMTPAuthCramMD5, "CRAM-MD5", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(DefaultHost)
			if err != nil {
				t.Errorf("failed to create new client: %s", err)
				return
			}
			c.SetSMTPAuth(tt.value)
			if string(c.smtpAuthType) != tt.want {
				t.Errorf("failed to set SMTP auth type. Expected %s, got: %s", tt.want, string(c.smtpAuthType))
			}
		})
	}
}

// TestWithDSN tests the WithDSN method for the Client object
func TestWithDSN(t *testing.T) {
	c, err := NewClient(DefaultHost, WithDSN())
	if err != nil {
		t.Errorf("failed to create new client: %s", err)
		return
	}
	if !c.dsn {
		t.Errorf("WithDSN failed. c.dsn expected to be: %t, got: %t", true, c.dsn)
	}
	if c.dsnmrtype != DSNMailReturnFull {
		t.Errorf("WithDSN failed. c.dsnmrtype expected to be: %s, got: %s", DSNMailReturnFull,
			c.dsnmrtype)
	}
	if c.dsnrntype[0] != string(DSNRcptNotifyFailure) {
		t.Errorf("WithDSN failed. c.dsnrntype[0] expected to be: %s, got: %s", DSNRcptNotifyFailure,
			c.dsnrntype[0])
	}
	if c.dsnrntype[1] != string(DSNRcptNotifySuccess) {
		t.Errorf("WithDSN failed. c.dsnrntype[1] expected to be: %s, got: %s", DSNRcptNotifySuccess,
			c.dsnrntype[1])
	}
}

// TestWithDSNMailReturnType tests the WithDSNMailReturnType method for the Client object
func TestWithDSNMailReturnType(t *testing.T) {
	tests := []struct {
		name  string
		value DSNMailReturnOption
		want  string
		sf    bool
	}{
		{"WithDSNMailReturnType: FULL", DSNMailReturnFull, "FULL", false},
		{"WithDSNMailReturnType: HDRS", DSNMailReturnHeadersOnly, "HDRS", false},
		{"WithDSNMailReturnType: INVALID", "INVALID", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(DefaultHost, WithDSNMailReturnType(tt.value))
			if err != nil && !tt.sf {
				t.Errorf("failed to create new client: %s", err)
				return
			}
			if string(c.dsnmrtype) != tt.want {
				t.Errorf("WithDSNMailReturnType failed. Expected %s, got: %s", tt.want, string(c.dsnmrtype))
			}
		})
	}
}

// TestWithDSNRcptNotifyType tests the WithDSNRcptNotifyType method for the Client object
func TestWithDSNRcptNotifyType(t *testing.T) {
	tests := []struct {
		name  string
		value DSNRcptNotifyOption
		want  string
		sf    bool
	}{
		{"WithDSNRcptNotifyType: NEVER", DSNRcptNotifyNever, "NEVER", false},
		{"WithDSNRcptNotifyType: SUCCESS", DSNRcptNotifySuccess, "SUCCESS", false},
		{"WithDSNRcptNotifyType: FAILURE", DSNRcptNotifyFailure, "FAILURE", false},
		{"WithDSNRcptNotifyType: DELAY", DSNRcptNotifyDelay, "DELAY", false},
		{"WithDSNRcptNotifyType: INVALID", "INVALID", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(DefaultHost, WithDSNRcptNotifyType(tt.value))
			if err != nil && !tt.sf {
				t.Errorf("failed to create new client: %s", err)
				return
			}
			if len(c.dsnrntype) <= 0 && !tt.sf {
				t.Errorf("WithDSNRcptNotifyType failed. Expected at least one DSNRNType but got none")
			}
			if !tt.sf && c.dsnrntype[0] != tt.want {
				t.Errorf("WithDSNRcptNotifyType failed. Expected %s, got: %s", tt.want, c.dsnrntype[0])
			}
		})
	}
}

// TestWithoutNoop tests the WithoutNoop method for the Client object
func TestWithoutNoop(t *testing.T) {
	c, err := NewClient(DefaultHost, WithoutNoop())
	if err != nil {
		t.Errorf("failed to create new client: %s", err)
		return
	}
	if !c.noNoop {
		t.Errorf("WithoutNoop failed. c.noNoop expected to be: %t, got: %t", true, c.noNoop)
	}

	c, err = NewClient(DefaultHost)
	if err != nil {
		t.Errorf("failed to create new client: %s", err)
		return
	}
	if c.noNoop {
		t.Errorf("WithoutNoop failed. c.noNoop expected to be: %t, got: %t", false, c.noNoop)
	}
}

// TestSetSMTPAuthCustom tests the SetSMTPAuthCustom method for the Client object
func TestSetSMTPAuthCustom(t *testing.T) {
	tests := []struct {
		name  string
		value smtp.Auth
		want  string
		sf    bool
	}{
		{"SMTPAuth: CRAM-MD5", smtp.CRAMMD5Auth("", ""), "CRAM-MD5", false},
		{"SMTPAuth: LOGIN", smtp.LoginAuth("", "", ""), "LOGIN", false},
		{"SMTPAuth: PLAIN", smtp.PlainAuth("", "", "", ""), "PLAIN", false},
	}
	si := smtp.ServerInfo{TLS: true}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(DefaultHost)
			if err != nil {
				t.Errorf("failed to create new client: %s", err)
				return
			}
			c.SetSMTPAuthCustom(tt.value)
			if c.smtpAuth == nil {
				t.Errorf("failed to set custom SMTP auth method. SMTP Auth method is empty")
			}
			p, _, err := c.smtpAuth.Start(&si)
			if err != nil {
				t.Errorf("SMTP Auth Start() method returned error: %s", err)
			}
			if p != tt.want {
				t.Errorf("SMTP Auth Start() method is returned proto: %s, expected: %s", p, tt.want)
			}
		})
	}
}

// TestClient_DialWithContext tests the DialWithContext method for the Client object
func TestClient_DialWithContext(t *testing.T) {
	c, err := getTestConnection(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}
	ctx := context.Background()
	if err := c.DialWithContext(ctx); err != nil {
		t.Errorf("failed to dial with context: %s", err)
		return
	}
	if c.connection == nil {
		t.Errorf("DialWithContext didn't fail but no connection found.")
	}
	if c.smtpClient == nil {
		t.Errorf("DialWithContext didn't fail but no SMTP client found.")
	}
	if err := c.Close(); err != nil {
		t.Errorf("failed to close connection: %s", err)
	}
}

// TestClient_DialWithContext_Fallback tests the Client.DialWithContext method with the fallback
// port functionality
func TestClient_DialWithContext_Fallback(t *testing.T) {
	c, err := getTestConnectionNoTestPort(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}
	c.SetTLSPortPolicy(TLSOpportunistic)
	c.port = 999
	ctx := context.Background()
	if err := c.DialWithContext(ctx); err != nil {
		t.Errorf("failed to dial with context: %s", err)
		return
	}
	if c.connection == nil {
		t.Errorf("DialWithContext didn't fail but no connection found.")
	}
	if c.smtpClient == nil {
		t.Errorf("DialWithContext didn't fail but no SMTP client found.")
	}
	if err := c.Close(); err != nil {
		t.Errorf("failed to close connection: %s", err)
	}

	c.port = 999
	c.fallbackPort = 999
	if err = c.DialWithContext(ctx); err == nil {
		t.Error("dial with context was supposed to fail, but didn't")
		return
	}
}

// TestClient_DialWithContext_Debug tests the DialWithContext method for the Client object with debug
// logging enabled on the SMTP client
func TestClient_DialWithContext_Debug(t *testing.T) {
	c, err := getTestClient(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}
	ctx := context.Background()
	if err := c.DialWithContext(ctx); err != nil {
		t.Errorf("failed to dial with context: %s", err)
		return
	}
	if c.connection == nil {
		t.Errorf("DialWithContext didn't fail but no connection found.")
	}
	if c.smtpClient == nil {
		t.Errorf("DialWithContext didn't fail but no SMTP client found.")
	}
	c.SetDebugLog(true)
	if err := c.Close(); err != nil {
		t.Errorf("failed to close connection: %s", err)
	}
}

// TestClient_DialWithContext_Debug_custom tests the DialWithContext method for the Client
// object with debug logging enabled and a custom logger on the SMTP client
func TestClient_DialWithContext_Debug_custom(t *testing.T) {
	c, err := getTestClient(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}
	ctx := context.Background()
	if err := c.DialWithContext(ctx); err != nil {
		t.Errorf("failed to dial with context: %s", err)
		return
	}
	if c.connection == nil {
		t.Errorf("DialWithContext didn't fail but no connection found.")
	}
	if c.smtpClient == nil {
		t.Errorf("DialWithContext didn't fail but no SMTP client found.")
	}
	c.SetDebugLog(true)
	c.SetLogger(log.New(os.Stderr, log.LevelDebug))
	if err := c.Close(); err != nil {
		t.Errorf("failed to close connection: %s", err)
	}
}

// TestClient_DialWithContextInvalidHost tests the DialWithContext method with intentional breaking
// for the Client object
func TestClient_DialWithContextInvalidHost(t *testing.T) {
	c, err := getTestConnection(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}
	c.connection = nil
	c.host = "invalid.addr"
	ctx := context.Background()
	if err := c.DialWithContext(ctx); err == nil {
		t.Errorf("dial succeeded but was supposed to fail")
		return
	}
}

// TestClient_DialWithContextInvalidHELO tests the DialWithContext method with intentional breaking
// for the Client object
func TestClient_DialWithContextInvalidHELO(t *testing.T) {
	c, err := getTestConnection(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}
	c.connection = nil
	c.helo = ""
	ctx := context.Background()
	if err := c.DialWithContext(ctx); err == nil {
		t.Errorf("dial succeeded but was supposed to fail")
		return
	}
}

// TestClient_DialWithContextInvalidAuth tests the DialWithContext method with intentional breaking
// for the Client object
func TestClient_DialWithContextInvalidAuth(t *testing.T) {
	c, err := getTestConnection(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}
	c.user = "invalid"
	c.pass = "invalid"
	c.SetSMTPAuthCustom(smtp.LoginAuth("invalid", "invalid", "invalid"))
	ctx := context.Background()
	if err := c.DialWithContext(ctx); err == nil {
		t.Errorf("dial succeeded but was supposed to fail")
		return
	}
}

// TestClient_checkConn tests the checkConn method with intentional breaking for the Client object
func TestClient_checkConn(t *testing.T) {
	c, err := getTestConnection(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}
	c.connection = nil
	if err := c.checkConn(); err == nil {
		t.Errorf("connCheck() should fail but succeeded")
	}
}

// TestClient_DiealWithContextOptions tests the DialWithContext method plus different options
// for the Client object
func TestClient_DialWithContextOptions(t *testing.T) {
	tests := []struct {
		name    string
		wantssl bool
		wanttls TLSPolicy
		sf      bool
	}{
		{"Want SSL (should fail)", true, NoTLS, true},
		{"Want Mandatory TLS", false, TLSMandatory, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := getTestConnection(true)
			if err != nil {
				t.Skipf("failed to create test client: %s. Skipping tests", err)
			}
			if tt.wantssl {
				c.SetSSL(true)
			}
			if tt.wanttls != NoTLS {
				c.SetTLSPolicy(tt.wanttls)
			}

			ctx := context.Background()
			if err := c.DialWithContext(ctx); err != nil && !tt.sf {
				t.Errorf("failed to dial with context: %s", err)
				return
			}
			if !tt.sf {
				if c.connection == nil && !tt.sf {
					t.Errorf("DialWithContext didn't fail but no connection found.")
				}
				if c.smtpClient == nil && !tt.sf {
					t.Errorf("DialWithContext didn't fail but no SMTP client found.")
				}
				if err := c.Reset(); err != nil {
					t.Errorf("failed to reset connection: %s", err)
				}
				if err := c.Close(); err != nil {
					t.Errorf("failed to close connection: %s", err)
				}
			}
		})
	}
}

// TestClient_DialWithContextOptionDialContextFunc tests the DialWithContext method plus
// use dialContextFunc option for the Client object
func TestClient_DialWithContextOptionDialContextFunc(t *testing.T) {
	c, err := getTestConnection(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}

	called := false
	c.dialContextFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
		called = true
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}

	ctx := context.Background()
	if err := c.DialWithContext(ctx); err != nil {
		t.Errorf("failed to dial with context: %s", err)
		return
	}

	if called == false {
		t.Errorf("dialContextFunc supposed to be called but not called")
	}
}

// TestClient_DialSendClose tests the Dial(), Send() and Close() method of Client
func TestClient_DialSendClose(t *testing.T) {
	if os.Getenv("TEST_ALLOW_SEND") == "" {
		t.Skipf("TEST_ALLOW_SEND is not set. Skipping mail sending test")
	}
	m := NewMsg()
	_ = m.FromFormat("go-mail Test Mailer", os.Getenv("TEST_FROM"))
	_ = m.To(TestRcpt)
	m.Subject(fmt.Sprintf("This is a test mail from go-mail/v%s", VERSION))
	m.SetBulk()
	m.SetDate()
	m.SetMessageID()
	m.SetBodyString(TypeTextPlain, "This is a test mail from the go-mail library")

	c, err := getTestConnection(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}

	ctx, cfn := context.WithTimeout(context.Background(), time.Second*10)
	defer cfn()
	if err := c.DialWithContext(ctx); err != nil {
		t.Errorf("Dial() failed: %s", err)
	}
	if err := c.Send(m); err != nil {
		t.Errorf("Send() failed: %s", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close() failed: %s", err)
	}
	if !m.IsDelivered() {
		t.Errorf("message should be delivered but is indicated no to")
	}
}

// TestClient_DialAndSendWithContext tests the DialAndSendWithContext() method of Client
func TestClient_DialAndSendWithContext(t *testing.T) {
	if os.Getenv("TEST_ALLOW_SEND") == "" {
		t.Skipf("TEST_ALLOW_SEND is not set. Skipping mail sending test")
	}
	m := NewMsg()
	_ = m.FromFormat("go-mail Test Mailer", os.Getenv("TEST_FROM"))
	_ = m.To(TestRcpt)
	m.Subject(fmt.Sprintf("This is a test mail from go-mail/v%s", VERSION))
	m.SetBulk()
	m.SetDate()
	m.SetMessageID()
	m.SetBodyString(TypeTextPlain, "This is a test mail from the go-mail library")

	tests := []struct {
		name string
		to   time.Duration
		sf   bool
	}{
		{"Timeout: 100s", time.Second * 100, false},
		{"Timeout: 100ms", time.Millisecond * 100, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := getTestConnection(true)
			if err != nil {
				t.Skipf("failed to create test client: %s. Skipping tests", err)
			}

			ctx, cfn := context.WithTimeout(context.Background(), tt.to)
			defer cfn()
			if err := c.DialAndSendWithContext(ctx, m); err != nil && !tt.sf {
				t.Errorf("DialAndSendWithContext() failed: %s", err)
			}
		})
	}
}

// TestClient_DialAndSend tests the DialAndSend() method of Client
func TestClient_DialAndSend(t *testing.T) {
	if os.Getenv("TEST_ALLOW_SEND") == "" {
		t.Skipf("TEST_ALLOW_SEND is not set. Skipping mail sending test")
	}
	m := NewMsg()
	_ = m.FromFormat("go-mail Test Mailer", os.Getenv("TEST_FROM"))
	_ = m.To(TestRcpt)
	m.Subject(fmt.Sprintf("This is a test mail from go-mail/v%s", VERSION))
	m.SetBulk()
	m.SetDate()
	m.SetMessageID()
	m.SetBodyString(TypeTextPlain, "This is a test mail from the go-mail library")

	c, err := getTestConnection(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}

	if err := c.DialAndSend(m); err != nil {
		t.Errorf("DialAndSend() failed: %s", err)
	}
}

// TestClient_DialAndSendWithDSN tests the DialAndSend() method of Client with DSN enabled
func TestClient_DialAndSendWithDSN(t *testing.T) {
	if os.Getenv("TEST_ALLOW_SEND") == "" {
		t.Skipf("TEST_ALLOW_SEND is not set. Skipping mail sending test")
	}
	m := NewMsg()
	_ = m.FromFormat("go-mail Test Mailer", os.Getenv("TEST_FROM"))
	_ = m.To(TestRcpt)
	m.Subject(fmt.Sprintf("This is a test mail from go-mail/v%s", VERSION))
	m.SetBulk()
	m.SetDate()
	m.SetMessageID()
	m.SetBodyString(TypeTextPlain, "This is a test mail from the go-mail library")

	c, err := getTestConnectionWithDSN(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}

	if err := c.DialAndSend(m); err != nil {
		t.Errorf("DialAndSend() failed: %s", err)
	}
}

// TestClient_DialSendCloseBroken tests the Dial(), Send() and Close() method of Client with broken settings
func TestClient_DialSendCloseBroken(t *testing.T) {
	if os.Getenv("TEST_ALLOW_SEND") == "" {
		t.Skipf("TEST_ALLOW_SEND is not set. Skipping mail sending test")
	}
	tests := []struct {
		name       string
		from       string
		to         string
		closestart bool
		closeearly bool
		sf         bool
	}{
		{"Invalid FROM", "foo@foo", TestRcpt, false, false, true},
		{"Invalid TO", os.Getenv("TEST_FROM"), "foo@foo", false, false, true},
		{"No FROM", "", TestRcpt, false, false, true},
		{"No TO", os.Getenv("TEST_FROM"), "", false, false, true},
		{"Close early", os.Getenv("TEST_FROM"), TestRcpt, false, true, true},
		{"Close start", os.Getenv("TEST_FROM"), TestRcpt, true, false, true},
		{"Close start/early", os.Getenv("TEST_FROM"), TestRcpt, true, true, true},
	}

	m := NewMsg(WithEncoding(NoEncoding))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.SetAddrHeaderIgnoreInvalid(HeaderFrom, tt.from)
			m.SetAddrHeaderIgnoreInvalid(HeaderTo, tt.to)

			c, err := getTestConnection(true)
			if err != nil {
				t.Skipf("failed to create test client: %s. Skipping tests", err)
			}

			ctx, cfn := context.WithTimeout(context.Background(), time.Second*10)
			defer cfn()
			if err := c.DialWithContext(ctx); err != nil && !tt.sf {
				t.Errorf("Dail() failed: %s", err)
				return
			}
			if tt.closestart {
				_ = c.smtpClient.Close()
				_ = c.connection.Close()
			}
			if err := c.Send(m); err != nil && !tt.sf {
				t.Errorf("Send() failed: %s", err)
				return
			}
			if tt.closeearly {
				_ = c.smtpClient.Close()
				_ = c.connection.Close()
			}
			if err := c.Close(); err != nil && !tt.sf {
				t.Errorf("Close() failed: %s", err)
				return
			}
		})
	}
}

// TestClient_DialSendCloseBrokenWithDSN tests the Dial(), Send() and Close() method of Client with
// broken settings and DSN enabled
func TestClient_DialSendCloseBrokenWithDSN(t *testing.T) {
	if os.Getenv("TEST_ALLOW_SEND") == "" {
		t.Skipf("TEST_ALLOW_SEND is not set. Skipping mail sending test")
	}
	tests := []struct {
		name       string
		from       string
		to         string
		closestart bool
		closeearly bool
		sf         bool
	}{
		{"Invalid FROM", "foo@foo", TestRcpt, false, false, true},
		{"Invalid TO", os.Getenv("TEST_FROM"), "foo@foo", false, false, true},
		{"No FROM", "", TestRcpt, false, false, true},
		{"No TO", os.Getenv("TEST_FROM"), "", false, false, true},
		{"Close early", os.Getenv("TEST_FROM"), TestRcpt, false, true, true},
		{"Close start", os.Getenv("TEST_FROM"), TestRcpt, true, false, true},
		{"Close start/early", os.Getenv("TEST_FROM"), TestRcpt, true, true, true},
	}

	m := NewMsg(WithEncoding(NoEncoding))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.SetAddrHeaderIgnoreInvalid(HeaderFrom, tt.from)
			m.SetAddrHeaderIgnoreInvalid(HeaderTo, tt.to)

			c, err := getTestConnectionWithDSN(true)
			if err != nil {
				t.Skipf("failed to create test client: %s. Skipping tests", err)
			}

			ctx, cfn := context.WithTimeout(context.Background(), time.Second*10)
			defer cfn()
			if err := c.DialWithContext(ctx); err != nil && !tt.sf {
				t.Errorf("Dail() failed: %s", err)
				return
			}
			if tt.closestart {
				_ = c.smtpClient.Close()
				_ = c.connection.Close()
			}
			if err := c.Send(m); err != nil && !tt.sf {
				t.Errorf("Send() failed: %s", err)
				return
			}
			if tt.closeearly {
				_ = c.smtpClient.Close()
				_ = c.connection.Close()
			}
			if err := c.Close(); err != nil && !tt.sf {
				t.Errorf("Close() failed: %s", err)
				return
			}
		})
	}
}

// TestClient_Send_withBrokenRecipient tests the Send() method of Client with a broken and a working recipient
func TestClient_Send_withBrokenRecipient(t *testing.T) {
	if os.Getenv("TEST_ALLOW_SEND") == "" {
		t.Skipf("TEST_ALLOW_SEND is not set. Skipping mail sending test")
	}
	var msgs []*Msg
	rcpts := []string{"invalid@domain.tld", TestRcpt, "invalid@address.invalid"}
	for _, rcpt := range rcpts {
		m := NewMsg()
		_ = m.FromFormat("go-mail Test Mailer", os.Getenv("TEST_FROM"))
		_ = m.To(rcpt)
		m.Subject(fmt.Sprintf("This is a test mail from go-mail/v%s", VERSION))
		m.SetBulk()
		m.SetDate()
		m.SetMessageID()
		m.SetBodyString(TypeTextPlain, "This is a test mail from the go-mail library")
		msgs = append(msgs, m)
	}

	c, err := getTestConnection(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}

	ctx, cfn := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cfn()
	if err := c.DialWithContext(ctx); err != nil {
		t.Errorf("failed to dial to sending server: %s", err)
	}
	if err := c.Send(msgs...); err != nil {
		if !strings.Contains(err.Error(), "invalid@domain.tld") ||
			!strings.Contains(err.Error(), "invalid@address.invalid") {
			t.Errorf("sending mails to invalid addresses was supposed to fail but didn't")
		}
		if strings.Contains(err.Error(), TestRcpt) {
			t.Errorf("sending mail to valid addresses failed: %s", err)
		}
	}
	if err := c.Close(); err != nil {
		t.Errorf("failed to close client connection: %s", err)
	}
}

// TestClient_auth tests the Dial(), Send() and Close() method of Client with broken settings
func TestClient_auth(t *testing.T) {
	tests := []struct {
		name string
		auth SMTPAuthType
		sf   bool
	}{
		{"SMTP AUTH: PLAIN", SMTPAuthPlain, false},
		{"SMTP AUTH: LOGIN", SMTPAuthLogin, false},
		{"SMTP AUTH: CRAM-MD5", SMTPAuthCramMD5, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := getTestConnection(false)
			if err != nil {
				t.Skipf("failed to create test client: %s. Skipping tests", err)
			}

			ctx, cfn := context.WithTimeout(context.Background(), time.Second*5)
			defer cfn()
			if err := c.DialWithContext(ctx); err != nil {
				t.Errorf("auth() failed: could not Dial() => %s", err)
				return
			}
			c.SetSMTPAuth(tt.auth)
			c.SetUsername(os.Getenv("TEST_SMTPAUTH_USER"))
			c.SetPassword(os.Getenv("TEST_SMTPAUTH_PASS"))
			if err := c.auth(); err != nil && !tt.sf {
				t.Errorf("auth() failed: %s", err)
			}
			if err := c.Close(); err != nil {
				t.Errorf("auth() failed: could not Close() => %s", err)
			}
		})
	}
}

// TestClient_Send_MsgSendError tests the Client.Send method with a broken recipient and verifies
// that the SendError type works properly
func TestClient_Send_MsgSendError(t *testing.T) {
	if os.Getenv("TEST_ALLOW_SEND") == "" {
		t.Skipf("TEST_ALLOW_SEND is not set. Skipping mail sending test")
	}
	var msgs []*Msg
	rcpts := []string{"invalid@domain.tld", "invalid@address.invalid"}
	for _, rcpt := range rcpts {
		m := NewMsg()
		_ = m.FromFormat("go-mail Test Mailer", os.Getenv("TEST_FROM"))
		_ = m.To(rcpt)
		m.Subject(fmt.Sprintf("This is a test mail from go-mail/v%s", VERSION))
		m.SetBulk()
		m.SetDate()
		m.SetMessageID()
		m.SetBodyString(TypeTextPlain, "This is a test mail from the go-mail library")
		msgs = append(msgs, m)
	}

	c, err := getTestConnection(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}

	ctx, cfn := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cfn()
	if err := c.DialWithContext(ctx); err != nil {
		t.Errorf("failed to dial to sending server: %s", err)
	}
	if err := c.Send(msgs...); err == nil {
		t.Errorf("sending messages with broken recipients was supposed to fail but didn't")
	}
	if err := c.Close(); err != nil {
		t.Errorf("failed to close client connection: %s", err)
	}
	for _, m := range msgs {
		if !m.HasSendError() {
			t.Errorf("message was expected to have a send error, but didn't")
		}
		se := &SendError{Reason: ErrSMTPRcptTo}
		if !errors.Is(m.SendError(), se) {
			t.Errorf("error mismatch, expected: %s, got: %s", se, m.SendError())
		}
		if m.SendErrorIsTemp() {
			t.Errorf("message was not expected to be a temporary error, but reported as such")
		}
	}
}

// TestClient_DialAndSendWithContext_withSendError tests the Client.DialAndSendWithContext method
// with a broken recipient to make sure that the returned error satisfies the Msg.SendError type
func TestClient_DialAndSendWithContext_withSendError(t *testing.T) {
	if os.Getenv("TEST_ALLOW_SEND") == "" {
		t.Skipf("TEST_ALLOW_SEND is not set. Skipping mail sending test")
	}
	m := NewMsg()
	_ = m.FromFormat("go-mail Test Mailer", os.Getenv("TEST_FROM"))
	_ = m.To("invalid@domain.tld")
	m.Subject(fmt.Sprintf("This is a test mail from go-mail/v%s", VERSION))
	m.SetBulk()
	m.SetDate()
	m.SetMessageID()
	m.SetBodyString(TypeTextPlain, "This is a test mail from the go-mail library")

	c, err := getTestConnection(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}
	ctx, cfn := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cfn()
	err = c.DialAndSendWithContext(ctx, m)
	if err == nil {
		t.Errorf("expected DialAndSendWithContext with broken mail recipient to fail, but didn't")
		return
	}
	var se *SendError
	if !errors.As(err, &se) {
		t.Errorf("expected *SendError type as returned error, but didn't")
		return
	}
	if se.IsTemp() {
		t.Errorf("expected permanent error but IsTemp() returned true")
	}
	if m.IsDelivered() {
		t.Errorf("message is indicated to be delivered but shouldn't")
	}
}

func TestClient_SendErrorNoEncoding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	featureSet := "250-AUTH PLAIN\r\n250-DSN\r\n250 SMTPUTF8"
	serverPort := TestServerPortBase + 1
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, false, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 300)

	message := NewMsg()
	if err := message.From("valid-from@domain.tld"); err != nil {
		t.Errorf("failed to set FROM address: %s", err)
		return
	}
	if err := message.To("valid-to@domain.tld"); err != nil {
		t.Errorf("failed to set TO address: %s", err)
		return
	}
	message.Subject("Test subject")
	message.SetBodyString(TypeTextPlain, "Test body")
	message.SetMessageIDWithValue("this.is.a.message.id")
	message.SetEncoding(NoEncoding)

	client, err := NewClient(TestServerAddr, WithPort(serverPort),
		WithTLSPortPolicy(NoTLS), WithSMTPAuth(SMTPAuthPlain),
		WithUsername("toni@tester.com"),
		WithPassword("V3ryS3cr3t+"))
	if err != nil {
		t.Errorf("unable to create new client: %s", err)
	}
	if err = client.DialWithContext(context.Background()); err != nil {
		t.Errorf("failed to dial to test server: %s", err)
	}
	if err = client.Send(message); err == nil {
		t.Error("expected Send() to fail but didn't")
	}

	var sendErr *SendError
	if !errors.As(err, &sendErr) {
		t.Errorf("expected *SendError type as returned error, but got %T", sendErr)
	}
	if errors.As(err, &sendErr) {
		if sendErr.IsTemp() {
			t.Errorf("expected permanent error but IsTemp() returned true")
		}
		if sendErr.Reason != ErrNoUnencoded {
			t.Errorf("expected ErrNoUnencoded error, but got %s", sendErr.Reason)
		}
		if !strings.EqualFold(sendErr.MessageID(), "<this.is.a.message.id>") {
			t.Errorf("expected message ID: %q, but got %q", "<this.is.a.message.id>",
				sendErr.MessageID())
		}
		if sendErr.Msg() == nil {
			t.Errorf("expected message to be set, but got nil")
		}
	}

	if err = client.Close(); err != nil {
		t.Errorf("failed to close server connection: %s", err)
	}
}

func TestClient_SendErrorMailFrom(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 2
	featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, false, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 300)

	message := NewMsg()
	if err := message.From("invalid-from@domain.tld"); err != nil {
		t.Errorf("failed to set FROM address: %s", err)
		return
	}
	if err := message.To("valid-to@domain.tld"); err != nil {
		t.Errorf("failed to set TO address: %s", err)
		return
	}
	message.Subject("Test subject")
	message.SetBodyString(TypeTextPlain, "Test body")
	message.SetMessageIDWithValue("this.is.a.message.id")

	client, err := NewClient(TestServerAddr, WithPort(serverPort),
		WithTLSPortPolicy(NoTLS), WithSMTPAuth(SMTPAuthPlain),
		WithUsername("toni@tester.com"),
		WithPassword("V3ryS3cr3t+"))
	if err != nil {
		t.Errorf("unable to create new client: %s", err)
	}
	if err = client.DialWithContext(context.Background()); err != nil {
		t.Errorf("failed to dial to test server: %s", err)
	}
	if err = client.Send(message); err == nil {
		t.Error("expected Send() to fail but didn't")
	}

	var sendErr *SendError
	if !errors.As(err, &sendErr) {
		t.Errorf("expected *SendError type as returned error, but got %T", sendErr)
	}
	if errors.As(err, &sendErr) {
		if sendErr.IsTemp() {
			t.Errorf("expected permanent error but IsTemp() returned true")
		}
		if sendErr.Reason != ErrSMTPMailFrom {
			t.Errorf("expected ErrSMTPMailFrom error, but got %s", sendErr.Reason)
		}
		if !strings.EqualFold(sendErr.MessageID(), "<this.is.a.message.id>") {
			t.Errorf("expected message ID: %q, but got %q", "<this.is.a.message.id>",
				sendErr.MessageID())
		}
		if sendErr.Msg() == nil {
			t.Errorf("expected message to be set, but got nil")
		}
	}

	if err = client.Close(); err != nil {
		t.Errorf("failed to close server connection: %s", err)
	}
}

func TestClient_SendErrorMailFromReset(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 3
	featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, true, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 300)

	message := NewMsg()
	if err := message.From("invalid-from@domain.tld"); err != nil {
		t.Errorf("failed to set FROM address: %s", err)
		return
	}
	if err := message.To("valid-to@domain.tld"); err != nil {
		t.Errorf("failed to set TO address: %s", err)
		return
	}
	message.Subject("Test subject")
	message.SetBodyString(TypeTextPlain, "Test body")
	message.SetMessageIDWithValue("this.is.a.message.id")

	client, err := NewClient(TestServerAddr, WithPort(serverPort),
		WithTLSPortPolicy(NoTLS), WithSMTPAuth(SMTPAuthPlain),
		WithUsername("toni@tester.com"),
		WithPassword("V3ryS3cr3t+"))
	if err != nil {
		t.Errorf("unable to create new client: %s", err)
	}
	if err = client.DialWithContext(context.Background()); err != nil {
		t.Errorf("failed to dial to test server: %s", err)
	}
	if err = client.Send(message); err == nil {
		t.Error("expected Send() to fail but didn't")
	}

	var sendErr *SendError
	if !errors.As(err, &sendErr) {
		t.Errorf("expected *SendError type as returned error, but got %T", sendErr)
	}
	if errors.As(err, &sendErr) {
		if sendErr.IsTemp() {
			t.Errorf("expected permanent error but IsTemp() returned true")
		}
		if sendErr.Reason != ErrSMTPMailFrom {
			t.Errorf("expected ErrSMTPMailFrom error, but got %s", sendErr.Reason)
		}
		if !strings.EqualFold(sendErr.MessageID(), "<this.is.a.message.id>") {
			t.Errorf("expected message ID: %q, but got %q", "<this.is.a.message.id>",
				sendErr.MessageID())
		}
		if len(sendErr.errlist) != 2 {
			t.Errorf("expected 2 errors, but got %d", len(sendErr.errlist))
			return
		}
		if !strings.EqualFold(sendErr.errlist[0].Error(), "503 5.1.2 Invalid from: <invalid-from@domain.tld>") {
			t.Errorf("expected error: %q, but got %q",
				"503 5.1.2 Invalid from: <invalid-from@domain.tld>", sendErr.errlist[0].Error())
		}
		if !strings.EqualFold(sendErr.errlist[1].Error(), "500 5.1.2 Error: reset failed") {
			t.Errorf("expected error: %q, but got %q",
				"500 5.1.2 Error: reset failed", sendErr.errlist[1].Error())
		}
	}

	if err = client.Close(); err != nil {
		t.Errorf("failed to close server connection: %s", err)
	}
}

func TestClient_SendErrorToReset(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 4
	featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, true, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 300)

	message := NewMsg()
	if err := message.From("valid-from@domain.tld"); err != nil {
		t.Errorf("failed to set FROM address: %s", err)
		return
	}
	if err := message.To("invalid-to@domain.tld"); err != nil {
		t.Errorf("failed to set TO address: %s", err)
		return
	}
	message.Subject("Test subject")
	message.SetBodyString(TypeTextPlain, "Test body")
	message.SetMessageIDWithValue("this.is.a.message.id")

	client, err := NewClient(TestServerAddr, WithPort(serverPort),
		WithTLSPortPolicy(NoTLS), WithSMTPAuth(SMTPAuthPlain),
		WithUsername("toni@tester.com"),
		WithPassword("V3ryS3cr3t+"))
	if err != nil {
		t.Errorf("unable to create new client: %s", err)
	}
	if err = client.DialWithContext(context.Background()); err != nil {
		t.Errorf("failed to dial to test server: %s", err)
	}
	if err = client.Send(message); err == nil {
		t.Error("expected Send() to fail but didn't")
	}

	var sendErr *SendError
	if !errors.As(err, &sendErr) {
		t.Errorf("expected *SendError type as returned error, but got %T", sendErr)
	}
	if errors.As(err, &sendErr) {
		if sendErr.IsTemp() {
			t.Errorf("expected permanent error but IsTemp() returned true")
		}
		if sendErr.Reason != ErrSMTPRcptTo {
			t.Errorf("expected ErrSMTPRcptTo error, but got %s", sendErr.Reason)
		}
		if !strings.EqualFold(sendErr.MessageID(), "<this.is.a.message.id>") {
			t.Errorf("expected message ID: %q, but got %q", "<this.is.a.message.id>",
				sendErr.MessageID())
		}
		if len(sendErr.errlist) != 2 {
			t.Errorf("expected 2 errors, but got %d", len(sendErr.errlist))
			return
		}
		if !strings.EqualFold(sendErr.errlist[0].Error(), "500 5.1.2 Invalid to: <invalid-to@domain.tld>") {
			t.Errorf("expected error: %q, but got %q",
				"500 5.1.2 Invalid to: <invalid-to@domain.tld>", sendErr.errlist[0].Error())
		}
		if !strings.EqualFold(sendErr.errlist[1].Error(), "500 5.1.2 Error: reset failed") {
			t.Errorf("expected error: %q, but got %q",
				"500 5.1.2 Error: reset failed", sendErr.errlist[1].Error())
		}
	}

	if err = client.Close(); err != nil {
		t.Errorf("failed to close server connection: %s", err)
	}
}

func TestClient_SendErrorDataClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 5
	featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, false, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 300)

	message := NewMsg()
	if err := message.From("valid-from@domain.tld"); err != nil {
		t.Errorf("failed to set FROM address: %s", err)
		return
	}
	if err := message.To("valid-to@domain.tld"); err != nil {
		t.Errorf("failed to set TO address: %s", err)
		return
	}
	message.Subject("Test subject")
	message.SetBodyString(TypeTextPlain, "DATA close should fail")
	message.SetMessageIDWithValue("this.is.a.message.id")

	client, err := NewClient(TestServerAddr, WithPort(serverPort),
		WithTLSPortPolicy(NoTLS), WithSMTPAuth(SMTPAuthPlain),
		WithUsername("toni@tester.com"),
		WithPassword("V3ryS3cr3t+"))
	if err != nil {
		t.Errorf("unable to create new client: %s", err)
	}
	if err = client.DialWithContext(context.Background()); err != nil {
		t.Errorf("failed to dial to test server: %s", err)
	}
	if err = client.Send(message); err == nil {
		t.Error("expected Send() to fail but didn't")
	}

	var sendErr *SendError
	if !errors.As(err, &sendErr) {
		t.Errorf("expected *SendError type as returned error, but got %T", sendErr)
	}
	if errors.As(err, &sendErr) {
		if sendErr.IsTemp() {
			t.Errorf("expected permanent error but IsTemp() returned true")
		}
		if sendErr.Reason != ErrSMTPDataClose {
			t.Errorf("expected ErrSMTPDataClose error, but got %s", sendErr.Reason)
		}
		if !strings.EqualFold(sendErr.MessageID(), "<this.is.a.message.id>") {
			t.Errorf("expected message ID: %q, but got %q", "<this.is.a.message.id>",
				sendErr.MessageID())
		}
	}

	if err = client.Close(); err != nil {
		t.Errorf("failed to close server connection: %s", err)
	}
}

func TestClient_SendErrorDataWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 6
	featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, false, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 300)

	message := NewMsg()
	if err := message.From("valid-from@domain.tld"); err != nil {
		t.Errorf("failed to set FROM address: %s", err)
		return
	}
	if err := message.To("valid-to@domain.tld"); err != nil {
		t.Errorf("failed to set TO address: %s", err)
		return
	}
	message.Subject("Test subject")
	message.SetBodyString(TypeTextPlain, "DATA write should fail")
	message.SetMessageIDWithValue("this.is.a.message.id")
	message.SetGenHeader("X-Test-Header", "DATA write should fail")

	client, err := NewClient(TestServerAddr, WithPort(serverPort),
		WithTLSPortPolicy(NoTLS), WithSMTPAuth(SMTPAuthPlain),
		WithUsername("toni@tester.com"),
		WithPassword("V3ryS3cr3t+"))
	if err != nil {
		t.Errorf("unable to create new client: %s", err)
	}
	if err = client.DialWithContext(context.Background()); err != nil {
		t.Errorf("failed to dial to test server: %s", err)
	}
	if err = client.Send(message); err == nil {
		t.Error("expected Send() to fail but didn't")
	}

	var sendErr *SendError
	if !errors.As(err, &sendErr) {
		t.Errorf("expected *SendError type as returned error, but got %T", sendErr)
	}
	if errors.As(err, &sendErr) {
		if sendErr.IsTemp() {
			t.Errorf("expected permanent error but IsTemp() returned true")
		}
		if sendErr.Reason != ErrSMTPDataClose {
			t.Errorf("expected ErrSMTPDataClose error, but got %s", sendErr.Reason)
		}
		if !strings.EqualFold(sendErr.MessageID(), "<this.is.a.message.id>") {
			t.Errorf("expected message ID: %q, but got %q", "<this.is.a.message.id>",
				sendErr.MessageID())
		}
	}
}

func TestClient_SendErrorReset(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 7
	featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, true, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 300)

	message := NewMsg()
	if err := message.From("valid-from@domain.tld"); err != nil {
		t.Errorf("failed to set FROM address: %s", err)
		return
	}
	if err := message.To("valid-to@domain.tld"); err != nil {
		t.Errorf("failed to set TO address: %s", err)
		return
	}
	message.Subject("Test subject")
	message.SetBodyString(TypeTextPlain, "Test body")
	message.SetMessageIDWithValue("this.is.a.message.id")

	client, err := NewClient(TestServerAddr, WithPort(serverPort),
		WithTLSPortPolicy(NoTLS), WithSMTPAuth(SMTPAuthPlain),
		WithUsername("toni@tester.com"),
		WithPassword("V3ryS3cr3t+"))
	if err != nil {
		t.Errorf("unable to create new client: %s", err)
	}
	if err = client.DialWithContext(context.Background()); err != nil {
		t.Errorf("failed to dial to test server: %s", err)
	}
	if err = client.Send(message); err == nil {
		t.Error("expected Send() to fail but didn't")
	}

	var sendErr *SendError
	if !errors.As(err, &sendErr) {
		t.Errorf("expected *SendError type as returned error, but got %T", sendErr)
	}
	if errors.As(err, &sendErr) {
		if sendErr.IsTemp() {
			t.Errorf("expected permanent error but IsTemp() returned true")
		}
		if sendErr.Reason != ErrSMTPReset {
			t.Errorf("expected ErrSMTPReset error, but got %s", sendErr.Reason)
		}
		if !strings.EqualFold(sendErr.MessageID(), "<this.is.a.message.id>") {
			t.Errorf("expected message ID: %q, but got %q", "<this.is.a.message.id>",
				sendErr.MessageID())
		}
	}

	if err = client.Close(); err != nil {
		t.Errorf("failed to close server connection: %s", err)
	}
}

// getTestConnection takes environment variables to establish a connection to a real
// SMTP server to test all functionality that requires a connection
func getTestConnection(auth bool) (*Client, error) {
	if os.Getenv("TEST_SKIP_ONLINE") != "" {
		return nil, fmt.Errorf("env variable TEST_SKIP_ONLINE is set. Skipping online tests")
	}
	th := os.Getenv("TEST_HOST")
	if th == "" {
		return nil, fmt.Errorf("no TEST_HOST set")
	}
	tp := 25
	if tps := os.Getenv("TEST_PORT"); tps != "" {
		tpi, err := strconv.Atoi(tps)
		if err == nil {
			tp = tpi
		}
	}
	sv := false
	if sve := os.Getenv("TEST_TLS_SKIP_VERIFY"); sve != "" {
		sv = true
	}
	c, err := NewClient(th, WithPort(tp))
	if err != nil {
		return c, err
	}
	c.tlsconfig.InsecureSkipVerify = sv
	if auth {
		st := os.Getenv("TEST_SMTPAUTH_TYPE")
		if st != "" {
			c.SetSMTPAuth(SMTPAuthType(st))
		}
		u := os.Getenv("TEST_SMTPAUTH_USER")
		if u != "" {
			c.SetUsername(u)
		}
		p := os.Getenv("TEST_SMTPAUTH_PASS")
		if p != "" {
			c.SetPassword(p)
		}
		// We don't want to log authentication data in tests
		c.SetDebugLog(false)
	}
	if err := c.DialWithContext(context.Background()); err != nil {
		return c, fmt.Errorf("connection to test server failed: %w", err)
	}
	if err := c.Close(); err != nil {
		return c, fmt.Errorf("disconnect from test server failed: %w", err)
	}
	return c, nil
}

// getTestConnectionNoTestPort takes environment variables (except the port) to establish a
// connection to a real SMTP server to test all functionality that requires a connection
func getTestConnectionNoTestPort(auth bool) (*Client, error) {
	if os.Getenv("TEST_SKIP_ONLINE") != "" {
		return nil, fmt.Errorf("env variable TEST_SKIP_ONLINE is set. Skipping online tests")
	}
	th := os.Getenv("TEST_HOST")
	if th == "" {
		return nil, fmt.Errorf("no TEST_HOST set")
	}
	sv := false
	if sve := os.Getenv("TEST_TLS_SKIP_VERIFY"); sve != "" {
		sv = true
	}
	c, err := NewClient(th)
	if err != nil {
		return c, err
	}
	c.tlsconfig.InsecureSkipVerify = sv
	if auth {
		st := os.Getenv("TEST_SMTPAUTH_TYPE")
		if st != "" {
			c.SetSMTPAuth(SMTPAuthType(st))
		}
		u := os.Getenv("TEST_SMTPAUTH_USER")
		if u != "" {
			c.SetUsername(u)
		}
		p := os.Getenv("TEST_SMTPAUTH_PASS")
		if p != "" {
			c.SetPassword(p)
		}
		// We don't want to log authentication data in tests
		c.SetDebugLog(false)
	}
	if err := c.DialWithContext(context.Background()); err != nil {
		return c, fmt.Errorf("connection to test server failed: %w", err)
	}
	if err := c.Close(); err != nil {
		return c, fmt.Errorf("disconnect from test server failed: %w", err)
	}
	return c, nil
}

// getTestClient takes environment variables to establish a client without connecting
// to the SMTP server
func getTestClient(auth bool) (*Client, error) {
	if os.Getenv("TEST_SKIP_ONLINE") != "" {
		return nil, fmt.Errorf("env variable TEST_SKIP_ONLINE is set. Skipping online tests")
	}
	th := os.Getenv("TEST_HOST")
	if th == "" {
		return nil, fmt.Errorf("no TEST_HOST set")
	}
	tp := 25
	if tps := os.Getenv("TEST_PORT"); tps != "" {
		tpi, err := strconv.Atoi(tps)
		if err == nil {
			tp = tpi
		}
	}
	sv := false
	if sve := os.Getenv("TEST_TLS_SKIP_VERIFY"); sve != "" {
		sv = true
	}
	c, err := NewClient(th, WithPort(tp))
	if err != nil {
		return c, err
	}
	c.tlsconfig.InsecureSkipVerify = sv
	if auth {
		st := os.Getenv("TEST_SMTPAUTH_TYPE")
		if st != "" {
			c.SetSMTPAuth(SMTPAuthType(st))
		}
		u := os.Getenv("TEST_SMTPAUTH_USER")
		if u != "" {
			c.SetUsername(u)
		}
		p := os.Getenv("TEST_SMTPAUTH_PASS")
		if p != "" {
			c.SetPassword(p)
		}
		// We don't want to log authentication data in tests
		c.SetDebugLog(false)
	}
	return c, nil
}

// getTestConnectionWithDSN takes environment variables to establish a connection to a real
// SMTP server to test all functionality that requires a connection. It also enables DSN
func getTestConnectionWithDSN(auth bool) (*Client, error) {
	if os.Getenv("TEST_SKIP_ONLINE") != "" {
		return nil, fmt.Errorf("env variable TEST_SKIP_ONLINE is set. Skipping online tests")
	}
	th := os.Getenv("TEST_HOST")
	if th == "" {
		return nil, fmt.Errorf("no TEST_HOST set")
	}
	tp := 25
	if tps := os.Getenv("TEST_PORT"); tps != "" {
		tpi, err := strconv.Atoi(tps)
		if err == nil {
			tp = tpi
		}
	}
	c, err := NewClient(th, WithDSN(), WithPort(tp))
	if err != nil {
		return c, err
	}
	if auth {
		st := os.Getenv("TEST_SMTPAUTH_TYPE")
		if st != "" {
			c.SetSMTPAuth(SMTPAuthType(st))
		}
		u := os.Getenv("TEST_SMTPAUTH_USER")
		if u != "" {
			c.SetUsername(u)
		}
		p := os.Getenv("TEST_SMTPAUTH_PASS")
		if p != "" {
			c.SetPassword(p)
		}
	}
	if err := c.DialWithContext(context.Background()); err != nil {
		return c, fmt.Errorf("connection to test server failed: %w", err)
	}
	if err := c.Close(); err != nil {
		return c, fmt.Errorf("disconnect from test server failed: %w", err)
	}
	return c, nil
}

func TestXOAuth2OK(t *testing.T) {
	server := []string{
		"220 Fake server ready ESMTP",
		"250-fake.server",
		"250-AUTH LOGIN XOAUTH2",
		"250 8BITMIME",
		"250 OK",
		"235 2.7.0 Accepted",
		"250 OK",
		"221 OK",
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
	c, err := NewClient("fake.host",
		WithDialContextFunc(getFakeDialFunc(fake)),
		WithTLSPortPolicy(TLSOpportunistic),
		WithSMTPAuth(SMTPAuthXOAUTH2),
		WithUsername("user"),
		WithPassword("token"))
	if err != nil {
		t.Fatalf("unable to create new client: %v", err)
	}
	if err := c.DialWithContext(context.Background()); err != nil {
		t.Fatalf("unexpected dial error: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("disconnect from test server failed: %v", err)
	}
	if !strings.Contains(wrote.String(), "AUTH XOAUTH2 dXNlcj11c2VyAWF1dGg9QmVhcmVyIHRva2VuAQE=\r\n") {
		t.Fatalf("got %q; want AUTH XOAUTH2 dXNlcj11c2VyAWF1dGg9QmVhcmVyIHRva2VuAQE=\r\n", wrote.String())
	}
}

func TestXOAuth2Unsupported(t *testing.T) {
	server := []string{
		"220 Fake server ready ESMTP",
		"250-fake.server",
		"250-AUTH LOGIN PLAIN",
		"250 8BITMIME",
		"250 OK",
		"250 OK",
		"221 OK",
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
	c, err := NewClient("fake.host",
		WithDialContextFunc(getFakeDialFunc(fake)),
		WithTLSPortPolicy(TLSOpportunistic),
		WithSMTPAuth(SMTPAuthXOAUTH2))
	if err != nil {
		t.Fatalf("unable to create new client: %v", err)
	}
	if err := c.DialWithContext(context.Background()); err == nil {
		t.Fatal("expected dial error got nil")
	} else {
		if !errors.Is(err, ErrXOauth2AuthNotSupported) {
			t.Fatalf("expected %v; got %v", ErrXOauth2AuthNotSupported, err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatalf("disconnect from test server failed: %v", err)
	}
	client := strings.Split(wrote.String(), "\r\n")
	if len(client) != 5 {
		t.Fatalf("unexpected number of client requests got %d; want 5", len(client))
	}
	if !strings.HasPrefix(client[0], "EHLO") {
		t.Fatalf("expected EHLO, got %q", client[0])
	}
	if client[1] != "NOOP" {
		t.Fatalf("expected NOOP, got %q", client[1])
	}
	if client[2] != "NOOP" {
		t.Fatalf("expected NOOP, got %q", client[2])
	}
	if client[3] != "QUIT" {
		t.Fatalf("expected QUIT, got %q", client[3])
	}
}

func getFakeDialFunc(conn net.Conn) DialContextFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return conn, nil
	}
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

// simpleSMTPServer starts a simple TCP server that resonds to SMTP commands.
// The provided featureSet represents in what the server responds to EHLO command
// failReset controls if a RSET succeeds
func simpleSMTPServer(ctx context.Context, featureSet string, failReset bool, port int) error {
	listener, err := net.Listen(TestServerProto, fmt.Sprintf("%s:%d", TestServerAddr, port))
	if err != nil {
		return fmt.Errorf("unable to listen on %s://%s: %w", TestServerProto, TestServerAddr, err)
	}

	defer func() {
		if err := listener.Close(); err != nil {
			fmt.Printf("unable to close listener: %s\n", err)
			os.Exit(1)
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
			handleTestServerConnection(connection, featureSet, failReset)
		}
	}
}

func handleTestServerConnection(connection net.Conn, featureSet string, failReset bool) {
	defer func() {
		if err := connection.Close(); err != nil {
			fmt.Printf("unable to close connection: %s\n", err)
		}
	}()

	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)

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
		fmt.Printf("unable to write to client: %s\n", err)
		return
	}

	data, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("unable to read from connection: %s\n", err)
		return
	}
	if !strings.HasPrefix(data, "EHLO") && !strings.HasPrefix(data, "HELO") {
		fmt.Printf("expected EHLO, got %q", data)
		return
	}
	if err = writeLine("250-localhost.localdomain\r\n" + featureSet); err != nil {
		fmt.Printf("unable to write to connection: %s\n", err)
		return
	}

	for {
		data, err = reader.ReadString('\n')
		if err != nil {
			break
		}

		var datastring string
		data = strings.TrimSpace(data)
		switch {
		case strings.HasPrefix(data, "MAIL FROM:"):
			from := strings.TrimPrefix(data, "MAIL FROM:")
			from = strings.ReplaceAll(from, "BODY=8BITMIME", "")
			from = strings.ReplaceAll(from, "SMTPUTF8", "")
			from = strings.TrimSpace(from)
			if !strings.EqualFold(from, "<valid-from@domain.tld>") {
				_ = writeLine(fmt.Sprintf("503 5.1.2 Invalid from: %s", from))
				break
			}
			writeOK()
		case strings.HasPrefix(data, "RCPT TO:"):
			to := strings.TrimPrefix(data, "RCPT TO:")
			to = strings.TrimSpace(to)
			if !strings.EqualFold(to, "<valid-to@domain.tld>") {
				_ = writeLine(fmt.Sprintf("500 5.1.2 Invalid to: %s", to))
				break
			}
			writeOK()
		case strings.HasPrefix(data, "AUTH PLAIN"):
			auth := strings.TrimPrefix(data, "AUTH PLAIN ")
			if !strings.EqualFold(auth, "AHRvbmlAdGVzdGVyLmNvbQBWM3J5UzNjcjN0Kw==") {
				_ = writeLine("535 5.7.8 Error: authentication failed")
				break
			}
			_ = writeLine("235 2.7.0 Authentication successful")
		case strings.EqualFold(data, "DATA"):
			_ = writeLine("354 End data with <CR><LF>.<CR><LF>")
			for {
				ddata, derr := reader.ReadString('\n')
				if derr != nil {
					fmt.Printf("failed to read DATA data from connection: %s\n", derr)
					break
				}
				ddata = strings.TrimSpace(ddata)
				if strings.EqualFold(ddata, "DATA write should fail") {
					_ = writeLine("500 5.0.0 Error during DATA transmission")
					break
				}
				if ddata == "." {
					if strings.Contains(datastring, "DATA close should fail") {
						_ = writeLine("500 5.0.0 Error during DATA closing")
						break
					}
					_ = writeLine("250 2.0.0 Ok: queued as 1234567890")
					break
				}
				datastring += ddata + "\n"
			}
		case strings.EqualFold(data, "noop"),
			strings.EqualFold(data, "vrfy"):
			writeOK()
		case strings.EqualFold(data, "rset"):
			if failReset {
				_ = writeLine("500 5.1.2 Error: reset failed")
				break
			}
			writeOK()
		case strings.EqualFold(data, "quit"):
			_ = writeLine("221 2.0.0 Bye")
		default:
			_ = writeLine("500 5.5.2 Error: bad syntax")
		}
	}
}
