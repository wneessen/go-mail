// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wneessen/go-mail/smtp"
)

// DefaultHost is used as default hostname for the Client
const DefaultHost = "localhost"

// TestRcpt
const TestRcpt = "go-mail@mytrashmailer.com"

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
			if c.cto != DefaultTimeout {
				t.Errorf("failed to create new client. Timeout expected: %s, got: %s", DefaultTimeout.String(),
					c.cto.String())
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
		{"WithHELO()", WithHELO(host), false},
		{"WithHELO(); helo is empty", WithHELO(""), true},
		{"WithTLSPolicy()", WithTLSPolicy(TLSOpportunistic), false},
		{"WithTLSConfig()", WithTLSConfig(&tls.Config{}), false},
		{"WithTLSConfig(); config is nil", WithTLSConfig(nil), true},
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
			if c.cto != tt.want {
				t.Errorf("failed to set custom timeout. Want: %d, got: %d", tt.want, c.cto)
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
			if c.ssl != tt.value {
				t.Errorf("failed to set SSL setting. Got: %t, want: %t", c.ssl, tt.value)
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
			if string(c.satype) != tt.want {
				t.Errorf("failed to set SMTP auth type. Expected %s, got: %s", tt.want, string(c.satype))
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
		{"SMTPAuth: PLAIN", smtp.PlainAuth("", "", "", ""), "PLAIN", false},
		{"SMTPAuth: CRAM-MD5", smtp.CRAMMD5Auth("", ""), "CRAM-MD5", false},
		{"SMTPAuth: LOGIN", smtp.LoginAuth("", "", ""), "LOGIN", false},
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
			if c.sa == nil {
				t.Errorf("failed to set custom SMTP auth method. SMTP Auth method is empty")
			}
			p, _, err := c.sa.Start(&si)
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
	if c.co == nil {
		t.Errorf("DialWithContext didn't fail but no connection found.")
	}
	if c.sc == nil {
		t.Errorf("DialWithContext didn't fail but no SMTP client found.")
	}
	if err := c.Close(); err != nil {
		t.Errorf("failed to close connection: %s", err)
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
	if c.co == nil {
		t.Errorf("DialWithContext didn't fail but no connection found.")
	}
	if c.sc == nil {
		t.Errorf("DialWithContext didn't fail but no SMTP client found.")
	}
	c.SetDebugLog(true)
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
	c.co = nil
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
	c.co = nil
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
	c.co = nil
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
				if c.co == nil && !tt.sf {
					t.Errorf("DialWithContext didn't fail but no connection found.")
				}
				if c.sc == nil && !tt.sf {
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
				_ = c.sc.Close()
				_ = c.co.Close()
			}
			if err := c.Send(m); err != nil && !tt.sf {
				t.Errorf("Send() failed: %s", err)
				return
			}
			if tt.closeearly {
				_ = c.sc.Close()
				_ = c.co.Close()
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
				_ = c.sc.Close()
				_ = c.co.Close()
			}
			if err := c.Send(m); err != nil && !tt.sf {
				t.Errorf("Send() failed: %s", err)
				return
			}
			if tt.closeearly {
				_ = c.sc.Close()
				_ = c.co.Close()
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
		return
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
	c, err := NewClient(th, WithDSN())
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
