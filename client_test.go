package mail

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/wneessen/go-mail/auth"
	"net/smtp"
	"os"
	"testing"
	"time"
)

// DefaultHost is used as default hostname for the Client
const DefaultHost = "localhost"

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
		{"WithSMTPAuthCustom()",
			WithSMTPAuthCustom(smtp.PlainAuth("", "", "", "")),
			false},
		{"WithUsername()", WithUsername("test"), false},
		{"WithPassword()", WithPassword("test"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(DefaultHost, tt.option)
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
		{"SMTPAuth: LOGIN", auth.LoginAuth("", "", ""), "LOGIN", false},
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
	c.SetSMTPAuthCustom(auth.LoginAuth("invalid", "invalid", "invalid"))
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
	c, err := NewClient(th)
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
		return c, fmt.Errorf("connection to test server failed: %s", err)
	}
	if err := c.Close(); err != nil {
		return c, fmt.Errorf("disconnect from test server failed: %s", err)
	}
	return c, nil
}
