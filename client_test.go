package mail

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
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
