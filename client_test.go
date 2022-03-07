package mail

import (
	"testing"
	"time"
)

// DefaultHost is used as default hostname for the Client
const DefaultHost = "localhost"

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
	}{
		{"set port to 25", 25, 25},
		{"set port to 465", 465, 465},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(DefaultHost, WithPort(tt.value))
			if err != nil {
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
	}{
		{"set timeout to 5s", time.Second * 5, time.Second * 5},
		{"set timeout to 30s", time.Second * 30, time.Second * 30},
		{"set timeout to 1m", time.Minute, time.Minute},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(DefaultHost, WithTimeout(tt.value))
			if err != nil {
				t.Errorf("failed to create new client: %s", err)
				return
			}
			if c.cto != tt.want {
				t.Errorf("failed to set custom timeout. Want: %d, got: %d", tt.want, c.cto)
			}
		})
	}
}

// TestWithSSL tests the WithSSL() option for the NewClient() method
func TestWithSSL(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"set SSL to true", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient(DefaultHost, WithSSL())
			if err != nil {
				t.Errorf("failed to create new client: %s", err)
				return
			}
			if c.ssl != tt.want {
				t.Errorf("failed to set SSL. Want: %t, got: %t", tt.want, c.ssl)
			}
		})
	}
}
