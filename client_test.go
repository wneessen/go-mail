package mail

import (
	"testing"
)

// DefaultHost is used as default hostname for the Client
const DefaultHost = "localhost"

// TestWithHELo tests the WithHELO() option for the NewClient() method
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
