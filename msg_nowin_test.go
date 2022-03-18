//go:build !windows

package mail

import "testing"

// TestMsg_WriteToSendmailWithCommand tests the WriteToSendmailWithCommand() method of the Msg
func TestMsg_WriteToSendmailWithCommand(t *testing.T) {
	tests := []struct {
		name string
		sp   string
		sf   bool
	}{
		{"Sendmail path: /dev/null", "/dev/null", true},
		{"Sendmail path: /bin/cat", "/bin/cat", true},
		{"Sendmail path: /is/invalid", "/is/invalid", true},
		{"Sendmail path: /bin/echo", "/bin/echo", false},
	}
	m := NewMsg()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.SetBodyString(TypeTextPlain, "Plain")
			if err := m.WriteToSendmailWithCommand(tt.sp); err != nil && !tt.sf {
				t.Errorf("WriteToSendmailWithCommand() failed: %s", err)
			}
			m.Reset()
		})
	}
}
