package mail

import (
	"net/mail"
	"testing"
)

// TestMsg_AddTo tests the AddTo() method for the Msg object
func TestMsg_AddTo(t *testing.T) {
	a := []string{"address1@example.com", "address2@example.com"}
	na := "address3@example.com"
	m := NewMsg()
	if err := m.To(a...); err != nil {
		t.Errorf("failed to set TO addresses: %s", err)
		return
	}
	if err := m.AddTo(na); err != nil {
		t.Errorf("AddTo failed: %s", err)
		return
	}

	atf := false
	for _, v := range m.addrHeader[HeaderTo] {
		if v.Address == na {
			atf = true
		}
	}
	if !atf {
		t.Errorf("AddTo() failed. Address %q not found in TO address slice.", na)
	}
}

// TestMsg_FromFormat tests the FromFormat() method for the Msg object
func TestMsg_FromFormat(t *testing.T) {
	tests := []struct {
		tname string
		name  string
		addr  string
		want  string
		fail  bool
	}{
		{"valid name and addr", "Toni Tester", "tester@example.com",
			`"Toni Tester" <tester@example.com>`, false},
		{"no name with valid addr", "", "tester@example.com",
			`<tester@example.com>`, false},
		{"valid name with invalid addr", "Toni Tester", "@example.com",
			``, true},
	}

	m := NewMsg()
	for _, tt := range tests {
		t.Run(tt.tname, func(t *testing.T) {
			if err := m.FromFormat(tt.name, tt.addr); err != nil && !tt.fail {
				t.Errorf("failed to FromFormat(): %s", err)
				return
			}

			var fa *mail.Address
			f, ok := m.addrHeader[HeaderFrom]
			if ok && len(f) > 0 {
				fa = f[0]
			}
			if (!ok || len(f) == 0) && !tt.fail {
				t.Errorf(`valid from address expected, but "From:" field is empty`)
				return
			}
			if tt.fail && len(f) > 0 {
				t.Errorf("FromFormat() was supposed to failed but got value: %s", fa.String())
				return
			}

			if !tt.fail && fa.String() != tt.want {
				t.Errorf("wrong result for FromFormat(). Want: %s, got: %s", tt.want, fa.String())
			}
			m.addrHeader[HeaderFrom] = nil
		})
	}
}
