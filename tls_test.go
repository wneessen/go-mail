// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

package mail

import "testing"

// TestTLSPolicy_String tests the TLSPolicy.String method
func TestTLSPolicy_String(t *testing.T) {
	tests := []struct {
		name  string
		value TLSPolicy
		want  int
	}{
		{"TLSPolicy is Mandatory", TLSMandatory, 0},
		{"TLSPolicy is Opportunistic", TLSOpportunistic, 1},
		{"TLSPolicy is NoTLS", NoTLS, 2},
		{"TLSPolicy is Unknown", 3, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := NewClient("mail.example.com", WithTLSPolicy(tt.value))
			if err != nil {
				t.Errorf("failed to create new Client: %s", err)
				return
			}

			if c.tlspolicy != tt.value {
				t.Errorf("WithTLSPolicy() failed. Expected: %s (%d), got: %s (%d)", tt.value.String(), tt.value,
					c.tlspolicy.String(), c.tlspolicy)
			}
			if c.tlspolicy.String() != tt.value.String() {
				t.Errorf("WithTLSPolicy() failed. Expected: %s (%d), got: %s (%d)", tt.value.String(), tt.value,
					c.tlspolicy.String(), c.tlspolicy)
			}
		})
	}
}
