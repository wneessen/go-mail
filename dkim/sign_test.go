// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

package dkim

import (
	"testing"
)

const (
	TestDomain   = "test.tld"
	TestSelector = "mail"
)

func TestNewConfig(t *testing.T) {
	tests := []struct {
		n string
		d string
		s string
		f bool
	}{
		{"valid domain and selector", TestDomain, TestSelector, false},
		{"valid domain and empty selector", TestDomain, "", true},
		{"empty domain and valid selector", "", TestSelector, true},
		{"empty domain and empty selector", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.n, func(t *testing.T) {
			c, err := NewConfig(tt.d, tt.s)
			if err != nil && !tt.f {
				t.Errorf("NewConfig failed but was supposed to succeed: %s", err)
			}
			if c.Domain != tt.d && !tt.f {
				t.Errorf("SignerConfig domain incorrect. Expected: %s, got: %s", tt.d, c.Domain)
			}
			if c.Selector != tt.s && !tt.f {
				t.Errorf("SignerConfig selector incorrect. Expected: %s, got: %s", tt.s, c.Selector)
			}
		})
	}
}

func TestNewConfig_WithAUID(t *testing.T) {
	a := "testauid"
	c, err := NewConfig(TestDomain, TestSelector, WithAUID(a))
	if err != nil {
		t.Errorf("NewConfig failed: %s", err)
	}
	if c.AUID != a {
		t.Errorf("WithAUID failed. Expected: %s, got: %s", a, c.AUID)
	}
}
