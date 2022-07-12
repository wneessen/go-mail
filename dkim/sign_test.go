// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

package dkim

import (
	"crypto"
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

	// Test nil option
	_, err := NewConfig(TestDomain, TestSelector, nil)
	if err != nil {
		t.Errorf("NewConfig with nil option failed: %s", err)
	}
}

func TestNewConfig_WithSetAUID(t *testing.T) {
	a := "testauid"
	c, err := NewConfig(TestDomain, TestSelector, WithAUID(a))
	if err != nil {
		t.Errorf("NewConfig failed: %s", err)
	}
	if c.AUID != a {
		t.Errorf("WithAUID failed. Expected: %s, got: %s", a, c.AUID)
	}
	c.SetAUID("auidtest")
	if c.AUID != "auidtest" {
		t.Errorf("SetAUID failed. Expected: %s, got: %s", "auidtest", c.AUID)
	}
}

func TestNewConfig_WithSetHashAlgo(t *testing.T) {
	tests := []struct {
		n  string
		ha crypto.Hash
		f  bool
	}{
		{"SHA-256", crypto.SHA256, false},
		{"SHA-1", crypto.SHA1, false},
		{"MD5", crypto.MD5, true},
	}

	for _, tt := range tests {
		t.Run(tt.n, func(t *testing.T) {
			c, err := NewConfig(TestDomain, TestSelector, WithHashAlgo(tt.ha))
			if err != nil && !tt.f {
				t.Errorf("NewConfig WithHashAlgo failed: %s", err)
			}
			if c.HashAlgo.String() != tt.ha.String() && !tt.f {
				t.Errorf("NewConfig WithHashAlgo failed. Expected algo: %s, got: %s",
					tt.ha.String(), c.HashAlgo.String())
			}

			c = nil
			c, err = NewConfig(TestDomain, TestSelector)
			if err != nil && !tt.f {
				t.Errorf("NewConfig WithHashAlgo failed: %s", err)
			}
			if err := c.SetHashAlgo(tt.ha); err != nil && !tt.f {
				t.Errorf("SetHashAlgo failed: %s", err)
			}
			if c.HashAlgo.String() != tt.ha.String() && !tt.f {
				t.Errorf("NewConfig WithHashAlgo failed. Expected algo: %s, got: %s",
					tt.ha.String(), c.HashAlgo.String())
			}
		})
	}
}

func TestNewConfig_SetSelector(t *testing.T) {
	s := "override_selector"
	c, err := NewConfig(TestDomain, TestSelector)
	if err != nil {
		t.Errorf("NewConfig failed: %s", err)
	}
	if err := c.SetSelector(s); err != nil {
		t.Errorf("SetSelector() failed: %s", err)
	}
	if c.Selector != s {
		t.Errorf("SetSelector failed. Expected: %s, got: %s", s, c.Selector)
	}
	if err := c.SetSelector(""); err == nil {
		t.Errorf("empty string in SetSelector() expected to fail, but did not")
	}
}

func TestNewSigner(t *testing.T) {
	confOk := &SignerConfig{Domain: TestDomain, Selector: TestSelector}
	confNoDomain := &SignerConfig{Selector: TestSelector}
	confNoSelector := &SignerConfig{Domain: TestDomain}
	confEmpty := &SignerConfig{}
	tests := []struct {
		n string
		c *SignerConfig
		f bool
	}{
		{"valid domain and selector", confOk, false},
		{"valid domain and empty selector", confNoSelector, true},
		{"empty domain and valid selector", confNoDomain, true},
		{"empty config", confEmpty, true},
	}

	for _, tt := range tests {
		t.Run(tt.n, func(t *testing.T) {
			s, err := NewSigner(tt.c)
			if err != nil && !tt.f {
				t.Errorf("NewSigner failed but was supposed to succeed: %s", err)
			}
			if s == nil && !tt.f {
				t.Errorf("NewSigner response is nil")
			}
		})
	}
}
