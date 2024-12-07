// SPDX-FileCopyrightText: 2024 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import "testing"

func TestSMTPAuthType_UnmarshalString(t *testing.T) {
	tests := []struct {
		name       string
		authString string
		expected   SMTPAuthType
	}{
		{"AUTODISCOVER: auto", "auto", SMTPAuthAutoDiscover},
		{"AUTODISCOVER: autodiscover", "autodiscover", SMTPAuthAutoDiscover},
		{"AUTODISCOVER: autodiscovery", "autodiscovery", SMTPAuthAutoDiscover},
		{"CRAM-MD5: cram-md5", "cram-md5", SMTPAuthCramMD5},
		{"CRAM-MD5: crammd5", "crammd5", SMTPAuthCramMD5},
		{"CRAM-MD5: cram", "cram", SMTPAuthCramMD5},
		{"CUSTOM", "custom", SMTPAuthCustom},
		{"LOGIN", "login", SMTPAuthLogin},
		{"LOGIN-NOENC", "login-noenc", SMTPAuthLoginNoEnc},
		{"NONE: none", "none", SMTPAuthNoAuth},
		{"NONE: noauth", "noauth", SMTPAuthNoAuth},
		{"NONE: no", "no", SMTPAuthNoAuth},
		{"PLAIN", "plain", SMTPAuthPlain},
		{"PLAIN-NOENC", "plain-noenc", SMTPAuthPlainNoEnc},
		{"SCRAM-SHA-1: scram-sha-1", "scram-sha-1", SMTPAuthSCRAMSHA1},
		{"SCRAM-SHA-1: scram-sha1", "scram-sha1", SMTPAuthSCRAMSHA1},
		{"SCRAM-SHA-1: scramsha1", "scramsha1", SMTPAuthSCRAMSHA1},
		{"SCRAM-SHA-1-PLUS: scram-sha-1-plus", "scram-sha-1-plus", SMTPAuthSCRAMSHA1PLUS},
		{"SCRAM-SHA-1-PLUS: scram-sha1-plus", "scram-sha1-plus", SMTPAuthSCRAMSHA1PLUS},
		{"SCRAM-SHA-1-PLUS: scramsha1plus", "scramsha1plus", SMTPAuthSCRAMSHA1PLUS},
		{"SCRAM-SHA-256: scram-sha-256", "scram-sha-256", SMTPAuthSCRAMSHA256},
		{"SCRAM-SHA-256: scram-sha256", "scram-sha256", SMTPAuthSCRAMSHA256},
		{"SCRAM-SHA-256: scramsha256", "scramsha256", SMTPAuthSCRAMSHA256},
		{"SCRAM-SHA-256-PLUS: scram-sha-256-plus", "scram-sha-256-plus", SMTPAuthSCRAMSHA256PLUS},
		{"SCRAM-SHA-256-PLUS: scram-sha256-plus", "scram-sha256-plus", SMTPAuthSCRAMSHA256PLUS},
		{"SCRAM-SHA-256-PLUS: scramsha256plus", "scramsha256plus", SMTPAuthSCRAMSHA256PLUS},
		{"XOAUTH2: xoauth2", "xoauth2", SMTPAuthXOAUTH2},
		{"XOAUTH2: oauth2", "oauth2", SMTPAuthXOAUTH2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var authType SMTPAuthType
			if err := authType.UnmarshalString(tt.authString); err != nil {
				t.Errorf("UnmarshalString() for type %s failed: %s", tt.authString, err)
			}
			if authType != tt.expected {
				t.Errorf("UnmarshalString() for type %s failed: expected %s, got %s",
					tt.authString, tt.expected, authType)
			}
		})
	}
	t.Run("should fail", func(t *testing.T) {
		var authType SMTPAuthType
		if err := authType.UnmarshalString("invalid"); err == nil {
			t.Error("UnmarshalString() should have failed")
		}
	})
}
