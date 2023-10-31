// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"strings"
	"testing"
)

const (
	exampleMailPlainNoEnc = `Date: Thu, 14 Sep 2023 14:35:28 +0200
MIME-Version: 1.0
Message-ID:
 <1305604950.683004066175.AAAAAAAAaaaaaaaaB@test.com>
Subject: Example mail Plain text no Encoding
User-Agent: go-mail v0.3.9 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.3.8 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: "Go Mail" <go-mail+test@go-mail.dev>
Cc: Second Recipient <recipient@test.com>
Bcc: "Invisible User" <bcc@bcc.de>
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

Dear Customer,

This is a test mail. Please do not reply to this.


Thank your for your business!
The go-mail team

-- 
This is a signature`
)

func TestEMLToMsgFromString(t *testing.T) {
	tests := []struct {
		name string
		eml  string
		enc  string
		sub  string
	}{
		{
			"Plain text no encoding", exampleMailPlainNoEnc, "8bit",
			"Example mail Plain text no Encoding",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := EMLToMsgFromString(tt.eml)
			if err != nil {
				t.Errorf("failed to parse EML: %s", err)
			}
			if m.Encoding() != tt.enc {
				t.Errorf("EMLToMsgFromString failed: expected encoding: %s, but got: %s", tt.enc, m.Encoding())
			}
			if s := m.GetGenHeader(HeaderSubject); len(s) > 0 && !strings.EqualFold(s[0], tt.sub) {
				t.Errorf("EMLToMsgFromString failed: expected subject: %s, but got: %s", tt.sub, s[0])
			}
		})
	}
}
