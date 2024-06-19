// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

const (
	exampleMailPlainNoEnc = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // plain text without encoding
User-Agent: go-mail v0.4.0 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.0 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Cc: <go-mail+cc@go-mail.dev>
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

Dear Customer,

This is a test mail. Please do not reply to this. Also this line is very long so it
should be wrapped.


Thank your for your business!
The go-mail team

--
This is a signature`
	exampleMailPlainNoEncInvalidDate = `Date: Inv, 99 Nov 9999 99:99:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // plain text without encoding
User-Agent: go-mail v0.4.0 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.0 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Cc: <go-mail+cc@go-mail.dev>
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

Dear Customer,

This is a test mail. Please do not reply to this. Also this line is very long so it
should be wrapped.


Thank your for your business!
The go-mail team

--
This is a signature`
	exampleMailPlainNoEncNoDate = `MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // plain text without encoding
User-Agent: go-mail v0.4.0 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.0 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Cc: <go-mail+cc@go-mail.dev>
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

Dear Customer,

This is a test mail. Please do not reply to this. Also this line is very long so it
should be wrapped.


Thank your for your business!
The go-mail team

--
This is a signature`
	exampleMailPlainQP = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // plain text quoted-printable
User-Agent: go-mail v0.4.0 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.0 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Cc: <go-mail+cc@go-mail.dev>
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: quoted-printable

Dear Customer,

This is a test mail. Please do not reply to this. Also this line is very lo=
ng so it
should be wrapped.


Thank your for your business!
The go-mail team

--
This is a signature`
	exampleMailPlainB64 = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // plain text base64
User-Agent: go-mail v0.4.0 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.0 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Cc: <go-mail+cc@go-mail.dev>
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: base64

RGVhciBDdXN0b21lciwKClRoaXMgaXMgYSB0ZXN0IG1haWwuIFBsZWFzZSBkbyBub3QgcmVwbHkg
dG8gdGhpcy4gQWxzbyB0aGlzIGxpbmUgaXMgdmVyeSBsb25nIHNvIGl0CnNob3VsZCBiZSB3cmFw
cGVkLgoKClRoYW5rIHlvdXIgZm9yIHlvdXIgYnVzaW5lc3MhClRoZSBnby1tYWlsIHRlYW0KCi0t
ClRoaXMgaXMgYSBzaWduYXR1cmU=`
	exampleMailPlainB64WithAttachment = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // plain text base64 with attachment
User-Agent: go-mail v0.4.1 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.1 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Cc: <go-mail+cc@go-mail.dev>
Content-Type: multipart/mixed;
 boundary=45c75ff528359022eb03679fbe91877d75343f2e1f8193e349deffa33ff7

--45c75ff528359022eb03679fbe91877d75343f2e1f8193e349deffa33ff7
Content-Transfer-Encoding: base64
Content-Type: text/plain; charset=UTF-8

RGVhciBDdXN0b21lciwKClRoaXMgaXMgYSB0ZXN0IG1haWwuIFBsZWFzZSBkbyBub3QgcmVwbHkg
dG8gdGhpcy4gQWxzbyB0aGlzIGxpbmUgaXMgdmVyeSBsb25nIHNvIGl0CnNob3VsZCBiZSB3cmFw
cGVkLgoKClRoYW5rIHlvdXIgZm9yIHlvdXIgYnVzaW5lc3MhClRoZSBnby1tYWlsIHRlYW0KCi0t
ClRoaXMgaXMgYSBzaWduYXR1cmU=

--45c75ff528359022eb03679fbe91877d75343f2e1f8193e349deffa33ff7
Content-Disposition: attachment; filename="test.attachment"
Content-Transfer-Encoding: base64
Content-Type: application/octet-stream; name="test.attachment"

VGhpcyBpcyBhIHNpbXBsZSB0ZXN0IHRleHQgZmlsZSBhdHRhY2htZW50LgoKSXQgCiAgaGFzCiAg
ICAgc2V2ZXJhbAogICAgICAgICAgICBuZXdsaW5lcwoJICAgICAgICAgICAgYW5kCgkgICAgc3Bh
Y2VzCiAgICAgaW4KICBpdAouCgpBcyB3ZWxsIGFzIGFuIGVtb2ppOiDwn5mCCg==

--45c75ff528359022eb03679fbe91877d75343f2e1f8193e349deffa33ff7--`
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
			"Example mail // plain text without encoding",
		},
		{
			"Plain text quoted-printable", exampleMailPlainQP, "quoted-printable",
			"Example mail // plain text quoted-printable",
		},
		{
			"Plain text base64", exampleMailPlainB64, "base64",
			"Example mail // plain text base64",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := EMLToMsgFromString(tt.eml)
			if err != nil {
				t.Errorf("failed to parse EML: %s", err)
			}
			if msg.Encoding() != tt.enc {
				t.Errorf("EMLToMsgFromString failed: expected encoding: %s, but got: %s", tt.enc, msg.Encoding())
			}
			if subject := msg.GetGenHeader(HeaderSubject); len(subject) > 0 && !strings.EqualFold(subject[0], tt.sub) {
				t.Errorf("EMLToMsgFromString failed: expected subject: %s, but got: %s",
					tt.sub, subject[0])
			}
		})
	}
}

func TestEMLToMsgFromFile(t *testing.T) {
	tests := []struct {
		name string
		eml  string
		enc  string
		sub  string
	}{
		{
			"Plain text no encoding", exampleMailPlainNoEnc, "8bit",
			"Example mail // plain text without encoding",
		},
		{
			"Plain text quoted-printable", exampleMailPlainQP, "quoted-printable",
			"Example mail // plain text quoted-printable",
		},
		{
			"Plain text base64", exampleMailPlainB64, "base64",
			"Example mail // plain text base64",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir, err := os.MkdirTemp("", fmt.Sprintf("*-%s", tt.name))
			if err != nil {
				t.Errorf("failed to create temp dir: %s", err)
				return
			}
			defer func() {
				if err = os.RemoveAll(tempDir); err != nil {
					t.Error("failed to remove temp dir:", err)
				}
			}()
			err = os.WriteFile(fmt.Sprintf("%s/%s.eml", tempDir, tt.name), []byte(tt.eml), 0666)
			if err != nil {
				t.Error("failed to write mail to temp file:", err)
				return
			}
			msg, err := EMLToMsgFromFile(fmt.Sprintf("%s/%s.eml", tempDir, tt.name))
			if err != nil {
				t.Errorf("failed to parse EML: %s", err)
			}
			if msg.Encoding() != tt.enc {
				t.Errorf("EMLToMsgFromString failed: expected encoding: %s, but got: %s", tt.enc, msg.Encoding())
			}
			if subject := msg.GetGenHeader(HeaderSubject); len(subject) > 0 && !strings.EqualFold(subject[0], tt.sub) {
				t.Errorf("EMLToMsgFromString failed: expected subject: %s, but got: %s",
					tt.sub, subject[0])
			}
		})
	}
}

func TestEMLToMsgFromStringBrokenDate(t *testing.T) {
	_, err := EMLToMsgFromString(exampleMailPlainNoEncInvalidDate)
	if err == nil {
		t.Error("EML with invalid date was supposed to fail, but didn't")
	}
	now := time.Now()
	m, err := EMLToMsgFromString(exampleMailPlainNoEncNoDate)
	if err != nil {
		t.Errorf("EML with no date parsing failed: %s", err)
	}
	da := m.GetGenHeader(HeaderDate)
	if len(da) < 1 {
		t.Error("EML with no date expected current date, but got nothing")
		return
	}
	d := da[0]
	if d != now.Format(time.RFC1123Z) {
		t.Errorf("EML with no date expected: %s, got: %s", now.Format(time.RFC1123Z), d)
	}
}

func TestEMLToMsgFromStringWithAttachment(t *testing.T) {
	wantSubject := "Example mail // plain text base64 with attachment"
	msg, err := EMLToMsgFromString(exampleMailPlainB64WithAttachment)
	if err != nil {
		t.Errorf("EML with attachment failed: %s", err)
	}
	if subject := msg.GetGenHeader(HeaderSubject); len(subject) > 0 && !strings.EqualFold(subject[0], wantSubject) {
		t.Errorf("EMLToMsgFromString of EML with attachment failed: expected subject: %s, but got: %s",
			wantSubject, subject[0])
	}
	if len(msg.attachments) != 1 {
		t.Errorf("EMLToMsgFromString of EML with attachment failed: expected no. of attachments: %d, but got: %d",
			1, len(msg.attachments))
	}
	contentTypeHeader := msg.GetGenHeader(HeaderContentType)
	if len(contentTypeHeader) != 1 {
		t.Errorf("EMLToMsgFromString of EML with attachment failed: expected no. of content-type header: %d, "+
			"but got: %d", 1, len(contentTypeHeader))
	}
	contentTypeSplit := strings.SplitN(contentTypeHeader[0], "; ", 2)
	if len(contentTypeSplit) != 2 {
		t.Error("failed to split Content-Type header")
		return
	}
	if !strings.EqualFold(contentTypeSplit[0], "multipart/mixed") {
		t.Errorf("EMLToMsgFromString of EML with attachment failed: expected content-type: %s, "+
			"but got: %s", "multipart/mixed", contentTypeSplit[0])
	}
}