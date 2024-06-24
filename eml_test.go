// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
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
	exampleMailPlainBrokenBody = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // plain text without encoding
User-Agent: go-mail v0.4.0 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.0 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Cc: <go-mail+cc@go-mail.dev>
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: base64

This plain text body should not be parsed as Base64.
`
	exampleMailPlainNoContentType = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // plain text without encoding
User-Agent: go-mail v0.4.0 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.0 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Cc: <go-mail+cc@go-mail.dev>

This plain text body should not be parsed as Base64.
`
	exampleMailPlainUnknownContentType = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // plain text without encoding
User-Agent: go-mail v0.4.0 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.0 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Cc: <go-mail+cc@go-mail.dev>
Content-Type: application/unknown; charset=UTF-8
Content-Transfer-Encoding: base64

This plain text body should not be parsed as Base64.
`
	exampleMailPlainBrokenHeader = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version = 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // plain text without encoding
User-Agent = go-mail v0.4.0 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.0 // https://github.com/wneessen/go-mail
From = "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Cc: <go-mail+cc@go-mail.dev>
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding = 8bit

Dear Customer,

This is a test mail. Please do not reply to this. Also this line is very long so it
should be wrapped.


Thank your for your business!
The go-mail team

--
This is a signature`
	exampleMailPlainBrokenFrom = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // plain text without encoding
User-Agent: go-mail v0.4.0 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.0 // https://github.com/wneessen/go-mail
From: Toni Tester" go-mail@go-mail.dev>
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
	exampleMailPlainBrokenTo = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // plain text without encoding
User-Agent: go-mail v0.4.0 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.0 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: go-mail+test.go-mail.dev>
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
	exampleMailPlainUnsupportedTransferEnc = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // plain text quoted-printable
User-Agent: go-mail v0.4.0 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.0 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Cc: <go-mail+cc@go-mail.dev>
Content-Type: text/plain; charset=ISO-8859-1
Content-Transfer-Encoding: unknown

Dear Customer,

This is a test mail. Please do not reply to this. Also this line is very long so it should be wrapped.
㋛
This is not ==D3

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
	exampleMailPlainB64BrokenBody = `Date: Wed, 01 Nov 2023 00:00:00 +0000
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
Content-Transfer-Encoding = base64
Content-Type = text/plain; charset=UTF-8

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
	exampleMailPlainB64WithEmbed = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // plain text base64 with embed
User-Agent: go-mail v0.4.1 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.1 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Cc: <go-mail+cc@go-mail.dev>
Content-Type: multipart/related;
 boundary=ffbcfb94b44e5297325102f6ced05b3b37f1d70fc38a5e78dc73c1a8434b

--ffbcfb94b44e5297325102f6ced05b3b37f1d70fc38a5e78dc73c1a8434b
Content-Transfer-Encoding: quoted-printable
Content-Type: text/plain; charset=UTF-8

This is a test body string
--ffbcfb94b44e5297325102f6ced05b3b37f1d70fc38a5e78dc73c1a8434b
Content-Disposition: inline; filename="pixel.png"
Content-Id: <pixel.png>
Content-Transfer-Encoding: base64
Content-Type: image/png; name="pixel.png"

iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2NgYGD4DwABBAEAwS2O
UAAAAABJRU5ErkJggg==

--ffbcfb94b44e5297325102f6ced05b3b37f1d70fc38a5e78dc73c1a8434b--`
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

func TestEMLToMsgFromReaderFailing(t *testing.T) {
	mailbuf := bytes.Buffer{}
	mailbuf.WriteString(exampleMailPlainBrokenFrom)
	_, err := EMLToMsgFromReader(&mailbuf)
	if err == nil {
		t.Error("EML from Reader with broken FROM was supposed to fail, but didn't")
	}
	mailbuf.Reset()
	mailbuf.WriteString(exampleMailPlainBrokenHeader)
	_, err = EMLToMsgFromReader(&mailbuf)
	if err == nil {
		t.Error("EML from Reader with broken header was supposed to fail, but didn't")
	}
	mailbuf.Reset()
	mailbuf.WriteString(exampleMailPlainB64BrokenBody)
	_, err = EMLToMsgFromReader(&mailbuf)
	if err == nil {
		t.Error("EML from Reader with broken body was supposed to fail, but didn't")
	}
	mailbuf.Reset()
	mailbuf.WriteString(exampleMailPlainBrokenBody)
	_, err = EMLToMsgFromReader(&mailbuf)
	if err == nil {
		t.Error("EML from Reader with broken body was supposed to fail, but didn't")
	}
	mailbuf.Reset()
	mailbuf.WriteString(exampleMailPlainUnknownContentType)
	_, err = EMLToMsgFromReader(&mailbuf)
	if err == nil {
		t.Error("EML from Reader with unknown content type was supposed to fail, but didn't")
	}
	mailbuf.Reset()
	mailbuf.WriteString(exampleMailPlainNoContentType)
	_, err = EMLToMsgFromReader(&mailbuf)
	if err == nil {
		t.Error("EML from Reader with no content type was supposed to fail, but didn't")
	}
	mailbuf.Reset()
	mailbuf.WriteString(exampleMailPlainUnsupportedTransferEnc)
	_, err = EMLToMsgFromReader(&mailbuf)
	if err == nil {
		t.Error("EML from Reader with unsupported Transer-Encoding was supposed to fail, but didn't")
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

func TestEMLToMsgFromStringBrokenFrom(t *testing.T) {
	_, err := EMLToMsgFromString(exampleMailPlainBrokenFrom)
	if err == nil {
		t.Error("EML with broken FROM was supposed to fail, but didn't")
	}
}

func TestEMLToMsgFromStringBrokenTo(t *testing.T) {
	_, err := EMLToMsgFromString(exampleMailPlainBrokenTo)
	if err == nil {
		t.Error("EML with broken TO was supposed to fail, but didn't")
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
}

func TestEMLToMsgFromStringWithEmbed(t *testing.T) {
	wantSubject := "Example mail // plain text base64 with embed"
	msg, err := EMLToMsgFromString(exampleMailPlainB64WithEmbed)
	if err != nil {
		t.Errorf("EML with embed failed: %s", err)
	}
	if subject := msg.GetGenHeader(HeaderSubject); len(subject) > 0 && !strings.EqualFold(subject[0], wantSubject) {
		t.Errorf("EMLToMsgFromString of EML with embed failed: expected subject: %s, but got: %s",
			wantSubject, subject[0])
	}
	if len(msg.embeds) != 1 {
		t.Errorf("EMLToMsgFromString of EML with embed failed: expected no. of embeds: %d, but got: %d",
			1, len(msg.attachments))
	}
}
