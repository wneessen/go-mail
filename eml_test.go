// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"strings"
	"testing"
)

const (
	// RFC 5322 example mail
	// See: https://datatracker.ietf.org/doc/html/rfc5322#appendix-A.1.1
	exampleMailRFC5322A11 = `From: John Doe <jdoe@machine.example>
To: Mary Smith <mary@example.net>
Subject: Saying Hello
Date: Fri, 21 Nov 1997 09:55:06 -0600
Message-ID: <1234@local.machine.example>

This is a message just to say hello.
So, "Hello".`
	exampleMailRFC5322A11InvalidFrom = `From: §§§§§§§§§
To: Mary Smith <mary@example.net>
Subject: Saying Hello
Date: Fri, 21 Nov 1997 09:55:06 -0600
Message-ID: <1234@local.machine.example>

This is a message just to say hello.
So, "Hello".`
	exampleMailInvalidHeader = `From: John Doe <jdoe@machine.example>
To: Mary Smith <mary@example.net>
Inva@id*Header; This is a header
Subject: Saying Hello
Date: Fri, 21 Nov 1997 09:55:06 -0600
Message-ID: <1234@local.machine.example>

This is a message just to say hello.
So, "Hello".`
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
	exampleMailPlainInvalidCTE = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // plain text without encoding
User-Agent: go-mail v0.4.0 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.0 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Cc: <go-mail+cc@go-mail.dev>
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: invalid

Dear Customer,

This is a test mail. Please do not reply to this. Also this line is very long so it
should be wrapped.


Thank your for your business!
The go-mail team

--
This is a signature`
	exampleMailInvalidContentType = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // plain text without encoding
User-Agent: go-mail v0.4.0 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.0 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Cc: <go-mail+cc@go-mail.dev>
Content-Type: text/plain @ charset=UTF-8; $foo; bar; --invalid--
Content-Transfer-Encoding: 8bit

Dear Customer,

This is a test mail. Please do not reply to this. Also this line is very long so it
should be wrapped.


Thank your for your business!
The go-mail team

--
This is a signature`
	exampleMailPlain7Bit = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // plain text without encoding
User-Agent: go-mail v0.4.0 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.0 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Cc: <go-mail+cc@go-mail.dev>
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 7bit

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
	exampleMailPlainB64WithAttachmentNoContentType = `Date: Wed, 01 Nov 2023 00:00:00 +0000
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

RGVhciBDdXN0b21lciwKClRoaXMgaXMgYSB0ZXN0IG1haWwuIFBsZWFzZSBkbyBub3QgcmVwbHkg
dG8gdGhpcy4gQWxzbyB0aGlzIGxpbmUgaXMgdmVyeSBsb25nIHNvIGl0CnNob3VsZCBiZSB3cmFw
cGVkLgoKClRoYW5rIHlvdXIgZm9yIHlvdXIgYnVzaW5lc3MhClRoZSBnby1tYWlsIHRlYW0KCi0t
ClRoaXMgaXMgYSBzaWduYXR1cmU=

--45c75ff528359022eb03679fbe91877d75343f2e1f8193e349deffa33ff7
Content-Disposition: attachment; filename="test.attachment"
Content-Transfer-Encoding: base64

VGhpcyBpcyBhIHNpbXBsZSB0ZXN0IHRleHQgZmlsZSBhdHRhY2htZW50LgoKSXQgCiAgaGFzCiAg
ICAgc2V2ZXJhbAogICAgICAgICAgICBuZXdsaW5lcwoJICAgICAgICAgICAgYW5kCgkgICAgc3Bh
Y2VzCiAgICAgaW4KICBpdAouCgpBcyB3ZWxsIGFzIGFuIGVtb2ppOiDwn5mCCg==

--45c75ff528359022eb03679fbe91877d75343f2e1f8193e349deffa33ff7--`
	exampleMailPlainB64WithAttachmentBrokenB64 = `Date: Wed, 01 Nov 2023 00:00:00 +0000
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
dG8gdGhpcy4gQWxzbyB0aGl§§§§§@@@@@XMgdmVyeSBsb25nIHNvIGl0CnNob3VsZCBiZSB3cmFw
cGVkLgoKClRoYW5rIHlvdXIgZm9yIHlvdXIgYnVzaW5lc3MhClRoZSBnby1tYWlsIHRlYW0KCi0t
ClRoaXMgaXMgYSBzaWduYXR1cmU=

--45c75ff528359022eb03679fbe91877d75343f2e1f8193e349deffa33ff7
Content-Disposition: attachment; filename="test.attachment"
Content-Transfer-Encoding: base64
Content-Type: application/octet-stream; name="test.attachment"

VGhpcyBpcyBhIHNpbXBsZSB0ZXN0IHRleHQgZmlsZSBhdHRhY2htZW50LgoKSXQgCiAgaGFzCiAg
ICAgc2V2ZXJhbAogICAg§§§§§@@@@@BuZXdsaW5lcwoJICAgICAgICAgICAgYW5kCgkgICAgc3Bh
Y2VzCiAgICAgaW4KICBpdAouCgpBcyB3ZWxsIGFzIGFuIGVtb2ppOiDwn5mCCg==

--45c75ff528359022eb03679fbe91877d75343f2e1f8193e349deffa33ff7--`
	exampleMailPlainB64WithAttachmentInvalidCTE = `Date: Wed, 01 Nov 2023 00:00:00 +0000
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
Content-Transfer-Encoding: invalid
Content-Type: text/plain; charset=UTF-8

RGVhciBDdXN0b21lciwKClRoaXMgaXMgYSB0ZXN0IG1haWwuIFBsZWFzZSBkbyBub3QgcmVwbHkg
dG8gdGhpcy4gQWxzbyB0aGlzIGxpbmUgaXMgdmVyeSBsb25nIHNvIGl0CnNob3VsZCBiZSB3cmFw
cGVkLgoKClRoYW5rIHlvdXIgZm9yIHlvdXIgYnVzaW5lc3MhClRoZSBnby1tYWlsIHRlYW0KCi0t
ClRoaXMgaXMgYSBzaWduYXR1cmU=

--45c75ff528359022eb03679fbe91877d75343f2e1f8193e349deffa33ff7
Content-Disposition: attachment; filename="test.attachment"
Content-Transfer-Encoding: invalid
Content-Type: application/octet-stream; name="test.attachment"

VGhpcyBpcyBhIHNpbXBsZSB0ZXN0IHRleHQgZmlsZSBhdHRhY2htZW50LgoKSXQgCiAgaGFzCiAg
ICAgc2V2ZXJhbAogICAgICAgICAgICBuZXdsaW5lcwoJICAgICAgICAgICAgYW5kCgkgICAgc3Bh
Y2VzCiAgICAgaW4KICBpdAouCgpBcyB3ZWxsIGFzIGFuIGVtb2ppOiDwn5mCCg==

--45c75ff528359022eb03679fbe91877d75343f2e1f8193e349deffa33ff7--`
	exampleMailPlainB64WithAttachmentInvalidContentType = `Date: Wed, 01 Nov 2023 00:00:00 +0000
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
Content-Type; text/plain @ charset=UTF-8; $foo; bar; --invalid--

VGhpcyBpcyBhIHNpbXBsZSB0ZXN0IHRleHQgZmlsZSBhdHRhY2htZW50LgoKSXQgCiAgaGFzCiAg
ICAgc2V2ZXJhbAogICAgICAgICAgICBuZXdsaW5lcwoJICAgICAgICAgICAgYW5kCgkgICAgc3Bh
Y2VzCiAgICAgaW4KICBpdAouCgpBcyB3ZWxsIGFzIGFuIGVtb2ppOiDwn5mCCg==

--45c75ff528359022eb03679fbe91877d75343f2e1f8193e349deffa33ff7--`
	exampleMailPlainB64WithAttachmentNoBoundary = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // plain text base64 with attachment
User-Agent: go-mail v0.4.1 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.1 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Cc: <go-mail+cc@go-mail.dev>
Content-Type: multipart/mixed;

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
	exampleMailPlainB64WithEmbedNoContentID = `Date: Wed, 01 Nov 2023 00:00:00 +0000
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
Content-Transfer-Encoding: base64
Content-Type: image/png; name="pixel.png"

iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2NgYGD4DwABBAEAwS2O
UAAAAABJRU5ErkJggg==

--ffbcfb94b44e5297325102f6ced05b3b37f1d70fc38a5e78dc73c1a8434b--`
	exampleMailMultipartMixedAlternativeRelated = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // plain text base64 with attachment, embed and alternative part
User-Agent: go-mail v0.4.1 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.1 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Cc: <go-mail+cc@go-mail.dev>
Content-Type: multipart/mixed;
 boundary=fe785e0384e2607697cc2ecb17cce003003bb7ca9112104f3e8ce727edb5

--fe785e0384e2607697cc2ecb17cce003003bb7ca9112104f3e8ce727edb5
Content-Type: multipart/related;
 boundary=5897e40a22c608e252cfab849e966112fcbd5a1c291208026b3ca2bfab8a



--5897e40a22c608e252cfab849e966112fcbd5a1c291208026b3ca2bfab8a
Content-Type: multipart/alternative;
 boundary=cbace12de35ef4eae53fd974ccd41cb2aee4f9c9c76057ec8bfdd0c97813



--cbace12de35ef4eae53fd974ccd41cb2aee4f9c9c76057ec8bfdd0c97813
Content-Transfer-Encoding: base64
Content-Type: text/plain; charset=UTF-8

RGVhciBDdXN0b21lciwKCkdvb2QgbmV3cyEgWW91ciBvcmRlciBpcyBvbiB0aGUgd2F5IGFuZCBp
bnZvaWNlIGlzIGF0dGFjaGVkIQoKWW91IHdpbGwgZmluZCB5b3VyIHRyYWNraW5nIG51bWJlciBv
biB0aGUgaW52b2ljZS4gVHJhY2tpbmcgZGF0YSBtYXkgdGFrZQp1cCB0byAyNCBob3VycyB0byBi
ZSBhY2Nlc3NpYmxlIG9ubGluZS4KCuKAoiBQbGVhc2UgcmVtaXQgcGF5bWVudCBhdCB5b3VyIGVh
cmxpZXN0IGNvbnZlbmllbmNlIHVubGVzcyBpbnZvaWNlIGlzCm1hcmtlZCDigJxQQUlE4oCdLgri
gKIgU29tZSBpdGVtcyBtYXkgc2hpcCBzZXBhcmF0ZWx5IGZyb20gbXVsdGlwbGUgbG9jYXRpb25z
LiBTZXBhcmF0ZQppbnZvaWNlcyB3aWxsIGJlIGlzc3VlZCB3aGVuIGFwcGxpY2FibGUuCuKAoiBQ
TEVBU0UgSU5TUEVDVCBVUE9OIFJFQ0VJUFQgRk9SIFBBVFRFUk4sIENPTE9SLCBERUZFQ1RTLCBE
QU1BR0UgRlJPTQpTSElQUElORywgQ09SUkVDVCBZQVJEQUdFLCBFVEMhIE9uY2UgYW4gb3JkZXIg
aXMgY3V0IG9yIHNld24sIG5vIHJldHVybnMKd2lsbCBiZSBhY2NlcHRlZCBmb3IgYW55IHJlYXNv
biwgbm8gbWF0dGVyIHRoZSBwYXJ0eSBpbiBlcnJvci4gTm8gcmV0dXJucwp3aWxsIGJlIGF1dGhv
cml6ZWQgYWZ0ZXIgMzAgZGF5cyBvZiBpbnZvaWNlIGRhdGUuIE5vIGV4Y2VwdGlvbnMgd2lsbCBi
ZQptYWRlLgoKVGhhbmsgeW91ciBmb3IgeW91ciBidXNpbmVzcyEKCk5haWxkb2N0b3IgRmFicmlj
cw==

--cbace12de35ef4eae53fd974ccd41cb2aee4f9c9c76057ec8bfdd0c97813
Content-Transfer-Encoding: base64
Content-Type: text/html; charset=UTF-8

PCFET0NUWVBFIGh0bWw+CjxodG1sIGxhbmc9ImVuIj4KPGJvZHk+CjxwPlRoaXMgaXMgSFRNTCA8
c3Ryb25nPmluIEJPTEQ8L3N0cm9uZz4KPHA+ClRoaXMgaXMgYW4gZW1iZWRkZWQgcGljdHVyZTog
CjxpbWcgYWx0PSJwaXhlbC5wbmciIHNyYz0iY2lkOmltYWdlMS5wbmciPgo8YnI+Rm9vPC9wPg==

--cbace12de35ef4eae53fd974ccd41cb2aee4f9c9c76057ec8bfdd0c97813--

--5897e40a22c608e252cfab849e966112fcbd5a1c291208026b3ca2bfab8a
Content-Disposition: inline; filename="pixel.png"
Content-Id: image1.png
Content-Transfer-Encoding: base64
Content-Type: image/png; name="pixel.png"

iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAAAAACoWZBhAAAFEmlUWHRYTUw6Y29tLmFkb2JlLnht
cAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQi
Pz4KPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iWE1QIENvcmUg
NS41LjAiPgogPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIy
LXJkZi1zeW50YXgtbnMjIj4KICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIgogICAgeG1s
bnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIgogICAgeG1sbnM6cGhvdG9zaG9w
PSJodHRwOi8vbnMuYWRvYmUuY29tL3Bob3Rvc2hvcC8xLjAvIgogICAgeG1sbnM6ZXhpZj0iaHR0
cDovL25zLmFkb2JlLmNvbS9leGlmLzEuMC8iCiAgICB4bWxuczp0aWZmPSJodHRwOi8vbnMuYWRv
YmUuY29tL3RpZmYvMS4wLyIKICAgIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hh
cC8xLjAvbW0vIgogICAgeG1sbnM6c3RFdnQ9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9z
VHlwZS9SZXNvdXJjZUV2ZW50IyIKICAgeG1wOkNyZWF0ZURhdGU9IjIwMjQtMDYtMjhUMTM6MjY6
MDYrMDIwMCIKICAgeG1wOk1vZGlmeURhdGU9IjIwMjQtMDYtMjhUMTM6Mjc6MDgrMDI6MDAiCiAg
IHhtcDpNZXRhZGF0YURhdGU9IjIwMjQtMDYtMjhUMTM6Mjc6MDgrMDI6MDAiCiAgIHBob3Rvc2hv
cDpEYXRlQ3JlYXRlZD0iMjAyNC0wNi0yOFQxMzoyNjowNiswMjAwIgogICBwaG90b3Nob3A6Q29s
b3JNb2RlPSIxIgogICBwaG90b3Nob3A6SUNDUHJvZmlsZT0iR3JleXNjYWxlIEQ1MCIKICAgZXhp
ZjpQaXhlbFhEaW1lbnNpb249IjEwIgogICBleGlmOlBpeGVsWURpbWVuc2lvbj0iMTAiCiAgIGV4
aWY6Q29sb3JTcGFjZT0iNjU1MzUiCiAgIHRpZmY6SW1hZ2VXaWR0aD0iMTAiCiAgIHRpZmY6SW1h
Z2VMZW5ndGg9IjEwIgogICB0aWZmOlJlc29sdXRpb25Vbml0PSIyIgogICB0aWZmOlhSZXNvbHV0
aW9uPSI3Mi8xIgogICB0aWZmOllSZXNvbHV0aW9uPSI3Mi8xIj4KICAgPHhtcE1NOkhpc3Rvcnk+
CiAgICA8cmRmOlNlcT4KICAgICA8cmRmOmxpCiAgICAgIHN0RXZ0OmFjdGlvbj0icHJvZHVjZWQi
CiAgICAgIHN0RXZ0OnNvZnR3YXJlQWdlbnQ9IkFmZmluaXR5IFBob3RvIDIgMi4zLjAiCiAgICAg
IHN0RXZ0OndoZW49IjIwMjQtMDYtMjhUMTM6Mjc6MDgrMDI6MDAiLz4KICAgIDwvcmRmOlNlcT4K
ICAgPC94bXBNTTpIaXN0b3J5PgogIDwvcmRmOkRlc2NyaXB0aW9uPgogPC9yZGY6UkRGPgo8L3g6
eG1wbWV0YT4KPD94cGFja2V0IGVuZD0iciI/PpwIGG4AAADdaUNDUEdyZXlzY2FsZSBENTAAABiV
dVC9CsJAGEul6KCDg4vSoQ+gIIjiKoou6qAVrLiUs/5gq8e1In0v30TwGRycnc0VcRD9IJdwfMmR
A4xlIMLIrAPhIVaDSceduws7d0cWFvIow/JEJEfTvoO/87zB0Hyt6az/ez/HXPmRIF+IlpAqJj+I
4TmW1EaburR3Jl3qIXUxDE7i7dWvFvzDbEquEBYGUPCRIIKAh4DaRg9N6H6/ffXUN8aRm4KnpFth
hw22iFHl7YlpOmedZvtMTfQffXeXnvI+rTKNxguyvDKvB7U4qQAAAAlwSFlzAAALEwAACxMBAJqc
GAAAABFJREFUCJljnMoAA0wMNGcCAEQrAKk9oHKhAAAAAElFTkSuQmCC

--5897e40a22c608e252cfab849e966112fcbd5a1c291208026b3ca2bfab8a--

--fe785e0384e2607697cc2ecb17cce003003bb7ca9112104f3e8ce727edb5
Content-Disposition: attachment; filename="attachment.png"
Content-Transfer-Encoding: base64
Content-Type: image/png; name="attachment.png"

iVBORw0KGgoAAAANSUhEUgAAAAoAAAAKCAAAAACoWZBhAAAFEmlUWHRYTUw6Y29tLmFkb2JlLnht
cAAAAAAAPD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQi
Pz4KPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iWE1QIENvcmUg
NS41LjAiPgogPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIy
LXJkZi1zeW50YXgtbnMjIj4KICA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIgogICAgeG1s
bnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIgogICAgeG1sbnM6cGhvdG9zaG9w
PSJodHRwOi8vbnMuYWRvYmUuY29tL3Bob3Rvc2hvcC8xLjAvIgogICAgeG1sbnM6ZXhpZj0iaHR0
cDovL25zLmFkb2JlLmNvbS9leGlmLzEuMC8iCiAgICB4bWxuczp0aWZmPSJodHRwOi8vbnMuYWRv
YmUuY29tL3RpZmYvMS4wLyIKICAgIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hh
cC8xLjAvbW0vIgogICAgeG1sbnM6c3RFdnQ9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9z
VHlwZS9SZXNvdXJjZUV2ZW50IyIKICAgeG1wOkNyZWF0ZURhdGU9IjIwMjQtMDYtMjhUMTM6MjY6
MDYrMDIwMCIKICAgeG1wOk1vZGlmeURhdGU9IjIwMjQtMDYtMjhUMTM6Mjc6MDgrMDI6MDAiCiAg
IHhtcDpNZXRhZGF0YURhdGU9IjIwMjQtMDYtMjhUMTM6Mjc6MDgrMDI6MDAiCiAgIHBob3Rvc2hv
cDpEYXRlQ3JlYXRlZD0iMjAyNC0wNi0yOFQxMzoyNjowNiswMjAwIgogICBwaG90b3Nob3A6Q29s
b3JNb2RlPSIxIgogICBwaG90b3Nob3A6SUNDUHJvZmlsZT0iR3JleXNjYWxlIEQ1MCIKICAgZXhp
ZjpQaXhlbFhEaW1lbnNpb249IjEwIgogICBleGlmOlBpeGVsWURpbWVuc2lvbj0iMTAiCiAgIGV4
aWY6Q29sb3JTcGFjZT0iNjU1MzUiCiAgIHRpZmY6SW1hZ2VXaWR0aD0iMTAiCiAgIHRpZmY6SW1h
Z2VMZW5ndGg9IjEwIgogICB0aWZmOlJlc29sdXRpb25Vbml0PSIyIgogICB0aWZmOlhSZXNvbHV0
aW9uPSI3Mi8xIgogICB0aWZmOllSZXNvbHV0aW9uPSI3Mi8xIj4KICAgPHhtcE1NOkhpc3Rvcnk+
CiAgICA8cmRmOlNlcT4KICAgICA8cmRmOmxpCiAgICAgIHN0RXZ0OmFjdGlvbj0icHJvZHVjZWQi
CiAgICAgIHN0RXZ0OnNvZnR3YXJlQWdlbnQ9IkFmZmluaXR5IFBob3RvIDIgMi4zLjAiCiAgICAg
IHN0RXZ0OndoZW49IjIwMjQtMDYtMjhUMTM6Mjc6MDgrMDI6MDAiLz4KICAgIDwvcmRmOlNlcT4K
ICAgPC94bXBNTTpIaXN0b3J5PgogIDwvcmRmOkRlc2NyaXB0aW9uPgogPC9yZGY6UkRGPgo8L3g6
eG1wbWV0YT4KPD94cGFja2V0IGVuZD0iciI/PpwIGG4AAADdaUNDUEdyZXlzY2FsZSBENTAAABiV
dVC9CsJAGEul6KCDg4vSoQ+gIIjiKoou6qAVrLiUs/5gq8e1In0v30TwGRycnc0VcRD9IJdwfMmR
A4xlIMLIrAPhIVaDSceduws7d0cWFvIow/JEJEfTvoO/87zB0Hyt6az/ez/HXPmRIF+IlpAqJj+I
4TmW1EaburR3Jl3qIXUxDE7i7dWvFvzDbEquEBYGUPCRIIKAh4DaRg9N6H6/ffXUN8aRm4KnpFth
hw22iFHl7YlpOmedZvtMTfQffXeXnvI+rTKNxguyvDKvB7U4qQAAAAlwSFlzAAALEwAACxMBAJqc
GAAAABFJREFUCJljnMoAA0wMNGcCAEQrAKk9oHKhAAAAAElFTkSuQmCC

--fe785e0384e2607697cc2ecb17cce003003bb7ca9112104f3e8ce727edb5--`
	exampleMultiPart7BitBase64 = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // 7bit with base64 attachment
User-Agent: go-mail v0.4.1 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.1 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Cc: <go-mail+cc@go-mail.dev>
Content-Type: multipart/mixed;
 boundary="------------26A45336F6C6196BD8BBA2A2"

This is a multi-part message in MIME format.
--------------26A45336F6C6196BD8BBA2A2
Content-Type: text/plain; charset=US-ASCII; format=flowed
Content-Transfer-Encoding: 7bit

testtest
testtest
testtest
testtest
testtest
testtest

--------------26A45336F6C6196BD8BBA2A2
Content-Type: text/plain; charset=UTF-8;
 name="testfile.txt"
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
 filename="testfile.txt"

VGhpcyBpcyBhIHRlc3QgaW4gQmFzZTY0
--------------26A45336F6C6196BD8BBA2A2--`
	exampleMultiPart7BitBase64BrokenB64 = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // 7bit with base64 attachment
User-Agent: go-mail v0.4.1 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.1 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Cc: <go-mail+cc@go-mail.dev>
Content-Type: multipart/mixed;
 boundary="------------26A45336F6C6196BD8BBA2A2"

This is a multi-part message in MIME format.
--------------26A45336F6C6196BD8BBA2A2
Content-Type: text/plain; charset=US-ASCII; format=flowed
Content-Transfer-Encoding: 7bit

testtest
testtest
testtest
testtest
testtest
testtest

--------------26A45336F6C6196BD8BBA2A2
Content-Type: text/plain; charset=UTF-8;
 name="testfile.txt"
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
 filename="testfile.txt"

VGh@@@@§§§§hIHRlc3QgaW4gQmFzZTY0
--------------26A45336F6C6196BD8BBA2A2--`
	exampleMultiPart8BitBase64 = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail // 8bit with base64 attachment
User-Agent: go-mail v0.4.1 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.1 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Cc: <go-mail+cc@go-mail.dev>
Content-Type: multipart/mixed;
 boundary="------------26A45336F6C6196BD8BBA2A2"

This is a multi-part message in MIME format.
--------------26A45336F6C6196BD8BBA2A2
Content-Type: text/plain; charset=US-ASCII; format=flowed
Content-Transfer-Encoding: 8bit

testtest
testtest
testtest
testtest
testtest
testtest

--------------26A45336F6C6196BD8BBA2A2
Content-Type: text/plain; charset=UTF-8;
 name="testfile.txt"
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
 filename="testfile.txt"

VGhpcyBpcyBhIHRlc3QgaW4gQmFzZTY0
--------------26A45336F6C6196BD8BBA2A2--`
	exampleMailWithInlineEmbed = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail with inline embed
User-Agent: go-mail v0.4.1 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.1 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Content-Type: multipart/related; boundary="abc123"

--abc123
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: quoted-printable

<html>
  <body>
    <p>Hello,</p>
    <p>This is an example email with an inline image:</p>
    <img src="cid:12345@go-mail.dev" alt="Inline Image">
    <p>Best regards,<br>The go-mail team</p>
  </body>
</html>
--abc123
Content-Type: image/png
Content-Transfer-Encoding: base64
Content-ID: <12345@go-mail.dev>
Content-Disposition: inline; filename="test.png"

iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2NgYGD4DwABBAEAwS2O
UAAAAABJRU5ErkJggg==
--abc123--`
	exampleMailWithInlineEmbedWrongDisposition = `Date: Wed, 01 Nov 2023 00:00:00 +0000
MIME-Version: 1.0
Message-ID: <1305604950.683004066175.AAAAAAAAaaaaaaaaB@go-mail.dev>
Subject: Example mail with inline embed
User-Agent: go-mail v0.4.1 // https://github.com/wneessen/go-mail
X-Mailer: go-mail v0.4.1 // https://github.com/wneessen/go-mail
From: "Toni Tester" <go-mail@go-mail.dev>
To: <go-mail+test@go-mail.dev>
Content-Type: multipart/related; boundary="abc123"

--abc123
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: quoted-printable

<html>
  <body>
    <p>Hello,</p>
    <p>This is an example email with an inline image:</p>
    <img src="cid:12345@go-mail.dev" alt="Inline Image">
    <p>Best regards,<br>The go-mail team</p>
  </body>
</html>
--abc123
Content-Type: image/png
Content-Transfer-Encoding: base64
Content-ID: <12345@go-mail.dev>
Content-Disposition: broken; filename="test.png"

iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIW2NgYGD4DwABBAEAwS2O
UAAAAABJRU5ErkJggg==
--abc123--`
)

func TestEMLToMsgFromReader(t *testing.T) {
	t.Run("EMLToMsgFromReader via EMLToMsgFromString, check subject and encoding", func(t *testing.T) {
		tests := []struct {
			name         string
			emlString    string
			wantEncoding Encoding
			wantSubject  string
		}{
			{
				"RFC5322 A1.1 example mail", exampleMailRFC5322A11, EncodingUSASCII,
				"Saying Hello"},
			{
				"Plain text no encoding (7bit)", exampleMailPlain7Bit, EncodingUSASCII,
				"Example mail // plain text without encoding",
			},
			{
				"Plain text no encoding", exampleMailPlainNoEnc, NoEncoding,
				"Example mail // plain text without encoding",
			},
			{
				"Plain text quoted-printable", exampleMailPlainQP, EncodingQP,
				"Example mail // plain text quoted-printable",
			},
			{
				"Plain text base64", exampleMailPlainB64, EncodingB64,
				"Example mail // plain text base64",
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				parsed, err := EMLToMsgFromString(tt.emlString)
				if err != nil {
					t.Fatalf("failed to parse EML string: %s", err)
				}
				if parsed.Encoding() != tt.wantEncoding.String() {
					t.Errorf("failed to parse EML string: want encoding %s, got %s", tt.wantEncoding,
						parsed.Encoding())
				}
				gotSubject, ok := parsed.genHeader[HeaderSubject]
				if !ok {
					t.Fatalf("failed to parse EML string. No subject header found")
				}
				if len(gotSubject) != 1 {
					t.Fatalf("failed to parse EML string, more than one subject header found")
				}
				if !strings.EqualFold(gotSubject[0], tt.wantSubject) {
					t.Errorf("failed to parse EML string: want subject %s, got %s", tt.wantSubject,
						gotSubject[0])
				}
			})
		}
	})
	t.Run("EMLToMsgFromReader fails on reader", func(t *testing.T) {
		emlReader := bytes.NewBufferString("invalid")
		if _, err := EMLToMsgFromReader(emlReader); err == nil {
			t.Errorf("EML parsing with invalid EML string should fail")
		}
	})
	t.Run("EMLToMsgFromReader fails on parseEML", func(t *testing.T) {
		emlReader := bytes.NewBufferString(exampleMailRFC5322A11InvalidFrom)
		if _, err := EMLToMsgFromReader(emlReader); err == nil {
			t.Errorf("EML parsing with invalid EML string should fail")
		}
	})
	t.Run("EMLToMsgFromReader via EMLToMsgFromString on different examples", func(t *testing.T) {
		tests := []struct {
			name       string
			emlString  string
			shouldFail bool
		}{
			{
				name:       "Valid RFC 5322 Example",
				emlString:  exampleMailRFC5322A11,
				shouldFail: false,
			},
			{
				name:       "Invalid From Header (RFC 5322)",
				emlString:  exampleMailRFC5322A11InvalidFrom,
				shouldFail: true,
			},
			{
				name:       "Invalid Header",
				emlString:  exampleMailInvalidHeader,
				shouldFail: true,
			},
			{
				name:       "Plain broken Content-Type",
				emlString:  exampleMailInvalidContentType,
				shouldFail: true,
			},
			{
				name:       "Plain No Encoding",
				emlString:  exampleMailPlainNoEnc,
				shouldFail: false,
			},
			{
				name:       "Plain invalid CTE",
				emlString:  exampleMailPlainInvalidCTE,
				shouldFail: true,
			},
			{
				name:       "Plain 7bit",
				emlString:  exampleMailPlain7Bit,
				shouldFail: false,
			},
			{
				name:       "Broken Body Base64",
				emlString:  exampleMailPlainBrokenBody,
				shouldFail: true,
			},
			{
				name:       "Unknown Content Type",
				emlString:  exampleMailPlainUnknownContentType,
				shouldFail: true,
			},
			{
				name:       "Broken Header",
				emlString:  exampleMailPlainBrokenHeader,
				shouldFail: true,
			},
			{
				name:       "Broken From Header",
				emlString:  exampleMailPlainBrokenFrom,
				shouldFail: true,
			},
			{
				name:       "Broken To Header",
				emlString:  exampleMailPlainBrokenTo,
				shouldFail: true,
			},
			{
				name:       "Invalid Date",
				emlString:  exampleMailPlainNoEncInvalidDate,
				shouldFail: true,
			},
			{
				name:       "No Date Header",
				emlString:  exampleMailPlainNoEncNoDate,
				shouldFail: false,
			},
			{
				name:       "Quoted Printable Encoding",
				emlString:  exampleMailPlainQP,
				shouldFail: false,
			},
			{
				name:       "Unsupported Transfer Encoding",
				emlString:  exampleMailPlainUnsupportedTransferEnc,
				shouldFail: true,
			},
			{
				name:       "Base64 Encoding",
				emlString:  exampleMailPlainB64,
				shouldFail: false,
			},
			{
				name:       "Base64 with Attachment",
				emlString:  exampleMailPlainB64WithAttachment,
				shouldFail: false,
			},
			{
				name:       "Base64 with Attachment no content types",
				emlString:  exampleMailPlainB64WithAttachmentNoContentType,
				shouldFail: true,
			},
			{
				name:       "Multipart Base64 with Attachment broken Base64",
				emlString:  exampleMailPlainB64WithAttachmentBrokenB64,
				shouldFail: true,
			},
			{
				name:       "Base64 with Attachment with invalid content type in attachment",
				emlString:  exampleMailPlainB64WithAttachmentInvalidContentType,
				shouldFail: true,
			},
			{
				name:       "Base64 with Attachment with invalid CTE in attachment",
				emlString:  exampleMailPlainB64WithAttachmentInvalidCTE,
				shouldFail: true,
			},
			{
				name:       "Base64 with Attachment No Boundary",
				emlString:  exampleMailPlainB64WithAttachmentNoBoundary,
				shouldFail: true,
			},
			{
				name:       "Broken Body Base64",
				emlString:  exampleMailPlainB64BrokenBody,
				shouldFail: true,
			},
			{
				name:       "Base64 with Embedded Image",
				emlString:  exampleMailPlainB64WithEmbed,
				shouldFail: false,
			},
			{
				name:       "Base64 with Embed No Content-ID",
				emlString:  exampleMailPlainB64WithEmbedNoContentID,
				shouldFail: false,
			},
			{
				name:       "Multipart Mixed with Attachment, Embed, and Alternative Part",
				emlString:  exampleMailMultipartMixedAlternativeRelated,
				shouldFail: false,
			},
			{
				name:       "Multipart 7bit Base64",
				emlString:  exampleMultiPart7BitBase64,
				shouldFail: false,
			},
			{
				name:       "Multipart 7bit Base64 with broken Base64",
				emlString:  exampleMultiPart7BitBase64BrokenB64,
				shouldFail: true,
			},
			{
				name:       "Multipart 8bit Base64",
				emlString:  exampleMultiPart8BitBase64,
				shouldFail: false,
			},
			{
				name:       "Multipart with inline embed",
				emlString:  exampleMailWithInlineEmbed,
				shouldFail: false,
			},
			{
				name:       "Multipart with inline embed disposition broken",
				emlString:  exampleMailWithInlineEmbedWrongDisposition,
				shouldFail: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				_, err := EMLToMsgFromString(tt.emlString)
				if tt.shouldFail && err == nil {
					t.Errorf("parsing of EML was supposed to fail, but it did not")
				}
				if !tt.shouldFail && err != nil {
					t.Errorf("parsing of EML failed: %s", err)
				}
			})
		}
	})
}

func TestEMLToMsgFromFile(t *testing.T) {
	t.Run("EMLToMsgFromFile succeeds", func(t *testing.T) {
		parsed, err := EMLToMsgFromFile("testdata/RFC5322-A1-1.eml")
		if err != nil {
			t.Fatalf("EMLToMsgFromFile failed: %s ", err)
		}
		if parsed.Encoding() != EncodingUSASCII.String() {
			t.Errorf("EMLToMsgFromFile failed: want encoding %s, got %s", EncodingUSASCII,
				parsed.Encoding())
		}
		gotSubject, ok := parsed.genHeader[HeaderSubject]
		if !ok {
			t.Fatalf("failed to parse EML string. No subject header found")
		}
		if len(gotSubject) != 1 {
			t.Fatalf("failed to parse EML string, more than one subject header found")
		}
		if !strings.EqualFold(gotSubject[0], "Saying Hello") {
			t.Errorf("failed to parse EML string: want subject %s, got %s", "Saying Hello",
				gotSubject[0])
		}

	})
	t.Run("EMLToMsgFromFile fails on file not found", func(t *testing.T) {
		if _, err := EMLToMsgFromFile("testdata/not-existing.eml"); err == nil {
			t.Errorf("EMLToMsgFromFile with invalid file should fail")
		}
	})
	t.Run("EMLToMsgFromFile fails on parseEML", func(t *testing.T) {
		if _, err := EMLToMsgFromFile("testdata/RFC5322-A1-1-invalid-from.eml"); err == nil {
			t.Errorf("EMLToMsgFromFile with invalid EML message should fail")
		}
	})
}

/*
func TestEMLToMsgFromString(t *testing.T) {
	tests := []struct {
		name string
		eml  string
		enc  string
		sub  string
	}{
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
			tempDir, tempFile, err := stringToTempFile(tt.eml, tt.name)
			defer func() {
				if err = os.RemoveAll(tempDir); err != nil {
					t.Error("failed to remove temp dir:", err)
				}
			}()
			msg, err := EMLToMsgFromFile(tempFile)
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
	mailbuf := bytes.NewBufferString(exampleMailPlainBrokenFrom)
	_, err := EMLToMsgFromReader(mailbuf)
	if err == nil {
		t.Error("EML from Reader with broken FROM was supposed to fail, but didn't")
	}
	mailbuf.Reset()
	mailbuf.WriteString(exampleMailPlainBrokenHeader)
	_, err = EMLToMsgFromReader(mailbuf)
	if err == nil {
		t.Error("EML from Reader with broken header was supposed to fail, but didn't")
	}
	mailbuf.Reset()
	mailbuf.WriteString(exampleMailPlainB64BrokenBody)
	_, err = EMLToMsgFromReader(mailbuf)
	if err == nil {
		t.Error("EML from Reader with broken body was supposed to fail, but didn't")
	}
	mailbuf.Reset()
	mailbuf.WriteString(exampleMailPlainBrokenBody)
	_, err = EMLToMsgFromReader(mailbuf)
	if err == nil {
		t.Error("EML from Reader with broken body was supposed to fail, but didn't")
	}
	mailbuf.Reset()
	mailbuf.WriteString(exampleMailPlainUnknownContentType)
	_, err = EMLToMsgFromReader(mailbuf)
	if err == nil {
		t.Error("EML from Reader with unknown content type was supposed to fail, but didn't")
	}
	mailbuf.Reset()
	mailbuf.WriteString(exampleMailPlainUnsupportedTransferEnc)
	_, err = EMLToMsgFromReader(mailbuf)
	if err == nil {
		t.Error("EML from Reader with unsupported Transer-Encoding was supposed to fail, but didn't")
	}
}

func TestEMLToMsgFromFileFailing(t *testing.T) {
	tempDir, tempFile, err := stringToTempFile(exampleMailPlainBrokenFrom, "testmail")
	if err != nil {
		t.Errorf("failed to write EML string to temp file: %s", err)
	}
	_, err = EMLToMsgFromFile(tempFile)
	if err == nil {
		t.Error("EML from Reader with broken FROM was supposed to fail, but didn't")
	}
	if err = os.RemoveAll(tempDir); err != nil {
		t.Error("failed to remove temp dir:", err)
	}
	tempDir, tempFile, err = stringToTempFile(exampleMailPlainBrokenHeader, "testmail")
	if err != nil {
		t.Errorf("failed to write EML string to temp file: %s", err)
	}
	_, err = EMLToMsgFromFile(tempFile)
	if err == nil {
		t.Error("EML from Reader with broken header was supposed to fail, but didn't")
	}
	if err = os.RemoveAll(tempDir); err != nil {
		t.Error("failed to remove temp dir:", err)
	}
	tempDir, tempFile, err = stringToTempFile(exampleMailPlainB64BrokenBody, "testmail")
	if err != nil {
		t.Errorf("failed to write EML string to temp file: %s", err)
	}
	_, err = EMLToMsgFromFile(tempFile)
	if err == nil {
		t.Error("EML from Reader with broken body was supposed to fail, but didn't")
	}
	if err = os.RemoveAll(tempDir); err != nil {
		t.Error("failed to remove temp dir:", err)
	}
	tempDir, tempFile, err = stringToTempFile(exampleMailPlainBrokenBody, "testmail")
	if err != nil {
		t.Errorf("failed to write EML string to temp file: %s", err)
	}
	_, err = EMLToMsgFromFile(tempFile)
	if err == nil {
		t.Error("EML from Reader with broken body was supposed to fail, but didn't")
	}
	if err = os.RemoveAll(tempDir); err != nil {
		t.Error("failed to remove temp dir:", err)
	}
	tempDir, tempFile, err = stringToTempFile(exampleMailPlainUnknownContentType, "testmail")
	if err != nil {
		t.Errorf("failed to write EML string to temp file: %s", err)
	}
	_, err = EMLToMsgFromFile(tempFile)
	if err == nil {
		t.Error("EML from Reader with unknown content type was supposed to fail, but didn't")
	}
	if err = os.RemoveAll(tempDir); err != nil {
		t.Error("failed to remove temp dir:", err)
	}
	tempDir, tempFile, err = stringToTempFile(exampleMailPlainUnsupportedTransferEnc, "testmail")
	if err != nil {
		t.Errorf("failed to write EML string to temp file: %s", err)
	}
	_, err = EMLToMsgFromFile(tempFile)
	if err == nil {
		t.Error("EML from Reader with unsupported Transer-Encoding was supposed to fail, but didn't")
	}
	if err = os.RemoveAll(tempDir); err != nil {
		t.Error("failed to remove temp dir:", err)
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

func TestEMLToMsgFromStringNoBoundary(t *testing.T) {
	_, err := EMLToMsgFromString(exampleMailPlainB64WithAttachmentNoBoundary)
	if err == nil {
		t.Error("EML with no boundary was supposed to fail, but didn't")
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
			1, len(msg.embeds))
	}
	msg, err = EMLToMsgFromString(exampleMailPlainB64WithEmbedNoContentID)
	if err != nil {
		t.Errorf("EML with embed failed: %s", err)
	}
	if subject := msg.GetGenHeader(HeaderSubject); len(subject) > 0 && !strings.EqualFold(subject[0], wantSubject) {
		t.Errorf("EMLToMsgFromString of EML with embed failed: expected subject: %s, but got: %s",
			wantSubject, subject[0])
	}
	if len(msg.embeds) != 1 {
		t.Errorf("EMLToMsgFromString of EML with embed failed: expected no. of embeds: %d, but got: %d",
			1, len(msg.embeds))
	}
}

func TestEMLToMsgFromStringMultipartMixedAlternativeRelated(t *testing.T) {
	wantSubject := "Example mail // plain text base64 with attachment, embed and alternative part"
	msg, err := EMLToMsgFromString(exampleMailMultipartMixedAlternativeRelated)
	if err != nil {
		t.Errorf("EML multipart mixed, related, alternative failed: %s", err)
	}
	if subject := msg.GetGenHeader(HeaderSubject); len(subject) > 0 && !strings.EqualFold(subject[0], wantSubject) {
		t.Errorf("EMLToMsgFromString of EML multipart mixed, related, alternative failed: expected subject: %s,"+
			" but got: %s", wantSubject, subject[0])
	}
	if len(msg.embeds) != 1 {
		t.Errorf("EMLToMsgFromString of EML multipart mixed, related, alternative failed: expected no. of "+
			"embeds: %d, but got: %d", 1, len(msg.embeds))
	}
	if len(msg.attachments) != 1 {
		t.Errorf("EMLToMsgFromString of EML multipart mixed, related, alternative failed: expected no. of "+
			"attachments: %d, but got: %d", 1, len(msg.attachments))
	}
	if len(msg.parts) != 3 {
		t.Errorf("EMLToMsgFromString of EML multipart mixed, related, alternative failed: expected no. of "+
			"parts: %d, but got: %d", 3, len(msg.parts))
	}

	var hasPlain, hasHTML, hasAlternative bool
	for _, part := range msg.parts {
		if strings.EqualFold(part.contentType.String(), TypeMultipartAlternative.String()) {
			hasAlternative = true
		}
		if strings.EqualFold(part.contentType.String(), TypeTextPlain.String()) {
			hasPlain = true
		}
		if strings.EqualFold(part.contentType.String(), TypeTextHTML.String()) {
			hasHTML = true
		}
	}
	if !hasPlain {
		t.Error("EMLToMsgFromString of EML multipart mixed, related, alternative failed: expected PLAIN " +
			"but got none")
	}
	if !hasHTML {
		t.Error("EMLToMsgFromString of EML multipart mixed, related, alternative failed: expected HTML " +
			"but got none")
	}
	if !hasAlternative {
		t.Error("EMLToMsgFromString of EML multipart mixed, related, alternative failed: expected Alternative " +
			"but got none")
	}
}

func TestEMLToMsgFromStringMultipartMixedWith7Bit(t *testing.T) {
	wantSubject := "Example mail // 7bit with base64 attachment"
	msg, err := EMLToMsgFromString(exampleMultiPart7BitBase64)
	if err != nil {
		t.Errorf("EML multipart mixed with 7bit: %s", err)
	}
	if subject := msg.GetGenHeader(HeaderSubject); len(subject) > 0 && !strings.EqualFold(subject[0], wantSubject) {
		t.Errorf("EMLToMsgFromString of EML multipart mixed with 7bit: expected subject: %s,"+
			" but got: %s", wantSubject, subject[0])
	}
	if len(msg.parts) != 1 {
		t.Errorf("EMLToMsgFromString of EML multipart mixed with 7bit failed: expected 1 part, got: %d",
			len(msg.parts))
		return
	}
	if !strings.EqualFold(msg.parts[0].GetEncoding().String(), EncodingUSASCII.String()) {
		t.Errorf("EMLToMsgFromString of EML multipart mixed with 7bit failed: expected encoding: %s, got %s",
			EncodingUSASCII.String(), msg.parts[0].GetEncoding().String())
	}
	if len(msg.attachments) != 1 {
		t.Errorf("EMLToMsgFromString of EML multipart mixed with 7bit failed: expected 1 attachment, got: %d",
			len(msg.attachments))
		return
	}
}

func TestEMLToMsgFromStringMultipartMixedWith8Bit(t *testing.T) {
	wantSubject := "Example mail // 8bit with base64 attachment"
	msg, err := EMLToMsgFromString(exampleMultiPart8BitBase64)
	if err != nil {
		t.Errorf("EML multipart mixed with 8bit: %s", err)
	}
	if subject := msg.GetGenHeader(HeaderSubject); len(subject) > 0 && !strings.EqualFold(subject[0], wantSubject) {
		t.Errorf("EMLToMsgFromString of EML multipart mixed with 8bit: expected subject: %s,"+
			" but got: %s", wantSubject, subject[0])
	}
	if len(msg.parts) != 1 {
		t.Errorf("EMLToMsgFromString of EML multipart mixed with 8bit failed: expected 1 part, got: %d",
			len(msg.parts))
		return
	}
	if !strings.EqualFold(msg.parts[0].GetEncoding().String(), NoEncoding.String()) {
		t.Errorf("EMLToMsgFromString of EML multipart mixed with 8bit failed: expected encoding: %s, got %s",
			NoEncoding.String(), msg.parts[0].GetEncoding().String())
	}
	if len(msg.attachments) != 1 {
		t.Errorf("EMLToMsgFromString of EML multipart mixed with 8bit failed: expected 1 attachment, got: %d",
			len(msg.attachments))
		return
	}
}

// stringToTempFile is a helper method that will create a temporary file form a give data string
func stringToTempFile(data, name string) (string, string, error) {
	tempDir, err := os.MkdirTemp("", fmt.Sprintf("*-%s", name))
	if err != nil {
		return tempDir, "", fmt.Errorf("failed to create temp dir: %w", err)
	}
	filePath := fmt.Sprintf("%s/%s", tempDir, name)
	err = os.WriteFile(filePath, []byte(data), 0o666)
	if err != nil {
		return tempDir, "", fmt.Errorf("failed to write data to temp file: %w", err)
	}
	return tempDir, filePath, nil
}


*/
