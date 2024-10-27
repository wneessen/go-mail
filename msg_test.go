// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

var (
	charsetTests = []struct {
		name  string
		value Charset
		want  Charset
	}{
		{"UTF-7", CharsetUTF7, "UTF-7"},
		{"UTF-8", CharsetUTF8, "UTF-8"},
		{"US-ASCII", CharsetASCII, "US-ASCII"},
		{"ISO-8859-1", CharsetISO88591, "ISO-8859-1"},
		{"ISO-8859-2", CharsetISO88592, "ISO-8859-2"},
		{"ISO-8859-3", CharsetISO88593, "ISO-8859-3"},
		{"ISO-8859-4", CharsetISO88594, "ISO-8859-4"},
		{"ISO-8859-5", CharsetISO88595, "ISO-8859-5"},
		{"ISO-8859-6", CharsetISO88596, "ISO-8859-6"},
		{"ISO-8859-7", CharsetISO88597, "ISO-8859-7"},
		{"ISO-8859-9", CharsetISO88599, "ISO-8859-9"},
		{"ISO-8859-13", CharsetISO885913, "ISO-8859-13"},
		{"ISO-8859-14", CharsetISO885914, "ISO-8859-14"},
		{"ISO-8859-15", CharsetISO885915, "ISO-8859-15"},
		{"ISO-8859-16", CharsetISO885916, "ISO-8859-16"},
		{"ISO-2022-JP", CharsetISO2022JP, "ISO-2022-JP"},
		{"ISO-2022-KR", CharsetISO2022KR, "ISO-2022-KR"},
		{"windows-1250", CharsetWindows1250, "windows-1250"},
		{"windows-1251", CharsetWindows1251, "windows-1251"},
		{"windows-1252", CharsetWindows1252, "windows-1252"},
		{"windows-1255", CharsetWindows1255, "windows-1255"},
		{"windows-1256", CharsetWindows1256, "windows-1256"},
		{"KOI8-R", CharsetKOI8R, "KOI8-R"},
		{"KOI8-U", CharsetKOI8U, "KOI8-U"},
		{"Big5", CharsetBig5, "Big5"},
		{"GB18030", CharsetGB18030, "GB18030"},
		{"GB2312", CharsetGB2312, "GB2312"},
		{"TIS-620", CharsetTIS620, "TIS-620"},
		{"EUC-KR", CharsetEUCKR, "EUC-KR"},
		{"Shift_JIS", CharsetShiftJIS, "Shift_JIS"},
		{"GBK", CharsetGBK, "GBK"},
		{"Unknown", CharsetUnknown, "Unknown"},
	}
	encodingTests = []struct {
		name  string
		value Encoding
		want  Encoding
	}{
		{"Quoted-Printable", EncodingQP, "quoted-printable"},
		{"Base64", EncodingB64, "base64"},
		{"Unencoded (8-Bit)", NoEncoding, "8bit"},
		{"US-ASCII (7-Bit)", EncodingUSASCII, "7bit"},
	}
	pgpTests = []struct {
		name  string
		value PGPType
	}{
		{"No PGP encoding", NoPGP},
		{"PGP encrypted", PGPEncrypt},
		{"PGP signed", PGPSignature},
	}
	boundaryTests = []struct {
		name  string
		value string
	}{
		{"test123", "test123"},
		{"empty string", ""},
	}
	mimeTests = []struct {
		name  string
		value MIMEVersion
		want  MIMEVersion
	}{
		{"1.0", MIME10, "1.0"},
		{"1.1 (not a valid version at this time)", MIMEVersion("1.1"), "1.1"},
	}
	contentTypeTests = []struct {
		name  string
		ctype ContentType
	}{
		{"text/plain", TypeTextPlain},
		{"text/html", TypeTextHTML},
		{"application/octet-stream", TypeAppOctetStream},
	}
	// Inspired by https://www.youtube.com/watch?v=xxX81WmXjPg&t=623s, yet, some assumptions in that video are
	// incorrect for RFC5321/RFC5322 but rely on deprecated information from RFC822. The tests have been
	// adjusted accordingly.
	rfc5322Test = []struct {
		value string
		valid bool
	}{
		{"hi@domain.tld", true},
		{"hi@", false},
		{`hi+there@domain.tld`, true},
		{"hi.there@domain.tld", true},
		{"hi.@domain.tld", false},            // Point at the end of localpart is not allowed
		{"hi..there@domain.tld", false},      // Double point is not allowed
		{`!#$%&'(-/=?'@domain.tld`, false},   // Invalid characters
		{"hi*there@domain.tld", true},        // * is allowed in localpart
		{`#$%!^/&@domain.tld`, true},         // Allowed localpart characters
		{"h(a)i@domain.tld", false},          // Not allowed to use parenthesis
		{"(hi)there@domain.tld", false},      // The (hi) at the start is a comment which is allowed in RFC822 but not in RFC5322 anymore
		{"hithere@domain.tld(tld)", true},    // The (tld) at the end is also a comment
		{"hi@there@domain.tld", false},       // Can't have two @ signs
		{`"hi@there"@domain.tld`, true},      // Quoted @-signs are allowed
		{`"hi there"@domain.tld`, true},      // Quoted whitespaces are allowed
		{`" "@domain.tld`, true},             // Still valid, since quoted
		{`"<\"@\".!#%$@domain.tld"`, false},  // Quoting with illegal characters is not allowed
		{`<\"@\\".!#%$@domain.tld`, false},   // Still a bunch of random illegal characters
		{`hi"@"there@domain.tld`, false},     // Quotes must be dot-seperated
		{`"<\"@\\".!.#%$@domain.tld`, false}, // Quote is escaped and dot-seperated which would be RFC822 compliant, but not RFC5322 compliant
		{`hi\ there@domain.tld`, false},      // Spaces must be quoted
		{"hello@tld", true},                  // TLD is enough
		{`你好@域名.顶级域名`, true},                 // We speak RFC6532
		{"1@23456789", true},                 // Hypothetically valid, if somebody registers that TLD
		{"1@[23456789]", false},              // While 23456789 is decimal for 1.101.236.21 it is not RFC5322 compliant
	}
)

/*
//go:embed README.md
var efs embed.FS
*/

func TestNewMsg(t *testing.T) {
	t.Run("create new message", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if message.addrHeader == nil {
			t.Errorf("address header map is nil")
		}
		if message.genHeader == nil {
			t.Errorf("generic header map is nil")
		}
		if message.preformHeader == nil {
			t.Errorf("preformatted header map is nil")
		}
		if message.charset != CharsetUTF8 {
			t.Errorf("default charset for new Msg mismatch. Expected: %s, got: %s", CharsetUTF8,
				message.charset)
		}
		if message.encoding != EncodingQP {
			t.Errorf("default encoding for new Msg mismatch. Expected: %s, got: %s", EncodingQP,
				message.encoding)
		}
		if message.mimever != MIME10 {
			t.Errorf("default MIME version for new Msg mismatch. Expected: %s, got: %s", MIME10,
				message.mimever)
		}
		if reflect.TypeOf(message.encoder).String() != "mime.WordEncoder" {
			t.Errorf("default encoder for new Msg mismatch. Expected: %s, got: %s", "mime.WordEncoder",
				reflect.TypeOf(message.encoder).String())
		}
		if !strings.EqualFold(message.encoder.Encode(message.charset.String(), "ab12§$/"),
			`=?UTF-8?q?ab12=C2=A7$/?=`) {
			t.Errorf("default encoder for new Msg mismatch. QP encoded expected string: %s, got: %s",
				`=?UTF-8?q?ab12=C2=A7$/?=`, message.encoder.Encode(message.charset.String(), "ab12§$/"))
		}
	})
	t.Run("new message with nil option", func(t *testing.T) {
		message := NewMsg(nil)
		if message == nil {
			t.Fatal("message is nil")
		}
	})
	t.Run("new message with custom charsets", func(t *testing.T) {
		for _, tt := range charsetTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg(WithCharset(tt.value), nil)
				if message == nil {
					t.Fatal("message is nil")
				}
				if message.charset != tt.want {
					t.Fatalf("NewMsg(WithCharset(%s)) failed. Expected charset: %s, got: %s", tt.value, tt.want,
						message.charset)
				}
			})
		}
	})
	t.Run("new message with custom encoding", func(t *testing.T) {
		for _, tt := range encodingTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg(WithEncoding(tt.value), nil)
				if message == nil {
					t.Fatal("message is nil")
				}
				if message.encoding != tt.want {
					t.Errorf("NewMsg(WithEncoding(%s)) failed. Expected encoding: %s, got: %s", tt.value,
						tt.want, message.encoding)
				}
			})
		}
	})
	t.Run("new message with custom MIME version", func(t *testing.T) {
		for _, tt := range mimeTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg(WithMIMEVersion(tt.value))
				if message == nil {
					t.Fatal("message is nil")
				}
				if message.mimever != tt.want {
					t.Errorf("NewMsg(WithMIMEVersion(%s)) failed. Expected MIME version: %s, got: %s",
						tt.value, tt.want, message.mimever)
				}
			})
		}
	})
	t.Run("new message with custom boundary", func(t *testing.T) {
		for _, tt := range boundaryTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg(WithBoundary(tt.value))
				if message == nil {
					t.Fatal("message is nil")
				}
				if message.boundary != tt.value {
					t.Errorf("NewMsg(WithBoundary(%s)) failed. Expected boundary: %s, got: %s", tt.value,
						tt.value, message.boundary)
				}
			})
		}
	})
	t.Run("new message with custom PGP type", func(t *testing.T) {
		for _, tt := range pgpTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg(WithPGPType(tt.value))
				if message == nil {
					t.Fatal("message is nil")
				}
				if message.pgptype != tt.value {
					t.Errorf("NewMsg(WithPGPType(%d)) failed. Expected PGP type: %d, got: %d", tt.value,
						tt.value, message.pgptype)
				}
			})
		}
	})
	t.Run("new message with middleware: uppercase", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if len(message.middlewares) != 0 {
			t.Errorf("NewMsg() failed. Expected empty middlewares, got: %d", len(message.middlewares))
		}
		message = NewMsg(WithMiddleware(uppercaseMiddleware{}))
		if len(message.middlewares) != 1 {
			t.Errorf("NewMsg(WithMiddleware(uppercaseMiddleware{})) failed. Expected 1 middleware, got: %d",
				len(message.middlewares))
		}
		message = NewMsg(WithMiddleware(uppercaseMiddleware{}), WithMiddleware(encodeMiddleware{}))
		if len(message.middlewares) != 2 {
			t.Errorf("NewMsg(WithMiddleware(uppercaseMiddleware{}),WithMiddleware(encodeMiddleware{})) "+
				"failed. Expected 2 middleware, got: %d", len(message.middlewares))
		}
	})
	t.Run("new message without default user-agent", func(t *testing.T) {
		message := NewMsg(WithNoDefaultUserAgent())
		if message == nil {
			t.Fatal("message is nil")
		}
		if !message.noDefaultUserAgent {
			t.Errorf("NewMsg(WithNoDefaultUserAgent()) failed. Expected noDefaultUserAgent to be true, got: %t",
				message.noDefaultUserAgent)
		}
	})
}

func TestMsg_SetCharset(t *testing.T) {
	t.Run("SetCharset on new message", func(t *testing.T) {
		for _, tt := range charsetTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				message.SetCharset(tt.value)
				if message.charset != tt.want {
					t.Errorf("failed to set charset. Expected: %s, got: %s", tt.want, message.charset)
				}
			})
		}
	})
	t.Run("SetCharset to override WithCharset", func(t *testing.T) {
		message := NewMsg(WithCharset(CharsetUTF7))
		if message == nil {
			t.Fatal("message is nil")
		}
		if message.charset != CharsetUTF7 {
			t.Errorf("failed to set charset on message creation. Expected: %s, got: %s", CharsetUTF7,
				message.charset)
		}
		message.SetCharset(CharsetUTF8)
		if message.charset != CharsetUTF8 {
			t.Errorf("failed to set charset. Expected: %s, got: %s", CharsetUTF8, message.charset)
		}
	})
}

func TestMsg_SetEncoding(t *testing.T) {
	t.Run("SetEncoding on new message", func(t *testing.T) {
		for _, tt := range encodingTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				message.SetEncoding(tt.value)
				if message.encoding != tt.want {
					t.Errorf("failed to set encoding. Expected: %s, got: %s", tt.want, message.encoding)
				}
			})
		}
	})
	t.Run("SetEncoding to override WithEncoding", func(t *testing.T) {
		message := NewMsg(WithEncoding(EncodingUSASCII))
		if message == nil {
			t.Fatal("message is nil")
		}
		if message.encoding != EncodingUSASCII {
			t.Errorf("failed to set encoding on message creation. Expected: %s, got: %s", EncodingUSASCII,
				message.encoding)
		}
		message.SetEncoding(EncodingB64)
		if message.encoding != EncodingB64 {
			t.Errorf("failed to set encoding. Expected: %s, got: %s", EncodingB64, message.encoding)
		}
	})
}

func TestMsg_SetBoundary(t *testing.T) {
	t.Run("SetBoundary on new message", func(t *testing.T) {
		for _, tt := range boundaryTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				message.SetBoundary(tt.value)
				if message.boundary != tt.value {
					t.Errorf("failed to set boundary. Expected: %s, got: %s", tt.value, message.boundary)
				}
			})
		}
	})
	t.Run("SetBoundary to override WithBoundary", func(t *testing.T) {
		message := NewMsg(WithBoundary("123Test"))
		if message == nil {
			t.Fatal("message is nil")
		}
		if message.boundary != "123Test" {
			t.Errorf("failed to set boundary on message creation. Expected: %s, got: %s", "123Test",
				message.boundary)
		}
		message.SetBoundary("test123")
		if message.boundary != "test123" {
			t.Errorf("failed to set boundary. Expected: %s, got: %s", "test123", message.boundary)
		}
	})
}

func TestMsg_SetMIMEVersion(t *testing.T) {
	t.Run("SetMIMEVersion on new message", func(t *testing.T) {
		for _, tt := range mimeTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				message.SetMIMEVersion(tt.value)
				if message.mimever != tt.value {
					t.Errorf("failed to set mime version. Expected: %s, got: %s", tt.value, message.mimever)
				}
			})
		}
	})
	t.Run("SetMIMEVersion to override WithMIMEVersion", func(t *testing.T) {
		message := NewMsg(WithMIMEVersion("1.1"))
		if message == nil {
			t.Fatal("message is nil")
		}
		if message.mimever != "1.1" {
			t.Errorf("failed to set mime version on message creation. Expected: %s, got: %s", "1.1",
				message.mimever)
		}
		message.SetMIMEVersion(MIME10)
		if message.mimever != MIME10 {
			t.Errorf("failed to set mime version. Expected: %s, got: %s", MIME10, message.mimever)
		}
	})
}

func TestMsg_SetPGPType(t *testing.T) {
	t.Run("SetPGPType on new message", func(t *testing.T) {
		for _, tt := range pgpTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				message.SetPGPType(tt.value)
				if message.pgptype != tt.value {
					t.Errorf("failed to set pgp type. Expected: %d, got: %d", tt.value, message.pgptype)
				}
			})
		}
	})
	t.Run("SetPGPType to override WithPGPType", func(t *testing.T) {
		message := NewMsg(WithPGPType(PGPSignature))
		if message == nil {
			t.Fatal("message is nil")
		}
		if message.pgptype != PGPSignature {
			t.Errorf("failed to set pgp type on message creation. Expected: %d, got: %d", PGPSignature,
				message.pgptype)
		}
		message.SetPGPType(PGPEncrypt)
		if message.pgptype != PGPEncrypt {
			t.Errorf("failed to set pgp type. Expected: %d, got: %d", PGPEncrypt, message.pgptype)
		}
	})
}

func TestMsg_Encoding(t *testing.T) {
	t.Run("Encoding returns expected string", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		for _, tt := range encodingTests {
			t.Run(tt.name, func(t *testing.T) {
				message.SetEncoding(tt.value)
				if message.Encoding() != tt.want.String() {
					t.Errorf("failed to get encoding. Expected: %s, got: %s", tt.want.String(), message.Encoding())
				}
			})
		}
	})
}

func TestMsg_Charset(t *testing.T) {
	t.Run("Charset returns expected string", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		for _, tt := range charsetTests {
			t.Run(tt.name, func(t *testing.T) {
				message.SetCharset(tt.value)
				if message.Charset() != tt.want.String() {
					t.Errorf("failed to get charset. Expected: %s, got: %s", tt.want.String(), message.Charset())
				}
			})
		}
	})
}

func TestMsg_SetHeader(t *testing.T) {
	t.Run("SetHeader on new message", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		for _, tt := range genHeaderTests {
			t.Run(tt.name, func(t *testing.T) {
				//goland:noinspection GoDeprecation
				message.SetHeader(tt.header, "test", "foo", "bar")
				values, ok := message.genHeader[tt.header]
				if !ok {
					t.Fatalf("failed to set header, genHeader field for %s is not set", tt.header)
				}
				if len(values) != 3 {
					t.Fatalf("failed to set header, genHeader value count for %s is %d, want: 3",
						tt.header, len(values))
				}
				if values[0] != "test" {
					t.Errorf("failed to set header, genHeader value for %s is %s, want: %s", tt.header,
						values[0], "test")
				}
				if values[1] != "foo" {
					t.Errorf("failed to set header, genHeader value for %s is %s, want: %s", tt.header,
						values[1], "foo")
				}
				if values[2] != "bar" {
					t.Errorf("failed to set header, genHeader value for %s is %s, want: %s", tt.header,
						values[1], "bar")
				}
			})
		}
	})
}

func TestMsg_SetGenHeader(t *testing.T) {
	t.Run("SetGenHeader on new message", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		for _, tt := range genHeaderTests {
			t.Run(tt.name, func(t *testing.T) {
				message.SetGenHeader(tt.header, "test", "foo", "bar")
				values, ok := message.genHeader[tt.header]
				if !ok {
					t.Fatalf("failed to set header, genHeader field for %s is not set", tt.header)
				}
				if len(values) != 3 {
					t.Fatalf("failed to set header, genHeader value count for %s is %d, want: 3",
						tt.header, len(values))
				}
				if values[0] != "test" {
					t.Errorf("failed to set header, genHeader value for %s is %s, want: %s", tt.header,
						values[0], "test")
				}
				if values[1] != "foo" {
					t.Errorf("failed to set header, genHeader value for %s is %s, want: %s", tt.header,
						values[1], "foo")
				}
				if values[2] != "bar" {
					t.Errorf("failed to set header, genHeader value for %s is %s, want: %s", tt.header,
						values[1], "bar")
				}
			})
		}
	})
	t.Run("SetGenHeader with empty genHeaderMap", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.genHeader = nil
		message.SetGenHeader(HeaderSubject, "test", "foo", "bar")
		values, ok := message.genHeader[HeaderSubject]
		if !ok {
			t.Fatalf("failed to set header, genHeader field for %s is not set", HeaderSubject)
		}
		if len(values) != 3 {
			t.Fatalf("failed to set header, genHeader value count for %s is %d, want: 3",
				HeaderSubject, len(values))
		}
		if values[0] != "test" {
			t.Errorf("failed to set header, genHeader value for %s is %s, want: %s", HeaderSubject,
				values[0], "test")
		}
		if values[1] != "foo" {
			t.Errorf("failed to set header, genHeader value for %s is %s, want: %s", HeaderSubject,
				values[1], "foo")
		}
		if values[2] != "bar" {
			t.Errorf("failed to set header, genHeader value for %s is %s, want: %s", HeaderSubject,
				values[1], "bar")
		}
	})
}

func TestMsg_SetHeaderPreformatted(t *testing.T) {
	t.Run("SetHeaderPreformatted on new message", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		for _, tt := range genHeaderTests {
			t.Run(tt.name, func(t *testing.T) {
				//goland:noinspection GoDeprecation
				message.SetHeaderPreformatted(tt.header, "test")
				value, ok := message.preformHeader[tt.header]
				if !ok {
					t.Fatalf("failed to set header, genHeader field for %s is not set", tt.header)
				}
				if value != "test" {
					t.Errorf("failed to set header, genHeader value for %s is %s, want: %s", tt.header,
						value, "test")
				}
			})
		}
	})
}

func TestMsg_SetGenHeaderPreformatted(t *testing.T) {
	t.Run("SetGenHeaderPreformatted on new message", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		for _, tt := range genHeaderTests {
			t.Run(tt.name, func(t *testing.T) {
				message.SetGenHeaderPreformatted(tt.header, "test")
				value, ok := message.preformHeader[tt.header]
				if !ok {
					t.Fatalf("failed to set header, genHeader field for %s is not set", tt.header)
				}
				if value != "test" {
					t.Errorf("failed to set header, genHeader value for %s is %s, want: %s", tt.header,
						value, "test")
				}
			})
		}
	})
	t.Run("SetGenHeaderPreformatted with empty preformHeader map", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.preformHeader = nil
		message.SetGenHeaderPreformatted(HeaderSubject, "test")
		value, ok := message.preformHeader[HeaderSubject]
		if !ok {
			t.Fatalf("failed to set header, genHeader field for %s is not set", HeaderSubject)
		}
		if value != "test" {
			t.Errorf("failed to set header, genHeader value for %s is %s, want: %s", HeaderSubject,
				value, "test")
		}
	})
}

func TestMsg_SetAddrHeader(t *testing.T) {
	t.Run("SetAddrHeader with valid address without <>", func(t *testing.T) {
		for _, tt := range addrHeaderTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				if err := message.SetAddrHeader(tt.header, "toni.tester@example.com"); err != nil {
					t.Fatalf("failed to set address header, err: %s", err)
				}
				checkAddrHeader(t, message, tt.header, "SetAddrHeader", 0, 1, "toni.tester@example.com", "")
			})
		}
	})
	t.Run("SetAddrHeader with valid address with <>", func(t *testing.T) {
		for _, tt := range addrHeaderTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				if err := message.SetAddrHeader(tt.header, "<toni.tester@example.com>"); err != nil {
					t.Fatalf("failed to set address header, err: %s", err)
				}
				checkAddrHeader(t, message, tt.header, "SetAddrHeader", 0, 1, "toni.tester@example.com", "")
			})
		}
	})
	t.Run("SetAddrHeader with valid address and name", func(t *testing.T) {
		for _, tt := range addrHeaderTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				if err := message.SetAddrHeader(tt.header, fmt.Sprintf("%q <%s>", "Toni Tester",
					"toni.tester@example.com")); err != nil {
					t.Fatalf("failed to set address header, err: %s", err)
				}
				checkAddrHeader(t, message, tt.header, "SetAddrHeader", 0, 1,
					"toni.tester@example.com", "Toni Tester")
			})
		}
	})
	t.Run("SetAddrHeader with multiple addresses", func(t *testing.T) {
		for _, tt := range addrHeaderTests {
			t.Run(tt.name, func(t *testing.T) {
				// From must only have one address
				if tt.header == HeaderFrom {
					return
				}

				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				if err := message.SetAddrHeader(tt.header, "toni.tester@example.com",
					"tina.tester@example.com"); err != nil {
					t.Fatalf("failed to set address header, err: %s", err)
				}
				checkAddrHeader(t, message, tt.header, "SetAddrHeader", 0, 2, "toni.tester@example.com", "")
				checkAddrHeader(t, message, tt.header, "SetAddrHeader", 1, 2, "tina.tester@example.com", "")
			})
		}
	})
	t.Run("SetAddrHeader with multiple addresses but from addresses should only return the first one", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.SetAddrHeader(HeaderFrom, "toni.tester@example.com",
			"tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set address header, err: %s", err)
		}
		checkAddrHeader(t, message, HeaderFrom, "SetAddrHeader", 0, 1, "toni.tester@example.com", "")
	})
	t.Run("SetAddrHeader with addrHeader map is nil", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.addrHeader = nil
		if err := message.SetAddrHeader(HeaderFrom, "toni.tester@example.com",
			"tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set address header, err: %s", err)
		}
		checkAddrHeader(t, message, HeaderFrom, "SetAddrHeader", 0, 1, "toni.tester@example.com", "")
	})
	t.Run("SetAddrHeader with invalid address", func(t *testing.T) {
		for _, tt := range addrHeaderTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				if err := message.SetAddrHeader(HeaderFrom, "invalid"); err == nil {
					t.Fatalf("SetAddrHeader with invalid address should fail")
				}
			})
		}
	})
}

func TestMsg_SetAddrHeaderIgnoreInvalid(t *testing.T) {
	t.Run("SetAddrHeaderIgnoreInvalid with valid address without <>", func(t *testing.T) {
		for _, tt := range addrHeaderTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				message.SetAddrHeaderIgnoreInvalid(tt.header, "toni.tester@example.com")
				checkAddrHeader(t, message, tt.header, "SetAddrHeaderIgnoreInvalid", 0, 1,
					"toni.tester@example.com", "")
			})
		}
	})
	t.Run("SetAddrHeaderIgnoreInvalid with valid address with <>", func(t *testing.T) {
		for _, tt := range addrHeaderTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				message.SetAddrHeaderIgnoreInvalid(tt.header, "<toni.tester@example.com>")
				checkAddrHeader(t, message, tt.header, "SetAddrHeaderIgnoreInvalid", 0, 1,
					"toni.tester@example.com", "")
			})
		}
	})
	t.Run("SetAddrHeaderIgnoreInvalid with multiple valid addresses", func(t *testing.T) {
		for _, tt := range addrHeaderTests {
			t.Run(tt.name, func(t *testing.T) {
				// From must only have one address
				if tt.header == HeaderFrom {
					return
				}

				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				message.SetAddrHeaderIgnoreInvalid(tt.header, "toni.tester@example.com",
					"tina.tester@example.com")
				checkAddrHeader(t, message, tt.header, "SetAddrHeaderIgnoreInvalid", 0, 2,
					"toni.tester@example.com", "")
				checkAddrHeader(t, message, tt.header, "SetAddrHeaderIgnoreInvalid", 1, 2,
					"tina.tester@example.com", "")
			})
		}
	})
	t.Run("SetAddrHeaderIgnoreInvalid with multiple addresses valid and invalid", func(t *testing.T) {
		for _, tt := range addrHeaderTests {
			t.Run(tt.name, func(t *testing.T) {
				// From must only have one address
				if tt.header == HeaderFrom {
					return
				}

				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				message.SetAddrHeaderIgnoreInvalid(tt.header, "toni.tester@example.com",
					"invalid", "tina.tester@example.com")
				checkAddrHeader(t, message, tt.header, "SetAddrHeaderIgnoreInvalid", 0, 2,
					"toni.tester@example.com", "")
				checkAddrHeader(t, message, tt.header, "SetAddrHeaderIgnoreInvalid", 1, 2,
					"tina.tester@example.com", "")
			})
		}
	})
	t.Run("SetAddrHeaderIgnoreInvalid with addrHeader map is nil", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.addrHeader = nil
		message.SetAddrHeaderIgnoreInvalid(HeaderFrom, "toni.tester@example.com", "tina.tester@example.com")
		checkAddrHeader(t, message, HeaderFrom, "SetAddrHeaderIgnoreInvalid", 0, 1, "toni.tester@example.com", "")
	})
	t.Run("SetAddrHeaderIgnoreInvalid with invalid addresses only", func(t *testing.T) {
		for _, tt := range addrHeaderTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				message.SetAddrHeaderIgnoreInvalid(HeaderTo, "invalid", "foo")
				addresses, ok := message.addrHeader[HeaderTo]
				if !ok {
					t.Fatalf("failed to set address header, addrHeader field for %s is not set", HeaderTo)
				}
				if len(addresses) != 0 {
					t.Fatalf("failed to set address header, addrHeader value count for To is: %d, want: 0",
						len(addresses))
				}
			})
		}
	})
}

func TestMsg_EnvelopeFrom(t *testing.T) {
	t.Run("EnvelopeFrom with valid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.EnvelopeFrom("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set envelope from: %s", err)
		}
		checkAddrHeader(t, message, HeaderEnvelopeFrom, "EnvelopeFrom", 0, 1, "toni.tester@example.com", "")
	})
	t.Run("EnvelopeFrom with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.EnvelopeFrom("invalid"); err == nil {
			t.Fatalf("EnvelopeFrom should fail with invalid address")
		}
	})
	t.Run("EnvelopeFrom with empty string should fail", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.EnvelopeFrom(""); err == nil {
			t.Fatalf("EnvelopeFrom should fail with invalid address")
		}
	})
}

func TestMsg_EnvelopeFromFormat(t *testing.T) {
	t.Run("EnvelopeFromFormat with valid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.EnvelopeFromFormat("Toni Tester", "toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set envelope From: %s", err)
		}
		checkAddrHeader(t, message, HeaderEnvelopeFrom, "FromFormat", 0, 1, "toni.tester@example.com", "Toni Tester")
	})
	t.Run("EnvelopeFromFormat with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.EnvelopeFromFormat("Toni Tester", "invalid"); err == nil {
			t.Fatalf("EnvelopeFromFormat should fail with invalid address")
		}
	})
	t.Run("EnvelopeFromFormat with empty string should fail", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.EnvelopeFromFormat("", ""); err == nil {
			t.Fatalf("EnvelopeFromFormat should fail with invalid address")
		}
	})
}

func TestMsg_From(t *testing.T) {
	t.Run("From with valid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.From("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set From: %s", err)
		}
		checkAddrHeader(t, message, HeaderFrom, "From", 0, 1, "toni.tester@example.com", "")
	})
	t.Run("From with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.From("invalid"); err == nil {
			t.Fatalf("From should fail with invalid address")
		}
	})
	t.Run("From with empty string should fail", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.From(""); err == nil {
			t.Fatalf("From should fail with invalid address")
		}
	})
	t.Run("From with different RFC5322 addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		for _, tt := range rfc5322Test {
			t.Run(tt.value, func(t *testing.T) {
				err := message.From(tt.value)
				if err != nil && tt.valid {
					t.Errorf("From on address %s should succeed, but failed with: %s", tt.value, err)
				}
				if err == nil && !tt.valid {
					t.Errorf("From on address %s should fail, but succeeded", tt.value)
				}
			})
		}
	})
}

func TestMsg_FromFormat(t *testing.T) {
	t.Run("FromFormat with valid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.FromFormat("Toni Tester", "toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set From: %s", err)
		}
		checkAddrHeader(t, message, HeaderFrom, "FromFormat", 0, 1, "toni.tester@example.com", "Toni Tester")
	})
	t.Run("FromFormat with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.FromFormat("Toni Tester", "invalid"); err == nil {
			t.Fatalf("FromFormat should fail with invalid address")
		}
	})
	t.Run("FromFormat with empty string should fail", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.FromFormat("", ""); err == nil {
			t.Fatalf("FromFormat should fail with invalid address")
		}
	})
}

func TestMsg_To(t *testing.T) {
	t.Run("To with valid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.To("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set To: %s", err)
		}
		checkAddrHeader(t, message, HeaderTo, "To", 0, 1, "toni.tester@example.com", "")
	})
	t.Run("To with multiple valid addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.To("toni.tester@example.com", "tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set To: %s", err)
		}
		checkAddrHeader(t, message, HeaderTo, "To", 0, 2, "toni.tester@example.com", "")
		checkAddrHeader(t, message, HeaderTo, "To", 1, 2, "tina.tester@example.com", "")
	})
	t.Run("To with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.To("invalid"); err == nil {
			t.Fatalf("To should fail with invalid address")
		}
	})
	t.Run("To with empty string should fail", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.To(""); err == nil {
			t.Fatalf("To should fail with invalid address")
		}
	})
	t.Run("To with different RFC5322 addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		for _, tt := range rfc5322Test {
			t.Run(tt.value, func(t *testing.T) {
				err := message.To(tt.value)
				if err != nil && tt.valid {
					t.Errorf("To on address %s should succeed, but failed with: %s", tt.value, err)
				}
				if err == nil && !tt.valid {
					t.Errorf("To on address %s should fail, but succeeded", tt.value)
				}
			})
		}
	})
}

func TestMsg_AddTo(t *testing.T) {
	t.Run("AddTo with valid addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.To("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set To: %s", err)
		}
		if err := message.AddTo("tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set additional To: %s", err)
		}
		checkAddrHeader(t, message, HeaderTo, "AddTo", 0, 2, "toni.tester@example.com", "")
		checkAddrHeader(t, message, HeaderTo, "AddTo", 1, 2, "tina.tester@example.com", "")
	})
	t.Run("AddTo with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.To("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set To: %s", err)
		}
		if err := message.AddTo("invalid"); err == nil {
			t.Errorf("AddTo should fail with invalid address")
		}
		checkAddrHeader(t, message, HeaderTo, "AddTo", 0, 1, "toni.tester@example.com", "")
	})
}

func TestMsg_AddToFormat(t *testing.T) {
	t.Run("AddToFormat with valid addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.To("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set To: %s", err)
		}
		if err := message.AddToFormat("Tina Tester", "tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set additional To: %s", err)
		}
		checkAddrHeader(t, message, HeaderTo, "AddToFormat", 0, 2, "toni.tester@example.com", "")
		checkAddrHeader(t, message, HeaderTo, "AddToFormat", 1, 2, "tina.tester@example.com", "Tina Tester")
	})
	t.Run("AddToFormat with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.To("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set To: %s", err)
		}
		if err := message.AddToFormat("Invalid", "invalid"); err == nil {
			t.Errorf("AddToFormat should fail with invalid address")
		}
		checkAddrHeader(t, message, HeaderTo, "AddToFormat", 0, 1, "toni.tester@example.com", "")
	})
}

func TestMsg_ToIgnoreInvalid(t *testing.T) {
	t.Run("ToIgnoreInvalid with valid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.ToIgnoreInvalid("toni.tester@example.com")
		checkAddrHeader(t, message, HeaderTo, "ToIgnoreInvalid", 0, 1, "toni.tester@example.com", "")
	})
	t.Run("ToIgnoreInvalid with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.ToIgnoreInvalid("invalid")
		addresses, ok := message.addrHeader[HeaderTo]
		if !ok {
			t.Fatalf("failed to set ToIgnoreInvalid, addrHeader field is not set")
		}
		if len(addresses) != 0 {
			t.Fatalf("failed to set ToIgnoreInvalid, addrHeader value count is: %d, want: 0", len(addresses))
		}
	})
	t.Run("ToIgnoreInvalid with valid and invalid addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.ToIgnoreInvalid("toni.tester@example.com", "invalid", "tina.tester@example.com")
		checkAddrHeader(t, message, HeaderTo, "ToIgnoreInvalid", 0, 2, "toni.tester@example.com", "")
		checkAddrHeader(t, message, HeaderTo, "ToIgnoreInvalid", 1, 2, "tina.tester@example.com", "")
	})
}

func TestMsg_ToFromString(t *testing.T) {
	t.Run("ToFromString with valid addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.ToFromString(`toni.tester@example.com,<tina.tester@example.com>`); err != nil {
			t.Fatalf("failed to set ToFromString: %s", err)
		}
		checkAddrHeader(t, message, HeaderTo, "ToFromString", 0, 2, "toni.tester@example.com", "")
		checkAddrHeader(t, message, HeaderTo, "ToFromString", 1, 2, "tina.tester@example.com", "")
	})
	t.Run("ToFromString with valid addresses and empty fields", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.ToFromString(`toni.tester@example.com ,,<tina.tester@example.com>`); err != nil {
			t.Fatalf("failed to set ToFromString: %s", err)
		}
		checkAddrHeader(t, message, HeaderTo, "ToFromString", 0, 2, "toni.tester@example.com", "")
		checkAddrHeader(t, message, HeaderTo, "ToFromString", 1, 2, "tina.tester@example.com", "")
	})
}

func TestMsg_Cc(t *testing.T) {
	t.Run("Cc with valid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Cc("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set Cc: %s", err)
		}
		checkAddrHeader(t, message, HeaderCc, "Cc", 0, 1, "toni.tester@example.com", "")
	})
	t.Run("Cc with multiple valid addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Cc("toni.tester@example.com", "tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set Cc: %s", err)
		}
		checkAddrHeader(t, message, HeaderCc, "Cc", 0, 2, "toni.tester@example.com", "")
		checkAddrHeader(t, message, HeaderCc, "Cc", 1, 2, "tina.tester@example.com", "")
	})
	t.Run("Cc with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Cc("invalid"); err == nil {
			t.Fatalf("Cc should fail with invalid address")
		}
	})
	t.Run("Cc with empty string should fail", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Cc(""); err == nil {
			t.Fatalf("Cc should fail with invalid address")
		}
	})
	t.Run("Cc with different RFC5322 addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		for _, tt := range rfc5322Test {
			t.Run(tt.value, func(t *testing.T) {
				err := message.Cc(tt.value)
				if err != nil && tt.valid {
					t.Errorf("Cc on address %s should succeed, but failed with: %s", tt.value, err)
				}
				if err == nil && !tt.valid {
					t.Errorf("Cc on address %s should fail, but succeeded", tt.value)
				}
			})
		}
	})
}

func TestMsg_AddCc(t *testing.T) {
	t.Run("AddCc with valid addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Cc("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set Cc: %s", err)
		}
		if err := message.AddCc("tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set additional Cc: %s", err)
		}
		checkAddrHeader(t, message, HeaderCc, "AddCc", 0, 2, "toni.tester@example.com", "")
		checkAddrHeader(t, message, HeaderCc, "AddCc", 1, 2, "tina.tester@example.com", "")
	})
	t.Run("AddCc with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Cc("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set Cc: %s", err)
		}
		if err := message.AddCc("invalid"); err == nil {
			t.Errorf("AddCc should fail with invalid address")
		}
		checkAddrHeader(t, message, HeaderCc, "AddCc", 0, 1, "toni.tester@example.com", "")
	})
}

func TestMsg_AddCcFormat(t *testing.T) {
	t.Run("AddCcFormat with valid addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Cc("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set Cc: %s", err)
		}
		if err := message.AddCcFormat("Tina Tester", "tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set additional Cc: %s", err)
		}
		checkAddrHeader(t, message, HeaderCc, "AddCcFormat", 0, 2, "toni.tester@example.com", "")
		checkAddrHeader(t, message, HeaderCc, "AddCcFormat", 1, 2, "tina.tester@example.com", "Tina Tester")
	})
	t.Run("AddCcFormat with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Cc("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set Cc: %s", err)
		}
		if err := message.AddCcFormat("Invalid", "invalid"); err == nil {
			t.Errorf("AddCcFormat should fail with invalid address")
		}
		checkAddrHeader(t, message, HeaderCc, "AddCcFormat", 0, 1, "toni.tester@example.com", "")
	})
}

func TestMsg_CcIgnoreInvalid(t *testing.T) {
	t.Run("CcIgnoreInvalid with valid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.CcIgnoreInvalid("toni.tester@example.com")
		checkAddrHeader(t, message, HeaderCc, "CcIgnoreInvalid", 0, 1, "toni.tester@example.com", "")
	})
	t.Run("CcIgnoreInvalid with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.CcIgnoreInvalid("invalid")
		addresses, ok := message.addrHeader[HeaderCc]
		if !ok {
			t.Fatalf("failed to set CcIgnoreInvalid, addrHeader field is not set")
		}
		if len(addresses) != 0 {
			t.Fatalf("failed to set CcIgnoreInvalid, addrHeader value count is: %d, want: 0", len(addresses))
		}
	})
	t.Run("CcIgnoreInvalid with valid and invalid addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.CcIgnoreInvalid("toni.tester@example.com", "invalid", "tina.tester@example.com")
		checkAddrHeader(t, message, HeaderCc, "CcIgnoreInvalid", 0, 2, "toni.tester@example.com", "")
		checkAddrHeader(t, message, HeaderCc, "CcIgnoreInvalid", 1, 2, "tina.tester@example.com", "")
	})
}

func TestMsg_CcFromString(t *testing.T) {
	t.Run("CcFromString with valid addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.CcFromString(`toni.tester@example.com,<tina.tester@example.com>`); err != nil {
			t.Fatalf("failed to set CcFromString: %s", err)
		}
		checkAddrHeader(t, message, HeaderCc, "CcFromString", 0, 2, "toni.tester@example.com", "")
		checkAddrHeader(t, message, HeaderCc, "CcFromString", 1, 2, "tina.tester@example.com", "")
	})
	t.Run("CcFromString with valid addresses and empty fields", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.CcFromString(`toni.tester@example.com ,,<tina.tester@example.com>`); err != nil {
			t.Fatalf("failed to set CcFromString: %s", err)
		}
		checkAddrHeader(t, message, HeaderCc, "CcFromString", 0, 2, "toni.tester@example.com", "")
		checkAddrHeader(t, message, HeaderCc, "CcFromString", 1, 2, "tina.tester@example.com", "")
	})
}

func TestMsg_Bcc(t *testing.T) {
	t.Run("Bcc with valid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Bcc("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set Bcc: %s", err)
		}
		checkAddrHeader(t, message, HeaderBcc, "Bcc", 0, 1, "toni.tester@example.com", "")
	})
	t.Run("Bcc with multiple valid addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Bcc("toni.tester@example.com", "tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set Bcc: %s", err)
		}
		checkAddrHeader(t, message, HeaderBcc, "Bcc", 0, 2, "toni.tester@example.com", "")
		checkAddrHeader(t, message, HeaderBcc, "Bcc", 1, 2, "tina.tester@example.com", "")
	})
	t.Run("Bcc with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Bcc("invalid"); err == nil {
			t.Fatalf("Bcc should fail with invalid address")
		}
	})
	t.Run("Bcc with empty string should fail", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Bcc(""); err == nil {
			t.Fatalf("Bcc should fail with invalid address")
		}
	})
	t.Run("Bcc with different RFC5322 addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		for _, tt := range rfc5322Test {
			t.Run(tt.value, func(t *testing.T) {
				err := message.Bcc(tt.value)
				if err != nil && tt.valid {
					t.Errorf("Bcc on address %s should succeed, but failed with: %s", tt.value, err)
				}
				if err == nil && !tt.valid {
					t.Errorf("Bcc on address %s should fail, but succeeded", tt.value)
				}
			})
		}
	})
}

func TestMsg_AddBcc(t *testing.T) {
	t.Run("AddBcc with valid addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Bcc("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set Bcc: %s", err)
		}
		if err := message.AddBcc("tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set additional Bcc: %s", err)
		}
		checkAddrHeader(t, message, HeaderBcc, "AddBcc", 0, 2, "toni.tester@example.com", "")
		checkAddrHeader(t, message, HeaderBcc, "AddBcc", 1, 2, "tina.tester@example.com", "")
	})
	t.Run("AddBcc with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Bcc("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set Bcc: %s", err)
		}
		if err := message.AddBcc("invalid"); err == nil {
			t.Errorf("AddBcc should fail with invalid address")
		}
		checkAddrHeader(t, message, HeaderBcc, "AddBcc", 0, 1, "toni.tester@example.com", "")
	})
}

func TestMsg_AddBccFormat(t *testing.T) {
	t.Run("AddBccFormat with valid addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Bcc("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set Bcc: %s", err)
		}
		if err := message.AddBccFormat("Tina Tester", "tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set additional Bcc: %s", err)
		}
		checkAddrHeader(t, message, HeaderBcc, "AddBccFormat", 0, 2, "toni.tester@example.com", "")
		checkAddrHeader(t, message, HeaderBcc, "AddBccFormat", 1, 2, "tina.tester@example.com", "Tina Tester")
	})
	t.Run("AddBccFormat with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Bcc("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set Bcc: %s", err)
		}
		if err := message.AddBccFormat("Invalid", "invalid"); err == nil {
			t.Errorf("AddBccFormat should fail with invalid address")
		}
		checkAddrHeader(t, message, HeaderBcc, "AddBccFormat", 0, 1, "toni.tester@example.com", "")
	})
}

func TestMsg_BccIgnoreInvalid(t *testing.T) {
	t.Run("BccIgnoreInvalid with valid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.BccIgnoreInvalid("toni.tester@example.com")
		checkAddrHeader(t, message, HeaderBcc, "BccIgnoreInvalid", 0, 1, "toni.tester@example.com", "")
	})
	t.Run("BccIgnoreInvalid with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.BccIgnoreInvalid("invalid")
		addresses, ok := message.addrHeader[HeaderBcc]
		if !ok {
			t.Fatalf("failed to set BccIgnoreInvalid, addrHeader field is not set")
		}
		if len(addresses) != 0 {
			t.Fatalf("failed to set BccIgnoreInvalid, addrHeader value count is: %d, want: 0", len(addresses))
		}
	})
	t.Run("BccIgnoreInvalid with valid and invalid addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.BccIgnoreInvalid("toni.tester@example.com", "invalid", "tina.tester@example.com")
		checkAddrHeader(t, message, HeaderBcc, "BccIgnoreInvalid", 0, 2, "toni.tester@example.com", "")
		checkAddrHeader(t, message, HeaderBcc, "BccIgnoreInvalid", 1, 2, "tina.tester@example.com", "")
	})
}

func TestMsg_BccFromString(t *testing.T) {
	t.Run("BccFromString with valid addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.BccFromString(`toni.tester@example.com,<tina.tester@example.com>`); err != nil {
			t.Fatalf("failed to set BccFromString: %s", err)
		}
		checkAddrHeader(t, message, HeaderBcc, "BccFromString", 0, 2, "toni.tester@example.com", "")
		checkAddrHeader(t, message, HeaderBcc, "BccFromString", 1, 2, "tina.tester@example.com", "")
	})
	t.Run("BccFromString with valid addresses and empty fields", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.BccFromString(`toni.tester@example.com ,,<tina.tester@example.com>`); err != nil {
			t.Fatalf("failed to set BccFromString: %s", err)
		}
		checkAddrHeader(t, message, HeaderBcc, "BccFromString", 0, 2, "toni.tester@example.com", "")
		checkAddrHeader(t, message, HeaderBcc, "BccFromString", 1, 2, "tina.tester@example.com", "")
	})
}

func TestMsg_ReplyTo(t *testing.T) {
	t.Run("ReplyTo with valid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.ReplyTo("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set ReplyTo: %s", err)
		}
		checkGenHeader(t, message, HeaderReplyTo, "ReplyTo", 0, 1, "<toni.tester@example.com>")
	})
	t.Run("ReplyTo with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.ReplyTo("invalid"); err == nil {
			t.Fatalf("ReplyTo should fail with invalid address")
		}
	})
	t.Run("ReplyTo with empty string should fail", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.ReplyTo(""); err == nil {
			t.Fatalf("ReplyTo should fail with invalid address")
		}
	})
	t.Run("ReplyTo with different RFC5322 addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		for _, tt := range rfc5322Test {
			t.Run(tt.value, func(t *testing.T) {
				err := message.ReplyTo(tt.value)
				if err != nil && tt.valid {
					t.Errorf("ReplyTo on address %s should succeed, but failed with: %s", tt.value, err)
				}
				if err == nil && !tt.valid {
					t.Errorf("ReplyTo on address %s should fail, but succeeded", tt.value)
				}
			})
		}
	})
}

func TestMsg_ReplyToFormat(t *testing.T) {
	t.Run("ReplyToFormat with valid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.ReplyToFormat("Tina Tester", "tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set ReplyTo: %s", err)
		}
		checkGenHeader(t, message, HeaderReplyTo, "ReplyToFormat", 0, 1, `"Tina Tester" <tina.tester@example.com>`)
	})
	t.Run("ReplyToFormat with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.ReplyToFormat("Invalid", "invalid"); err == nil {
			t.Errorf("ReplyToFormat should fail with invalid address")
		}
	})
}

func TestMsg_Subject(t *testing.T) {
	tests := []struct {
		name    string
		subject string
		want    string
	}{
		{"Normal latin characters", "Hello world!", "Hello world!"},
		{"Empty string", "", ""},
		{
			"European umlaut characters", "Héllô wörld! äöüß",
			"=?UTF-8?q?H=C3=A9ll=C3=B4_w=C3=B6rld!_=C3=A4=C3=B6=C3=BC=C3=9F?=",
		},
		{
			"Japanese characters", `これはテスト対象です。`,
			`=?UTF-8?q?=E3=81=93=E3=82=8C=E3=81=AF=E3=83=86=E3=82=B9=E3=83=88=E5=AF=BE?= ` +
				`=?UTF-8?q?=E8=B1=A1=E3=81=A7=E3=81=99=E3=80=82?=`,
		},
		{
			"Simplified chinese characters", `这是一个测试主题`,
			`=?UTF-8?q?=E8=BF=99=E6=98=AF=E4=B8=80=E4=B8=AA=E6=B5=8B=E8=AF=95=E4=B8=BB?= ` +
				`=?UTF-8?q?=E9=A2=98?=`,
		},
		{
			"Cyrillic characters", `Это испытуемый`,
			`=?UTF-8?q?=D0=AD=D1=82=D0=BE_=D0=B8=D1=81=D0=BF=D1=8B=D1=82=D1=83=D0=B5?= ` +
				`=?UTF-8?q?=D0=BC=D1=8B=D0=B9?=`,
		},
		{"Emoji characters", `New Offer 🚀`, `=?UTF-8?q?New_Offer_=F0=9F=9A=80?=`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := NewMsg()
			if message == nil {
				t.Fatal("message is nil")
			}
			message.Subject(tt.subject)
			checkGenHeader(t, message, HeaderSubject, "Subject", 0, 1, tt.want)
		})
	}
}

func TestMsg_SetMessageID(t *testing.T) {
	t.Run("SetMessageID randomness", func(t *testing.T) {
		var mids []string
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		for i := 0; i < 50_000; i++ {
			message.SetMessageID()
			mid := message.GetMessageID()
			mids = append(mids, mid)
		}
		c := make(map[string]int)
		for i := range mids {
			c[mids[i]]++
		}
		for k, v := range c {
			if v > 1 {
				t.Errorf("MessageID randomness not given. MessageID %q was generated %d times", k, v)
			}
		}
	})
}

func TestMsg_GetMessageID(t *testing.T) {
	t.Run("GetMessageID with normal IDs", func(t *testing.T) {
		tests := []struct {
			msgid string
			want  string
		}{
			{"this.is.a.test", "<this.is.a.test>"},
			{"12345.6789@domain.com", "<12345.6789@domain.com>"},
			{"abcd1234@sub.domain.com", "<abcd1234@sub.domain.com>"},
			{"uniqeID-123@domain.co.tld", "<uniqeID-123@domain.co.tld>"},
			{"2024_10_26192300@domain.tld", "<2024_10_26192300@domain.tld>"},
		}
		for _, tt := range tests {
			t.Run(tt.msgid, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				message.SetMessageIDWithValue(tt.msgid)
				msgid := message.GetMessageID()
				if !strings.EqualFold(tt.want, msgid) {
					t.Errorf("GetMessageID() failed. Want: %s, got: %s", tt.want, msgid)
				}
			})
		}
	})
	t.Run("GetMessageID no messageID set should return an empty string", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		msgid := message.GetMessageID()
		if msgid != "" {
			t.Errorf("GetMessageID() failed. Want: empty string, got: %s", msgid)
		}
	})
}

func TestMsg_SetMessageIDWithValue(t *testing.T) {
	// We have already covered SetMessageIDWithValue in SetMessageID and GetMessageID
	t.Skip("SetMessageIDWithValue is fully covered by TestMsg_GetMessageID")
}

func TestMsg_SetBulk(t *testing.T) {
	message := NewMsg()
	if message == nil {
		t.Fatal("message is nil")
	}
	message.SetBulk()
	checkGenHeader(t, message, HeaderPrecedence, "SetBulk", 0, 1, "bulk")
	checkGenHeader(t, message, HeaderXAutoResponseSuppress, "Bulk", 0, 1, "All")
}

func TestMsg_SetDate(t *testing.T) {
	t.Run("SetDate and compare date down to the minute", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}

		message.SetDate()
		values, ok := message.genHeader[HeaderDate]
		if !ok {
			t.Fatal("failed to set SetDate, genHeader field is not set")
		}
		if len(values) != 1 {
			t.Fatalf("failed to set SetDate, genHeader value count is: %d, want: %d", len(values), 1)
		}
		date := values[0]
		parsed, err := time.Parse(time.RFC1123Z, date)
		if err != nil {
			t.Fatalf("SetDate failed, failed to parse retrieved date: %s, error: %s", date, err)
		}
		now := time.Now()
		nowNoSec := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), 0, 0, now.Location())
		parsedNoSec := time.Date(parsed.Year(), parsed.Month(), parsed.Day(), parsed.Hour(), parsed.Minute(),
			0, 0, parsed.Location())
		if !nowNoSec.Equal(parsedNoSec) {
			t.Errorf("SetDate failed, retrieved date mismatch, got: %s, want: %s", parsedNoSec.String(),
				nowNoSec.String())
		}
	})
}

func TestMsg_SetDateWithValue(t *testing.T) {
	t.Run("SetDateWithValue and compare date down to the second", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}

		now := time.Now()
		message.SetDateWithValue(now)
		values, ok := message.genHeader[HeaderDate]
		if !ok {
			t.Fatal("failed to set SetDate, genHeader field is not set")
		}
		if len(values) != 1 {
			t.Fatalf("failed to set SetDate, genHeader value count is: %d, want: %d", len(values), 1)
		}
		date := values[0]
		parsed, err := time.Parse(time.RFC1123Z, date)
		if err != nil {
			t.Fatalf("SetDate failed, failed to parse retrieved date: %s, error: %s", date, err)
		}
		if !strings.EqualFold(parsed.Format(time.RFC1123Z), now.Format(time.RFC1123Z)) {
			t.Errorf("SetDate failed, retrieved date mismatch, got: %s, want: %s", now.Format(time.RFC1123Z),
				parsed.Format(time.RFC1123Z))
		}
	})
}

func TestMsg_SetImportance(t *testing.T) {
	tests := []struct {
		name       string
		importance Importance
	}{
		{"Non-Urgent", ImportanceNonUrgent},
		{"Low", ImportanceLow},
		{"Normal", ImportanceNormal},
		{"High", ImportanceHigh},
		{"Urgent", ImportanceUrgent},
		{"Unknown", 9},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := NewMsg()
			if message == nil {
				t.Fatal("message is nil")
			}
			message.SetImportance(tt.importance)
			if tt.importance == ImportanceNormal {
				t.Skip("ImportanceNormal is does currently not set any values")
			}
			checkGenHeader(t, message, HeaderImportance, "SetImportance", 0, 1, tt.importance.String())
			checkGenHeader(t, message, HeaderPriority, "SetImportance", 0, 1, tt.importance.NumString())
			checkGenHeader(t, message, HeaderXPriority, "SetImportance", 0, 1, tt.importance.XPrioString())
			checkGenHeader(t, message, HeaderXMSMailPriority, "SetImportance", 0, 1, tt.importance.NumString())
		})
	}
}

func TestMsg_SetOrganization(t *testing.T) {
	message := NewMsg()
	if message == nil {
		t.Fatal("message is nil")
	}
	message.SetOrganization("ACME Inc.")
	checkGenHeader(t, message, HeaderOrganization, "SetOrganization", 0, 1, "ACME Inc.")
}

func TestMsg_SetUserAgent(t *testing.T) {
	t.Run("SetUserAgent with value", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.SetUserAgent("go-mail test suite")
		checkGenHeader(t, message, HeaderUserAgent, "SetUserAgent", 0, 1, "go-mail test suite")
		checkGenHeader(t, message, HeaderXMailer, "SetUserAgent", 0, 1, "go-mail test suite")
	})
	t.Run("Message without SetUserAgent should provide default agent", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		want := fmt.Sprintf("go-mail v%s // https://github.com/wneessen/go-mail", VERSION)
		message.checkUserAgent()
		checkGenHeader(t, message, HeaderUserAgent, "SetUserAgent", 0, 1, want)
		checkGenHeader(t, message, HeaderXMailer, "SetUserAgent", 0, 1, want)
	})
}

func TestMsg_IsDelivered(t *testing.T) {
	t.Run("IsDelivered on unsent message", func(t *testing.T) {
		message := testMessage(t)
		if message.IsDelivered() {
			t.Error("IsDelivered on unsent message should return false")
		}
	})
	t.Run("IsDelivered on sent message", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}

		message := testMessage(t)
		if err = client.DialAndSend(message); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})

		if !message.IsDelivered() {
			t.Error("IsDelivered on sent message should return true")
		}
	})
	t.Run("IsDelivered on failed message delivery (DATA close)", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnDataClose: true,
				FeatureSet:      featureSet,
				ListenPort:      serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}

		message := testMessage(t)
		if err = client.DialAndSend(message); err == nil {
			t.Error("message delivery was supposed to fail on data close")
		}
		if message.IsDelivered() {
			t.Error("IsDelivered on failed message delivery should return false")
		}
	})
	t.Run("IsDelivered on failed message delivery (final RESET)", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnReset: true,
				FeatureSet:  featureSet,
				ListenPort:  serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}

		message := testMessage(t)
		if err = client.DialAndSend(message); err == nil {
			t.Error("message delivery was supposed to fail on data close")
		}
		if !message.IsDelivered() {
			t.Error("IsDelivered on sent message should return true")
		}
	})
}

func TestMsg_RequestMDNTo(t *testing.T) {
	t.Run("RequestMDNTo with valid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.RequestMDNTo("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set RequestMDNTo: %s", err)
		}
		checkGenHeader(t, message, HeaderDispositionNotificationTo, "RequestMDNTo", 0, 1, "<toni.tester@example.com>")
	})
	t.Run("RequestMDNTo with valid address and nil-genHeader", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.genHeader = nil
		if err := message.RequestMDNTo("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set RequestMDNTo: %s", err)
		}
		checkGenHeader(t, message, HeaderDispositionNotificationTo, "RequestMDNTo", 0, 1, "<toni.tester@example.com>")
	})
	t.Run("RequestMDNTo with multiple valid addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.RequestMDNTo("toni.tester@example.com", "tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set RequestMDNTo: %s", err)
		}
		checkGenHeader(t, message, HeaderDispositionNotificationTo, "RequestMDNTo", 0, 2, "<toni.tester@example.com>")
		checkGenHeader(t, message, HeaderDispositionNotificationTo, "RequestMDNTo", 1, 2, "<tina.tester@example.com>")
	})
	t.Run("RequestMDNTo with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.RequestMDNTo("invalid"); err == nil {
			t.Fatalf("RequestMDNTo should fail with invalid address")
		}
	})
	t.Run("RequestMDNTo with empty string should fail", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.RequestMDNTo(""); err == nil {
			t.Fatalf("RequestMDNTo should fail with invalid address")
		}
	})
	t.Run("RequestMDNTo with different RFC5322 addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		for _, tt := range rfc5322Test {
			t.Run(tt.value, func(t *testing.T) {
				err := message.RequestMDNTo(tt.value)
				if err != nil && tt.valid {
					t.Errorf("RequestMDNTo on address %s should succeed, but failed with: %s", tt.value, err)
				}
				if err == nil && !tt.valid {
					t.Errorf("RequestMDNTo on address %s should fail, but succeeded", tt.value)
				}
			})
		}
	})
}

func TestMsg_RequestMDNToFormat(t *testing.T) {
	t.Run("RequestMDNToFormat with valid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.RequestMDNToFormat("Toni Tester", "toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set RequestMDNToFormat: %s", err)
		}
		checkGenHeader(t, message, HeaderDispositionNotificationTo, "RequestMDNToFormat", 0, 1,
			`"Toni Tester" <toni.tester@example.com>`)
	})
	t.Run("RequestMDNToFormat with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.RequestMDNToFormat("invalid", "invalid"); err == nil {
			t.Fatalf("RequestMDNToFormat should fail with invalid address")
		}
	})
}

func TestMsg_RequestMDNAddTo(t *testing.T) {
	t.Run("RequestMDNAddTo with valid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.RequestMDNTo("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set RequestMDNTo: %s", err)
		}
		if err := message.RequestMDNAddTo("tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set RequestMDNAddTo: %s", err)
		}
		checkGenHeader(t, message, HeaderDispositionNotificationTo, "RequestMDNAddTo", 0, 2,
			`<toni.tester@example.com>`)
		checkGenHeader(t, message, HeaderDispositionNotificationTo, "RequestMDNAddTo", 1, 2,
			`<tina.tester@example.com>`)
	})
	t.Run("RequestMDNAddTo with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.RequestMDNTo("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set RequestMDNTo: %s", err)
		}
		if err := message.RequestMDNAddTo("invalid"); err == nil {
			t.Errorf("RequestMDNAddTo should fail with invalid address")
		}
		checkGenHeader(t, message, HeaderDispositionNotificationTo, "RequestMDNAddTo", 0, 1,
			`<toni.tester@example.com>`)
	})
}

func TestMsg_RequestMDNAddToFormat(t *testing.T) {
	t.Run("RequestMDNAddToFormat with valid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.RequestMDNTo("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set RequestMDNTo: %s", err)
		}
		if err := message.RequestMDNAddToFormat("Tina Tester", "tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set RequestMDNAddToFormat: %s", err)
		}
		checkGenHeader(t, message, HeaderDispositionNotificationTo, "RequestMDNAddToFormat", 0, 2,
			`<toni.tester@example.com>`)
		checkGenHeader(t, message, HeaderDispositionNotificationTo, "RequestMDNAddToFormat", 1, 2,
			`"Tina Tester" <tina.tester@example.com>`)
	})
	t.Run("RequestMDNAddToFormat with invalid address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.RequestMDNTo("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set RequestMDNTo: %s", err)
		}
		if err := message.RequestMDNAddToFormat("invalid", "invalid"); err == nil {
			t.Errorf("RequestMDNAddToFormat should fail with invalid address")
		}
		checkGenHeader(t, message, HeaderDispositionNotificationTo, "RequestMDNAddToFormat", 0, 1,
			`<toni.tester@example.com>`)
	})
}

func TestMsg_GetSender(t *testing.T) {
	t.Run("GetSender with envelope from only (no full address)", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.EnvelopeFrom("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set envelope from address: %s", err)
		}
		sender, err := message.GetSender(false)
		if err != nil {
			t.Errorf("failed to get sender: %s", err)
		}
		if !strings.EqualFold(sender, "toni.tester@example.com") {
			t.Errorf("expected sender not returned. Want: %s, got: %s", "toni.tester@example.com", sender)
		}
	})
	t.Run("GetSender with envelope from only (full address)", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.EnvelopeFrom("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set envelope from address: %s", err)
		}
		sender, err := message.GetSender(true)
		if err != nil {
			t.Errorf("failed to get sender: %s", err)
		}
		if !strings.EqualFold(sender, "<toni.tester@example.com>") {
			t.Errorf("expected sender not returned. Want: %s, got: %s", "<toni.tester@example.com>", sender)
		}
	})
	t.Run("GetSender with from only (no full address)", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.From("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set from address: %s", err)
		}
		sender, err := message.GetSender(false)
		if err != nil {
			t.Errorf("failed to get sender: %s", err)
		}
		if !strings.EqualFold(sender, "toni.tester@example.com") {
			t.Errorf("expected sender not returned. Want: %s, got: %s", "toni.tester@example.com", sender)
		}
	})
	t.Run("GetSender with from only (full address)", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.From("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set from address: %s", err)
		}
		sender, err := message.GetSender(true)
		if err != nil {
			t.Errorf("failed to get sender: %s", err)
		}
		if !strings.EqualFold(sender, "<toni.tester@example.com>") {
			t.Errorf("expected sender not returned. Want: %s, got: %s", "<toni.tester@example.com>", sender)
		}
	})
	t.Run("GetSender with envelope from and from (no full address)", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.EnvelopeFrom("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set envelope from address: %s", err)
		}
		if err := message.From("tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set from address: %s", err)
		}
		sender, err := message.GetSender(false)
		if err != nil {
			t.Errorf("failed to get sender: %s", err)
		}
		if !strings.EqualFold(sender, "toni.tester@example.com") {
			t.Errorf("expected sender not returned. Want: %s, got: %s", "toni.tester@example.com", sender)
		}
	})
	t.Run("GetSender with envelope from and from (full address)", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.EnvelopeFrom("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set envelope from address: %s", err)
		}
		if err := message.From("tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set from address: %s", err)
		}
		sender, err := message.GetSender(true)
		if err != nil {
			t.Errorf("failed to get sender: %s", err)
		}
		if !strings.EqualFold(sender, "<toni.tester@example.com>") {
			t.Errorf("expected sender not returned. Want: %s, got: %s", "<toni.tester@example.com>", sender)
		}
	})
	t.Run("GetSender with no envelope from or from", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		_, err := message.GetSender(false)
		if err == nil {
			t.Errorf("GetSender with no envelope from or from should return error")
		}
		if !errors.Is(err, ErrNoFromAddress) {
			t.Errorf("GetSender with no envelope from or from should return error. Want: %s, got: %s",
				ErrNoFromAddress, err)
		}
	})
}

func TestMsg_GetRecipients(t *testing.T) {
	t.Run("GetRecipients with only to", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.To("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set to address: %s", err)
		}
		rcpts, err := message.GetRecipients()
		if err != nil {
			t.Errorf("failed to get recipients: %s", err)
		}
		if len(rcpts) != 1 {
			t.Fatalf("expected 1 recipient, got: %d", len(rcpts))
		}
		if !strings.EqualFold(rcpts[0], "toni.tester@example.com") {
			t.Errorf("expected recipient not returned. Want: %s, got: %s",
				"toni.tester@example.com", rcpts[0])
		}
	})
	t.Run("GetRecipients with only cc", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Cc("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set cc address: %s", err)
		}
		rcpts, err := message.GetRecipients()
		if err != nil {
			t.Errorf("failed to get recipients: %s", err)
		}
		if len(rcpts) != 1 {
			t.Fatalf("expected 1 recipient, got: %d", len(rcpts))
		}
		if !strings.EqualFold(rcpts[0], "toni.tester@example.com") {
			t.Errorf("expected recipient not returned. Want: %s, got: %s",
				"toni.tester@example.com", rcpts[0])
		}
	})
	t.Run("GetRecipients with only bcc", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Bcc("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set bcc address: %s", err)
		}
		rcpts, err := message.GetRecipients()
		if err != nil {
			t.Errorf("failed to get recipients: %s", err)
		}
		if len(rcpts) != 1 {
			t.Fatalf("expected 1 recipient, got: %d", len(rcpts))
		}
		if !strings.EqualFold(rcpts[0], "toni.tester@example.com") {
			t.Errorf("expected recipient not returned. Want: %s, got: %s",
				"toni.tester@example.com", rcpts[0])
		}
	})
	t.Run("GetRecipients with to and cc", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.To("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set to address: %s", err)
		}
		if err := message.Cc("tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set cc address: %s", err)
		}
		rcpts, err := message.GetRecipients()
		if err != nil {
			t.Errorf("failed to get recipients: %s", err)
		}
		if len(rcpts) != 2 {
			t.Fatalf("expected 2 recipient, got: %d", len(rcpts))
		}
		if !strings.EqualFold(rcpts[0], "toni.tester@example.com") {
			t.Errorf("expected recipient not returned. Want: %s, got: %s",
				"toni.tester@example.com", rcpts[0])
		}
		if !strings.EqualFold(rcpts[1], "tina.tester@example.com") {
			t.Errorf("expected recipient not returned. Want: %s, got: %s",
				"tina.tester@example.com", rcpts[1])
		}
	})
	t.Run("GetRecipients with to and bcc", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.To("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set to address: %s", err)
		}
		if err := message.Bcc("tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set bcc address: %s", err)
		}
		rcpts, err := message.GetRecipients()
		if err != nil {
			t.Errorf("failed to get recipients: %s", err)
		}
		if len(rcpts) != 2 {
			t.Fatalf("expected 2 recipient, got: %d", len(rcpts))
		}
		if !strings.EqualFold(rcpts[0], "toni.tester@example.com") {
			t.Errorf("expected recipient not returned. Want: %s, got: %s",
				"toni.tester@example.com", rcpts[0])
		}
		if !strings.EqualFold(rcpts[1], "tina.tester@example.com") {
			t.Errorf("expected recipient not returned. Want: %s, got: %s",
				"tina.tester@example.com", rcpts[1])
		}
	})
	t.Run("GetRecipients with cc and bcc", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Cc("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set cc address: %s", err)
		}
		if err := message.Bcc("tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set bcc address: %s", err)
		}
		rcpts, err := message.GetRecipients()
		if err != nil {
			t.Errorf("failed to get recipients: %s", err)
		}
		if len(rcpts) != 2 {
			t.Fatalf("expected 2 recipient, got: %d", len(rcpts))
		}
		if !strings.EqualFold(rcpts[0], "toni.tester@example.com") {
			t.Errorf("expected recipient not returned. Want: %s, got: %s",
				"toni.tester@example.com", rcpts[0])
		}
		if !strings.EqualFold(rcpts[1], "tina.tester@example.com") {
			t.Errorf("expected recipient not returned. Want: %s, got: %s",
				"tina.tester@example.com", rcpts[1])
		}
	})
	t.Run("GetRecipients with to, cc and bcc", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.To("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set to address: %s", err)
		}
		if err := message.Cc("tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set cc address: %s", err)
		}
		if err := message.Bcc("tom.tester@example.com"); err != nil {
			t.Fatalf("failed to set bcc address: %s", err)
		}
		rcpts, err := message.GetRecipients()
		if err != nil {
			t.Errorf("failed to get recipients: %s", err)
		}
		if len(rcpts) != 3 {
			t.Fatalf("expected 3 recipient, got: %d", len(rcpts))
		}
		if !strings.EqualFold(rcpts[0], "toni.tester@example.com") {
			t.Errorf("expected recipient not returned. Want: %s, got: %s",
				"toni.tester@example.com", rcpts[0])
		}
		if !strings.EqualFold(rcpts[1], "tina.tester@example.com") {
			t.Errorf("expected recipient not returned. Want: %s, got: %s",
				"tina.tester@example.com", rcpts[1])
		}
		if !strings.EqualFold(rcpts[2], "tom.tester@example.com") {
			t.Errorf("expected recipient not returned. Want: %s, got: %s",
				"tina.tester@example.com", rcpts[2])
		}
	})
	t.Run("GetRecipients with no recipients", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		_, err := message.GetRecipients()
		if err == nil {
			t.Errorf("expected error, got nil")
		}
		if !errors.Is(err, ErrNoRcptAddresses) {
			t.Errorf("expected ErrNoRcptAddresses, got: %s", err)
		}
	})
}

func TestMsg_GetAddrHeader(t *testing.T) {
	t.Run("GetAddrHeader with valid address (from)", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.From("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set header: %s", err)
		}
		addrheader := message.GetAddrHeader(HeaderFrom)
		if len(addrheader) != 1 {
			t.Errorf("expected 1 address, got: %d", len(addrheader))
		}
		if addrheader[0] == nil {
			t.Fatalf("expected address, got nil")
		}
		if addrheader[0].String() != "<toni.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<toni.tester@example.com>", addrheader[0].String())
		}
	})
	t.Run("GetAddrHeader with valid address (to, cc, bcc)", func(t *testing.T) {
		var fn func(...string) error
		for _, tt := range addrHeaderTests {
			message := NewMsg()
			if message == nil {
				t.Fatal("message is nil")
			}

			switch tt.header {
			case HeaderFrom:
				continue
			case HeaderTo:
				fn = message.To
			case HeaderCc:
				fn = message.Cc
			case HeaderBcc:
				fn = message.Bcc
			default:
				t.Logf("header %s not supported", tt.header)
				continue
			}
			t.Run(tt.name, func(t *testing.T) {
				if err := fn("toni.tester@example.com"); err != nil {
					t.Fatalf("failed to set header: %s", err)
				}
				addrheader := message.GetAddrHeader(tt.header)
				if len(addrheader) != 1 {
					t.Errorf("expected 1 address, got: %d", len(addrheader))
				}
				if addrheader[0] == nil {
					t.Fatalf("expected address, got nil")
				}
				if addrheader[0].String() != "<toni.tester@example.com>" {
					t.Errorf("expected address not returned. Want: %s, got: %s",
						"<toni.tester@example.com>", addrheader[0].String())
				}
			})
		}
	})
	t.Run("GetAddrHeader with multiple valid address (to, cc, bcc)", func(t *testing.T) {
		var fn func(...string) error
		var addfn func(string) error
		for _, tt := range addrHeaderTests {
			message := NewMsg()
			if message == nil {
				t.Fatal("message is nil")
			}

			switch tt.header {
			case HeaderFrom:
				continue
			case HeaderTo:
				fn = message.To
				addfn = message.AddTo
			case HeaderCc:
				fn = message.Cc
				addfn = message.AddCc
			case HeaderBcc:
				fn = message.Bcc
				addfn = message.AddBcc
			default:
				t.Logf("header %s not supported", tt.header)
				continue
			}
			t.Run(tt.name, func(t *testing.T) {
				if err := fn("toni.tester@example.com"); err != nil {
					t.Fatalf("failed to set header: %s", err)
				}
				if err := addfn("tina.tester@example.com"); err != nil {
					t.Fatalf("failed to set additional header value: %s", err)
				}
				addrheader := message.GetAddrHeader(tt.header)
				if len(addrheader) != 2 {
					t.Errorf("expected 1 address, got: %d", len(addrheader))
				}
				if addrheader[0] == nil {
					t.Fatalf("expected address, got nil")
				}
				if addrheader[0].String() != "<toni.tester@example.com>" {
					t.Errorf("expected address not returned. Want: %s, got: %s",
						"<toni.tester@example.com>", addrheader[0].String())
				}
				if addrheader[1] == nil {
					t.Fatalf("expected address, got nil")
				}
				if addrheader[1].String() != "<tina.tester@example.com>" {
					t.Errorf("expected address not returned. Want: %s, got: %s",
						"<tina.tester@example.com>", addrheader[1].String())
				}
			})
		}
	})
	t.Run("GetAddrHeader with no addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		for _, tt := range addrHeaderTests {
			t.Run(tt.name, func(t *testing.T) {
				addrheader := message.GetAddrHeader(HeaderFrom)
				if len(addrheader) != 0 {
					t.Errorf("expected 0 address, got: %d", len(addrheader))
				}
			})
		}
	})
}

func TestMsg_GetAddrHeaderString(t *testing.T) {
	t.Run("GetAddrHeaderString with valid address (from)", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.From("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set header: %s", err)
		}
		addrheader := message.GetAddrHeaderString(HeaderFrom)
		if len(addrheader) != 1 {
			t.Errorf("expected 1 address, got: %d", len(addrheader))
		}
		if addrheader[0] == "" {
			t.Fatalf("expected address, got empty string")
		}
		if addrheader[0] != "<toni.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<toni.tester@example.com>", addrheader[0])
		}
	})
	t.Run("GetAddrHeaderString with valid address (to, cc, bcc)", func(t *testing.T) {
		var fn func(...string) error
		for _, tt := range addrHeaderTests {
			message := NewMsg()
			if message == nil {
				t.Fatal("message is nil")
			}

			switch tt.header {
			case HeaderFrom:
				continue
			case HeaderTo:
				fn = message.To
			case HeaderCc:
				fn = message.Cc
			case HeaderBcc:
				fn = message.Bcc
			default:
				t.Logf("header %s not supported", tt.header)
				continue
			}
			t.Run(tt.name, func(t *testing.T) {
				if err := fn("toni.tester@example.com"); err != nil {
					t.Fatalf("failed to set header: %s", err)
				}
				addrheader := message.GetAddrHeaderString(tt.header)
				if len(addrheader) != 1 {
					t.Errorf("expected 1 address, got: %d", len(addrheader))
				}
				if addrheader[0] == "" {
					t.Fatalf("expected address, got empty string")
				}
				if addrheader[0] != "<toni.tester@example.com>" {
					t.Errorf("expected address not returned. Want: %s, got: %s",
						"<toni.tester@example.com>", addrheader[0])
				}
			})
		}
	})
	t.Run("GetAddrHeaderString with multiple valid address (to, cc, bcc)", func(t *testing.T) {
		var fn func(...string) error
		var addfn func(string) error
		for _, tt := range addrHeaderTests {
			message := NewMsg()
			if message == nil {
				t.Fatal("message is nil")
			}

			switch tt.header {
			case HeaderFrom:
				continue
			case HeaderTo:
				fn = message.To
				addfn = message.AddTo
			case HeaderCc:
				fn = message.Cc
				addfn = message.AddCc
			case HeaderBcc:
				fn = message.Bcc
				addfn = message.AddBcc
			default:
				t.Logf("header %s not supported", tt.header)
				continue
			}
			t.Run(tt.name, func(t *testing.T) {
				if err := fn("toni.tester@example.com"); err != nil {
					t.Fatalf("failed to set header: %s", err)
				}
				if err := addfn("tina.tester@example.com"); err != nil {
					t.Fatalf("failed to set additional header value: %s", err)
				}
				addrheader := message.GetAddrHeaderString(tt.header)
				if len(addrheader) != 2 {
					t.Errorf("expected 1 address, got: %d", len(addrheader))
				}
				if addrheader[0] == "" {
					t.Fatalf("expected address, got empty string")
				}
				if addrheader[0] != "<toni.tester@example.com>" {
					t.Errorf("expected address not returned. Want: %s, got: %s",
						"<toni.tester@example.com>", addrheader[0])
				}
				if addrheader[1] == "" {
					t.Fatalf("expected address, got nil")
				}
				if addrheader[1] != "<tina.tester@example.com>" {
					t.Errorf("expected address not returned. Want: %s, got: %s",
						"<tina.tester@example.com>", addrheader[1])
				}
			})
		}
	})
	t.Run("GetAddrHeaderString with no addresses", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		for _, tt := range addrHeaderTests {
			t.Run(tt.name, func(t *testing.T) {
				addrheader := message.GetAddrHeaderString(HeaderFrom)
				if len(addrheader) != 0 {
					t.Errorf("expected 0 address, got: %d", len(addrheader))
				}
			})
		}
	})
}

func TestMsg_GetFrom(t *testing.T) {
	t.Run("GetFrom with address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.From("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set from address: %s", err)
		}
		addresses := message.GetFrom()
		if len(addresses) != 1 {
			t.Fatalf("expected 1 address, got: %d", len(addresses))
		}
		if addresses[0] == nil {
			t.Fatalf("expected address, got nil")
		}
		if addresses[0].String() != "<toni.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<toni.tester@example.com>", addresses[0].String())
		}
	})
	t.Run("GetFrom with no address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		addresses := message.GetFrom()
		if len(addresses) != 0 {
			t.Errorf("expected 0 address, got: %d", len(addresses))
		}
	})
}

func TestMsg_GetFromString(t *testing.T) {
	t.Run("GetFromString with address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.From("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set from address: %s", err)
		}
		addresses := message.GetFromString()
		if len(addresses) != 1 {
			t.Fatalf("expected 1 address, got: %d", len(addresses))
		}
		if addresses[0] == "" {
			t.Fatalf("expected address, got nil")
		}
		if addresses[0] != "<toni.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<toni.tester@example.com>", addresses[0])
		}
	})
	t.Run("GetFromString with no address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		addresses := message.GetFromString()
		if len(addresses) != 0 {
			t.Errorf("expected 0 address, got: %d", len(addresses))
		}
	})
}

func TestMsg_GetTo(t *testing.T) {
	t.Run("GetTo with address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.To("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set from address: %s", err)
		}
		addresses := message.GetTo()
		if len(addresses) != 1 {
			t.Fatalf("expected 1 address, got: %d", len(addresses))
		}
		if addresses[0] == nil {
			t.Fatalf("expected address, got nil")
		}
		if addresses[0].String() != "<toni.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<toni.tester@example.com>", addresses[0].String())
		}
	})
	t.Run("GetTo with multiple address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.To("toni.tester@example.com", "tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set from address: %s", err)
		}
		addresses := message.GetTo()
		if len(addresses) != 2 {
			t.Fatalf("expected 2 address, got: %d", len(addresses))
		}
		if addresses[0] == nil {
			t.Fatalf("expected address, got nil")
		}
		if addresses[0].String() != "<toni.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<toni.tester@example.com>", addresses[0].String())
		}
		if addresses[1] == nil {
			t.Fatalf("expected address, got nil")
		}
		if addresses[1].String() != "<tina.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<tina.tester@example.com>", addresses[1].String())
		}
	})
	t.Run("GetTo with no address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		addresses := message.GetTo()
		if len(addresses) != 0 {
			t.Errorf("expected 0 address, got: %d", len(addresses))
		}
	})
}

func TestMsg_GetToString(t *testing.T) {
	t.Run("GetToString with address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.To("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set from address: %s", err)
		}
		addresses := message.GetToString()
		if len(addresses) != 1 {
			t.Fatalf("expected 1 address, got: %d", len(addresses))
		}
		if addresses[0] == "" {
			t.Fatalf("expected address, got nil")
		}
		if addresses[0] != "<toni.tester@example.com>" {
			t.Errorf("GetToString: expected address not returned. Want: %s, got: %s",
				"<toni.tester@example.com>", addresses[0])
		}
	})
	t.Run("GetToString with multiple address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.To("toni.tester@example.com", "tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set from address: %s", err)
		}
		addresses := message.GetToString()
		if len(addresses) != 2 {
			t.Fatalf("expected 2 address, got: %d", len(addresses))
		}
		if addresses[0] == "" {
			t.Fatalf("expected address, got nil")
		}
		if addresses[0] != "<toni.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<toni.tester@example.com>", addresses[0])
		}
		if addresses[1] == "" {
			t.Fatalf("expected address, got nil")
		}
		if addresses[1] != "<tina.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<tina.tester@example.com>", addresses[1])
		}
	})
	t.Run("GetToString with no address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		addresses := message.GetToString()
		if len(addresses) != 0 {
			t.Errorf("expected 0 address, got: %d", len(addresses))
		}
	})
}

func TestMsg_GetCc(t *testing.T) {
	t.Run("GetCc with address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Cc("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set from address: %s", err)
		}
		addresses := message.GetCc()
		if len(addresses) != 1 {
			t.Fatalf("expected 1 address, got: %d", len(addresses))
		}
		if addresses[0] == nil {
			t.Fatalf("expected address, got nil")
		}
		if addresses[0].String() != "<toni.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<toni.tester@example.com>", addresses[0].String())
		}
	})
	t.Run("GetCc with multiple address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Cc("toni.tester@example.com", "tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set from address: %s", err)
		}
		addresses := message.GetCc()
		if len(addresses) != 2 {
			t.Fatalf("expected 2 address, got: %d", len(addresses))
		}
		if addresses[0] == nil {
			t.Fatalf("expected address, got nil")
		}
		if addresses[0].String() != "<toni.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<toni.tester@example.com>", addresses[0].String())
		}
		if addresses[1] == nil {
			t.Fatalf("expected address, got nil")
		}
		if addresses[1].String() != "<tina.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<tina.tester@example.com>", addresses[1].String())
		}
	})
	t.Run("GetCc with no address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		addresses := message.GetCc()
		if len(addresses) != 0 {
			t.Errorf("expected 0 address, got: %d", len(addresses))
		}
	})
}

func TestMsg_GetCcString(t *testing.T) {
	t.Run("GetCcString with address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Cc("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set from address: %s", err)
		}
		addresses := message.GetCcString()
		if len(addresses) != 1 {
			t.Fatalf("expected 1 address, got: %d", len(addresses))
		}
		if addresses[0] == "" {
			t.Fatalf("expected address, got nil")
		}
		if addresses[0] != "<toni.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<toni.tester@example.com>", addresses[0])
		}
	})
	t.Run("GetCcString with multiple address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Cc("toni.tester@example.com", "tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set from address: %s", err)
		}
		addresses := message.GetCcString()
		if len(addresses) != 2 {
			t.Fatalf("expected 2 address, got: %d", len(addresses))
		}
		if addresses[0] == "" {
			t.Fatalf("expected address, got nil")
		}
		if addresses[0] != "<toni.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<toni.tester@example.com>", addresses[0])
		}
		if addresses[1] == "" {
			t.Fatalf("GetCcString: expected address, got nil")
		}
		if addresses[1] != "<tina.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<tina.tester@example.com>", addresses[1])
		}
	})
	t.Run("GetCcString with no address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		addresses := message.GetCcString()
		if len(addresses) != 0 {
			t.Errorf("expected 0 address, got: %d", len(addresses))
		}
	})
}

func TestMsg_GetBcc(t *testing.T) {
	t.Run("GetBcc with address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Bcc("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set from address: %s", err)
		}
		addresses := message.GetBcc()
		if len(addresses) != 1 {
			t.Fatalf("expected 1 address, got: %d", len(addresses))
		}
		if addresses[0] == nil {
			t.Fatalf("expected address, got nil")
		}
		if addresses[0].String() != "<toni.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<toni.tester@example.com>", addresses[0].String())
		}
	})
	t.Run("GetBcc with multiple address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Bcc("toni.tester@example.com", "tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set from address: %s", err)
		}
		addresses := message.GetBcc()
		if len(addresses) != 2 {
			t.Fatalf("expected 2 address, got: %d", len(addresses))
		}
		if addresses[0] == nil {
			t.Fatalf("expected address, got nil")
		}
		if addresses[0].String() != "<toni.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<toni.tester@example.com>", addresses[0].String())
		}
		if addresses[1] == nil {
			t.Fatalf("expected address, got nil")
		}
		if addresses[1].String() != "<tina.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<tina.tester@example.com>", addresses[1].String())
		}
	})
	t.Run("GetBcc with no address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		addresses := message.GetBcc()
		if len(addresses) != 0 {
			t.Errorf("expected 0 address, got: %d", len(addresses))
		}
	})
}

func TestMsg_GetBccString(t *testing.T) {
	t.Run("GetBccString with address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Bcc("toni.tester@example.com"); err != nil {
			t.Fatalf("failed to set from address: %s", err)
		}
		addresses := message.GetBccString()
		if len(addresses) != 1 {
			t.Fatalf("expected 1 address, got: %d", len(addresses))
		}
		if addresses[0] == "" {
			t.Fatalf("expected address, got nil")
		}
		if addresses[0] != "<toni.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<toni.tester@example.com>", addresses[0])
		}
	})
	t.Run("GetBccString with multiple address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.Bcc("toni.tester@example.com", "tina.tester@example.com"); err != nil {
			t.Fatalf("failed to set from address: %s", err)
		}
		addresses := message.GetBccString()
		if len(addresses) != 2 {
			t.Fatalf("expected 2 address, got: %d", len(addresses))
		}
		if addresses[0] == "" {
			t.Fatalf("expected address, got nil")
		}
		if addresses[0] != "<toni.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<toni.tester@example.com>", addresses[0])
		}
		if addresses[1] == "" {
			t.Fatalf("expected address, got nil")
		}
		if addresses[1] != "<tina.tester@example.com>" {
			t.Errorf("expected address not returned. Want: %s, got: %s",
				"<tina.tester@example.com>", addresses[1])
		}
	})
	t.Run("GetBccString with no address", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		addresses := message.GetBccString()
		if len(addresses) != 0 {
			t.Errorf("expected 0 address, got: %d", len(addresses))
		}
	})
}

func TestMsg_GetGenHeader(t *testing.T) {
	t.Run("GetGenHeader with single value", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		for _, tt := range genHeaderTests {
			t.Run(tt.name, func(t *testing.T) {
				message.SetGenHeader(tt.header, "test")
				values := message.GetGenHeader(tt.header)
				if len(values) != 1 {
					t.Errorf("expected 1 value, got: %d", len(values))
				}
				if values[0] != "test" {
					t.Errorf("expected value not returned. Want: %s, got: %s",
						"test", values[0])
				}
			})
		}
	})
	t.Run("GetGenHeader with multiple values", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		for _, tt := range genHeaderTests {
			t.Run(tt.name, func(t *testing.T) {
				message.SetGenHeader(tt.header, "test", "foobar")
				values := message.GetGenHeader(tt.header)
				if len(values) != 2 {
					t.Errorf("expected 1 value, got: %d", len(values))
				}
				if values[0] != "test" {
					t.Errorf("expected value not returned. Want: %s, got: %s",
						"test", values[0])
				}
				if values[1] != "foobar" {
					t.Errorf("expected value not returned. Want: %s, got: %s",
						"foobar", values[1])
				}
			})
		}
	})
	t.Run("GetGenHeader with nil", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		for _, tt := range genHeaderTests {
			t.Run(tt.name, func(t *testing.T) {
				message.SetGenHeader(tt.header)
				values := message.GetGenHeader(tt.header)
				if len(values) != 0 {
					t.Errorf("expected 1 value, got: %d", len(values))
				}
			})
		}
	})
}

func TestMsg_GetParts(t *testing.T) {
	t.Run("GetParts with single part", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.SetBodyString(TypeTextPlain, "this is a test body")
		parts := message.GetParts()
		if len(parts) != 1 {
			t.Fatalf("expected 1 part, got: %d", len(parts))
		}
		if parts[0] == nil {
			t.Fatalf("expected part, got nil")
		}
		if parts[0].contentType != TypeTextPlain {
			t.Errorf("expected contentType to be TypeTextPlain, got: %s", parts[0].contentType)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err := parts[0].writeFunc(messageBuf)
		if err != nil {
			t.Errorf("writeFunc failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "this is a test body") {
			t.Errorf("expected message body to be %s, got: %s", "this is a test body",
				messageBuf.String())
		}
	})
	t.Run("GetParts with multiple parts", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.SetBodyString(TypeTextPlain, "this is a test body")
		message.AddAlternativeString(TypeTextHTML, "<p>This is HTML</p>")
		parts := message.GetParts()
		if len(parts) != 2 {
			t.Fatalf("expected 2 parts, got: %d", len(parts))
		}
		if parts[0] == nil || parts[1] == nil {
			t.Fatalf("expected parts, got nil")
		}
		if parts[0].contentType != TypeTextPlain {
			t.Errorf("expected contentType to be TypeTextPlain, got: %s", parts[0].contentType)
		}
		if parts[1].contentType != TypeTextHTML {
			t.Errorf("expected contentType to be TypeTextHTML, got: %s", parts[1].contentType)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err := parts[0].writeFunc(messageBuf)
		if err != nil {
			t.Errorf("writeFunc failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "this is a test body") {
			t.Errorf("expected message body to be %s, got: %s", "this is a test body",
				messageBuf.String())
		}
		messageBuf.Reset()
		_, err = parts[1].writeFunc(messageBuf)
		if err != nil {
			t.Errorf("GetParts: writeFunc failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "<p>This is HTML</p>") {
			t.Errorf("expected message body to be %s, got: %s", "<p>This is HTML</p>",
				messageBuf.String())
		}
	})
	t.Run("GetParts with no parts", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		parts := message.GetParts()
		if len(parts) != 0 {
			t.Fatalf("expected no parts, got: %d", len(parts))
		}
	})
}

func TestMsg_GetAttachments(t *testing.T) {
	t.Run("GetAttachments with single attachment", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.AttachFile("testdata/attachment.txt")
		attachments := message.GetAttachments()
		if len(attachments) != 1 {
			t.Fatalf("expected 1 attachment, got: %d", len(attachments))
		}
		if attachments[0] == nil {
			t.Fatalf("expected attachment, got nil")
		}
		if attachments[0].Name != "attachment.txt" {
			t.Errorf("expected attachment name to be %s, got: %s", "attachment.txt",
				attachments[0].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err := attachments[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "This is a test attachment\n") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test attachment\n",
				messageBuf.String())
		}
	})
	t.Run("GetAttachments with multiple attachments", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.AttachFile("testdata/attachment.txt")
		message.AttachFile("testdata/attachment.txt", WithFileName("attachment2.txt"))
		attachments := message.GetAttachments()
		if len(attachments) != 2 {
			t.Fatalf("expected 2 attachment, got: %d", len(attachments))
		}
		if attachments[0] == nil || attachments[1] == nil {
			t.Fatalf("expected attachment, got nil")
		}
		if attachments[0].Name != "attachment.txt" {
			t.Errorf("expected attachment name to be %s, got: %s", "attachment.txt",
				attachments[0].Name)
		}
		if attachments[1].Name != "attachment2.txt" {
			t.Errorf("expected attachment name to be %s, got: %s", "attachment2.txt",
				attachments[1].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err := attachments[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "This is a test attachment\n") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test attachment\n",
				messageBuf.String())
		}
		messageBuf.Reset()
		_, err = attachments[1].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "This is a test attachment\n") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test attachment\n",
				messageBuf.String())
		}
	})
	t.Run("GetAttachments with no attachment", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		attachments := message.GetAttachments()
		if len(attachments) != 0 {
			t.Fatalf("expected 1 attachment, got: %d", len(attachments))
		}
	})
}

func TestMsg_GetBoundary(t *testing.T) {
	t.Run("GetBoundary", func(t *testing.T) {
		message := NewMsg(WithBoundary("test"))
		if message == nil {
			t.Fatal("message is nil")
		}
		if message.GetBoundary() != "test" {
			t.Errorf("expected %s, got: %s", "test", message.GetBoundary())
		}
	})
	t.Run("GetBoundary with no boundary", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if message.GetBoundary() != "" {
			t.Errorf("expected empty, got: %s", message.GetBoundary())
		}
	})
}

func TestMsg_SetAttachments(t *testing.T) {
	t.Run("SetAttachments with single file", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		file := &File{
			ContentType: TypeTextPlain,
			Desc:        "Test file",
			Name:        "attachment.txt",
			Writer: func(w io.Writer) (int64, error) {
				buf := bytes.NewBuffer([]byte("This is a test attachment\n"))
				n, err := w.Write(buf.Bytes())
				return int64(n), err
			},
		}
		message.SetAttachments([]*File{file})
		attachments := message.GetAttachments()
		if len(attachments) != 1 {
			t.Fatalf("expected 1 attachment, got: %d", len(attachments))
		}
		if attachments[0] == nil {
			t.Fatalf("expected attachment, got nil")
		}
		if attachments[0].Name != "attachment.txt" {
			t.Errorf("expected attachment name to be %s, got: %s", "attachment.txt",
				attachments[0].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err := attachments[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "This is a test attachment\n") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test attachment\n",
				messageBuf.String())
		}
	})
	t.Run("SetAttachments with multiple files", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		file1 := &File{
			ContentType: TypeTextPlain,
			Desc:        "Test file",
			Name:        "attachment.txt",
			Writer: func(w io.Writer) (int64, error) {
				buf := bytes.NewBuffer([]byte("This is a test attachment\n"))
				n, err := w.Write(buf.Bytes())
				return int64(n), err
			},
		}
		file2 := &File{
			ContentType: TypeTextPlain,
			Desc:        "Test file no. 2",
			Name:        "attachment2.txt",
			Writer: func(w io.Writer) (int64, error) {
				buf := bytes.NewBuffer([]byte("This is also a test attachment\n"))
				n, err := w.Write(buf.Bytes())
				return int64(n), err
			},
		}
		message.SetAttachments([]*File{file1, file2})
		attachments := message.GetAttachments()
		if len(attachments) != 2 {
			t.Fatalf("expected 2 attachment, got: %d", len(attachments))
		}
		if attachments[0] == nil || attachments[1] == nil {
			t.Fatalf("expected attachment, got nil")
		}
		if attachments[0].Name != "attachment.txt" {
			t.Errorf("expected attachment name to be %s, got: %s", "attachment.txt",
				attachments[0].Name)
		}
		if attachments[1].Name != "attachment2.txt" {
			t.Errorf("expected attachment name to be %s, got: %s", "attachment2.txt",
				attachments[1].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err := attachments[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "This is a test attachment\n") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test attachment\n",
				messageBuf.String())
		}
		messageBuf.Reset()
		_, err = attachments[1].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "This is also a test attachment\n") {
			t.Errorf("expected message body to be %s, got: %s", "This is also a test attachment\n",
				messageBuf.String())
		}
	})
	t.Run("SetAttachments with no file", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.SetAttachments(nil)
		attachments := message.GetAttachments()
		if len(attachments) != 0 {
			t.Fatalf("expected 0 attachment, got: %d", len(attachments))
		}
	})
}

func TestMsg_SetAttachements(t *testing.T) {
	message := NewMsg()
	//goland:noinspection GoDeprecation
	message.SetAttachements(nil)
	t.Skip("SetAttachements is deprecated and fully tested by SetAttachments already")
}

func TestMsg_UnsetAllAttachments(t *testing.T) {
	message := NewMsg()
	if message == nil {
		t.Fatal("message is nil")
	}
	file1 := &File{
		ContentType: TypeTextPlain,
		Desc:        "Test file",
		Name:        "attachment.txt",
		Writer: func(w io.Writer) (int64, error) {
			buf := bytes.NewBuffer([]byte("This is a test attachment\n"))
			n, err := w.Write(buf.Bytes())
			return int64(n), err
		},
	}
	file2 := &File{
		ContentType: TypeTextPlain,
		Desc:        "Test file no. 2",
		Name:        "attachment2.txt",
		Writer: func(w io.Writer) (int64, error) {
			buf := bytes.NewBuffer([]byte("This is also a test attachment\n"))
			n, err := w.Write(buf.Bytes())
			return int64(n), err
		},
	}
	message.SetAttachments([]*File{file1, file2})
	message.UnsetAllAttachments()
	if message.attachments != nil {
		t.Errorf("expected attachments to be nil, got: %v", message.attachments)
	}
	attachments := message.GetAttachments()
	if len(attachments) != 0 {
		t.Fatalf("expected 0 attachment, got: %d", len(attachments))
	}
}

func TestMsg_GetEmbeds(t *testing.T) {
	t.Run("GetEmbeds with single embed", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.EmbedFile("testdata/embed.txt")
		embeds := message.GetEmbeds()
		if len(embeds) != 1 {
			t.Fatalf("expected 1 embed, got: %d", len(embeds))
		}
		if embeds[0] == nil {
			t.Fatalf("expected embed, got nil")
		}
		if embeds[0].Name != "embed.txt" {
			t.Errorf("expected embed name to be %s, got: %s", "embed.txt",
				embeds[0].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err := embeds[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("Writer func failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "This is a test embed\n") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test embed\n",
				messageBuf.String())
		}
	})
	t.Run("GetEmbeds with multiple embeds", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.EmbedFile("testdata/embed.txt")
		message.EmbedFile("testdata/embed.txt", WithFileName("embed2.txt"))
		embeds := message.GetEmbeds()
		if len(embeds) != 2 {
			t.Fatalf("expected 2 embed, got: %d", len(embeds))
		}
		if embeds[0] == nil || embeds[1] == nil {
			t.Fatalf("expected embed, got nil")
		}
		if embeds[0].Name != "embed.txt" {
			t.Errorf("expected embed name to be %s, got: %s", "embed.txt",
				embeds[0].Name)
		}
		if embeds[1].Name != "embed2.txt" {
			t.Errorf("expected embed name to be %s, got: %s", "embed2.txt",
				embeds[1].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err := embeds[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("Writer func failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "This is a test embed\n") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test embed\n",
				messageBuf.String())
		}
		messageBuf.Reset()
		_, err = embeds[1].Writer(messageBuf)
		if err != nil {
			t.Errorf("Writer func failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "This is a test embed\n") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test embed\n",
				messageBuf.String())
		}
	})
	t.Run("GetEmbeds with no embeds", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		embeds := message.GetEmbeds()
		if len(embeds) != 0 {
			t.Fatalf("expected 1 embeds, got: %d", len(embeds))
		}
	})
}

func TestMsg_SetEmbeds(t *testing.T) {
	t.Run("SetEmbeds with single file", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		file := &File{
			ContentType: TypeTextPlain,
			Desc:        "Test file",
			Name:        "embed.txt",
			Writer: func(w io.Writer) (int64, error) {
				buf := bytes.NewBuffer([]byte("This is a test embed\n"))
				n, err := w.Write(buf.Bytes())
				return int64(n), err
			},
		}
		message.SetEmbeds([]*File{file})
		embeds := message.GetEmbeds()
		if len(embeds) != 1 {
			t.Fatalf("expected 1 embed, got: %d", len(embeds))
		}
		if embeds[0] == nil {
			t.Fatalf("expected embed, got nil")
		}
		if embeds[0].Name != "embed.txt" {
			t.Errorf("expected embed name to be %s, got: %s", "embed.txt",
				embeds[0].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err := embeds[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("Writer func failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "This is a test embed\n") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test embed\n",
				messageBuf.String())
		}
	})
	t.Run("SetEmbeds with multiple files", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		file1 := &File{
			ContentType: TypeTextPlain,
			Desc:        "Test file",
			Name:        "embed.txt",
			Writer: func(w io.Writer) (int64, error) {
				buf := bytes.NewBuffer([]byte("This is a test embed\n"))
				n, err := w.Write(buf.Bytes())
				return int64(n), err
			},
		}
		file2 := &File{
			ContentType: TypeTextPlain,
			Desc:        "Test file no. 2",
			Name:        "embed2.txt",
			Writer: func(w io.Writer) (int64, error) {
				buf := bytes.NewBuffer([]byte("This is also a test embed\n"))
				n, err := w.Write(buf.Bytes())
				return int64(n), err
			},
		}
		message.SetEmbeds([]*File{file1, file2})
		embeds := message.GetEmbeds()
		if len(embeds) != 2 {
			t.Fatalf("expected 2 embed, got: %d", len(embeds))
		}
		if embeds[0] == nil || embeds[1] == nil {
			t.Fatalf("expected embed, got nil")
		}
		if embeds[0].Name != "embed.txt" {
			t.Errorf("expected embed name to be %s, got: %s", "embed.txt",
				embeds[0].Name)
		}
		if embeds[1].Name != "embed2.txt" {
			t.Errorf("expected embed name to be %s, got: %s", "embed2.txt",
				embeds[1].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err := embeds[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("Writer func failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "This is a test embed\n") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test embed\n",
				messageBuf.String())
		}
		messageBuf.Reset()
		_, err = embeds[1].Writer(messageBuf)
		if err != nil {
			t.Errorf("Writer func failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "This is also a test embed\n") {
			t.Errorf("expected message body to be %s, got: %s", "This is also a test embed\n",
				messageBuf.String())
		}
	})
	t.Run("SetEmbeds with no file", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.SetEmbeds(nil)
		embeds := message.GetEmbeds()
		if len(embeds) != 0 {
			t.Fatalf("expected 0 embed, got: %d", len(embeds))
		}
	})
}

func TestMsg_UnsetAllEmbeds(t *testing.T) {
	message := NewMsg()
	if message == nil {
		t.Fatal("message is nil")
	}
	file1 := &File{
		ContentType: TypeTextPlain,
		Desc:        "Test file",
		Name:        "embed.txt",
		Writer: func(w io.Writer) (int64, error) {
			buf := bytes.NewBuffer([]byte("This is a test embed\n"))
			n, err := w.Write(buf.Bytes())
			return int64(n), err
		},
	}
	file2 := &File{
		ContentType: TypeTextPlain,
		Desc:        "Test file no. 2",
		Name:        "embed2.txt",
		Writer: func(w io.Writer) (int64, error) {
			buf := bytes.NewBuffer([]byte("This is also a test embed\n"))
			n, err := w.Write(buf.Bytes())
			return int64(n), err
		},
	}
	message.SetEmbeds([]*File{file1, file2})
	message.UnsetAllEmbeds()
	if message.embeds != nil {
		t.Errorf("expected embeds to be nil, got: %v", message.embeds)
	}
	embeds := message.GetEmbeds()
	if len(embeds) != 0 {
		t.Fatalf("expected 0 embed, got: %d", len(embeds))
	}
}

func TestMsg_UnsetAllParts(t *testing.T) {
	message := NewMsg()
	if message == nil {
		t.Fatal("message is nil")
	}
	file1 := &File{
		ContentType: TypeTextPlain,
		Desc:        "Test file",
		Name:        "embed.txt",
		Writer: func(w io.Writer) (int64, error) {
			buf := bytes.NewBuffer([]byte("This is a test embed\n"))
			n, err := w.Write(buf.Bytes())
			return int64(n), err
		},
	}
	file2 := &File{
		ContentType: TypeTextPlain,
		Desc:        "Test file no. 2",
		Name:        "embed2.txt",
		Writer: func(w io.Writer) (int64, error) {
			buf := bytes.NewBuffer([]byte("This is also a test embed\n"))
			n, err := w.Write(buf.Bytes())
			return int64(n), err
		},
	}
	message.SetAttachments([]*File{file1})
	message.SetEmbeds([]*File{file2})
	message.UnsetAllParts()
	if message.embeds != nil || message.attachments != nil {
		t.Error("expected attachments/embeds to be nil, got: value")
	}
	embeds := message.GetEmbeds()
	if len(embeds) != 0 {
		t.Fatalf("expected 0 embed, got: %d", len(embeds))
	}
	attachments := message.GetAttachments()
	if len(attachments) != 0 {
		t.Fatalf("expected 0 attachments, got: %d", len(attachments))
	}
}

func TestMsg_SetBodyString(t *testing.T) {
	t.Run("SetBodyString on all types", func(t *testing.T) {
		for _, tt := range contentTypeTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				message.SetBodyString(tt.ctype, "test")
				parts := message.GetParts()
				if len(parts) != 1 {
					t.Fatalf("expected 1 part, got: %d", len(parts))
				}
				if parts[0] == nil {
					t.Fatal("expected part to be not nil")
				}
				if parts[0].contentType != tt.ctype {
					t.Errorf("expected contentType to be %s, got: %s", tt.ctype,
						parts[0].contentType)
				}
				messageBuf := bytes.NewBuffer(nil)
				_, err := parts[0].writeFunc(messageBuf)
				if err != nil {
					t.Errorf("writeFunc failed: %s", err)
				}
				if !strings.EqualFold(messageBuf.String(), "test") {
					t.Errorf("expected message body to be %s, got: %s", "test", messageBuf.String())
				}
			})
		}
	})
}

func TestMsg_SetBodyWriter(t *testing.T) {
	writerFunc := func(w io.Writer) (int64, error) {
		buffer := bytes.NewBufferString("test")
		n, err := w.Write(buffer.Bytes())
		return int64(n), err
	}
	t.Run("SetBodyWriter on all types", func(t *testing.T) {
		for _, tt := range contentTypeTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				message.SetBodyWriter(tt.ctype, writerFunc)
				parts := message.GetParts()
				if len(parts) != 1 {
					t.Fatalf("expected 1 part, got: %d", len(parts))
				}
				if parts[0] == nil {
					t.Fatal("expected part to be not nil")
				}
				if parts[0].contentType != tt.ctype {
					t.Errorf("expected contentType to be %s, got: %s", tt.ctype,
						parts[0].contentType)
				}
				messageBuf := bytes.NewBuffer(nil)
				_, err := parts[0].writeFunc(messageBuf)
				if err != nil {
					t.Errorf("writeFunc failed: %s", err)
				}
				if !strings.EqualFold(messageBuf.String(), "test") {
					t.Errorf("expected message body to be %s, got: %s", "test", messageBuf.String())
				}
			})
		}
	})
	t.Run("SetBodyWriter WithPartCharset", func(t *testing.T) {
		for _, tt := range charsetTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				message.SetBodyWriter(TypeTextPlain, writerFunc, WithPartCharset(tt.value))
				parts := message.GetParts()
				if len(parts) != 1 {
					t.Fatalf("expected 1 part, got: %d", len(parts))
				}
				if parts[0] == nil {
					t.Fatal("expected part to be not nil")
				}
				if parts[0].contentType != TypeTextPlain {
					t.Errorf("expected contentType to be %s, got: %s", TypeTextPlain,
						parts[0].contentType)
				}
				if parts[0].charset != tt.value {
					t.Errorf("expected charset to be %s, got: %s", tt.value, parts[0].charset)
				}
				messageBuf := bytes.NewBuffer(nil)
				_, err := parts[0].writeFunc(messageBuf)
				if err != nil {
					t.Errorf("writeFunc failed: %s", err)
				}
				if !strings.EqualFold(messageBuf.String(), "test") {
					t.Errorf("expected message body to be %s, got: %s", "test", messageBuf.String())
				}
			})
		}
	})
}

// checkAddrHeader verifies the correctness of an AddrHeader in a Msg based on the provided criteria.
// It checks whether the AddrHeader contains the correct address, name, and number of fields.
func checkAddrHeader(t *testing.T, message *Msg, header AddrHeader, fn string, field, wantFields int,
	wantMail, wantName string,
) {
	t.Helper()
	addresses, ok := message.addrHeader[header]
	if !ok {
		t.Fatalf("failed to set %s, addrHeader field is not set", fn)
	}
	if len(addresses) != wantFields {
		t.Fatalf("failed to set %s, addrHeader value count is: %d, want: %d", fn, len(addresses), field)
	}
	if addresses[field].Address != wantMail {
		t.Errorf("failed to set %s, addrHeader value is %s, want: %s", fn, addresses[field].Address, wantMail)
	}
	wantString := fmt.Sprintf(`<%s>`, wantMail)
	if wantName != "" {
		wantString = fmt.Sprintf(`%q <%s>`, wantName, wantMail)
	}
	if addresses[field].String() != wantString {
		t.Errorf("failed to set %s, addrHeader value is %s, want: %s", fn, addresses[field].String(), wantString)
	}
	if addresses[field].Name != wantName {
		t.Errorf("failed to set %s, addrHeader name is %s, want: %s", fn, addresses[field].Name, wantName)
	}
}

// checkGenHeader validates the generated header in an email message, verifying its presence and expected values.
func checkGenHeader(t *testing.T, message *Msg, header Header, fn string, field, wantFields int,
	wantVal string,
) {
	t.Helper()
	values, ok := message.genHeader[header]
	if !ok {
		t.Fatalf("failed to set %s, genHeader field is not set", fn)
	}
	if len(values) != wantFields {
		t.Fatalf("failed to set %s, genHeader value count is: %d, want: %d", fn, len(values), field)
	}
	if values[field] != wantVal {
		t.Errorf("failed to set %s, genHeader value is %s, want: %s", fn, values[field], wantVal)
	}
}

/*
// TestNewMsgWithMiddleware tests WithMiddleware

	func TestNewMsgWithMiddleware(t *testing.T) {
		m := NewMsg()
		if len(m.middlewares) != 0 {
			t.Errorf("empty middlewares failed. m.middlewares expected to be: empty, got: %d middleware", len(m.middlewares))
		}
		m = NewMsg(WithMiddleware(uppercaseMiddleware{}))
		if len(m.middlewares) != 1 {
			t.Errorf("empty middlewares failed. m.middlewares expected to be: 1, got: %d middleware", len(m.middlewares))
		}
		m = NewMsg(WithMiddleware(uppercaseMiddleware{}), WithMiddleware(encodeMiddleware{}))
		if len(m.middlewares) != 2 {
			t.Errorf("empty middlewares failed. m.middlewares expected to be: 2, got: %d middleware", len(m.middlewares))
		}
	}

// TestApplyMiddlewares tests the applyMiddlewares for the Msg object

	func TestApplyMiddlewares(t *testing.T) {
		tests := []struct {
			name string
			sub  string
			want string
		}{
			{"normal subject", "This is a test subject", "THIS IS @ TEST SUBJECT"},
			{"subject with one middleware effect", "This is test subject", "THIS IS TEST SUBJECT"},
			{"subject with one middleware effect", "This is A test subject", "THIS IS A TEST SUBJECT"},
		}
		m := NewMsg(WithMiddleware(encodeMiddleware{}), WithMiddleware(uppercaseMiddleware{}))
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				m.Subject(tt.sub)
				if m.genHeader[HeaderSubject] == nil {
					t.Errorf("Subject() method failed in applyMiddlewares() test. Generic header for subject is empty")
					return
				}
				m = m.applyMiddlewares(m)
				s, ok := m.genHeader[HeaderSubject]
				if !ok {
					t.Errorf("failed to get subject header")
				}
				if s[0] != tt.want {
					t.Errorf("applyMiddlewares() method failed. Expected: %s, got: %s", tt.want, s[0])
				}
			})
		}
	}

// TestMsg_SetBodyString tests the Msg.SetBodyString method

	func TestMsg_SetBodyString(t *testing.T) {
		tests := []struct {
			name  string
			ct    ContentType
			value string
			want  string
			sf    bool
		}{
			{"Body: test", TypeTextPlain, "test", "test", false},
			{
				"Body: with Umlauts", TypeTextHTML, "<strong>üäöß</strong>",
				"<strong>üäöß</strong>", false,
			},
			{"Body: with emoji", TypeTextPlain, "📧", "📧", false},
		}
		m := NewMsg()
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				m.SetBodyString(tt.ct, tt.value)
				if len(m.parts) != 1 {
					t.Errorf("SetBodyString() failed: no mail parts found")
				}
				part := m.parts[0]
				res := bytes.Buffer{}
				if _, err := part.writeFunc(&res); err != nil && !tt.sf {
					t.Errorf("WriteFunc of part failed: %s", err)
				}
				if res.String() != tt.want {
					t.Errorf("SetBodyString() failed. Expecteding: %s, got: %s", tt.want, res.String())
				}
			})
		}
	}

// TestMsg_AddAlternativeString tests the Msg.AddAlternativeString method

	func TestMsg_AddAlternativeString(t *testing.T) {
		tests := []struct {
			name  string
			value string
			want  string
			sf    bool
		}{
			{"Body: test", "test", "test", false},
			{"Body: with Umlauts", "<strong>üäöß</strong>", "<strong>üäöß</strong>", false},
			{"Body: with emoji", "📧", "📧", false},
		}
		m := NewMsg()
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				m.SetBodyString(TypeTextPlain, tt.value)
				if len(m.parts) != 1 {
					t.Errorf("AddAlternativeString() => SetBodyString() failed: no mail parts found")
				}
				m.AddAlternativeString(TypeTextHTML, tt.value)
				if len(m.parts) != 2 {
					t.Errorf("AddAlternativeString() failed: no alternative mail parts found")
				}
				apart := m.parts[1]
				res := bytes.Buffer{}
				if _, err := apart.writeFunc(&res); err != nil && !tt.sf {
					t.Errorf("WriteFunc of part failed: %s", err)
				}
				if res.String() != tt.want {
					t.Errorf("AddAlternativeString() failed. Expecteding: %s, got: %s", tt.want, res.String())
				}
			})
		}
	}

// TestMsg_AttachFile tests the Msg.AttachFile and the WithFilename FileOption method

	func TestMsg_AttachFile(t *testing.T) {
		tests := []struct {
			name string
			file string
			fn   string
			sf   bool
		}{
			{"File: README.md", "README.md", "README.md", false},
			{"File: doc.go", "doc.go", "foo.go", false},
			{"File: nonexisting", "", "invalid.file", true},
		}
		m := NewMsg()
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				m.AttachFile(tt.file, WithFileName(tt.fn), nil)
				if len(m.attachments) != 1 && !tt.sf {
					t.Errorf("AttachFile() failed. Number of attachments expected: %d, got: %d", 1,
						len(m.attachments))
					return
				}
				if !tt.sf {
					file := m.attachments[0]
					if file == nil {
						t.Errorf("AttachFile() failed. Attachment file pointer is nil")
						return
					}
					if file.Name != tt.fn {
						t.Errorf("AttachFile() failed. Filename of attachment expected: %s, got: %s", tt.fn,
							file.Name)
					}
					buf := bytes.Buffer{}
					if _, err := file.Writer(&buf); err != nil {
						t.Errorf("failed to execute WriterFunc: %s", err)
						return
					}
				}
				m.Reset()
			})
		}
	}

// TestMsg_UnsetAllAttachments tests the Msg.UnsetAllAttachments method

	func TestMsg_UnsetAllAttachments(t *testing.T) {
		tests := []struct {
			name        string
			attachments []string
		}{
			{"File: one file", []string{"README.md"}},
			{"File: two files", []string{"README.md", "doc.go"}},
			{"File: nil", nil},
		}
		m := NewMsg()
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var files []*File
				for _, f := range tt.attachments {
					files = append(files, &File{Name: f})
				}
				m.SetAttachments(files)

				if len(m.attachments) != len(files) {
					t.Errorf("SetAttachements() failed. Number of attachments expected: %d, got: %d", len(files),
						len(m.attachments))
					return
				}
				m.UnsetAllAttachments()
				if m.attachments != nil {
					t.Errorf("UnsetAllAttachments() failed. The attachments file's pointer is not nil")
					return
				}
				m.Reset()
			})
		}
	}

// TestMsg_GetEmbeds tests the Msg.GetEmbeds method

	func TestMsg_GetEmbeds(t *testing.T) {
		tests := []struct {
			name  string
			files []string
		}{
			{"File: README.md", []string{"README.md"}},
			{"File: doc.go", []string{"doc.go"}},
			{"File: README.md and doc.go", []string{"README.md", "doc.go"}},
			{"File: nonexisting", nil},
		}
		m := NewMsg()
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				for _, f := range tt.files {
					m.EmbedFile(f, WithFileName(f), nil)
				}
				if len(m.embeds) != len(tt.files) {
					t.Errorf("EmbedFile() failed. Number of embedded files expected: %d, got: %d", len(tt.files),
						len(m.embeds))
					return
				}
				ff := m.GetEmbeds()
				if len(m.embeds) != len(ff) {
					t.Errorf("GetEmbeds() failed. Number of embedded files expected: %d, got: %d", len(m.embeds),
						len(ff))
					return
				}
				var fn []string
				for _, f := range ff {
					fn = append(fn, f.Name)
				}
				sort.Strings(fn)
				sort.Strings(tt.files)
				for i, f := range tt.files {
					if f != fn[i] {
						t.Errorf("GetEmbeds() failed. Embedded file name expected: %s, got: %s", f,
							fn[i])
						return
					}
				}
				m.Reset()
			})
		}
	}

// TestMsg_SetEmbeds tests the Msg.GetEmbeds method

	func TestMsg_SetEmbeds(t *testing.T) {
		tests := []struct {
			name   string
			embeds []string
			files  []string
		}{
			{"File: replace README.md  with doc.go", []string{"README.md"}, []string{"doc.go"}},
			{"File: add README.md with doc.go ", []string{"doc.go"}, []string{"README.md", "doc.go"}},
			{"File: remove README.md and doc.go", []string{"README.md", "doc.go"}, nil},
			{"File: add README.md and doc.go", nil, []string{"README.md", "doc.go"}},
		}
		m := NewMsg()
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				sort.Strings(tt.embeds)
				sort.Strings(tt.files)
				for _, a := range tt.embeds {
					m.EmbedFile(a, WithFileName(a), nil)
				}
				if len(m.embeds) != len(tt.embeds) {
					t.Errorf("EmbedFile() failed. Number of embedded files expected: %d, got: %d", len(tt.files),
						len(m.embeds))
					return
				}
				var files []*File
				for _, f := range tt.files {
					files = append(files, &File{Name: f})
				}
				m.SetEmbeds(files)
				if len(m.embeds) != len(files) {
					t.Errorf("SetEmbeds() failed. Number of embedded files expected: %d, got: %d", len(files),
						len(m.embeds))
					return
				}
				for i, f := range tt.files {
					if f != m.embeds[i].Name {
						t.Errorf("SetEmbeds() failed. Embedded file name expected: %s, got: %s", f,
							m.embeds[i].Name)
						return
					}
				}
				m.Reset()
			})
		}
	}

// TestMsg_UnsetAllEmbeds tests the Msg.TestMsg_UnsetAllEmbeds method

	func TestMsg_UnsetAllEmbeds(t *testing.T) {
		tests := []struct {
			name   string
			embeds []string
		}{
			{"File: one file", []string{"README.md"}},
			{"File: two files", []string{"README.md", "doc.go"}},
			{"File: nil", nil},
		}
		m := NewMsg()
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var files []*File
				for _, f := range tt.embeds {
					files = append(files, &File{Name: f})
				}
				m.SetEmbeds(files)
				if len(m.embeds) != len(files) {
					t.Errorf("SetEmbeds() failed. Number of embedded files expected: %d, got: %d", len(files),
						len(m.embeds))
					return
				}
				m.UnsetAllEmbeds()
				if m.embeds != nil {
					t.Errorf("UnsetAllEmbeds() failed. The embeds file's point is not nil")
					return
				}
				m.Reset()
			})
		}
	}

// TestMsg_UnsetAllParts tests the Msg.TestMsg_UnsetAllParts method

	func TestMsg_UnsetAllParts(t *testing.T) {
		tests := []struct {
			name        string
			attachments []string
			embeds      []string
		}{
			{"File: both is exist", []string{"README.md"}, []string{"doc.go"}},
			{"File: both is nil", nil, nil},
			{"File: attachment exist, embed nil", []string{"README.md"}, nil},
			{"File: attachment nil, embed exist", nil, []string{"README.md"}},
		}
		m := NewMsg()
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var attachments []*File
				for _, f := range tt.attachments {
					attachments = append(attachments, &File{Name: f})
				}
				m.SetAttachments(attachments)
				if len(m.attachments) != len(attachments) {
					t.Errorf("SetAttachements() failed. Number of attachments files expected: %d, got: %d",
						len(attachments), len(m.attachments))
					return
				}
				var embeds []*File
				for _, f := range tt.embeds {
					embeds = append(embeds, &File{Name: f})
				}
				m.SetEmbeds(embeds)
				if len(m.embeds) != len(embeds) {
					t.Errorf("SetEmbeds() failed. Number of embedded files expected: %d, got: %d", len(embeds),
						len(m.embeds))
					return
				}
				m.UnsetAllParts()
				if m.attachments != nil {
					t.Errorf("UnsetAllParts() failed. The attachments file's point is not nil")
					return
				}
				if m.embeds != nil {
					t.Errorf("UnsetAllParts() failed. The embeds file's point is not nil")
					return
				}
				m.Reset()
			})
		}
	}

// TestMsg_AttachFromEmbedFS tests the Msg.AttachFromEmbedFS and the WithFilename FileOption method

	func TestMsg_AttachFromEmbedFS(t *testing.T) {
		tests := []struct {
			name string
			file string
			fn   string
			sf   bool
		}{
			{"File: README.md", "README.md", "README.md", false},
			{"File: nonexisting", "", "invalid.file", true},
		}
		m := NewMsg()
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if err := m.AttachFromEmbedFS(tt.file, &efs, WithFileName(tt.fn)); err != nil && !tt.sf {
					t.Errorf("AttachFromEmbedFS() failed: %s", err)
					return
				}
				if len(m.attachments) != 1 && !tt.sf {
					t.Errorf("AttachFile() failed. Number of attachments expected: %d, got: %d", 1,
						len(m.attachments))
					return
				}
				if !tt.sf {
					file := m.attachments[0]
					if file == nil {
						t.Errorf("AttachFile() failed. Attachment file pointer is nil")
						return
					}
					if file.Name != tt.fn {
						t.Errorf("AttachFile() failed. Filename of attachment expected: %s, got: %s", tt.fn,
							file.Name)
					}
					buf := bytes.Buffer{}
					if _, err := file.Writer(&buf); err != nil {
						t.Errorf("failed to execute WriterFunc: %s", err)
						return
					}
				}
				m.Reset()
			})
		}
	}

// TestMsg_AttachFileBrokenFunc tests WriterFunc of the Msg.AttachFile  method

	func TestMsg_AttachFileBrokenFunc(t *testing.T) {
		m := NewMsg()
		m.AttachFile("README.md")
		if len(m.attachments) != 1 {
			t.Errorf("AttachFile() failed. Number of attachments expected: %d, got: %d", 1,
				len(m.attachments))
			return
		}
		file := m.attachments[0]
		if file == nil {
			t.Errorf("AttachFile() failed. Attachment file pointer is nil")
			return
		}
		file.Writer = func(io.Writer) (int64, error) {
			return 0, fmt.Errorf("failing intentionally")
		}
		buf := bytes.Buffer{}
		if _, err := file.Writer(&buf); err == nil {
			t.Errorf("execute WriterFunc did not fail, but was expected to fail")
		}
	}

// TestMsg_AttachReader tests the Msg.AttachReader method

	func TestMsg_AttachReader(t *testing.T) {
		m := NewMsg()
		ts := "This is a test string"
		rbuf := bytes.Buffer{}
		rbuf.WriteString(ts)
		r := bufio.NewReader(&rbuf)
		if err := m.AttachReader("testfile.txt", r); err != nil {
			t.Errorf("AttachReader() failed. Expected no error, got: %s", err.Error())
			return
		}
		if len(m.attachments) != 1 {
			t.Errorf("AttachReader() failed. Number of attachments expected: %d, got: %d", 1,
				len(m.attachments))
			return
		}
		file := m.attachments[0]
		if file == nil {
			t.Errorf("AttachReader() failed. Attachment file pointer is nil")
			return
		}
		if file.Name != "testfile.txt" {
			t.Errorf("AttachReader() failed. Expected file name: %s, got: %s", "testfile.txt",
				file.Name)
		}
		wbuf := bytes.Buffer{}
		if _, err := file.Writer(&wbuf); err != nil {
			t.Errorf("execute WriterFunc failed: %s", err)
		}
		if wbuf.String() != ts {
			t.Errorf("AttachReader() failed. Expected string: %q, got: %q", ts, wbuf.String())
		}
	}

// TestMsg_EmbedFile tests the Msg.EmbedFile and the WithFilename FileOption method

	func TestMsg_EmbedFile(t *testing.T) {
		tests := []struct {
			name string
			file string
			fn   string
			sf   bool
		}{
			{"File: README.md", "README.md", "README.md", false},
			{"File: doc.go", "doc.go", "foo.go", false},
			{"File: nonexisting", "", "invalid.file", true},
		}
		m := NewMsg()
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				m.EmbedFile(tt.file, WithFileName(tt.fn), nil)
				if len(m.embeds) != 1 && !tt.sf {
					t.Errorf("EmbedFile() failed. Number of embeds expected: %d, got: %d", 1,
						len(m.embeds))
					return
				}
				if !tt.sf {
					file := m.embeds[0]
					if file == nil {
						t.Errorf("EmbedFile() failed. Embedded file pointer is nil")
						return
					}
					if file.Name != tt.fn {
						t.Errorf("EmbedFile() failed. Filename of embeds expected: %s, got: %s", tt.fn,
							file.Name)
					}
					buf := bytes.Buffer{}
					if _, err := file.Writer(&buf); err != nil {
						t.Errorf("failed to execute WriterFunc: %s", err)
						return
					}
				}
				m.Reset()
			})
		}
	}

// TestMsg_EmbedFromEmbedFS tests the Msg.EmbedFromEmbedFS and the WithFilename FileOption method

	func TestMsg_EmbedFromEmbedFS(t *testing.T) {
		tests := []struct {
			name string
			file string
			fn   string
			sf   bool
		}{
			{"File: README.md", "README.md", "README.md", false},
			{"File: nonexisting", "", "invalid.file", true},
		}
		m := NewMsg()
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if err := m.EmbedFromEmbedFS(tt.file, &efs, WithFileName(tt.fn)); err != nil && !tt.sf {
					t.Errorf("EmbedFromEmbedFS() failed: %s", err)
					return
				}
				if len(m.embeds) != 1 && !tt.sf {
					t.Errorf("EmbedFile() failed. Number of embeds expected: %d, got: %d", 1,
						len(m.embeds))
					return
				}
				if !tt.sf {
					file := m.embeds[0]
					if file == nil {
						t.Errorf("EmbedFile() failed. Embedded file pointer is nil")
						return
					}
					if file.Name != tt.fn {
						t.Errorf("EmbedFile() failed. Filename of embeds expected: %s, got: %s", tt.fn,
							file.Name)
					}
					buf := bytes.Buffer{}
					if _, err := file.Writer(&buf); err != nil {
						t.Errorf("failed to execute WriterFunc: %s", err)
						return
					}
				}
				m.Reset()
			})
		}
	}

// TestMsg_EmbedFileBrokenFunc tests WriterFunc of the Msg.EmbedFile  method

	func TestMsg_EmbedFileBrokenFunc(t *testing.T) {
		m := NewMsg()
		m.EmbedFile("README.md")
		if len(m.embeds) != 1 {
			t.Errorf("EmbedFile() failed. Number of embeds expected: %d, got: %d", 1,
				len(m.embeds))
			return
		}
		file := m.embeds[0]
		if file == nil {
			t.Errorf("EmbedFile() failed. Embedded file pointer is nil")
			return
		}
		file.Writer = func(io.Writer) (int64, error) {
			return 0, fmt.Errorf("failing intentionally")
		}
		buf := bytes.Buffer{}
		if _, err := file.Writer(&buf); err == nil {
			t.Errorf("execute WriterFunc did not fail, but was expected to fail")
		}
	}

// TestMsg_EmbedReader tests the Msg.EmbedReader method

	func TestMsg_EmbedReader(t *testing.T) {
		m := NewMsg()
		ts := "This is a test string"
		rbuf := bytes.Buffer{}
		rbuf.WriteString(ts)
		r := bufio.NewReader(&rbuf)
		if err := m.EmbedReader("testfile.txt", r); err != nil {
			t.Errorf("EmbedReader() failed. Expected no error, got: %s", err.Error())
			return
		}
		if len(m.embeds) != 1 {
			t.Errorf("EmbedReader() failed. Number of embeds expected: %d, got: %d", 1,
				len(m.embeds))
			return
		}
		file := m.embeds[0]
		if file == nil {
			t.Errorf("EmbedReader() failed. Embedded file pointer is nil")
			return
		}
		if file.Name != "testfile.txt" {
			t.Errorf("EmbedReader() failed. Expected file name: %s, got: %s", "testfile.txt",
				file.Name)
		}
		wbuf := bytes.Buffer{}
		if _, err := file.Writer(&wbuf); err != nil {
			t.Errorf("execute WriterFunc failed: %s", err)
		}
		if wbuf.String() != ts {
			t.Errorf("EmbedReader() failed. Expected string: %q, got: %q", ts, wbuf.String())
		}
	}

// TestMsg_hasAlt tests the hasAlt() method of the Msg

	func TestMsg_hasAlt(t *testing.T) {
		m := NewMsg()
		m.SetBodyString(TypeTextPlain, "Plain")
		m.AddAlternativeString(TypeTextHTML, "<b>HTML</b>")
		if !m.hasAlt() {
			t.Errorf("mail has alternative parts but hasAlt() returned true")
		}
	}

// TestMsg_hasRelated tests the hasRelated() method of the Msg

	func TestMsg_hasRelated(t *testing.T) {
		m := NewMsg()
		m.SetBodyString(TypeTextPlain, "Plain")
		m.EmbedFile("README.md")
		if !m.hasRelated() {
			t.Errorf("mail has related parts but hasRelated() returned true")
		}
	}

// TestMsg_hasMixed tests the hasMixed() method of the Msg

	func TestMsg_hasMixed(t *testing.T) {
		m := NewMsg()
		m.SetBodyString(TypeTextPlain, "Plain")
		m.AttachFile("README.md")
		if !m.hasMixed() {
			t.Errorf("mail has mixed parts but hasMixed() returned true")
		}
	}

// TestMsg_WriteTo tests the WriteTo() method of the Msg

	func TestMsg_WriteTo(t *testing.T) {
		m := NewMsg()
		m.SetBodyString(TypeTextPlain, "Plain")
		wbuf := bytes.Buffer{}
		n, err := m.WriteTo(&wbuf)
		if err != nil {
			t.Errorf("WriteTo() failed: %s", err)
			return
		}
		if n != int64(wbuf.Len()) {
			t.Errorf("WriteTo() failed: expected written byte length: %d, got: %d", n, wbuf.Len())
		}
	}

// TestMsg_WriteToSkipMiddleware tests the WriteTo() method of the Msg

	func TestMsg_WriteToSkipMiddleware(t *testing.T) {
		m := NewMsg(WithMiddleware(encodeMiddleware{}), WithMiddleware(uppercaseMiddleware{}))
		m.Subject("This is a test")
		m.SetBodyString(TypeTextPlain, "Plain")
		wbuf := bytes.Buffer{}
		n, err := m.WriteToSkipMiddleware(&wbuf, "uppercase")
		if err != nil {
			t.Errorf("WriteToSkipMiddleware() failed: %s", err)
			return
		}
		if n != int64(wbuf.Len()) {
			t.Errorf("WriteToSkipMiddleware() failed: expected written byte length: %d, got: %d", n, wbuf.Len())
		}
		if !strings.Contains(wbuf.String(), "Subject: This is @ test") {
			t.Errorf("WriteToSkipMiddleware failed. Unable to find encoded subject")
		}

		wbuf2 := bytes.Buffer{}
		n, err = m.WriteTo(&wbuf2)
		if err != nil {
			t.Errorf("WriteTo() failed: %s", err)
			return
		}
		if n != int64(wbuf2.Len()) {
			t.Errorf("WriteTo() failed: expected written byte length: %d, got: %d", n, wbuf2.Len())
		}
		if !strings.Contains(wbuf2.String(), "Subject: THIS IS @ TEST") {
			t.Errorf("WriteToSkipMiddleware failed. Unable to find encoded and upperchase subject")
		}
	}

// TestMsg_WriteTo_fails tests the WriteTo() method of the Msg but with a failing body writer function

	func TestMsg_WriteTo_fails(t *testing.T) {
		m := NewMsg()
		m.SetBodyWriter(TypeTextPlain, func(io.Writer) (int64, error) {
			return 0, errors.New("failed")
		})
		_, err := m.WriteTo(io.Discard)
		if err == nil {
			t.Errorf("WriteTo() with failing BodyWriter function was supposed to fail, but didn't")
			return
		}

		// NoEncoding handles the errors separately
		m = NewMsg(WithEncoding(NoEncoding))
		m.SetBodyWriter(TypeTextPlain, func(io.Writer) (int64, error) {
			return 0, errors.New("failed")
		})
		_, err = m.WriteTo(io.Discard)
		if err == nil {
			t.Errorf("WriteTo() (no encoding) with failing BodyWriter function was supposed to fail, but didn't")
			return
		}
	}

// TestMsg_Write tests the Write() method of the Msg

	func TestMsg_Write(t *testing.T) {
		m := NewMsg()
		m.SetBodyString(TypeTextPlain, "Plain")
		wbuf := bytes.Buffer{}
		n, err := m.Write(&wbuf)
		if err != nil {
			t.Errorf("WriteTo() failed: %s", err)
			return
		}
		if n != int64(wbuf.Len()) {
			t.Errorf("WriteTo() failed: expected written byte length: %d, got: %d", n, wbuf.Len())
		}
	}

// TestMsg_WriteWithLongHeader tests the WriteTo() method of the Msg with a long header

	func TestMsg_WriteWithLongHeader(t *testing.T) {
		m := NewMsg()
		m.SetBodyString(TypeTextPlain, "Plain")
		m.SetGenHeader(HeaderContentLang, "de", "en", "fr", "es", "xxxx", "yyyy", "de", "en", "fr",
			"es", "xxxx", "yyyy", "de", "en", "fr", "es", "xxxx", "yyyy", "de", "en", "fr")
		m.SetGenHeader(HeaderContentID, "XXXXXXXXXXXXXXX XXXXXXXXXXXXXXX XXXXXXXXXXXXXXXXXX XXXXXXXXXXXXXXXXXXXXXX",
			"XXXXXXXXXXXXX XXXXXXXXXXXXXXXXXXX XXXXXXXXXXXXXXXXXXX XXXXXXXXXXXXXXXXXXXXXXXXXXX")
		wbuf := bytes.Buffer{}
		n, err := m.WriteTo(&wbuf)
		if err != nil {
			t.Errorf("WriteTo() failed: %s", err)
			return
		}
		if n != int64(wbuf.Len()) {
			t.Errorf("WriteTo() failed: expected written byte length: %d, got: %d", n, wbuf.Len())
		}
	}

// TestMsg_WriteDiffEncoding tests the WriteTo() method of the Msg with different Encoding

	func TestMsg_WriteDiffEncoding(t *testing.T) {
		tests := []struct {
			name string
			ct   ContentType
			en   Encoding
			alt  bool
			wa   bool
			we   bool
		}{
			{"Plain/QP/NoAlt/NoAttach/NoEmbed", TypeTextPlain, EncodingQP, false, false, false},
			{"Plain/B64/NoAlt/NoAttach/NoEmbed", TypeTextPlain, EncodingB64, false, false, false},
			{"Plain/No/NoAlt/NoAttach/NoEmbed", TypeTextPlain, NoEncoding, false, false, false},
			{"HTML/QP/NoAlt/NoAttach/NoEmbed", TypeTextHTML, EncodingQP, false, false, false},
			{"HTML/B64/NoAlt/NoAttach/NoEmbed", TypeTextHTML, EncodingB64, false, false, false},
			{"HTML/No/NoAlt/NoAttach/NoEmbed", TypeTextHTML, NoEncoding, false, false, false},
			{"Plain/QP/HTML/NoAttach/NoEmbed", TypeTextPlain, EncodingQP, true, false, false},
			{"Plain/B64/HTML/NoAttach/NoEmbed", TypeTextPlain, EncodingB64, true, false, false},
			{"Plain/No/HTML/NoAttach/NoEmbed", TypeTextPlain, NoEncoding, true, false, false},
			{"Plain/QP/NoAlt/Attach/NoEmbed", TypeTextPlain, EncodingQP, false, true, false},
			{"Plain/B64/NoAlt/Attach/NoEmbed", TypeTextPlain, EncodingB64, false, true, false},
			{"Plain/No/NoAlt/Attach/NoEmbed", TypeTextPlain, NoEncoding, false, true, false},
			{"Plain/QP/NoAlt/NoAttach/Embed", TypeTextPlain, EncodingQP, false, false, true},
			{"Plain/B64/NoAlt/NoAttach/Embed", TypeTextPlain, EncodingB64, false, false, true},
			{"Plain/No/NoAlt/NoAttach/Embed", TypeTextPlain, NoEncoding, false, false, true},
			{"Plain/QP/HTML/Attach/Embed", TypeTextPlain, EncodingQP, true, true, true},
			{"Plain/B64/HTML/Attach/Embed", TypeTextPlain, EncodingB64, true, true, true},
			{"Plain/No/HTML/Attach/Embed", TypeTextPlain, NoEncoding, true, true, true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				m := NewMsg(WithEncoding(tt.en))
				m.SetBodyString(tt.ct, tt.name)
				if tt.alt {
					m.AddAlternativeString(TypeTextHTML, fmt.Sprintf("<p>%s</p>", tt.name))
				}
				if tt.wa {
					m.AttachFile("README.md")
				}
				if tt.we {
					m.EmbedFile("README.md")
				}
				wbuf := bytes.Buffer{}
				n, err := m.WriteTo(&wbuf)
				if err != nil {
					t.Errorf("WriteTo() failed: %s", err)
					return
				}
				if n != int64(wbuf.Len()) {
					t.Errorf("WriteTo() failed: expected written byte length: %d, got: %d", n, wbuf.Len())
				}
				wbuf.Reset()
			})
		}
	}

// TestMsg_appendFile tests the appendFile() method of the Msg

	func TestMsg_appendFile(t *testing.T) {
		m := NewMsg()
		var fl []*File
		f := &File{
			Name: "file.txt",
		}
		fl = m.appendFile(fl, f, nil)
		if len(fl) != 1 {
			t.Errorf("appendFile() failed. Expected length: %d, got: %d", 1, len(fl))
		}
		fl = m.appendFile(fl, f, nil)
		if len(fl) != 2 {
			t.Errorf("appendFile() failed. Expected length: %d, got: %d", 2, len(fl))
		}
	}

// TestMsg_multipleWrites tests multiple executions of WriteTo on the Msg

	func TestMsg_multipleWrites(t *testing.T) {
		ts := "XXX_UNIQUE_STRING_XXX"
		wbuf := bytes.Buffer{}
		m := NewMsg()
		m.SetBodyString(TypeTextPlain, ts)

		// First WriteTo()
		_, err := m.WriteTo(&wbuf)
		if err != nil {
			t.Errorf("failed to write body to buffer: %s", err)
		}
		if !strings.Contains(wbuf.String(), ts) {
			t.Errorf("first WriteTo() body does not contain unique string: %s", ts)
		}

		// Second WriteTo()
		wbuf.Reset()
		_, err = m.WriteTo(&wbuf)
		if err != nil {
			t.Errorf("failed to write body to buffer: %s", err)
		}
		if !strings.Contains(wbuf.String(), ts) {
			t.Errorf("second WriteTo() body does not contain unique string: %s", ts)
		}
	}

// TestMsg_NewReader tests the Msg.NewReader method

	func TestMsg_NewReader(t *testing.T) {
		m := NewMsg()
		m.SetBodyString(TypeTextPlain, "TEST123")
		mr := m.NewReader()
		if mr == nil {
			t.Errorf("NewReader failed: Reader is nil")
		}
		if mr.Error() != nil {
			t.Errorf("NewReader failed: %s", mr.Error())
		}
	}

// TestMsg_NewReader_ioCopy tests the Msg.NewReader method using io.Copy

	func TestMsg_NewReader_ioCopy(t *testing.T) {
		wbuf1 := bytes.Buffer{}
		wbuf2 := bytes.Buffer{}
		m := NewMsg()
		m.SetBodyString(TypeTextPlain, "TEST123")
		mr := m.NewReader()
		if mr == nil {
			t.Errorf("NewReader failed: Reader is nil")
		}

		// First we use WriteTo to have something to compare to
		_, err := m.WriteTo(&wbuf1)
		if err != nil {
			t.Errorf("failed to write body to buffer: %s", err)
		}

		// Then we write to wbuf2 via io.Copy
		n, err := io.Copy(&wbuf2, mr)
		if err != nil {
			t.Errorf("failed to use io.Copy on Reader: %s", err)
		}
		if n != int64(wbuf1.Len()) {
			t.Errorf("message length of WriteTo and io.Copy differ. Expected: %d, got: %d", wbuf1.Len(), n)
		}
		if wbuf1.String() != wbuf2.String() {
			t.Errorf("message content of WriteTo and io.Copy differ")
		}
	}

// TestMsg_UpdateReader tests the Msg.UpdateReader method

	func TestMsg_UpdateReader(t *testing.T) {
		m := NewMsg()
		m.Subject("Subject-Run 1")
		mr := m.NewReader()
		if mr == nil {
			t.Errorf("NewReader failed: Reader is nil")
		}
		wbuf1 := bytes.Buffer{}
		_, err := io.Copy(&wbuf1, mr)
		if err != nil {
			t.Errorf("io.Copy on Reader failed: %s", err)
		}
		if !strings.Contains(wbuf1.String(), "Subject: Subject-Run 1") {
			t.Errorf("io.Copy on Reader failed. Expected to find %q but string in Subject was not found",
				"Subject-Run 1")
		}

		m.Subject("Subject-Run 2")
		m.UpdateReader(mr)
		wbuf2 := bytes.Buffer{}
		_, err = io.Copy(&wbuf2, mr)
		if err != nil {
			t.Errorf("2nd io.Copy on Reader failed: %s", err)
		}
		if !strings.Contains(wbuf2.String(), "Subject: Subject-Run 2") {
			t.Errorf("io.Copy on Reader failed. Expected to find %q but string in Subject was not found",
				"Subject-Run 2")
		}
	}

// TestMsg_SetBodyTextTemplate tests the Msg.SetBodyTextTemplate method

	func TestMsg_SetBodyTextTemplate(t *testing.T) {
		tests := []struct {
			name string
			tpl  string
			ph   string
			sf   bool
		}{
			{"normal text", "This is a {{.Placeholder}}", "TemplateTest", false},
			{"invalid tpl", "This is a {{ foo .Placeholder}}", "TemplateTest", true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				data := struct {
					Placeholder string
				}{Placeholder: tt.ph}
				tpl, err := ttpl.New("test").Parse(tt.tpl)
				if err != nil && !tt.sf {
					t.Errorf("failed to render template: %s", err)
					return
				}
				m := NewMsg()
				if err := m.SetBodyTextTemplate(tpl, data); err != nil && !tt.sf {
					t.Errorf("failed to set template as body: %s", err)
				}

				wbuf := bytes.Buffer{}
				_, err = m.WriteTo(&wbuf)
				if err != nil {
					t.Errorf("failed to write body to buffer: %s", err)
				}
				if !strings.Contains(wbuf.String(), tt.ph) && !tt.sf {
					t.Errorf("SetBodyTextTemplate failed: Body does not contain the expected tpl placeholder: %s", tt.ph)
				}
				m.Reset()
			})
		}
	}

// TestMsg_SetBodyHTMLTemplate tests the Msg.SetBodyHTMLTemplate method

	func TestMsg_SetBodyHTMLTemplate(t *testing.T) {
		tests := []struct {
			name string
			tpl  string
			ph   string
			ex   string
			sf   bool
		}{
			{"normal HTML", "<p>This is a {{.Placeholder}}</p>", "TemplateTest", "TemplateTest", false},
			{
				"HTML with HTML", "<p>This is a {{.Placeholder}}</p>", "<script>alert(1)</script>",
				"&lt;script&gt;alert(1)&lt;/script&gt;", false,
			},
			{"invalid tpl", "<p>This is a {{ foo .Placeholder}}</p>", "TemplateTest", "", true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				data := struct {
					Placeholder string
				}{Placeholder: tt.ph}
				tpl, err := htpl.New("test").Parse(tt.tpl)
				if err != nil && !tt.sf {
					t.Errorf("failed to render template: %s", err)
					return
				}
				m := NewMsg()
				if err := m.SetBodyHTMLTemplate(tpl, data); err != nil && !tt.sf {
					t.Errorf("failed to set template as body: %s", err)
				}

				wbuf := bytes.Buffer{}
				_, err = m.WriteTo(&wbuf)
				if err != nil {
					t.Errorf("failed to write body to buffer: %s", err)
				}
				if !strings.Contains(wbuf.String(), tt.ex) && !tt.sf {
					t.Errorf("SetBodyTextTemplate failed: Body does not contain the expected tpl placeholder: %s", tt.ph)
				}
				m.Reset()
			})
		}
	}

// TestMsg_AddAlternativeTextTemplate tests the Msg.AddAlternativeTextTemplate method

	func TestMsg_AddAlternativeTextTemplate(t *testing.T) {
		tests := []struct {
			name string
			tpl  string
			ph   string
			sf   bool
		}{
			{"normal text", "This is a {{.Placeholder}}", "TemplateTest", false},
			{"invalid tpl", "This is a {{ foo .Placeholder}}", "TemplateTest", true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				data := struct {
					Placeholder string
				}{Placeholder: tt.ph}
				tpl, err := ttpl.New("test").Parse(tt.tpl)
				if err != nil && !tt.sf {
					t.Errorf("failed to render template: %s", err)
					return
				}
				m := NewMsg()
				m.SetBodyString(TypeTextHTML, "")
				if err := m.AddAlternativeTextTemplate(tpl, data); err != nil && !tt.sf {
					t.Errorf("failed to set template as alternative part: %s", err)
				}

				wbuf := bytes.Buffer{}
				_, err = m.WriteTo(&wbuf)
				if err != nil {
					t.Errorf("failed to write body to buffer: %s", err)
				}
				if !strings.Contains(wbuf.String(), tt.ph) && !tt.sf {
					t.Errorf("SetBodyTextTemplate failed: Body does not contain the expected tpl placeholder: %s", tt.ph)
				}
				m.Reset()
			})
		}
	}

// TestMsg_AddAlternativeHTMLTemplate tests the Msg.AddAlternativeHTMLTemplate method

	func TestMsg_AddAlternativeHTMLTemplate(t *testing.T) {
		tests := []struct {
			name string
			tpl  string
			ph   string
			ex   string
			sf   bool
		}{
			{"normal HTML", "<p>This is a {{.Placeholder}}</p>", "TemplateTest", "TemplateTest", false},
			{
				"HTML with HTML", "<p>This is a {{.Placeholder}}</p>", "<script>alert(1)</script>",
				"&lt;script&gt;alert(1)&lt;/script&gt;", false,
			},
			{"invalid tpl", "<p>This is a {{ foo .Placeholder}}</p>", "TemplateTest", "", true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				data := struct {
					Placeholder string
				}{Placeholder: tt.ph}
				tpl, err := htpl.New("test").Parse(tt.tpl)
				if err != nil && !tt.sf {
					t.Errorf("failed to render template: %s", err)
					return
				}
				m := NewMsg()
				m.SetBodyString(TypeTextPlain, "")
				if err := m.AddAlternativeHTMLTemplate(tpl, data); err != nil && !tt.sf {
					t.Errorf("failed to set template as alternative part: %s", err)
				}

				wbuf := bytes.Buffer{}
				_, err = m.WriteTo(&wbuf)
				if err != nil {
					t.Errorf("failed to write body to buffer: %s", err)
				}
				if !strings.Contains(wbuf.String(), tt.ex) && !tt.sf {
					t.Errorf("SetBodyTextTemplate failed: Body does not contain the expected tpl placeholder: %s", tt.ph)
				}
				m.Reset()
			})
		}
	}

// TestMsg_AttachTextTemplate tests the Msg.AttachTextTemplate method

	func TestMsg_AttachTextTemplate(t *testing.T) {
		tests := []struct {
			name string
			tpl  string
			ph   string
			ex   string
			ac   int
			sf   bool
		}{
			{
				"normal text", "This is a {{.Placeholder}}", "TemplateTest",
				"VGhpcyBpcyBhIFRlbXBsYXRlVGVzdA==", 1, false,
			},
			{"invalid tpl", "This is a {{ foo .Placeholder}}", "TemplateTest", "", 0, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				data := struct {
					Placeholder string
				}{Placeholder: tt.ph}
				tpl, err := ttpl.New("test").Parse(tt.tpl)
				if err != nil && !tt.sf {
					t.Errorf("failed to render template: %s", err)
					return
				}
				m := NewMsg()
				m.SetBodyString(TypeTextPlain, "This is the body")
				if err := m.AttachTextTemplate("attachment.txt", tpl, data); err != nil && !tt.sf {
					t.Errorf("failed to attach template: %s", err)
				}

				wbuf := bytes.Buffer{}
				_, err = m.WriteTo(&wbuf)
				if err != nil {
					t.Errorf("failed to write body to buffer: %s", err)
				}
				if !strings.Contains(wbuf.String(), tt.ex) && !tt.sf {
					t.Errorf("SetBodyTextTemplate failed: Body does not contain the expected tpl placeholder: %s", tt.ph)
				}
				if len(m.attachments) != tt.ac {
					t.Errorf("wrong number of attachments. Expected: %d, got: %d", tt.ac, len(m.attachments))
				}
				m.Reset()
			})
		}
	}

// TestMsg_AttachHTMLTemplate tests the Msg.AttachHTMLTemplate method

	func TestMsg_AttachHTMLTemplate(t *testing.T) {
		tests := []struct {
			name string
			tpl  string
			ph   string
			ex   string
			ac   int
			sf   bool
		}{
			{
				"normal HTML", "<p>This is a {{.Placeholder}}</p>", "TemplateTest",
				"PHA+VGhpcyBpcyBhIFRlbXBsYXRlVGVzdDwvcD4=", 1, false,
			},
			{
				"HTML with HTML", "<p>This is a {{.Placeholder}}</p>", "<script>alert(1)</script>",
				"PHA+VGhpcyBpcyBhICZsdDtzY3JpcHQmZ3Q7YWxlcnQoMSkmbHQ7L3NjcmlwdCZndDs8L3A+", 1, false,
			},
			{"invalid tpl", "<p>This is a {{ foo .Placeholder}}</p>", "TemplateTest", "", 0, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				data := struct {
					Placeholder string
				}{Placeholder: tt.ph}
				tpl, err := htpl.New("test").Parse(tt.tpl)
				if err != nil && !tt.sf {
					t.Errorf("failed to render template: %s", err)
					return
				}
				m := NewMsg()
				m.SetBodyString(TypeTextPlain, "")
				if err := m.AttachHTMLTemplate("attachment.html", tpl, data); err != nil && !tt.sf {
					t.Errorf("failed to set template as alternative part: %s", err)
				}

				wbuf := bytes.Buffer{}
				_, err = m.WriteTo(&wbuf)
				if err != nil {
					t.Errorf("failed to write body to buffer: %s", err)
				}
				if !strings.Contains(wbuf.String(), tt.ex) && !tt.sf {
					t.Errorf("SetBodyTextTemplate failed: Body does not contain the expected tpl placeholder: %s", tt.ph)
				}
				if len(m.attachments) != tt.ac {
					t.Errorf("wrong number of attachments. Expected: %d, got: %d", tt.ac, len(m.attachments))
				}
				m.Reset()
			})
		}
	}

// TestMsg_EmbedTextTemplate tests the Msg.EmbedTextTemplate method

	func TestMsg_EmbedTextTemplate(t *testing.T) {
		tests := []struct {
			name string
			tpl  string
			ph   string
			ex   string
			ec   int
			sf   bool
		}{
			{
				"normal text", "This is a {{.Placeholder}}", "TemplateTest",
				"VGhpcyBpcyBhIFRlbXBsYXRlVGVzdA==", 1, false,
			},
			{"invalid tpl", "This is a {{ foo .Placeholder}}", "TemplateTest", "", 0, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				data := struct {
					Placeholder string
				}{Placeholder: tt.ph}
				tpl, err := ttpl.New("test").Parse(tt.tpl)
				if err != nil && !tt.sf {
					t.Errorf("failed to render template: %s", err)
					return
				}
				m := NewMsg()
				m.SetBodyString(TypeTextPlain, "This is the body")
				if err := m.EmbedTextTemplate("attachment.txt", tpl, data); err != nil && !tt.sf {
					t.Errorf("failed to attach template: %s", err)
				}

				wbuf := bytes.Buffer{}
				_, err = m.WriteTo(&wbuf)
				if err != nil {
					t.Errorf("failed to write body to buffer: %s", err)
				}
				if !strings.Contains(wbuf.String(), tt.ex) && !tt.sf {
					t.Errorf("SetBodyTextTemplate failed: Body does not contain the expected tpl placeholder: %s", tt.ph)
				}
				if len(m.embeds) != tt.ec {
					t.Errorf("wrong number of attachments. Expected: %d, got: %d", tt.ec, len(m.attachments))
				}
				m.Reset()
			})
		}
	}

// TestMsg_EmbedHTMLTemplate tests the Msg.EmbedHTMLTemplate method

	func TestMsg_EmbedHTMLTemplate(t *testing.T) {
		tests := []struct {
			name string
			tpl  string
			ph   string
			ex   string
			ec   int
			sf   bool
		}{
			{
				"normal HTML", "<p>This is a {{.Placeholder}}</p>", "TemplateTest",
				"PHA+VGhpcyBpcyBhIFRlbXBsYXRlVGVzdDwvcD4=", 1, false,
			},
			{
				"HTML with HTML", "<p>This is a {{.Placeholder}}</p>", "<script>alert(1)</script>",
				"PHA+VGhpcyBpcyBhICZsdDtzY3JpcHQmZ3Q7YWxlcnQoMSkmbHQ7L3NjcmlwdCZndDs8L3A+", 1, false,
			},
			{"invalid tpl", "<p>This is a {{ foo .Placeholder}}</p>", "TemplateTest", "", 0, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				data := struct {
					Placeholder string
				}{Placeholder: tt.ph}
				tpl, err := htpl.New("test").Parse(tt.tpl)
				if err != nil && !tt.sf {
					t.Errorf("failed to render template: %s", err)
					return
				}
				m := NewMsg()
				m.SetBodyString(TypeTextPlain, "")
				if err := m.EmbedHTMLTemplate("attachment.html", tpl, data); err != nil && !tt.sf {
					t.Errorf("failed to set template as alternative part: %s", err)
				}

				wbuf := bytes.Buffer{}
				_, err = m.WriteTo(&wbuf)
				if err != nil {
					t.Errorf("failed to write body to buffer: %s", err)
				}
				if !strings.Contains(wbuf.String(), tt.ex) && !tt.sf {
					t.Errorf("SetBodyTextTemplate failed: Body does not contain the expected tpl placeholder: %s", tt.ph)
				}
				if len(m.embeds) != tt.ec {
					t.Errorf("wrong number of attachments. Expected: %d, got: %d", tt.ec, len(m.attachments))
				}
				m.Reset()
			})
		}
	}

// TestMsg_WriteToTempFile will test the output to temporary files

	func TestMsg_WriteToTempFile(t *testing.T) {
		m := NewMsg()
		_ = m.From("Toni Tester <tester@example.com>")
		_ = m.To("Ellenor Tester <ellinor@example.com>")
		m.SetBodyString(TypeTextPlain, "This is a test")
		f, err := m.WriteToTempFile()
		if err != nil {
			t.Errorf("failed to write message to temporary output file: %s", err)
		}
		_ = os.Remove(f)
	}

// TestMsg_WriteToFile will test the output to a file

	func TestMsg_WriteToFile(t *testing.T) {
		f, err := os.CreateTemp("", "go-mail-test_*.eml")
		if err != nil {
			t.Errorf("failed to create temporary output file: %s", err)
		}
		defer func() {
			_ = f.Close()
			_ = os.Remove(f.Name())
		}()

		m := NewMsg()
		_ = m.From("Toni Tester <tester@example.com>")
		_ = m.To("Ellenor Tester <ellinor@example.com>")
		m.SetBodyString(TypeTextPlain, "This is a test")
		if err := m.WriteToFile(f.Name()); err != nil {
			t.Errorf("failed to write to output file: %s", err)
		}
		fi, err := os.Stat(f.Name())
		if err != nil {
			t.Errorf("failed to stat output file: %s", err)
		}
		if fi == nil {
			t.Errorf("received empty file handle")
			return
		}
		if fi.Size() <= 0 {
			t.Errorf("output file is expected to contain data but its size is zero")
		}
	}

// TestMsg_GetGenHeader will test the GetGenHeader method of the Msg

	func TestMsg_GetGenHeader(t *testing.T) {
		m := NewMsg()
		m.Subject("this is a test")
		sa := m.GetGenHeader(HeaderSubject)
		if len(sa) <= 0 {
			t.Errorf("GetGenHeader on subject failed. Got empty slice")
			return
		}
		if sa[0] == "" {
			t.Errorf("GetGenHeader on subject failed. Got empty value")
		}
		if sa[0] != "this is a test" {
			t.Errorf("GetGenHeader on subject failed. Expected: %q, got: %q", "this is a test", sa[0])
		}
	}

// TestMsg_GetAddrHeader will test the Msg.GetAddrHeader method

	func TestMsg_GetAddrHeader(t *testing.T) {
		m := NewMsg()
		if err := m.FromFormat("Toni Sender", "sender@example.com"); err != nil {
			t.Errorf("failed to set FROM address: %s", err)
		}
		if err := m.AddToFormat("Toni To", "to@example.com"); err != nil {
			t.Errorf("failed to set TO address: %s", err)
		}
		if err := m.AddCcFormat("Toni Cc", "cc@example.com"); err != nil {
			t.Errorf("failed to set CC address: %s", err)
		}
		if err := m.AddBccFormat("Toni Bcc", "bcc@example.com"); err != nil {
			t.Errorf("failed to set BCC address: %s", err)
		}
		fh := m.GetAddrHeader(HeaderFrom)
		if len(fh) <= 0 {
			t.Errorf("GetAddrHeader on FROM failed. Got empty slice")
			return
		}
		if fh[0].String() == "" {
			t.Errorf("GetAddrHeader on FROM failed. Got empty value")
		}
		if fh[0].String() != `"Toni Sender" <sender@example.com>` {
			t.Errorf("GetAddrHeader on FROM failed. Expected: %q, got: %q",
				`"Toni Sender" <sender@example.com>"`, fh[0].String())
		}
		th := m.GetAddrHeader(HeaderTo)
		if len(th) <= 0 {
			t.Errorf("GetAddrHeader on TO failed. Got empty slice")
			return
		}
		if th[0].String() == "" {
			t.Errorf("GetAddrHeader on TO failed. Got empty value")
		}
		if th[0].String() != `"Toni To" <to@example.com>` {
			t.Errorf("GetAddrHeader on TO failed. Expected: %q, got: %q",
				`"Toni To" <to@example.com>"`, th[0].String())
		}
		ch := m.GetAddrHeader(HeaderCc)
		if len(ch) <= 0 {
			t.Errorf("GetAddrHeader on CC failed. Got empty slice")
			return
		}
		if ch[0].String() == "" {
			t.Errorf("GetAddrHeader on CC failed. Got empty value")
		}
		if ch[0].String() != `"Toni Cc" <cc@example.com>` {
			t.Errorf("GetAddrHeader on CC failed. Expected: %q, got: %q",
				`"Toni Cc" <cc@example.com>"`, ch[0].String())
		}
		bh := m.GetAddrHeader(HeaderBcc)
		if len(bh) <= 0 {
			t.Errorf("GetAddrHeader on BCC failed. Got empty slice")
			return
		}
		if bh[0].String() == "" {
			t.Errorf("GetAddrHeader on BCC failed. Got empty value")
		}
		if bh[0].String() != `"Toni Bcc" <bcc@example.com>` {
			t.Errorf("GetAddrHeader on BCC failed. Expected: %q, got: %q",
				`"Toni Bcc" <bcc@example.com>"`, bh[0].String())
		}
	}

// TestMsg_GetFrom will test the Msg.GetFrom method

	func TestMsg_GetFrom(t *testing.T) {
		m := NewMsg()
		if err := m.FromFormat("Toni Sender", "sender@example.com"); err != nil {
			t.Errorf("failed to set FROM address: %s", err)
		}
		fh := m.GetFrom()
		if len(fh) <= 0 {
			t.Errorf("GetFrom failed. Got empty slice")
			return
		}
		if fh[0].String() == "" {
			t.Errorf("GetFrom failed. Got empty value")
		}
		if fh[0].String() != `"Toni Sender" <sender@example.com>` {
			t.Errorf("GetFrom failed. Expected: %q, got: %q",
				`"Toni Sender" <sender@example.com>"`, fh[0].String())
		}
	}

// TestMsg_GetFromString will test the Msg.GetFromString method

	func TestMsg_GetFromString(t *testing.T) {
		m := NewMsg()
		if err := m.FromFormat("Toni Sender", "sender@example.com"); err != nil {
			t.Errorf("failed to set FROM address: %s", err)
		}
		fh := m.GetFromString()
		if len(fh) <= 0 {
			t.Errorf("GetFromString failed. Got empty slice")
			return
		}
		if fh[0] == "" {
			t.Errorf("GetFromString failed. Got empty value")
		}
		if fh[0] != `"Toni Sender" <sender@example.com>` {
			t.Errorf("GetFromString failed. Expected: %q, got: %q",
				`"Toni Sender" <sender@example.com>"`, fh[0])
		}
	}

// TestMsg_GetTo will test the Msg.GetTo method

	func TestMsg_GetTo(t *testing.T) {
		m := NewMsg()
		if err := m.AddToFormat("Toni To", "to@example.com"); err != nil {
			t.Errorf("failed to set TO address: %s", err)
		}
		fh := m.GetTo()
		if len(fh) <= 0 {
			t.Errorf("GetTo failed. Got empty slice")
			return
		}
		if fh[0].String() == "" {
			t.Errorf("GetTo failed. Got empty value")
		}
		if fh[0].String() != `"Toni To" <to@example.com>` {
			t.Errorf("GetTo failed. Expected: %q, got: %q",
				`"Toni To" <to@example.com>"`, fh[0].String())
		}
	}

// TestMsg_GetToString will test the Msg.GetToString method

	func TestMsg_GetToString(t *testing.T) {
		m := NewMsg()
		if err := m.AddToFormat("Toni To", "to@example.com"); err != nil {
			t.Errorf("failed to set TO address: %s", err)
		}
		fh := m.GetToString()
		if len(fh) <= 0 {
			t.Errorf("GetToString failed. Got empty slice")
			return
		}
		if fh[0] == "" {
			t.Errorf("GetToString failed. Got empty value")
		}
		if fh[0] != `"Toni To" <to@example.com>` {
			t.Errorf("GetToString failed. Expected: %q, got: %q",
				`"Toni To" <to@example.com>"`, fh[0])
		}
	}

// TestMsg_GetCc will test the Msg.GetCc method

	func TestMsg_GetCc(t *testing.T) {
		m := NewMsg()
		if err := m.AddCcFormat("Toni Cc", "cc@example.com"); err != nil {
			t.Errorf("failed to set TO address: %s", err)
		}
		fh := m.GetCc()
		if len(fh) <= 0 {
			t.Errorf("GetCc failed. Got empty slice")
			return
		}
		if fh[0].String() == "" {
			t.Errorf("GetCc failed. Got empty value")
		}
		if fh[0].String() != `"Toni Cc" <cc@example.com>` {
			t.Errorf("GetCc failed. Expected: %q, got: %q",
				`"Toni Cc" <cc@example.com>"`, fh[0].String())
		}
	}

// TestMsg_GetCcString will test the Msg.GetCcString method

	func TestMsg_GetCcString(t *testing.T) {
		m := NewMsg()
		if err := m.AddCcFormat("Toni Cc", "cc@example.com"); err != nil {
			t.Errorf("failed to set TO address: %s", err)
		}
		fh := m.GetCcString()
		if len(fh) <= 0 {
			t.Errorf("GetCcString failed. Got empty slice")
			return
		}
		if fh[0] == "" {
			t.Errorf("GetCcString failed. Got empty value")
		}
		if fh[0] != `"Toni Cc" <cc@example.com>` {
			t.Errorf("GetCcString failed. Expected: %q, got: %q",
				`"Toni Cc" <cc@example.com>"`, fh[0])
		}
	}

// TestMsg_GetBcc will test the Msg.GetBcc method

	func TestMsg_GetBcc(t *testing.T) {
		m := NewMsg()
		if err := m.AddBccFormat("Toni Bcc", "bcc@example.com"); err != nil {
			t.Errorf("failed to set TO address: %s", err)
		}
		fh := m.GetBcc()
		if len(fh) <= 0 {
			t.Errorf("GetBcc failed. Got empty slice")
			return
		}
		if fh[0].String() == "" {
			t.Errorf("GetBcc failed. Got empty value")
		}
		if fh[0].String() != `"Toni Bcc" <bcc@example.com>` {
			t.Errorf("GetBcc failed. Expected: %q, got: %q",
				`"Toni Cc" <bcc@example.com>"`, fh[0].String())
		}
	}

// TestMsg_GetBccString will test the Msg.GetBccString method

	func TestMsg_GetBccString(t *testing.T) {
		m := NewMsg()
		if err := m.AddBccFormat("Toni Bcc", "bcc@example.com"); err != nil {
			t.Errorf("failed to set TO address: %s", err)
		}
		fh := m.GetBccString()
		if len(fh) <= 0 {
			t.Errorf("GetBccString failed. Got empty slice")
			return
		}
		if fh[0] == "" {
			t.Errorf("GetBccString failed. Got empty value")
		}
		if fh[0] != `"Toni Bcc" <bcc@example.com>` {
			t.Errorf("GetBccString failed. Expected: %q, got: %q",
				`"Toni Cc" <bcc@example.com>"`, fh[0])
		}
	}

// TestMsg_GetBoundary will test the Msg.GetBoundary method

	func TestMsg_GetBoundary(t *testing.T) {
		b := "random_boundary_string"
		m := NewMsg()
		if boundary := m.GetBoundary(); boundary != "" {
			t.Errorf("GetBoundary failed. Expected empty string, but got: %s", boundary)
		}
		m = NewMsg(WithBoundary(b))
		if boundary := m.GetBoundary(); boundary != b {
			t.Errorf("GetBoundary failed. Expected boundary: %s, got: %s", b, boundary)
		}
	}

// TestMsg_AttachEmbedReader_consecutive tests the Msg.AttachReader and Msg.EmbedReader
// methods with consecutive calls to Msg.WriteTo to make sure the attachments are not
// lost (see Github issue #110)

	func TestMsg_AttachEmbedReader_consecutive(t *testing.T) {
		ts1 := "This is a test string"
		ts2 := "Another test string"
		m := NewMsg()
		if err := m.AttachReader("attachment.txt", bytes.NewBufferString(ts1)); err != nil {
			t.Errorf("AttachReader() failed. Expected no error, got: %s", err.Error())
			return
		}
		if err := m.EmbedReader("embedded.txt", bytes.NewBufferString(ts2)); err != nil {
			t.Errorf("EmbedReader() failed. Expected no error, got: %s", err.Error())
			return
		}
		obuf1 := &bytes.Buffer{}
		obuf2 := &bytes.Buffer{}
		_, err := m.WriteTo(obuf1)
		if err != nil {
			t.Errorf("WriteTo to first output buffer failed: %s", err)
		}
		_, err = m.WriteTo(obuf2)
		if err != nil {
			t.Errorf("WriteTo to second output buffer failed: %s", err)
		}
		if !strings.Contains(obuf1.String(), "VGhpcyBpcyBhIHRlc3Qgc3RyaW5n") {
			t.Errorf("Expected file attachment string not found in first output buffer")
		}
		if !strings.Contains(obuf2.String(), "VGhpcyBpcyBhIHRlc3Qgc3RyaW5n") {
			t.Errorf("Expected file attachment string not found in second output buffer")
		}
		if !strings.Contains(obuf1.String(), "QW5vdGhlciB0ZXN0IHN0cmluZw==") {
			t.Errorf("Expected embedded file string not found in first output buffer")
		}
		if !strings.Contains(obuf2.String(), "QW5vdGhlciB0ZXN0IHN0cmluZw==") {
			t.Errorf("Expected embded file string not found in second output buffer")
		}
	}

// TestMsg_AttachEmbedReadSeeker_consecutive tests the Msg.AttachReadSeeker and
// Msg.EmbedReadSeeker methods with consecutive calls to Msg.WriteTo to make
// sure the attachments are not lost (see Github issue #110)

	func TestMsg_AttachEmbedReadSeeker_consecutive(t *testing.T) {
		ts1 := []byte("This is a test string")
		ts2 := []byte("Another test string")
		m := NewMsg()
		m.AttachReadSeeker("attachment.txt", bytes.NewReader(ts1))
		m.EmbedReadSeeker("embedded.txt", bytes.NewReader(ts2))
		obuf1 := &bytes.Buffer{}
		obuf2 := &bytes.Buffer{}
		_, err := m.WriteTo(obuf1)
		if err != nil {
			t.Errorf("WriteTo to first output buffer failed: %s", err)
		}
		_, err = m.WriteTo(obuf2)
		if err != nil {
			t.Errorf("WriteTo to second output buffer failed: %s", err)
		}
		if !strings.Contains(obuf1.String(), "VGhpcyBpcyBhIHRlc3Qgc3RyaW5n") {
			t.Errorf("Expected file attachment string not found in first output buffer")
		}
		if !strings.Contains(obuf2.String(), "VGhpcyBpcyBhIHRlc3Qgc3RyaW5n") {
			t.Errorf("Expected file attachment string not found in second output buffer")
		}
		if !strings.Contains(obuf1.String(), "QW5vdGhlciB0ZXN0IHN0cmluZw==") {
			t.Errorf("Expected embedded file string not found in first output buffer")
		}
		if !strings.Contains(obuf2.String(), "QW5vdGhlciB0ZXN0IHN0cmluZw==") {
			t.Errorf("Expected embded file string not found in second output buffer")
		}
	}

// TestMsg_AttachReadSeeker tests the Msg.AttachReadSeeker method

	func TestMsg_AttachReadSeeker(t *testing.T) {
		m := NewMsg()
		ts := []byte("This is a test string")
		r := bytes.NewReader(ts)
		m.AttachReadSeeker("testfile.txt", r)
		if len(m.attachments) != 1 {
			t.Errorf("AttachReadSeeker() failed. Number of attachments expected: %d, got: %d", 1,
				len(m.attachments))
			return
		}
		file := m.attachments[0]
		if file == nil {
			t.Errorf("AttachReadSeeker() failed. Attachment file pointer is nil")
			return
		}
		if file.Name != "testfile.txt" {
			t.Errorf("AttachReadSeeker() failed. Expected file name: %s, got: %s", "testfile.txt",
				file.Name)
		}
		wbuf := bytes.Buffer{}
		if _, err := file.Writer(&wbuf); err != nil {
			t.Errorf("execute WriterFunc failed: %s", err)
		}
		if wbuf.String() != string(ts) {
			t.Errorf("AttachReadSeeker() failed. Expected string: %q, got: %q", ts, wbuf.String())
		}
	}

// TestMsg_EmbedReadSeeker tests the Msg.EmbedReadSeeker method

	func TestMsg_EmbedReadSeeker(t *testing.T) {
		m := NewMsg()
		ts := []byte("This is a test string")
		r := bytes.NewReader(ts)
		m.EmbedReadSeeker("testfile.txt", r)
		if len(m.embeds) != 1 {
			t.Errorf("EmbedReadSeeker() failed. Number of attachments expected: %d, got: %d", 1,
				len(m.embeds))
			return
		}
		file := m.embeds[0]
		if file == nil {
			t.Errorf("EmbedReadSeeker() failed. Embedded file pointer is nil")
			return
		}
		if file.Name != "testfile.txt" {
			t.Errorf("EmbedReadSeeker() failed. Expected file name: %s, got: %s", "testfile.txt",
				file.Name)
		}
		wbuf := bytes.Buffer{}
		if _, err := file.Writer(&wbuf); err != nil {
			t.Errorf("execute WriterFunc failed: %s", err)
		}
		if wbuf.String() != string(ts) {
			t.Errorf("EmbedReadSeeker() failed. Expected string: %q, got: %q", ts, wbuf.String())
		}
	}

// TestMsg_ToFromString tests Msg.ToFromString in different scenarios

	func TestMsg_ToFromString(t *testing.T) {
		tests := []struct {
			n  string
			v  string
			w  []*mail.Address
			sf bool
		}{
			{"valid single address", "test@test.com", []*mail.Address{
				{Name: "", Address: "test@test.com"},
			}, false},
			{
				"valid multiple addresses", "test@test.com,test2@example.com",
				[]*mail.Address{
					{Name: "", Address: "test@test.com"},
					{Name: "", Address: "test2@example.com"},
				},
				false,
			},
			{
				"valid multiple addresses with space and name",
				`test@test.com, "Toni Tester" <test2@example.com>`,
				[]*mail.Address{
					{Name: "", Address: "test@test.com"},
					{Name: "Toni Tester", Address: "test2@example.com"},
				},
				false,
			},
			{
				"invalid and valid multiple addresses", "test@test.com,test2#example.com", nil,
				true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.n, func(t *testing.T) {
				m := NewMsg()
				if err := m.ToFromString(tt.v); err != nil && !tt.sf {
					t.Errorf("Msg.ToFromString failed: %s", err)
					return
				}
				mto := m.GetTo()
				if len(mto) != len(tt.w) {
					t.Errorf("Msg.ToFromString failed, expected len: %d, got: %d", len(tt.w),
						len(mto))
					return
				}
				for i := range mto {
					w := tt.w[i]
					g := mto[i]
					if w.String() != g.String() {
						t.Errorf("Msg.ToFromString failed, expected address: %s, got: %s",
							w.String(), g.String())
					}
				}
			})
		}
	}

// TestMsg_CcFromString tests Msg.CcFromString in different scenarios

	func TestMsg_CcFromString(t *testing.T) {
		tests := []struct {
			n  string
			v  string
			w  []*mail.Address
			sf bool
		}{
			{"valid single address", "test@test.com", []*mail.Address{
				{Name: "", Address: "test@test.com"},
			}, false},
			{
				"valid multiple addresses", "test@test.com,test2@example.com",
				[]*mail.Address{
					{Name: "", Address: "test@test.com"},
					{Name: "", Address: "test2@example.com"},
				},
				false,
			},
			{
				"valid multiple addresses with space and name",
				`test@test.com, "Toni Tester" <test2@example.com>`,
				[]*mail.Address{
					{Name: "", Address: "test@test.com"},
					{Name: "Toni Tester", Address: "test2@example.com"},
				},
				false,
			},
			{
				"invalid and valid multiple addresses", "test@test.com,test2#example.com", nil,
				true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.n, func(t *testing.T) {
				m := NewMsg()
				if err := m.CcFromString(tt.v); err != nil && !tt.sf {
					t.Errorf("Msg.CcFromString failed: %s", err)
					return
				}
				mto := m.GetCc()
				if len(mto) != len(tt.w) {
					t.Errorf("Msg.CcFromString failed, expected len: %d, got: %d", len(tt.w),
						len(mto))
					return
				}
				for i := range mto {
					w := tt.w[i]
					g := mto[i]
					if w.String() != g.String() {
						t.Errorf("Msg.CcFromString failed, expected address: %s, got: %s",
							w.String(), g.String())
					}
				}
			})
		}
	}

// TestMsg_BccFromString tests Msg.BccFromString in different scenarios

	func TestMsg_BccFromString(t *testing.T) {
		tests := []struct {
			n  string
			v  string
			w  []*mail.Address
			sf bool
		}{
			{"valid single address", "test@test.com", []*mail.Address{
				{Name: "", Address: "test@test.com"},
			}, false},
			{
				"valid multiple addresses", "test@test.com,test2@example.com",
				[]*mail.Address{
					{Name: "", Address: "test@test.com"},
					{Name: "", Address: "test2@example.com"},
				},
				false,
			},
			{
				"valid multiple addresses with space and name",
				`test@test.com, "Toni Tester" <test2@example.com>`,
				[]*mail.Address{
					{Name: "", Address: "test@test.com"},
					{Name: "Toni Tester", Address: "test2@example.com"},
				},
				false,
			},
			{
				"invalid and valid multiple addresses", "test@test.com,test2#example.com", nil,
				true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.n, func(t *testing.T) {
				m := NewMsg()
				if err := m.BccFromString(tt.v); err != nil && !tt.sf {
					t.Errorf("Msg.BccFromString failed: %s", err)
					return
				}
				mto := m.GetBcc()
				if len(mto) != len(tt.w) {
					t.Errorf("Msg.BccFromString failed, expected len: %d, got: %d", len(tt.w),
						len(mto))
					return
				}
				for i := range mto {
					w := tt.w[i]
					g := mto[i]
					if w.String() != g.String() {
						t.Errorf("Msg.BccFromString failed, expected address: %s, got: %s",
							w.String(), g.String())
					}
				}
			})
		}
	}

// TestMsg_checkUserAgent tests the checkUserAgent method of the Msg

	func TestMsg_checkUserAgent(t *testing.T) {
		tests := []struct {
			name               string
			noDefaultUserAgent bool
			genHeader          map[Header][]string
			wantUserAgent      string
			sf                 bool
		}{
			{
				name:               "check default user agent",
				noDefaultUserAgent: false,
				wantUserAgent:      fmt.Sprintf("go-mail v%s // https://github.com/wneessen/go-mail", VERSION),
				sf:                 false,
			},
			{
				name:               "check no default user agent",
				noDefaultUserAgent: true,
				wantUserAgent:      "",
				sf:                 true,
			},
			{
				name:               "check if ua and xm is already set",
				noDefaultUserAgent: false,
				genHeader: map[Header][]string{
					HeaderUserAgent: {"custom UA"},
					HeaderXMailer:   {"custom XM"},
				},
				wantUserAgent: "custom UA",
				sf:            false,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				msg := &Msg{
					noDefaultUserAgent: tt.noDefaultUserAgent,
					genHeader:          tt.genHeader,
				}
				msg.checkUserAgent()
				gotUserAgent := ""
				if val, ok := msg.genHeader[HeaderUserAgent]; ok {
					gotUserAgent = val[0] // Assuming the first one is the needed value
				}
				if gotUserAgent != tt.wantUserAgent && !tt.sf {
					t.Errorf("UserAgent got = %v, want = %v", gotUserAgent, tt.wantUserAgent)
				}
			})
		}
	}

// TestNewMsgWithMIMEVersion tests WithMIMEVersion and Msg.SetMIMEVersion

	func TestNewMsgWithNoDefaultUserAgent(t *testing.T) {
		m := NewMsg(WithNoDefaultUserAgent())
		if m.noDefaultUserAgent != true {
			t.Errorf("WithNoDefaultUserAgent() failed. Expected: %t, got: %t", true, false)
		}
	}

// Fuzzing tests

	func FuzzMsg_Subject(f *testing.F) {
		f.Add("Testsubject")
		f.Add("")
		f.Add("This is a longer test subject.")
		f.Add("Let's add some umlauts: üäöß")
		f.Add("Or even emojis: ☝️💪👍")
		f.Fuzz(func(t *testing.T, data string) {
			m := NewMsg()
			m.Subject(data)
			m.Reset()
		})
	}

	func FuzzMsg_From(f *testing.F) {
		f.Add("Toni Tester <toni@tester.com>")
		f.Add("<tester@example.com>")
		f.Add("mail@server.com")
		f.Fuzz(func(t *testing.T, data string) {
			m := NewMsg()
			if err := m.From(data); err != nil &&
				!strings.Contains(err.Error(), "failed to parse mail address") {
				t.Errorf("failed set set FROM address: %s", err)
			}
			m.Reset()
		})
	}
*/
type uppercaseMiddleware struct{}

func (mw uppercaseMiddleware) Handle(m *Msg) *Msg {
	s, ok := m.genHeader[HeaderSubject]
	if !ok {
		fmt.Println("can't find the subject header")
	}
	if s == nil || len(s) < 1 {
		s = append(s, "")
	}
	m.Subject(strings.ToUpper(s[0]))
	return m
}

func (mw uppercaseMiddleware) Type() MiddlewareType {
	return "uppercase"
}

type encodeMiddleware struct{}

func (mw encodeMiddleware) Handle(m *Msg) *Msg {
	s, ok := m.genHeader[HeaderSubject]
	if !ok {
		fmt.Println("can't find the subject header")
	}
	if s == nil || len(s) < 1 {
		s = append(s, "")
	}
	m.Subject(strings.Replace(s[0], "a", "@", -1))
	return m
}

func (mw encodeMiddleware) Type() MiddlewareType {
	return "encode"
}
