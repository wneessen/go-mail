// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"errors"
	"fmt"
	ht "html/template"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	ttpl "text/template"
	"time"
)

type msgContentTest struct {
	line         int
	data         string
	exact        bool
	dataIsPrefix bool
	dataIsSuffix bool
}

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
		{`hi"@"there@domain.tld`, false},     // Quotes must be dot-separated
		{`"<\"@\\".!.#%$@domain.tld`, false}, // Quote is escaped and dot-separated which would be RFC822 compliant, but not RFC5322 compliant
		{`hi\ there@domain.tld`, false},      // Spaces must be quoted
		{"hello@tld", true},                  // TLD is enough
		{`你好@域名.顶级域名`, true},                 // We speak RFC6532
		{"1@23456789", true},                 // Hypothetically valid, if somebody registers that TLD
		{"1@[23456789]", false},              // While 23456789 is decimal for 1.101.236.21 it is not RFC5322 compliant
	}
)

//go:embed testdata/attachment.txt testdata/embed.txt
var efs embed.FS

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
	t.Log("SetMessageIDWithValue is fully covered by TestMsg_GetMessageID")
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
				t.Log("ImportanceNormal is does currently not set any values")
				return
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
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is a test attachment") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test attachment", got)
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
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is a test attachment") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test attachment", got)
		}
		messageBuf.Reset()
		_, err = attachments[1].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got = strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is a test attachment") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test attachment", got)
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
				buf := bytes.NewBuffer([]byte("This is a test attachment"))
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
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is a test attachment") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test attachment", got)
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
				buf := bytes.NewBuffer([]byte("This is a test attachment"))
				n, err := w.Write(buf.Bytes())
				return int64(n), err
			},
		}
		file2 := &File{
			ContentType: TypeTextPlain,
			Desc:        "Test file no. 2",
			Name:        "attachment2.txt",
			Writer: func(w io.Writer) (int64, error) {
				buf := bytes.NewBuffer([]byte("This is also a test attachment"))
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
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(messageBuf.String(), "This is a test attachment") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test attachment", got)
		}
		messageBuf.Reset()
		_, err = attachments[1].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got = strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is also a test attachment") {
			t.Errorf("expected message body to be %s, got: %s", "This is also a test attachment", got)
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
	t.Log("SetAttachements is deprecated and fully tested by SetAttachments already")
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
			buf := bytes.NewBuffer([]byte("This is a test attachment"))
			n, err := w.Write(buf.Bytes())
			return int64(n), err
		},
	}
	file2 := &File{
		ContentType: TypeTextPlain,
		Desc:        "Test file no. 2",
		Name:        "attachment2.txt",
		Writer: func(w io.Writer) (int64, error) {
			buf := bytes.NewBuffer([]byte("This is also a test attachment"))
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
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is a test embed") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test embed", got)
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
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is a test embed") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test embed", got)
		}
		messageBuf.Reset()
		_, err = embeds[1].Writer(messageBuf)
		if err != nil {
			t.Errorf("Writer func failed: %s", err)
		}
		got = strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is a test embed") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test embed", got)
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
				buf := bytes.NewBuffer([]byte("This is a test embed"))
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
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is a test embed") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test embed", got)
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
				buf := bytes.NewBuffer([]byte("This is a test embed"))
				n, err := w.Write(buf.Bytes())
				return int64(n), err
			},
		}
		file2 := &File{
			ContentType: TypeTextPlain,
			Desc:        "Test file no. 2",
			Name:        "embed2.txt",
			Writer: func(w io.Writer) (int64, error) {
				buf := bytes.NewBuffer([]byte("This is also a test embed"))
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
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is a test embed") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test embed", got)
		}
		messageBuf.Reset()
		_, err = embeds[1].Writer(messageBuf)
		if err != nil {
			t.Errorf("Writer func failed: %s", err)
		}
		got = strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is also a test embed") {
			t.Errorf("expected message body to be %s, got: %s", "This is also a test embed", got)
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
			buf := bytes.NewBuffer([]byte("This is a test embed"))
			n, err := w.Write(buf.Bytes())
			return int64(n), err
		},
	}
	file2 := &File{
		ContentType: TypeTextPlain,
		Desc:        "Test file no. 2",
		Name:        "embed2.txt",
		Writer: func(w io.Writer) (int64, error) {
			buf := bytes.NewBuffer([]byte("This is also a test embed"))
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
			buf := bytes.NewBuffer([]byte("This is a test embed"))
			n, err := w.Write(buf.Bytes())
			return int64(n), err
		},
	}
	file2 := &File{
		ContentType: TypeTextPlain,
		Desc:        "Test file no. 2",
		Name:        "embed2.txt",
		Writer: func(w io.Writer) (int64, error) {
			buf := bytes.NewBuffer([]byte("This is also a test embed"))
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
	t.Run("SetBodyWriter WithPartEncoding", func(t *testing.T) {
		for _, tt := range encodingTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				message.SetBodyWriter(TypeTextPlain, writerFunc, WithPartEncoding(tt.value))
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
				if parts[0].encoding != tt.value {
					t.Errorf("expected encoding to be %s, got: %s", tt.value, parts[0].encoding)
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
	t.Run("SetBodyWriter WithPartContentDescription", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.SetBodyWriter(TypeTextPlain, writerFunc, WithPartContentDescription("description"))
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
		if parts[0].description != "description" {
			t.Errorf("expected description to be %s, got: %s", "description", parts[0].description)
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
	t.Run("SetBodyWriter with nil option", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.SetBodyWriter(TypeTextPlain, writerFunc, nil)
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

func TestMsg_SetBodyHTMLTemplate(t *testing.T) {
	tplString := `<p>{{.teststring}}</p>`
	invalidTplString := `<p>{{call $.invalid .teststring}}</p>`
	data := map[string]interface{}{"teststring": "this is a test"}
	htmlTpl, err := ht.New("htmltpl").Parse(tplString)
	if err != nil {
		t.Fatalf("failed to parse HTML template: %s", err)
	}
	invalidTpl, err := ht.New("htmltpl").Parse(invalidTplString)
	if err != nil {
		t.Fatalf("failed to parse invalid HTML template: %s", err)
	}
	t.Run("SetBodyHTMLTemplate default", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err = message.SetBodyHTMLTemplate(htmlTpl, data); err != nil {
			t.Fatalf("failed to set body HTML template: %s", err)
		}
		parts := message.GetParts()
		if len(parts) != 1 {
			t.Fatalf("expected 1 part, got: %d", len(parts))
		}
		if parts[0] == nil {
			t.Fatal("expected part to be not nil")
		}
		if parts[0].contentType != TypeTextHTML {
			t.Errorf("expected contentType to be %s, got: %s", TypeTextHTML, parts[0].contentType)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = parts[0].writeFunc(messageBuf)
		if err != nil {
			t.Errorf("writeFunc failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "<p>this is a test</p>") {
			t.Errorf("expected message body to be %s, got: %s", "<p>this is a test</p>", messageBuf.String())
		}
	})
	t.Run("SetBodyHTMLTemplate with nil tpl", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err = message.SetBodyHTMLTemplate(nil, nil)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.EqualFold(err.Error(), errTplPointerNil) {
			t.Errorf("expected error to be %s, got: %s", errTplPointerNil, err.Error())
		}
	})
	t.Run("SetBodyHTMLTemplate with invalid tpl", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err = message.SetBodyHTMLTemplate(invalidTpl, data)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		expectErr := `failed to execute template: template: htmltpl:1:5: executing "htmltpl" at <call $.invalid ` +
			`.teststring>: error calling call: call of nil`
		if !strings.EqualFold(err.Error(), expectErr) {
			t.Errorf("expected error to be %s, got: %s", expectErr, err.Error())
		}
	})
}

func TestMsg_SetBodyTextTemplate(t *testing.T) {
	tplString := `Teststring: {{.teststring}}`
	invalidTplString := `Teststring: {{call $.invalid .teststring}}`
	data := map[string]interface{}{"teststring": "this is a test"}
	textTpl, err := ttpl.New("texttpl").Parse(tplString)
	if err != nil {
		t.Fatalf("failed to parse Text template: %s", err)
	}
	invalidTpl, err := ttpl.New("texttpl").Parse(invalidTplString)
	if err != nil {
		t.Fatalf("failed to parse invalid Text template: %s", err)
	}
	t.Run("SetBodyTextTemplate default", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err = message.SetBodyTextTemplate(textTpl, data); err != nil {
			t.Fatalf("failed to set body text template: %s", err)
		}
		parts := message.GetParts()
		if len(parts) != 1 {
			t.Fatalf("expected 1 part, got: %d", len(parts))
		}
		if parts[0] == nil {
			t.Fatal("expected part to be not nil")
		}
		if parts[0].contentType != TypeTextPlain {
			t.Errorf("expected contentType to be %s, got: %s", TypeTextPlain, parts[0].contentType)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = parts[0].writeFunc(messageBuf)
		if err != nil {
			t.Errorf("writeFunc failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "Teststring: this is a test") {
			t.Errorf("expected message body to be %s, got: %s", "Teststring: this is a test", messageBuf.String())
		}
	})
	t.Run("SetBodyTextTemplate with nil tpl", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err = message.SetBodyTextTemplate(nil, nil)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.EqualFold(err.Error(), errTplPointerNil) {
			t.Errorf("expected error to be %s, got: %s", errTplPointerNil, err.Error())
		}
	})
	t.Run("SetBodyTextTemplate with invalid tpl", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err = message.SetBodyTextTemplate(invalidTpl, data)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		expectErr := `failed to execute template: template: texttpl:1:14: executing "texttpl" at <call $.invalid ` +
			`.teststring>: error calling call: call of nil`
		if !strings.EqualFold(err.Error(), expectErr) {
			t.Errorf("expected error to be %s, got: %s", expectErr, err.Error())
		}
	})
}

func TestMsg_AddAlternativeString(t *testing.T) {
	t.Run("AddAlternativeString on all types", func(t *testing.T) {
		for _, tt := range contentTypeTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				message.AddAlternativeString(tt.ctype, "test")
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

func TestMsg_AddAlternativeWriter(t *testing.T) {
	writerFunc := func(w io.Writer) (int64, error) {
		buffer := bytes.NewBufferString("test")
		n, err := w.Write(buffer.Bytes())
		return int64(n), err
	}
	t.Run("AddAlternativeWriter on all types", func(t *testing.T) {
		for _, tt := range contentTypeTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				message.AddAlternativeWriter(tt.ctype, writerFunc)
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
	t.Run("AddAlternativeWriter WithPartCharset", func(t *testing.T) {
		for _, tt := range charsetTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				message.AddAlternativeWriter(TypeTextPlain, writerFunc, WithPartCharset(tt.value))
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
	t.Run("AddAlternativeWriter WithPartEncoding", func(t *testing.T) {
		for _, tt := range encodingTests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				message.AddAlternativeWriter(TypeTextPlain, writerFunc, WithPartEncoding(tt.value))
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
				if parts[0].encoding != tt.value {
					t.Errorf("expected encoding to be %s, got: %s", tt.value, parts[0].encoding)
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
	t.Run("AddAlternativeWriter WithPartContentDescription", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.AddAlternativeWriter(TypeTextPlain, writerFunc, WithPartContentDescription("description"))
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
		if parts[0].description != "description" {
			t.Errorf("expected description to be %s, got: %s", "description", parts[0].description)
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
	t.Run("AddAlternativeWriter with body string set", func(t *testing.T) {
		writerFunc = func(w io.Writer) (int64, error) {
			buffer := bytes.NewBufferString("<p>alternative body</p>")
			n, err := w.Write(buffer.Bytes())
			return int64(n), err
		}
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.SetBodyString(TypeTextPlain, "body string")
		message.AddAlternativeWriter(TypeTextHTML, writerFunc)
		parts := message.GetParts()
		if len(parts) != 2 {
			t.Fatalf("expected 2 part, got: %d", len(parts))
		}
		if parts[0] == nil || parts[1] == nil {
			t.Fatal("expected part to be not nil")
		}
		if parts[0].contentType != TypeTextPlain {
			t.Errorf("expected contentType to be %s, got: %s", TypeTextPlain,
				parts[0].contentType)
		}
		if parts[1].contentType != TypeTextHTML {
			t.Errorf("expected alternative contentType to be %s, got: %s", TypeTextHTML,
				parts[1].contentType)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err := parts[0].writeFunc(messageBuf)
		if err != nil {
			t.Errorf("writeFunc failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "body string") {
			t.Errorf("expected message body to be %s, got: %s", "body string", messageBuf.String())
		}
		messageBuf.Reset()
		_, err = parts[1].writeFunc(messageBuf)
		if err != nil {
			t.Errorf("writeFunc failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "<p>alternative body</p>") {
			t.Errorf("expected alternative message body to be %s, got: %s", "<p>alternative body</p>", messageBuf.String())
		}
	})
}

func TestMsg_AddAlternativeHTMLTemplate(t *testing.T) {
	tplString := `<p>{{.teststring}}</p>`
	invalidTplString := `<p>{{call $.invalid .teststring}}</p>`
	data := map[string]interface{}{"teststring": "this is a test"}
	htmlTpl, err := ht.New("htmltpl").Parse(tplString)
	if err != nil {
		t.Fatalf("failed to parse HTML template: %s", err)
	}
	invalidTpl, err := ht.New("htmltpl").Parse(invalidTplString)
	if err != nil {
		t.Fatalf("failed to parse invalid HTML template: %s", err)
	}
	t.Run("AddAlternativeHTMLTemplate default", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err = message.AddAlternativeHTMLTemplate(htmlTpl, data); err != nil {
			t.Fatalf("failed to set body HTML template: %s", err)
		}
		parts := message.GetParts()
		if len(parts) != 1 {
			t.Fatalf("expected 1 part, got: %d", len(parts))
		}
		if parts[0] == nil {
			t.Fatal("expected part to be not nil")
		}
		if parts[0].contentType != TypeTextHTML {
			t.Errorf("expected contentType to be %s, got: %s", TypeTextHTML, parts[0].contentType)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = parts[0].writeFunc(messageBuf)
		if err != nil {
			t.Errorf("writeFunc failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "<p>this is a test</p>") {
			t.Errorf("expected message body to be %s, got: %s", "<p>this is a test</p>", messageBuf.String())
		}
	})
	t.Run("AddAlternativeHTMLTemplate with body string", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.SetBodyString(TypeTextPlain, "body string")
		if err = message.AddAlternativeHTMLTemplate(htmlTpl, data); err != nil {
			t.Fatalf("failed to set body HTML template: %s", err)
		}
		parts := message.GetParts()
		if len(parts) != 2 {
			t.Fatalf("expected 2 part, got: %d", len(parts))
		}
		if parts[0] == nil || parts[1] == nil {
			t.Fatal("expected part to be not nil")
		}
		if parts[0].contentType != TypeTextPlain {
			t.Errorf("expected contentType to be %s, got: %s", TypeTextPlain, parts[0].contentType)
		}
		if parts[1].contentType != TypeTextHTML {
			t.Errorf("expected contentType to be %s, got: %s", TypeTextHTML, parts[1].contentType)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = parts[0].writeFunc(messageBuf)
		if err != nil {
			t.Errorf("writeFunc failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "body string") {
			t.Errorf("expected message body to be %s, got: %s", "body string", messageBuf.String())
		}
		messageBuf.Reset()
		_, err = parts[1].writeFunc(messageBuf)
		if err != nil {
			t.Errorf("writeFunc failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "<p>this is a test</p>") {
			t.Errorf("expected message body to be %s, got: %s", "<p>this is a test</p>", messageBuf.String())
		}
	})
	t.Run("AddAlternativeHTMLTemplate with nil tpl", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err = message.AddAlternativeHTMLTemplate(nil, nil)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.EqualFold(err.Error(), errTplPointerNil) {
			t.Errorf("expected error to be %s, got: %s", errTplPointerNil, err.Error())
		}
	})
	t.Run("AddAlternativeHTMLTemplate with invalid tpl", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err = message.AddAlternativeHTMLTemplate(invalidTpl, data)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		expectErr := `failed to execute template: template: htmltpl:1:5: executing "htmltpl" at <call $.invalid ` +
			`.teststring>: error calling call: call of nil`
		if !strings.EqualFold(err.Error(), expectErr) {
			t.Errorf("expected error to be %s, got: %s", expectErr, err.Error())
		}
	})
}

func TestMsg_AddAlternativeTextTemplate(t *testing.T) {
	tplString := `Teststring: {{.teststring}}`
	invalidTplString := `Teststring: {{call $.invalid .teststring}}`
	data := map[string]interface{}{"teststring": "this is a test"}
	textTpl, err := ttpl.New("texttpl").Parse(tplString)
	if err != nil {
		t.Fatalf("failed to parse Text template: %s", err)
	}
	invalidTpl, err := ttpl.New("texttpl").Parse(invalidTplString)
	if err != nil {
		t.Fatalf("failed to parse invalid Text template: %s", err)
	}
	t.Run("AddAlternativeTextTemplate default", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err = message.AddAlternativeTextTemplate(textTpl, data); err != nil {
			t.Fatalf("failed to set body text template: %s", err)
		}
		parts := message.GetParts()
		if len(parts) != 1 {
			t.Fatalf("expected 1 part, got: %d", len(parts))
		}
		if parts[0] == nil {
			t.Fatal("expected part to be not nil")
		}
		if parts[0].contentType != TypeTextPlain {
			t.Errorf("expected contentType to be %s, got: %s", TypeTextPlain, parts[0].contentType)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = parts[0].writeFunc(messageBuf)
		if err != nil {
			t.Errorf("writeFunc failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "Teststring: this is a test") {
			t.Errorf("expected message body to be %s, got: %s", "Teststring: this is a test", messageBuf.String())
		}
	})
	t.Run("AddAlternativeTextTemplate with body string", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.SetBodyString(TypeTextPlain, "body string")
		if err = message.AddAlternativeTextTemplate(textTpl, data); err != nil {
			t.Fatalf("failed to set body text template: %s", err)
		}
		parts := message.GetParts()
		if len(parts) != 2 {
			t.Fatalf("expected 2 part, got: %d", len(parts))
		}
		if parts[0] == nil || parts[1] == nil {
			t.Fatal("expected part to be not nil")
		}
		if parts[0].contentType != TypeTextPlain {
			t.Errorf("expected contentType to be %s, got: %s", TypeTextPlain, parts[0].contentType)
		}
		if parts[1].contentType != TypeTextPlain {
			t.Errorf("expected contentType to be %s, got: %s", TypeTextPlain, parts[1].contentType)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = parts[0].writeFunc(messageBuf)
		if err != nil {
			t.Errorf("writeFunc failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "body string") {
			t.Errorf("expected message body to be %s, got: %s", "body string", messageBuf.String())
		}
		messageBuf.Reset()
		_, err = parts[1].writeFunc(messageBuf)
		if err != nil {
			t.Errorf("writeFunc failed: %s", err)
		}
		if !strings.EqualFold(messageBuf.String(), "Teststring: this is a test") {
			t.Errorf("expected message body to be %s, got: %s", "Teststring: this is a test", messageBuf.String())
		}
	})
	t.Run("AddAlternativeTextTemplate with nil tpl", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err = message.AddAlternativeTextTemplate(nil, nil)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.EqualFold(err.Error(), errTplPointerNil) {
			t.Errorf("expected error to be %s, got: %s", errTplPointerNil, err.Error())
		}
	})
	t.Run("AddAlternativeTextTemplate with invalid tpl", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err = message.AddAlternativeTextTemplate(invalidTpl, data)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		expectErr := `failed to execute template: template: texttpl:1:14: executing "texttpl" at <call $.invalid ` +
			`.teststring>: error calling call: call of nil`
		if !strings.EqualFold(err.Error(), expectErr) {
			t.Errorf("expected error to be %s, got: %s", expectErr, err.Error())
		}
	})
}

func TestMsg_AttachFile(t *testing.T) {
	t.Run("AttachFile with file", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.AttachFile("testdata/attachment.txt")
		attachments := message.GetAttachments()
		if len(attachments) != 1 {
			t.Fatalf("failed to retrieve attachments list")
		}
		if attachments[0] == nil {
			t.Fatal("expected attachment to be not nil")
		}
		if attachments[0].Name != "attachment.txt" {
			t.Errorf("expected attachment name to be %s, got: %s", "attachment.txt", attachments[0].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err := attachments[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is a test attachment") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test attachment", got)
		}
	})
	t.Run("AttachFile with non-existent file", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.AttachFile("testdata/non-existent-file.txt")
		attachments := message.GetAttachments()
		if len(attachments) != 0 {
			t.Fatalf("failed to retrieve attachments list")
		}
	})
	t.Run("AttachFile with options", func(t *testing.T) {
		t.Log("all options have already been tested in file_test.go")
	})
	t.Run("AttachFile with normal file and nil option", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.AttachFile("testdata/attachment.txt", nil)
		attachments := message.GetAttachments()
		if len(attachments) != 1 {
			t.Fatalf("failed to retrieve attachments list")
		}
		if attachments[0] == nil {
			t.Fatal("expected attachment to be not nil")
		}
		if attachments[0].Name != "attachment.txt" {
			t.Errorf("expected attachment name to be %s, got: %s", "attachment.txt", attachments[0].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err := attachments[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is a test attachment") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test attachment", got)
		}
	})
	t.Run("AttachFile with fileFromFS fails on copy", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.AttachFile("testdata/attachment.txt")
		attachments := message.GetAttachments()
		if len(attachments) != 1 {
			t.Fatalf("failed to get attachments, expected 1, got: %d", len(attachments))
		}
		_, err := attachments[0].Writer(failReadWriteSeekCloser{})
		if err == nil {
			t.Error("writer func expected to fail, but didn't")
		}
	})
}

func TestMsg_AttachReader(t *testing.T) {
	t.Run("AttachReader with file", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		file, err := os.Open("testdata/attachment.txt")
		if err != nil {
			t.Fatalf("failed to open file: %s", err)
		}
		t.Cleanup(func() {
			if err := file.Close(); err != nil {
				t.Errorf("failed to close file: %s", err)
			}
		})
		if err = message.AttachReader("attachment.txt", file); err != nil {
			t.Fatalf("failed to attach reader: %s", err)
		}
		attachments := message.GetAttachments()
		if len(attachments) != 1 {
			t.Fatalf("failed to retrieve attachments list")
		}
		if attachments[0] == nil {
			t.Fatal("expected attachment to be not nil")
		}
		if attachments[0].Name != "attachment.txt" {
			t.Errorf("expected attachment name to be %s, got: %s", "attachment.txt", attachments[0].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = attachments[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is a test attachment") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test attachment", got)
		}
	})
	t.Run("AttachReader with fileFromReader fails on copy", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		file, err := os.Open("testdata/attachment.txt")
		if err != nil {
			t.Fatalf("failed to open file: %s", err)
		}
		t.Cleanup(func() {
			if err := file.Close(); err != nil {
				t.Errorf("failed to close file: %s", err)
			}
		})
		if err = message.AttachReader("attachment.txt", file); err != nil {
			t.Fatalf("failed to attach reader: %s", err)
		}
		attachments := message.GetAttachments()
		if len(attachments) != 1 {
			t.Fatalf("failed to get attachments, expected 1, got: %d", len(attachments))
		}
		_, err = attachments[0].Writer(failReadWriteSeekCloser{})
		if err == nil {
			t.Error("writer func expected to fail, but didn't")
		}
	})
	// Tests the Msg.AttachReader methods with consecutive calls to Msg.WriteTo to make sure
	// the attachments are not lost.
	// https://github.com/wneessen/go-mail/issues/110
	t.Run("AttachReader with consecutive writes", func(t *testing.T) {
		teststring := "This is a test string"
		message := testMessage(t)
		if err := message.AttachReader("attachment.txt", bytes.NewBufferString(teststring)); err != nil {
			t.Fatalf("failed to attach teststring buffer: %s", err)
		}
		messageBuffer := bytes.NewBuffer(nil)
		altBuffer := bytes.NewBuffer(nil)
		// First write
		n1, err := message.WriteTo(messageBuffer)
		if err != nil {
			t.Fatalf("failed to write message to buffer: %s", err)
		}
		// Second write
		n2, err := message.WriteTo(altBuffer)
		if err != nil {
			t.Fatalf("failed to write message to alternative buffer: %s", err)
		}
		if n1 != n2 {
			t.Errorf("number of written bytes between consecutive writes differ, got: %d and %d", n1, n2)
		}
		if !strings.Contains(messageBuffer.String(), "VGhpcyBpcyBhIHRlc3Qgc3RyaW5n") {
			t.Errorf("expected string not found in message buffer, want: %s, got: %s",
				"VGhpcyBpcyBhIHRlc3Qgc3RyaW5n", messageBuffer.String())
		}
		if !strings.Contains(altBuffer.String(), "VGhpcyBpcyBhIHRlc3Qgc3RyaW5n") {
			t.Errorf("expected string not found in alternative message buffer, want: %s, got: %s",
				"VGhpcyBpcyBhIHRlc3Qgc3RyaW5n", altBuffer.String())
		}
	})
}

func TestMsg_AttachReadSeeker(t *testing.T) {
	t.Run("AttachReadSeeker with file", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		file, err := os.Open("testdata/attachment.txt")
		if err != nil {
			t.Fatalf("failed to open file: %s", err)
		}
		t.Cleanup(func() {
			if err := file.Close(); err != nil {
				t.Errorf("failed to close file: %s", err)
			}
		})
		message.AttachReadSeeker("attachment.txt", file)
		attachments := message.GetAttachments()
		if len(attachments) != 1 {
			t.Fatalf("failed to retrieve attachments list")
		}
		if attachments[0] == nil {
			t.Fatal("expected attachment to be not nil")
		}
		if attachments[0].Name != "attachment.txt" {
			t.Errorf("expected attachment name to be %s, got: %s", "attachment.txt", attachments[0].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = attachments[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is a test attachment") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test attachment", got)
		}
	})
	t.Run("AttachReadSeeker with fileFromReadSeeker fails on copy", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		file, err := os.Open("testdata/attachment.txt")
		if err != nil {
			t.Fatalf("failed to open file: %s", err)
		}
		t.Cleanup(func() {
			if err := file.Close(); err != nil {
				t.Errorf("failed to close file: %s", err)
			}
		})
		message.AttachReadSeeker("attachment.txt", file)
		attachments := message.GetAttachments()
		if len(attachments) != 1 {
			t.Fatalf("failed to get attachments, expected 1, got: %d", len(attachments))
		}
		_, err = attachments[0].Writer(failReadWriteSeekCloser{})
		if err == nil {
			t.Error("writer func expected to fail, but didn't")
		}
	})
	// Tests the Msg.AttachReadSeeker methods with consecutive calls to Msg.WriteTo to make sure
	// the attachments are not lost.
	// https://github.com/wneessen/go-mail/issues/110
	t.Run("AttachReadSeeker with consecutive writes", func(t *testing.T) {
		teststring := []byte("This is a test string")
		message := testMessage(t)
		message.AttachReadSeeker("attachment.txt", bytes.NewReader(teststring))
		messageBuffer := bytes.NewBuffer(nil)
		altBuffer := bytes.NewBuffer(nil)
		// First write
		n1, err := message.WriteTo(messageBuffer)
		if err != nil {
			t.Fatalf("failed to write message to buffer: %s", err)
		}
		// Second write
		n2, err := message.WriteTo(altBuffer)
		if err != nil {
			t.Fatalf("failed to write message to alternative buffer: %s", err)
		}
		if n1 != n2 {
			t.Errorf("number of written bytes between consecutive writes differ, got: %d and %d", n1, n2)
		}
		if !strings.Contains(messageBuffer.String(), "VGhpcyBpcyBhIHRlc3Qgc3RyaW5n") {
			t.Errorf("expected string not found in message buffer, want: %s, got: %s",
				"VGhpcyBpcyBhIHRlc3Qgc3RyaW5n", messageBuffer.String())
		}
		if !strings.Contains(altBuffer.String(), "VGhpcyBpcyBhIHRlc3Qgc3RyaW5n") {
			t.Errorf("expected string not found in alternative message buffer, want: %s, got: %s",
				"VGhpcyBpcyBhIHRlc3Qgc3RyaW5n", altBuffer.String())
		}
	})
}

func TestMsg_AttachHTMLTemplate(t *testing.T) {
	tplString := `<p>{{.teststring}}</p>`
	invalidTplString := `<p>{{call $.invalid .teststring}}</p>`
	data := map[string]interface{}{"teststring": "this is a test"}
	htmlTpl, err := ht.New("htmltpl").Parse(tplString)
	if err != nil {
		t.Fatalf("failed to parse HTML template: %s", err)
	}
	invalidTpl, err := ht.New("htmltpl").Parse(invalidTplString)
	if err != nil {
		t.Fatalf("failed to parse invalid HTML template: %s", err)
	}
	t.Run("AttachHTMLTemplate with valid template", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err = message.AttachHTMLTemplate("attachment.html", htmlTpl, data); err != nil {
			t.Fatalf("failed to set body HTML template: %s", err)
		}
		attachments := message.GetAttachments()
		if len(attachments) != 1 {
			t.Fatalf("failed to retrieve attachments list")
		}
		if attachments[0] == nil {
			t.Fatal("expected attachment to be not nil")
		}
		if attachments[0].Name != "attachment.html" {
			t.Errorf("expected attachment name to be %s, got: %s", "attachment.html", attachments[0].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = attachments[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "<p>this is a test</p>") {
			t.Errorf("expected message body to be %s, got: %s", "<p>this is a test</p>", got)
		}
	})
	t.Run("AttachHTMLTemplate with invalid template", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err = message.AttachHTMLTemplate("attachment.html", invalidTpl, data)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		expectErr := `failed to attach template: failed to execute template: template: htmltpl:1:5: executing "htmltpl" ` +
			`at <call $.invalid .teststring>: error calling call: call of nil`
		if !strings.EqualFold(err.Error(), expectErr) {
			t.Errorf("expected error to be %s, got: %s", expectErr, err.Error())
		}
	})
	t.Run("AttachHTMLTemplate with nil template", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err = message.AttachHTMLTemplate("attachment.html", nil, data)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		expectedErr := `failed to attach template: ` + errTplPointerNil
		if !strings.EqualFold(err.Error(), expectedErr) {
			t.Errorf("expected error to be %s, got: %s", expectedErr, err.Error())
		}
	})
}

func TestMsg_AttachTextTemplate(t *testing.T) {
	tplString := `Teststring: {{.teststring}}`
	invalidTplString := `Teststring: {{call $.invalid .teststring}}`
	data := map[string]interface{}{"teststring": "this is a test"}
	textTpl, err := ttpl.New("texttpl").Parse(tplString)
	if err != nil {
		t.Fatalf("failed to parse Text template: %s", err)
	}
	invalidTpl, err := ttpl.New("texttpl").Parse(invalidTplString)
	if err != nil {
		t.Fatalf("failed to parse invalid Text template: %s", err)
	}
	t.Run("AttachTextTemplate with valid template", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err = message.AttachTextTemplate("attachment.txt", textTpl, data); err != nil {
			t.Fatalf("failed to set body HTML template: %s", err)
		}
		attachments := message.GetAttachments()
		if len(attachments) != 1 {
			t.Fatalf("failed to retrieve attachments list")
		}
		if attachments[0] == nil {
			t.Fatal("expected attachment to be not nil")
		}
		if attachments[0].Name != "attachment.txt" {
			t.Errorf("expected attachment name to be %s, got: %s", "attachment.txt", attachments[0].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = attachments[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "Teststring: this is a test") {
			t.Errorf("expected message body to be %s, got: %s", "Teststring: this is a test", got)
		}
	})
	t.Run("AttachTextTemplate with invalid template", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err = message.AttachTextTemplate("attachment.txt", invalidTpl, data)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		expectErr := `failed to attach template: failed to execute template: template: texttpl:1:14: executing "texttpl" ` +
			`at <call $.invalid .teststring>: error calling call: call of nil`
		if !strings.EqualFold(err.Error(), expectErr) {
			t.Errorf("expected error to be %s, got: %s", expectErr, err.Error())
		}
	})
	t.Run("AttachTextTemplate with nil template", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err = message.AttachTextTemplate("attachment.html", nil, data)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		expectedErr := `failed to attach template: ` + errTplPointerNil
		if !strings.EqualFold(err.Error(), expectedErr) {
			t.Errorf("expected error to be %s, got: %s", expectedErr, err.Error())
		}
	})
}

func TestMsg_AttachFromEmbedFS(t *testing.T) {
	t.Run("AttachFromEmbedFS successful", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.AttachFromEmbedFS("testdata/attachment.txt", &efs,
			WithFileName("attachment.txt")); err != nil {
			t.Fatalf("failed to attach from embed FS: %s", err)
		}
		attachments := message.GetAttachments()
		if len(attachments) != 1 {
			t.Fatalf("failed to retrieve attachments list")
		}
		if attachments[0] == nil {
			t.Fatal("expected attachment to be not nil")
		}
		if attachments[0].Name != "attachment.txt" {
			t.Errorf("expected attachment name to be %s, got: %s", "attachment.txt", attachments[0].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err := attachments[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is a test attachment") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test attachment", got)
		}
	})
	t.Run("AttachFromEmbedFS with invalid path", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err := message.AttachFromEmbedFS("testdata/invalid.txt", &efs, WithFileName("attachment.txt"))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
	t.Run("AttachFromEmbedFS with nil embed FS", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err := message.AttachFromEmbedFS("testdata/invalid.txt", nil, WithFileName("attachment.txt"))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestMsg_AttachFromIOFS(t *testing.T) {
	t.Run("AttachFromIOFS successful", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.AttachFromIOFS("testdata/attachment.txt", efs,
			WithFileName("attachment.txt")); err != nil {
			t.Fatalf("failed to attach from embed FS: %s", err)
		}
		attachments := message.GetAttachments()
		if len(attachments) != 1 {
			t.Fatalf("failed to retrieve attachments list")
		}
		if attachments[0] == nil {
			t.Fatal("expected attachment to be not nil")
		}
		if attachments[0].Name != "attachment.txt" {
			t.Errorf("expected attachment name to be %s, got: %s", "attachment.txt", attachments[0].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err := attachments[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is a test attachment") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test attachment", got)
		}
	})
	t.Run("AttachFromIOFS with invalid path", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err := message.AttachFromIOFS("testdata/invalid.txt", efs, WithFileName("attachment.txt"))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
	t.Run("AttachFromIOFS with nil embed FS", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err := message.AttachFromIOFS("testdata/invalid.txt", nil, WithFileName("attachment.txt"))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
	t.Run("AttachFromIOFS with fs.FS fails on copy", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.AttachFromIOFS("testdata/attachment.txt", efs); err != nil {
			t.Fatalf("failed to attach file from fs.FS: %s", err)
		}
		attachments := message.GetAttachments()
		if len(attachments) != 1 {
			t.Fatalf("failed to get attachments, expected 1, got: %d", len(attachments))
		}
		_, err := attachments[0].Writer(failReadWriteSeekCloser{})
		if err == nil {
			t.Error("writer func expected to fail, but didn't")
		}
	})
}

func TestMsg_EmbedFile(t *testing.T) {
	t.Run("EmbedFile with file", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.EmbedFile("testdata/embed.txt")
		embeds := message.GetEmbeds()
		if len(embeds) != 1 {
			t.Fatalf("failed to retrieve embeds list")
		}
		if embeds[0] == nil {
			t.Fatal("expected embed to be not nil")
		}
		if embeds[0].Name != "embed.txt" {
			t.Errorf("expected embed name to be %s, got: %s", "embed.txt", embeds[0].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err := embeds[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is a test embed") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test embed", got)
		}
	})
	t.Run("EmbedFile with non-existent file", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.EmbedFile("testdata/non-existent-file.txt")
		embeds := message.GetEmbeds()
		if len(embeds) != 0 {
			t.Fatalf("failed to retrieve attachments list")
		}
	})
	t.Run("EmbedFile with fileFromFS fails on copy", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.EmbedFile("testdata/embed.txt")
		emebeds := message.GetEmbeds()
		if len(emebeds) != 1 {
			t.Fatalf("failed to get emebeds, expected 1, got: %d", len(emebeds))
		}
		_, err := emebeds[0].Writer(failReadWriteSeekCloser{})
		if err == nil {
			t.Error("writer func expected to fail, but didn't")
		}
	})
	t.Run("EmbedFile with options", func(t *testing.T) {
		t.Log("all options have already been tested in file_test.go")
	})
}

func TestMsg_EmbedReader(t *testing.T) {
	t.Run("EmbedReader with file", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		file, err := os.Open("testdata/embed.txt")
		if err != nil {
			t.Fatalf("failed to open file: %s", err)
		}
		t.Cleanup(func() {
			if err := file.Close(); err != nil {
				t.Errorf("failed to close file: %s", err)
			}
		})
		if err = message.EmbedReader("embed.txt", file); err != nil {
			t.Fatalf("failed to embed reader: %s", err)
		}
		embeds := message.GetEmbeds()
		if len(embeds) != 1 {
			t.Fatalf("failed to retrieve embeds list")
		}
		if embeds[0] == nil {
			t.Fatal("expected embed to be not nil")
		}
		if embeds[0].Name != "embed.txt" {
			t.Errorf("expected embed name to be %s, got: %s", "embed.txt", embeds[0].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = embeds[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is a test embed") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test embed", got)
		}
	})
	t.Run("EmbedReader with fileFromReader fails on copy", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		file, err := os.Open("testdata/embed.txt")
		if err != nil {
			t.Fatalf("failed to open file: %s", err)
		}
		t.Cleanup(func() {
			if err := file.Close(); err != nil {
				t.Errorf("failed to close file: %s", err)
			}
		})
		if err = message.EmbedReader("embed.txt", file); err != nil {
			t.Fatalf("failed to embed reader: %s", err)
		}
		embeds := message.GetEmbeds()
		if len(embeds) != 1 {
			t.Fatalf("failed to get embeds, expected 1, got: %d", len(embeds))
		}
		_, err = embeds[0].Writer(failReadWriteSeekCloser{})
		if err == nil {
			t.Error("writer func expected to fail, but didn't")
		}
	})
	t.Run("EmbedReader with fileFromReader on closed reader", func(t *testing.T) {
		tempfile, err := os.CreateTemp("", "embedfile-close-reader.*.txt")
		if err != nil {
			t.Fatalf("failed to create temp file: %s", err)
		}
		if err = tempfile.Close(); err != nil {
			t.Fatalf("failed to close temp file: %s", err)
		}
		t.Cleanup(func() {
			if err := os.Remove(tempfile.Name()); err != nil {
				t.Errorf("failed to remove temp file: %s", err)
			}
		})
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err = message.EmbedReader("embed.txt", tempfile); err == nil {
			t.Fatalf("expected error, got nil")
		}
	})
	// Tests the Msg.EmbedReader methods with consecutive calls to Msg.WriteTo to make sure
	// the attachments are not lost.
	// https://github.com/wneessen/go-mail/issues/110
	t.Run("EmbedReader with consecutive writes", func(t *testing.T) {
		teststring := "This is a test string"
		message := testMessage(t)
		if err := message.EmbedReader("embed.txt", bytes.NewBufferString(teststring)); err != nil {
			t.Fatalf("failed to embed teststring buffer: %s", err)
		}
		messageBuffer := bytes.NewBuffer(nil)
		altBuffer := bytes.NewBuffer(nil)
		// First write
		n1, err := message.WriteTo(messageBuffer)
		if err != nil {
			t.Fatalf("failed to write message to buffer: %s", err)
		}
		// Second write
		n2, err := message.WriteTo(altBuffer)
		if err != nil {
			t.Fatalf("failed to write message to alternative buffer: %s", err)
		}
		if n1 != n2 {
			t.Errorf("number of written bytes between consecutive writes differ, got: %d and %d", n1, n2)
		}
		if !strings.Contains(messageBuffer.String(), "VGhpcyBpcyBhIHRlc3Qgc3RyaW5n") {
			t.Errorf("expected string not found in message buffer, want: %s, got: %s",
				"VGhpcyBpcyBhIHRlc3Qgc3RyaW5n", messageBuffer.String())
		}
		if !strings.Contains(altBuffer.String(), "VGhpcyBpcyBhIHRlc3Qgc3RyaW5n") {
			t.Errorf("expected string not found in alternative message buffer, want: %s, got: %s",
				"VGhpcyBpcyBhIHRlc3Qgc3RyaW5n", altBuffer.String())
		}
	})
}

func TestMsg_EmbedReadSeeker(t *testing.T) {
	t.Run("EmbedReadSeeker with file", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		file, err := os.Open("testdata/embed.txt")
		if err != nil {
			t.Fatalf("failed to open file: %s", err)
		}
		t.Cleanup(func() {
			if err := file.Close(); err != nil {
				t.Errorf("failed to close file: %s", err)
			}
		})
		message.EmbedReadSeeker("embed.txt", file)
		embeds := message.GetEmbeds()
		if len(embeds) != 1 {
			t.Fatalf("failed to retrieve embeds list")
		}
		if embeds[0] == nil {
			t.Fatal("expected embed to be not nil")
		}
		if embeds[0].Name != "embed.txt" {
			t.Errorf("expected embed name to be %s, got: %s", "embed.txt", embeds[0].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = embeds[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is a test embed") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test embed", got)
		}
	})
	t.Run("EmbedReadSeeker with fileFromReadSeeker fails on copy", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		file, err := os.Open("testdata/embed.txt")
		if err != nil {
			t.Fatalf("failed to open file: %s", err)
		}
		t.Cleanup(func() {
			if err := file.Close(); err != nil {
				t.Errorf("failed to close file: %s", err)
			}
		})
		message.EmbedReadSeeker("embed.txt", file)
		embeds := message.GetEmbeds()
		if len(embeds) != 1 {
			t.Fatalf("failed to get embeds, expected 1, got: %d", len(embeds))
		}
		_, err = embeds[0].Writer(failReadWriteSeekCloser{})
		if err == nil {
			t.Error("writer func expected to fail, but didn't")
		}
	})
	// Tests the Msg.EmbedReadSeeker methods with consecutive calls to Msg.WriteTo to make sure
	// the attachments are not lost.
	// https://github.com/wneessen/go-mail/issues/110
	t.Run("EmbedReadSeeker with consecutive writes", func(t *testing.T) {
		teststring := []byte("This is a test string")
		message := testMessage(t)
		message.EmbedReadSeeker("embed.txt", bytes.NewReader(teststring))
		messageBuffer := bytes.NewBuffer(nil)
		altBuffer := bytes.NewBuffer(nil)
		// First write
		n1, err := message.WriteTo(messageBuffer)
		if err != nil {
			t.Fatalf("failed to write message to buffer: %s", err)
		}
		// Second write
		n2, err := message.WriteTo(altBuffer)
		if err != nil {
			t.Fatalf("failed to write message to alternative buffer: %s", err)
		}
		if n1 != n2 {
			t.Errorf("number of written bytes between consecutive writes differ, got: %d and %d", n1, n2)
		}
		if !strings.Contains(messageBuffer.String(), "VGhpcyBpcyBhIHRlc3Qgc3RyaW5n") {
			t.Errorf("expected string not found in message buffer, want: %s, got: %s",
				"VGhpcyBpcyBhIHRlc3Qgc3RyaW5n", messageBuffer.String())
		}
		if !strings.Contains(altBuffer.String(), "VGhpcyBpcyBhIHRlc3Qgc3RyaW5n") {
			t.Errorf("expected string not found in alternative message buffer, want: %s, got: %s",
				"VGhpcyBpcyBhIHRlc3Qgc3RyaW5n", altBuffer.String())
		}
	})
}

func TestMsg_EmbedHTMLTemplate(t *testing.T) {
	tplString := `<p>{{.teststring}}</p>`
	invalidTplString := `<p>{{call $.invalid .teststring}}</p>`
	data := map[string]interface{}{"teststring": "this is a test"}
	htmlTpl, err := ht.New("htmltpl").Parse(tplString)
	if err != nil {
		t.Fatalf("failed to parse HTML template: %s", err)
	}
	invalidTpl, err := ht.New("htmltpl").Parse(invalidTplString)
	if err != nil {
		t.Fatalf("failed to parse invalid HTML template: %s", err)
	}
	t.Run("EmbedHTMLTemplate with valid template", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err = message.EmbedHTMLTemplate("embed.html", htmlTpl, data); err != nil {
			t.Fatalf("failed to set body HTML template: %s", err)
		}
		embeds := message.GetEmbeds()
		if len(embeds) != 1 {
			t.Fatalf("failed to retrieve embeds list")
		}
		if embeds[0] == nil {
			t.Fatal("expected embed to be not nil")
		}
		if embeds[0].Name != "embed.html" {
			t.Errorf("expected embed name to be %s, got: %s", "embed.html", embeds[0].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = embeds[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "<p>this is a test</p>") {
			t.Errorf("expected message body to be %s, got: %s", "<p>this is a test</p>", got)
		}
	})
	t.Run("EmbedHTMLTemplate with invalid template", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err = message.EmbedHTMLTemplate("embed.html", invalidTpl, data)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		expectErr := `failed to embed template: failed to execute template: template: htmltpl:1:5: executing "htmltpl" ` +
			`at <call $.invalid .teststring>: error calling call: call of nil`
		if !strings.EqualFold(err.Error(), expectErr) {
			t.Errorf("expected error to be %s, got: %s", expectErr, err.Error())
		}
	})
	t.Run("EmbedHTMLTemplate with nil template", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err = message.EmbedHTMLTemplate("embed.html", nil, data)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		expectedErr := `failed to embed template: ` + errTplPointerNil
		if !strings.EqualFold(err.Error(), expectedErr) {
			t.Errorf("expected error to be %s, got: %s", expectedErr, err.Error())
		}
	})
}

func TestMsg_EmbedTextTemplate(t *testing.T) {
	tplString := `Teststring: {{.teststring}}`
	invalidTplString := `Teststring: {{call $.invalid .teststring}}`
	data := map[string]interface{}{"teststring": "this is a test"}
	textTpl, err := ttpl.New("texttpl").Parse(tplString)
	if err != nil {
		t.Fatalf("failed to parse Text template: %s", err)
	}
	invalidTpl, err := ttpl.New("texttpl").Parse(invalidTplString)
	if err != nil {
		t.Fatalf("failed to parse invalid Text template: %s", err)
	}
	t.Run("EmbedTextTemplate with valid template", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err = message.EmbedTextTemplate("embed.txt", textTpl, data); err != nil {
			t.Fatalf("failed to set body HTML template: %s", err)
		}
		embeds := message.GetEmbeds()
		if len(embeds) != 1 {
			t.Fatalf("failed to retrieve embeds list")
		}
		if embeds[0] == nil {
			t.Fatal("expected embed to be not nil")
		}
		if embeds[0].Name != "embed.txt" {
			t.Errorf("expected embed name to be %s, got: %s", "embed.txt", embeds[0].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = embeds[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "Teststring: this is a test") {
			t.Errorf("expected message body to be %s, got: %s", "Teststring: this is a test", got)
		}
	})
	t.Run("EmbedTextTemplate with invalid template", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err = message.EmbedTextTemplate("embed.txt", invalidTpl, data)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		expectErr := `failed to embed template: failed to execute template: template: texttpl:1:14: executing "texttpl" ` +
			`at <call $.invalid .teststring>: error calling call: call of nil`
		if !strings.EqualFold(err.Error(), expectErr) {
			t.Errorf("expected error to be %s, got: %s", expectErr, err.Error())
		}
	})
	t.Run("EmbedTextTemplate with nil template", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err = message.EmbedTextTemplate("embed.html", nil, data)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		expectedErr := `failed to embed template: ` + errTplPointerNil
		if !strings.EqualFold(err.Error(), expectedErr) {
			t.Errorf("expected error to be %s, got: %s", expectedErr, err.Error())
		}
	})
}

func TestMsg_EmbedFromEmbedFS(t *testing.T) {
	t.Run("EmbedFromEmbedFS successful", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.EmbedFromEmbedFS("testdata/embed.txt", &efs,
			WithFileName("embed.txt")); err != nil {
			t.Fatalf("failed to embed from embed FS: %s", err)
		}
		embeds := message.GetEmbeds()
		if len(embeds) != 1 {
			t.Fatalf("failed to retrieve embeds list")
		}
		if embeds[0] == nil {
			t.Fatal("expected embed to be not nil")
		}
		if embeds[0].Name != "embed.txt" {
			t.Errorf("expected embed name to be %s, got: %s", "embed.txt", embeds[0].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err := embeds[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is a test embed") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test embed", got)
		}
	})
	t.Run("EmbedFromEmbedFS with invalid path", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err := message.EmbedFromEmbedFS("testdata/invalid.txt", &efs, WithFileName("embed.txt"))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
	t.Run("EmbedFromEmbedFS with nil embed FS", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err := message.EmbedFromEmbedFS("testdata/invalid.txt", nil, WithFileName("embed.txt"))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestMsg_EmbedFromIOFS(t *testing.T) {
	t.Run("EmbedFromIOFS successful", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		if err := message.EmbedFromIOFS("testdata/embed.txt", efs,
			WithFileName("embed.txt")); err != nil {
			t.Fatalf("failed to embed from embed FS: %s", err)
		}
		embeds := message.GetEmbeds()
		if len(embeds) != 1 {
			t.Fatalf("failed to retrieve embeds list")
		}
		if embeds[0] == nil {
			t.Fatal("expected embed to be not nil")
		}
		if embeds[0].Name != "embed.txt" {
			t.Errorf("expected embed name to be %s, got: %s", "embed.txt", embeds[0].Name)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err := embeds[0].Writer(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.EqualFold(got, "This is a test embed") {
			t.Errorf("expected message body to be %s, got: %s", "This is a test embed", got)
		}
	})
	t.Run("EmbedFromIOFS with invalid path", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err := message.EmbedFromIOFS("testdata/invalid.txt", efs, WithFileName("embed.txt"))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
	t.Run("EmbedFromIOFS with nil embed FS", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		err := message.EmbedFromIOFS("testdata/invalid.txt", nil, WithFileName("embed.txt"))
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}

func TestMsg_Reset(t *testing.T) {
	message := NewMsg()
	if message == nil {
		t.Fatal("message is nil")
	}
	if err := message.From("toni.tester@example.com"); err != nil {
		t.Fatalf("failed to set From address: %s", err)
	}
	if err := message.To("tina.tester@example.com"); err != nil {
		t.Fatalf("failed to set To address: %s", err)
	}
	message.Subject("This is the subject")
	message.SetBodyString(TypeTextPlain, "This is the body")
	message.AddAlternativeString(TypeTextPlain, "This is the alternative string")
	message.EmbedFile("testdata/embed.txt")
	message.AttachFile("testdata/attach.txt")

	message.Reset()
	if len(message.GetFromString()) != 0 {
		t.Errorf("expected message From address to be empty, got: %+v", message.GetFromString())
	}
	if len(message.GetToString()) != 0 {
		t.Errorf("expected message To address to be empty, got: %+v", message.GetFromString())
	}
	if len(message.GetGenHeader(HeaderSubject)) != 0 {
		t.Errorf("expected message Subject to be empty, got: %+v", message.GetGenHeader(HeaderSubject))
	}
	if len(message.GetAttachments()) != 0 {
		t.Errorf("expected message Attachments to be empty, got: %d", len(message.GetAttachments()))
	}
	if len(message.GetEmbeds()) != 0 {
		t.Errorf("expected message Embeds to be empty, got: %d", len(message.GetEmbeds()))
	}
	if len(message.GetParts()) != 0 {
		t.Errorf("expected message Parts to be empty, got: %d", len(message.GetParts()))
	}
}

func TestMsg_applyMiddlewares(t *testing.T) {
	t.Run("new message with middleware: uppercase", func(t *testing.T) {
		tests := []struct {
			subject string
			want    string
		}{
			{"This is test subject", "THIS IS TEST SUBJECT"},
			{"This is also a test subject", "THIS IS ALSO A TEST SUBJECT"},
		}

		for _, tt := range tests {
			t.Run(tt.subject, func(t *testing.T) {
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
				message.Subject(tt.subject)
				checkGenHeader(t, message, HeaderSubject, "applyMiddleware", 0, 1, tt.subject)
				message = message.applyMiddlewares(message)
				checkGenHeader(t, message, HeaderSubject, "applyMiddleware", 0, 1, tt.want)
			})
		}
	})
	t.Run("new message with middleware: encode", func(t *testing.T) {
		tests := []struct {
			subject string
			want    string
		}{
			{"This is a test subject", "This is @ test subject"},
			{"This is also a test subject", "This is @lso @ test subject"},
		}

		for _, tt := range tests {
			t.Run(tt.subject, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				if len(message.middlewares) != 0 {
					t.Errorf("NewMsg() failed. Expected empty middlewares, got: %d", len(message.middlewares))
				}
				message = NewMsg(WithMiddleware(encodeMiddleware{}))
				if len(message.middlewares) != 1 {
					t.Errorf("NewMsg(WithMiddleware(encodeMiddleware{})) failed. Expected 1 middleware, got: %d",
						len(message.middlewares))
				}
				message.Subject(tt.subject)
				checkGenHeader(t, message, HeaderSubject, "applyMiddleware", 0, 1, tt.subject)
				message = message.applyMiddlewares(message)
				checkGenHeader(t, message, HeaderSubject, "applyMiddleware", 0, 1, tt.want)
			})
		}
	})
	t.Run("new message with middleware: uppercase and encode", func(t *testing.T) {
		tests := []struct {
			subject string
			want    string
		}{
			{"This is a test subject", "THIS IS @ TEST SUBJECT"},
			{"This is also a test subject", "THIS IS @LSO @ TEST SUBJECT"},
		}

		for _, tt := range tests {
			t.Run(tt.subject, func(t *testing.T) {
				message := NewMsg()
				if message == nil {
					t.Fatal("message is nil")
				}
				if len(message.middlewares) != 0 {
					t.Errorf("NewMsg() failed. Expected empty middlewares, got: %d", len(message.middlewares))
				}
				message = NewMsg(WithMiddleware(encodeMiddleware{}), WithMiddleware(uppercaseMiddleware{}))
				if len(message.middlewares) != 2 {
					t.Errorf("NewMsg(WithMiddleware(encodeMiddleware{})) failed. Expected 2 middlewares, got: %d",
						len(message.middlewares))
				}
				message.Subject(tt.subject)
				checkGenHeader(t, message, HeaderSubject, "applyMiddleware", 0, 1, tt.subject)
				message = message.applyMiddlewares(message)
				checkGenHeader(t, message, HeaderSubject, "applyMiddleware", 0, 1, tt.want)
			})
		}
	})
}

func TestMsg_WriteTo(t *testing.T) {
	t.Run("WriteTo memory buffer with normal mail parts", func(t *testing.T) {
		message := testMessage(t)
		buffer := bytes.NewBuffer(nil)
		if _, err := message.WriteTo(buffer); err != nil {
			t.Fatalf("failed to write message to buffer: %s", err)
		}
		parsed, err := EMLToMsgFromReader(buffer)
		if err != nil {
			t.Fatalf("failed to parse message in buffer: %s", err)
		}
		checkAddrHeader(t, parsed, HeaderFrom, "WriteTo", 0, 1, TestSenderValid, "")
		checkAddrHeader(t, parsed, HeaderTo, "WriteTo", 0, 1, TestRcptValid, "")
		checkGenHeader(t, parsed, HeaderSubject, "WriteTo", 0, 1, "Testmail")
		parts := parsed.GetParts()
		if len(parts) != 1 {
			t.Fatalf("expected 1 parts, got: %d", len(parts))
		}
		if parts[0].contentType != TypeTextPlain {
			t.Errorf("expected contentType to be %s, got: %s", TypeTextPlain, parts[0].contentType)
		}
		if parts[0].encoding != EncodingQP {
			t.Errorf("expected encoding to be %s, got: %s", EncodingQP, parts[0].encoding)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = parts[0].writeFunc(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.HasSuffix(got, "Testmail") {
			t.Errorf("expected message buffer to contain Testmail, got: %s", got)
		}
	})
	t.Run("WriteTo fails to write", func(t *testing.T) {
		message := testMessage(t)
		_, err := message.WriteTo(failReadWriteSeekCloser{})
		if err == nil {
			t.Fatalf("writing to failReadWriteSeekCloser should fail")
		}
		if strings.EqualFold(err.Error(), "failed to write message to buffer: intentional write failure") {
			t.Fatalf("expected error to be: failed to write message to buffer: intentional write failure, got: %s",
				err)
		}
	})
	t.Run("WriteTo with long headers", func(t *testing.T) {
		message := testMessage(t)
		message.SetGenHeader(HeaderContentLang, "de", "en", "fr", "es", "xxxx", "yyyy", "de", "en", "fr",
			"es", "xxxx", "yyyy", "de", "en", "fr", "es", "xxxx", "yyyy", "de", "en", "fr")
		message.SetGenHeader(HeaderContentID, "XXXXXXXXXXXXXXX XXXXXXXXXXXXXXX XXXXXXXXXXXXXXXXXX "+
			"XXXXXXXXXXXXXXXXXXXXXX XXXXXXXXXXXXX XXXXXXXXXXXXXXXXXXX XXXXXXXXXXXXXXXXXXX XXXXXXXXXXXXXXXXXXXXXXXXXXX")
		messageBuffer := bytes.NewBuffer(nil)
		n, err := message.WriteTo(messageBuffer)
		if err != nil {
			t.Fatalf("failed to write message to buffer: %s", err)
		}
		if n != int64(messageBuffer.Len()) {
			t.Errorf("expected written bytes: %d, got: %d", n, messageBuffer.Len())
		}
	})
	t.Run("WriteTo with multiple writes", func(t *testing.T) {
		message := testMessage(t)
		buffer := bytes.NewBuffer(nil)
		messageBuf := bytes.NewBuffer(nil)
		for i := 0; i < 10; i++ {
			t.Run(fmt.Sprintf("write %d", i), func(t *testing.T) {
				if _, err := message.WriteTo(buffer); err != nil {
					t.Fatalf("failed to write message to buffer: %s", err)
				}
				parsed, err := EMLToMsgFromReader(buffer)
				if err != nil {
					t.Fatalf("failed to parse message in buffer: %s", err)
				}
				checkAddrHeader(t, parsed, HeaderFrom, "WriteTo", 0, 1, TestSenderValid, "")
				checkAddrHeader(t, parsed, HeaderTo, "WriteTo", 0, 1, TestRcptValid, "")
				checkGenHeader(t, parsed, HeaderSubject, "WriteTo", 0, 1, "Testmail")
				parts := parsed.GetParts()
				if len(parts) != 1 {
					t.Fatalf("expected 1 parts, got: %d", len(parts))
				}
				if parts[0].contentType != TypeTextPlain {
					t.Errorf("expected contentType to be %s, got: %s", TypeTextPlain, parts[0].contentType)
				}
				if parts[0].encoding != EncodingQP {
					t.Errorf("expected encoding to be %s, got: %s", EncodingQP, parts[0].encoding)
				}
				_, err = parts[0].writeFunc(messageBuf)
				if err != nil {
					t.Errorf("writer func failed: %s", err)
				}
				got := strings.TrimSpace(messageBuf.String())
				if !strings.HasSuffix(got, "Testmail") {
					t.Errorf("expected message buffer to contain Testmail, got: %s", got)
				}
				buffer.Reset()
			})
		}
	})
	t.Run("WriteTo with S/MIME signing", func(t *testing.T) {
		keypair, err := getDummyKeyPairTLS()
		if err != nil {
			t.Fatalf("failed to get dummy key material: %s", err)
		}
		message := testMessage(t)
		if err = message.SignWithTLSCertificate(keypair); err != nil {
			t.Fatalf("failed to initialize S/MIME signing: %s", err)
		}
		buffer := bytes.NewBuffer(nil)
		if _, err = message.WriteTo(buffer); err != nil {
			t.Errorf("failed to write S/MIME signed message to buffer: %s", err)
		}
		if !strings.Contains(buffer.String(), TypeSMIMESigned.String()) {
			t.Error("expected message to be S/MIME signature Content-Type in mail body")
		}
		if !strings.Contains(buffer.String(), `application/pkcs7-signature; name="smime.p7s"`) {
			t.Error("expected message to be S/MIME signature attachment in mail body")
		}
	})
	t.Run("WriteTo with S/MIME signing on multipart/alternative message", func(t *testing.T) {
		keypair, err := getDummyKeyPairTLS()
		if err != nil {
			t.Fatalf("failed to get dummy key material: %s", err)
		}
		message := testMessage(t)
		message.AddAlternativeString(TypeTextHTML, "<p>HTML alternative</p>")
		if err = message.SignWithTLSCertificate(keypair); err != nil {
			t.Fatalf("failed to initialize S/MIME signing: %s", err)
		}
		buffer := bytes.NewBuffer(nil)
		if _, err = message.WriteTo(buffer); err != nil {
			t.Errorf("failed to write S/MIME signed message to buffer: %s", err)
		}
		if !strings.Contains(buffer.String(), TypeSMIMESigned.String()) {
			t.Error("expected message to be S/MIME signature Content-Type in mail body")
		}
		if !strings.Contains(buffer.String(), `application/pkcs7-signature; name="smime.p7s"`) {
			t.Error("expected message to be S/MIME signature attachment in mail body")
		}
		if !strings.Contains(buffer.String(), TypeTextHTML.String()) {
			t.Error("expected message to have HTML alternative in mail body")
		}
		if !strings.Contains(buffer.String(), TypeMultipartAlternative.String()) {
			t.Error("expected message to have multipart/alternative in mail body")
		}
		if !strings.Contains(buffer.String(), "<p>HTML alternative</p>") {
			t.Error("expected message to have HTML alternative in mail body")
		}
	})
	t.Run("WriteTo with S/MIME signing on multipart/mixed message", func(t *testing.T) {
		keypair, err := getDummyKeyPairTLS()
		if err != nil {
			t.Fatalf("failed to get dummy key material: %s", err)
		}
		message := testMessage(t)
		message.AttachFile("testdata/attachment.txt")
		if err = message.SignWithTLSCertificate(keypair); err != nil {
			t.Fatalf("failed to initialize S/MIME signing: %s", err)
		}
		buffer := bytes.NewBuffer(nil)
		if _, err = message.WriteTo(buffer); err != nil {
			t.Errorf("failed to write S/MIME signed message to buffer: %s", err)
		}
		if !strings.Contains(buffer.String(), TypeSMIMESigned.String()) {
			t.Error("expected message to be S/MIME signature Content-Type in mail body")
		}
		if !strings.Contains(buffer.String(), `application/pkcs7-signature; name="smime.p7s"`) {
			t.Error("expected message to be S/MIME signature attachment in mail body")
		}
		if !strings.Contains(buffer.String(), TypeMultipartMixed.String()) {
			t.Error("expected message to have multipart/mixed in mail body")
		}
		if !strings.Contains(buffer.String(), "attachment.txt") {
			t.Error("expected message to have attachment in mail body")
		}
	})
	t.Run("WriteTo with S/MIME signing on multipart/related message", func(t *testing.T) {
		keypair, err := getDummyKeyPairTLS()
		if err != nil {
			t.Fatalf("failed to get dummy key material: %s", err)
		}
		message := testMessage(t)
		message.EmbedFile("testdata/embed.txt")
		if err = message.SignWithTLSCertificate(keypair); err != nil {
			t.Fatalf("failed to initialize S/MIME signing: %s", err)
		}
		buffer := bytes.NewBuffer(nil)
		if _, err = message.WriteTo(buffer); err != nil {
			t.Errorf("failed to write S/MIME signed message to buffer: %s", err)
		}
		if !strings.Contains(buffer.String(), TypeSMIMESigned.String()) {
			t.Error("expected message to be S/MIME signature Content-Type in mail body")
		}
		if !strings.Contains(buffer.String(), `application/pkcs7-signature; name="smime.p7s"`) {
			t.Error("expected message to be S/MIME signature attachment in mail body")
		}
		if !strings.Contains(buffer.String(), TypeMultipartRelated.String()) {
			t.Error("expected message to have multipart/related in mail body")
		}
		if !strings.Contains(buffer.String(), "embed.txt") {
			t.Error("expected message to have embedded file in mail body")
		}
	})
	t.Run("WriteTo with S/MIME signing fails with invalid key", func(t *testing.T) {
		keypair, err := getDummyKeyPairTLS()
		if err != nil {
			t.Fatalf("failed to get dummy key material: %s", err)
		}
		message := testMessage(t)
		if err = message.SignWithTLSCertificate(keypair); err != nil {
			t.Fatalf("failed to initialize S/MIME signing: %s", err)
		}
		message.sMIME.privateKey = unsupportedPrivKey{}

		buffer := bytes.NewBuffer(nil)
		_, err = message.WriteTo(buffer)
		if err == nil {
			t.Error("expected WritoTo with invalid S/MIME private key to fail")
		}
		expErr := "failed to sign message: could not add signer message: pkcs7: cannot convert encryption algorithm " +
			"to oid, unknown private key type"
		if !strings.Contains(err.Error(), expErr) {
			t.Errorf("expected S/MIME signing error to be: %s, got: %s", expErr, err)
		}
	})
	t.Run("WriteTo with S/MIME signing fails with broken rand.Reader", func(t *testing.T) {
		defaultRandReader := rand.Reader
		t.Cleanup(func() { rand.Reader = defaultRandReader })
		rand.Reader = &randReader{failon: 1}

		keypair, err := getDummyKeyPairTLS()
		if err != nil {
			t.Fatalf("failed to get dummy key material: %s", err)
		}
		message := testMessage(t)
		if err = message.SignWithTLSCertificate(keypair); err != nil {
			t.Fatalf("failed to initialize S/MIME signing: %s", err)
		}

		buffer := bytes.NewBuffer(nil)
		_, err = message.WriteTo(buffer)
		if err == nil {
			t.Error("expected WriteTo with invalid S/MIME private key to fail")
		}
		expErr := "broken reader"
		if !strings.Contains(err.Error(), expErr) {
			t.Errorf("expected S/MIME signing error to contain: %q, got: %s", expErr, err)
		}
	})
	t.Run("WriteTo Multipart plain text with attachment", func(t *testing.T) {
		message := testMessage(t)
		message.AttachFile("testdata/attachment.txt")
		buffer := bytes.NewBuffer(nil)
		if _, err := message.WriteTo(buffer); err != nil {
			t.Fatalf("failed to write message to buffer: %s", err)
		}
		wants := []msgContentTest{
			{0, "Date:", false, true, false},
			{1, "MIME-Version: 1.0", true, true, false},
			{2, "Message-ID: <", false, true, false},
			{2, ">", false, false, true},
			{8, "Content-Type: multipart/mixed;", true, true, false},
			{9, " boundary=", false, true, false},
			{10, "", true, false, false},
			{11, "--", false, true, false},
			{12, "Content-Transfer-Encoding: quoted-printable", true, true, false},
			{13, "Content-Type: text/plain; charset=UTF-8", true, true, false},
			{14, "", true, false, false},
			{15, "Testmail", true, true, false},
			{16, "--", false, true, false},
			{17, `Content-Disposition: attachment; filename="attachment.txt"`, true, true, false},
			{18, `Content-Transfer-Encoding: base64`, true, true, false},
			{19, `Content-Type: text/plain; charset=utf-8; name="attachment.txt"`, true, true, false},
			{20, "", true, false, false},
			{21, "VGhpcyBpcyBhIHRlc3Qg", false, true, false},
			{22, "", true, false, false},
			{23, "--", false, true, true},
		}
		checkMessageContent(t, buffer, wants)
	})
	t.Run("WriteTo Multipart plain text with alternative", func(t *testing.T) {
		message := testMessage(t)
		message.AddAlternativeString(TypeTextHTML, "<p>HTML alternative</p>")
		buffer := bytes.NewBuffer(nil)
		if _, err := message.WriteTo(buffer); err != nil {
			t.Fatalf("failed to write message to buffer: %s", err)
		}
		wants := []msgContentTest{
			{0, "Date:", false, true, false},
			{1, "MIME-Version: 1.0", true, true, false},
			{2, "Message-ID: <", false, true, false},
			{2, ">", false, false, true},
			{8, "Content-Type: multipart/alternative;", true, true, false},
			{9, " boundary=", false, true, false},
			{10, "", true, false, false},
			{11, "--", false, true, false},
			{12, "Content-Transfer-Encoding: quoted-printable", true, true, false},
			{13, "Content-Type: text/plain; charset=UTF-8", true, true, false},
			{14, "", true, false, false},
			{15, "Testmail", true, true, false},
			{16, "--", false, true, false},
			{17, `Content-Transfer-Encoding: quoted-printable`, true, true, false},
			{18, `Content-Type: text/html; charset=UTF-8`, true, true, false},
			{19, "", true, false, false},
			{20, `<p>HTML alternative</p>`, true, true, false},
			{21, "--", false, true, true},
		}
		checkMessageContent(t, buffer, wants)
	})
}

func TestMsg_WriteToFile(t *testing.T) {
	t.Run("WriteToFile with normal mail parts", func(t *testing.T) {
		tempfile, err := os.CreateTemp("", "testmail.*.eml")
		if err != nil {
			t.Fatalf("failed to create temp file: %s", err)
		}
		if err = tempfile.Close(); err != nil {
			t.Fatalf("failed to close temp file: %s", err)
		}
		if err = os.Remove(tempfile.Name()); err != nil {
			t.Fatalf("failed to remove temp file: %s", err)
		}

		message := testMessage(t)
		if err = message.WriteToFile(tempfile.Name()); err != nil {
			t.Fatalf("failed to write message to tempfile %q: %s", tempfile.Name(), err)
		}
		parsed, err := EMLToMsgFromFile(tempfile.Name())
		if err != nil {
			t.Fatalf("failed to parse message in buffer: %s", err)
		}
		checkAddrHeader(t, parsed, HeaderFrom, "WriteTo", 0, 1, TestSenderValid, "")
		checkAddrHeader(t, parsed, HeaderTo, "WriteTo", 0, 1, TestRcptValid, "")
		checkGenHeader(t, parsed, HeaderSubject, "WriteTo", 0, 1, "Testmail")
		parts := parsed.GetParts()
		if len(parts) != 1 {
			t.Fatalf("expected 1 parts, got: %d", len(parts))
		}
		if parts[0].contentType != TypeTextPlain {
			t.Errorf("expected contentType to be %s, got: %s", TypeTextPlain, parts[0].contentType)
		}
		if parts[0].encoding != EncodingQP {
			t.Errorf("expected encoding to be %s, got: %s", EncodingQP, parts[0].encoding)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = parts[0].writeFunc(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.HasSuffix(got, "Testmail") {
			t.Errorf("expected message buffer to contain Testmail, got: %s", got)
		}
	})
}

func TestMsg_Write(t *testing.T) {
	message := testMessage(t)
	if _, err := message.Write(io.Discard); err != nil {
		t.Fatalf("failed to write message to io.Discard: %s", err)
	}
	t.Log("Write() is just an alias to WriteTo(), which has already been tested.")
}

func TestMsg_WriteToSkipMiddleware(t *testing.T) {
	t.Run("WriteToSkipMiddleware with two middlewares, skipping uppercase", func(t *testing.T) {
		message := NewMsg(WithMiddleware(encodeMiddleware{}), WithMiddleware(uppercaseMiddleware{}))
		if message == nil {
			t.Fatal("failed to create new message")
		}
		if err := message.From(TestSenderValid); err != nil {
			t.Errorf("failed to set sender address: %s", err)
		}
		if err := message.To(TestRcptValid); err != nil {
			t.Errorf("failed to set recipient address: %s", err)
		}
		message.Subject("This is a test subject")
		message.SetBodyString(TypeTextPlain, "Testmail")

		buffer := bytes.NewBuffer(nil)
		if _, err := message.WriteToSkipMiddleware(buffer, uppercaseMiddleware{}.Type()); err != nil {
			t.Fatalf("failed to write message with middleware to buffer: %s", err)
		}
		parsed, err := EMLToMsgFromReader(buffer)
		if err != nil {
			t.Fatalf("failed to parse message in buffer: %s", err)
		}
		checkAddrHeader(t, parsed, HeaderFrom, "WriteTo", 0, 1, TestSenderValid, "")
		checkAddrHeader(t, parsed, HeaderTo, "WriteTo", 0, 1, TestRcptValid, "")
		checkGenHeader(t, parsed, HeaderSubject, "WriteTo", 0, 1, "This is @ test subject")
		parts := parsed.GetParts()
		if len(parts) != 1 {
			t.Fatalf("expected 1 parts, got: %d", len(parts))
		}
		if parts[0].contentType != TypeTextPlain {
			t.Errorf("expected contentType to be %s, got: %s", TypeTextPlain, parts[0].contentType)
		}
		if parts[0].encoding != EncodingQP {
			t.Errorf("expected encoding to be %s, got: %s", EncodingQP, parts[0].encoding)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = parts[0].writeFunc(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.HasSuffix(got, "Testmail") {
			t.Errorf("expected message buffer to contain Testmail, got: %s", got)
		}
	})
}

// TestMsg_WriteToSendmailWithContext tests the WriteToSendmailWithContext() method of the Msg
func TestMsg_WriteToSendmailWithContext(t *testing.T) {
	if os.Getenv("PERFORM_SENDMAIL_TESTS") != "true" {
		t.Skipf("PERFORM_SENDMAIL_TESTS variable is not set to true, skipping sendmail test")
	}

	if !hasSendmail() {
		t.Skipf("sendmail binary not found, skipping test")
	}
	tests := []struct {
		sendmailPath string
		shouldFail   bool
	}{
		{"/dev/null", true},
		{"/bin/cat", true},
		{"/is/invalid", true},
		{SendmailPath, false},
	}
	t.Run("WriteToSendmailWithContext on different paths", func(t *testing.T) {
		for _, tt := range tests {
			t.Run(tt.sendmailPath, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
				defer cancel()

				message := testMessage(t)
				err := message.WriteToSendmailWithContext(ctx, tt.sendmailPath)
				if err != nil && !tt.shouldFail {
					t.Errorf("failed to write message to sendmail: %s", err)
				}
				if err == nil && tt.shouldFail {
					t.Error("expected error, got nil")
				}
			})
		}
	})
	t.Run("WriteToSendmailWithContext on canceled context", func(t *testing.T) {
		if !hasSendmail() {
			t.Skipf("sendmail binary not found, skipping test")
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*1)
		cancel()

		message := testMessage(t)
		if err := message.WriteToSendmailWithContext(ctx, SendmailPath); err == nil {
			t.Fatalf("expected error on canceled context, got nil")
		}
	})
	t.Run("WriteToSendmailWithContext via WriteToSendmail", func(t *testing.T) {
		if !hasSendmail() {
			t.Skipf("sendmail binary not found, skipping test")
		}
		message := testMessage(t)
		if err := message.WriteToSendmail(); err != nil {
			t.Fatalf("failed to write message to sendmail: %s", err)
		}
	})
	t.Run("WriteToSendmailWithContext via WriteToSendmailWithCommand", func(t *testing.T) {
		if !hasSendmail() {
			t.Skipf("sendmail binary not found, skipping test")
		}
		message := testMessage(t)
		if err := message.WriteToSendmailWithCommand(SendmailPath); err != nil {
			t.Fatalf("failed to write message to sendmail: %s", err)
		}
	})
}

func TestMsg_NewReader(t *testing.T) {
	t.Run("NewReader succeeds", func(t *testing.T) {
		message := testMessage(t)
		reader := message.NewReader()
		if reader == nil {
			t.Fatalf("failed to create message reader")
		}
		if reader.Error() != nil {
			t.Errorf("failed to create message reader: %s", reader.Error())
		}
		parsed, err := EMLToMsgFromReader(reader)
		if err != nil {
			t.Fatalf("failed to parse message in buffer: %s", err)
		}
		checkAddrHeader(t, parsed, HeaderFrom, "WriteTo", 0, 1, TestSenderValid, "")
		checkAddrHeader(t, parsed, HeaderTo, "WriteTo", 0, 1, TestRcptValid, "")
		checkGenHeader(t, parsed, HeaderSubject, "WriteTo", 0, 1, "Testmail")
		parts := parsed.GetParts()
		if len(parts) != 1 {
			t.Fatalf("expected 1 parts, got: %d", len(parts))
		}
		if parts[0].contentType != TypeTextPlain {
			t.Errorf("expected contentType to be %s, got: %s", TypeTextPlain, parts[0].contentType)
		}
		if parts[0].encoding != EncodingQP {
			t.Errorf("expected encoding to be %s, got: %s", EncodingQP, parts[0].encoding)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = parts[0].writeFunc(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.HasSuffix(got, "Testmail") {
			t.Errorf("expected message buffer to contain Testmail, got: %s", got)
		}
	})
	t.Run("NewReader should fail on write", func(t *testing.T) {
		message := testMessage(t)
		if len(message.parts) != 1 {
			t.Fatalf("expected 1 parts, got: %d", len(message.parts))
		}
		message.parts[0].writeFunc = func(io.Writer) (int64, error) {
			return 0, errors.New("intentional write error")
		}
		reader := message.NewReader()
		if reader == nil {
			t.Fatalf("failed to create message reader")
		}
		if reader.Error() == nil {
			t.Fatalf("expected error on write, got nil")
		}
		if !strings.EqualFold(reader.Error().Error(), `failed to write Msg to Reader buffer: bodyWriter function: `+
			`intentional write error`) {
			t.Errorf("expected error to be %s, got: %s", `failed to write Msg to Reader buffer: bodyWriter function: `+
				`intentional write error`, reader.Error().Error())
		}
	})
}

func TestMsg_UpdateReader(t *testing.T) {
	t.Run("UpdateReader succeeds", func(t *testing.T) {
		message := testMessage(t)
		reader := message.NewReader()
		if reader == nil {
			t.Fatalf("failed to create message reader")
		}
		if reader.Error() != nil {
			t.Errorf("failed to create message reader: %s", reader.Error())
		}
		message.Subject("This is the actual subject")
		message.UpdateReader(reader)
		if reader == nil {
			t.Fatalf("failed to create message reader")
		}
		if reader.Error() != nil {
			t.Errorf("failed to create message reader: %s", reader.Error())
		}
		parsed, err := EMLToMsgFromReader(reader)
		if err != nil {
			t.Fatalf("failed to parse message in buffer: %s", err)
		}
		checkAddrHeader(t, parsed, HeaderFrom, "WriteTo", 0, 1, TestSenderValid, "")
		checkAddrHeader(t, parsed, HeaderTo, "WriteTo", 0, 1, TestRcptValid, "")
		checkGenHeader(t, parsed, HeaderSubject, "WriteTo", 0, 1, "This is the actual subject")
		parts := parsed.GetParts()
		if len(parts) != 1 {
			t.Fatalf("expected 1 parts, got: %d", len(parts))
		}
		if parts[0].contentType != TypeTextPlain {
			t.Errorf("expected contentType to be %s, got: %s", TypeTextPlain, parts[0].contentType)
		}
		if parts[0].encoding != EncodingQP {
			t.Errorf("expected encoding to be %s, got: %s", EncodingQP, parts[0].encoding)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = parts[0].writeFunc(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.HasSuffix(got, "Testmail") {
			t.Errorf("expected message buffer to contain Testmail, got: %s", got)
		}
	})
	t.Run("UpdateReader should fail on write", func(t *testing.T) {
		message := testMessage(t)
		reader := message.NewReader()
		if reader == nil {
			t.Fatalf("failed to create message reader")
		}
		if reader.Error() != nil {
			t.Errorf("failed to create message reader: %s", reader.Error())
		}
		message.Subject("This is the actual subject")
		if len(message.parts) != 1 {
			t.Fatalf("expected 1 parts, got: %d", len(message.parts))
		}
		message.parts[0].writeFunc = func(io.Writer) (int64, error) {
			return 0, errors.New("intentional write error")
		}
		message.UpdateReader(reader)
		if reader == nil {
			t.Fatalf("failed to create message reader")
		}
		if reader.Error() == nil {
			t.Fatalf("expected error on write, got nil")
		}
		if !strings.EqualFold(reader.Error().Error(), `bodyWriter function: intentional write error`) {
			t.Errorf("expected error to be %s, got: %s", `bodyWriter function: intentional write error`,
				reader.Error().Error())
		}
	})
}

func TestMsg_HasSendError(t *testing.T) {
	t.Run("HasSendError on unsent message", func(t *testing.T) {
		message := testMessage(t)
		if message.HasSendError() {
			t.Error("HasSendError on unsent message should return false")
		}
	})
	t.Run("HasSendError on sent message", func(t *testing.T) {
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

		if message.HasSendError() {
			t.Error("HasSendError on sent message should return false")
		}
	})
	t.Run("HasSendError on failed message delivery", func(t *testing.T) {
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
		if !message.HasSendError() {
			t.Error("HasSendError on failed message delivery should return true")
		}
	})
	t.Run("HasSendError on failed message with SendError", func(t *testing.T) {
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
		if !message.HasSendError() {
			t.Fatal("HasSendError on failed message delivery should return true")
		}
		if message.SendError() == nil {
			t.Fatal("SendError on failed message delivery should return SendErr")
		}
		var sendErr *SendError
		if !errors.As(message.SendError(), &sendErr) {
			t.Fatal("expected SendError to return a SendError type")
		}
	})
	t.Run("HasSendError with SendErrorIsTemp", func(t *testing.T) {
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
		if !message.HasSendError() {
			t.Error("HasSendError on failed message delivery should return true")
		}
		if message.SendErrorIsTemp() {
			t.Error("SendErrorIsTemp on hard failed message delivery should return false")
		}
	})
	t.Run("HasSendError with SendErrorIsTemp on temp error", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailTemp:   true,
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
		if err = client.DialAndSend(message); err == nil {
			t.Error("message delivery was supposed to fail on data close")
		}
		if !message.HasSendError() {
			t.Error("HasSendError on failed message delivery should return true")
		}
		if !message.SendErrorIsTemp() {
			t.Error("SendErrorIsTemp on temp failed message delivery should return true")
		}
	})
	t.Run("HasSendError with not a SendErr", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailTemp:   true,
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
		if err = client.DialAndSend(message); err == nil {
			t.Error("message delivery was supposed to fail on data close")
		}
		message.sendError = errors.New("not a SendErr")
		if !message.HasSendError() {
			t.Error("HasSendError with not a SendErr should still return true")
		}
		if message.SendErrorIsTemp() {
			t.Error("SendErrorIsTemp on not a SendErr should return false")
		}
	})
}

func TestMsg_WriteToTempFile(t *testing.T) {
	if os.Getenv("PERFORM_UNIX_OPEN_WRITE_TESTS") != "true" {
		t.Skipf("PERFORM_UNIX_OPEN_WRITE_TESTS variable is not set. Skipping unix open/write tests")
	}

	t.Run("WriteToTempFile succeeds", func(t *testing.T) {
		message := testMessage(t)
		tempFile, err := message.WriteToTempFile()
		if err != nil {
			t.Fatalf("failed to write message to temp file: %s", err)
		}
		parsed, err := EMLToMsgFromFile(tempFile)
		if err != nil {
			t.Fatalf("failed to parse message in buffer: %s", err)
		}
		checkAddrHeader(t, parsed, HeaderFrom, "WriteTo", 0, 1, TestSenderValid, "")
		checkAddrHeader(t, parsed, HeaderTo, "WriteTo", 0, 1, TestRcptValid, "")
		checkGenHeader(t, parsed, HeaderSubject, "WriteTo", 0, 1, "Testmail")
		parts := parsed.GetParts()
		if len(parts) != 1 {
			t.Fatalf("expected 1 parts, got: %d", len(parts))
		}
		if parts[0].contentType != TypeTextPlain {
			t.Errorf("expected contentType to be %s, got: %s", TypeTextPlain, parts[0].contentType)
		}
		if parts[0].encoding != EncodingQP {
			t.Errorf("expected encoding to be %s, got: %s", EncodingQP, parts[0].encoding)
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = parts[0].writeFunc(messageBuf)
		if err != nil {
			t.Errorf("writer func failed: %s", err)
		}
		got := strings.TrimSpace(messageBuf.String())
		if !strings.HasSuffix(got, "Testmail") {
			t.Errorf("expected message buffer to contain Testmail, got: %s", got)
		}
	})
}

func TestMsg_hasAlt(t *testing.T) {
	t.Run("message has no alt", func(t *testing.T) {
		message := testMessage(t)
		if message.hasAlt() {
			t.Error("message has no alt, but hasAlt returned true")
		}
	})
	t.Run("message has alt", func(t *testing.T) {
		message := testMessage(t)
		message.AddAlternativeString(TypeTextHTML, "this is the alt")
		if !message.hasAlt() {
			t.Error("message has alt, but hasAlt returned false")
		}
	})
	t.Run("message has no alt due to deleted part", func(t *testing.T) {
		message := testMessage(t)
		message.AddAlternativeString(TypeTextHTML, "this is the alt")
		if len(message.GetParts()) != 2 {
			t.Errorf("expected message to have 2 parts, got: %d", len(message.GetParts()))
		}
		message.parts[1].isDeleted = true
		if message.hasAlt() {
			t.Error("message has no alt, but hasAlt returned true")
		}
	})
	t.Run("message has alt and deleted parts", func(t *testing.T) {
		message := testMessage(t)
		message.AddAlternativeString(TypeTextHTML, "this is the alt")
		message.AddAlternativeString(TypeTextPlain, "this is also a alt")
		if len(message.GetParts()) != 3 {
			t.Errorf("expected message to have 3 parts, got: %d", len(message.GetParts()))
		}
		message.parts[1].isDeleted = true
		if !message.hasAlt() {
			t.Error("message has alt, but hasAlt returned false")
		}
	})
	t.Run("message has alt but it is pgptype", func(t *testing.T) {
		message := testMessage(t)
		message.SetPGPType(PGPSignature)
		if message.hasAlt() {
			t.Error("message has alt but it is a pgpType, hence hasAlt should return false")
		}
	})
}

// TestMsg_hasSMime tests the hasSMIME() method of the Msg
func TestMsg_hasSMime(t *testing.T) {
	privateKey, certificate, intermediateCertificate, err := getDummyRSACryptoMaterial()
	if err != nil {
		t.Fatalf("failed to load dummy crypto material: %s", err)
	}
	m := NewMsg()
	if err := m.SignWithKeypair(privateKey, certificate, intermediateCertificate); err != nil {
		t.Errorf("failed to init smime configuration")
	}
	m.SetBodyString(TypeTextPlain, "Plain")
	if !m.hasSMIME() {
		t.Errorf("mail has smime configured but hasSMIME() returned true")
	}
}

func TestMsg_hasMixed(t *testing.T) {
	t.Run("message has no mixed", func(t *testing.T) {
		message := testMessage(t)
		if message.hasMixed() {
			t.Error("message has no mixed, but hasMixed returned true")
		}
	})
	t.Run("message with alt has no mixed", func(t *testing.T) {
		message := testMessage(t)
		message.AddAlternativeString(TypeTextHTML, "this is the alt")
		if message.hasMixed() {
			t.Error("message has no mixed, but hasMixed returned true")
		}
	})
	t.Run("message with attachment is mixed", func(t *testing.T) {
		message := testMessage(t)
		message.AttachFile("testdata/attachment.txt")
		if !message.hasMixed() {
			t.Error("message with attachment is supposed to be mixed")
		}
	})
	t.Run("message with embed is not mixed", func(t *testing.T) {
		message := testMessage(t)
		message.EmbedFile("testdata/embed.txt")
		if message.hasMixed() {
			t.Error("message with embed is not supposed to be mixed")
		}
	})
	t.Run("message with attachment and embed is mixed", func(t *testing.T) {
		message := testMessage(t)
		message.AttachFile("testdata/attachment.txt")
		message.EmbedFile("testdata/embed.txt")
		if !message.hasMixed() {
			t.Error("message with attachment and embed is supposed to be mixed")
		}
	})
}

func TestMsg_hasRelated(t *testing.T) {
	t.Run("message has no related", func(t *testing.T) {
		message := testMessage(t)
		if message.hasRelated() {
			t.Error("message has no related, but hasRelated returned true")
		}
	})
	t.Run("message with alt has no related", func(t *testing.T) {
		message := testMessage(t)
		message.AddAlternativeString(TypeTextHTML, "this is the alt")
		if message.hasRelated() {
			t.Error("message has no related, but hasRelated returned true")
		}
	})
	t.Run("message with attachment is not related", func(t *testing.T) {
		message := testMessage(t)
		message.AttachFile("testdata/attachment.txt")
		if message.hasRelated() {
			t.Error("message with attachment is not supposed to be related")
		}
	})
	t.Run("message with embed is related", func(t *testing.T) {
		message := testMessage(t)
		message.EmbedFile("testdata/embed.txt")
		if !message.hasRelated() {
			t.Error("message with embed is supposed to be related")
		}
	})
	t.Run("message with attachment and embed is related", func(t *testing.T) {
		message := testMessage(t)
		message.AttachFile("testdata/attachment.txt")
		message.EmbedFile("testdata/embed.txt")
		if !message.hasRelated() {
			t.Error("message with attachment and embed is supposed to be related")
		}
	})
}

func TestMsg_hasPGPType(t *testing.T) {
	t.Run("message has no pgpType", func(t *testing.T) {
		message := testMessage(t)
		if message.hasPGPType() {
			t.Error("message has no PGPType, but hasPGPType returned true")
		}
	})
	t.Run("message has signature", func(t *testing.T) {
		message := testMessage(t)
		message.SetPGPType(PGPSignature)
		if !message.hasPGPType() {
			t.Error("message has signature, but hasPGPType returned false")
		}
	})
	t.Run("message has encryption", func(t *testing.T) {
		message := testMessage(t)
		message.SetPGPType(PGPEncrypt)
		if !message.hasPGPType() {
			t.Error("message has encryption, but hasPGPType returned false")
		}
	})
	t.Run("message has encryption and signature", func(t *testing.T) {
		message := testMessage(t)
		message.SetPGPType(PGPEncrypt | PGPSignature)
		if !message.hasPGPType() {
			t.Error("message has encryption and signature, but hasPGPType returned false")
		}
	})
	t.Run("message has NoPGP", func(t *testing.T) {
		message := testMessage(t)
		message.SetPGPType(NoPGP)
		if message.hasPGPType() {
			t.Error("message has NoPGP, but hasPGPType returned true")
		}
	})
}

func TestMsg_checkUserAgent(t *testing.T) {
	t.Run("default user agent should be set", func(t *testing.T) {
		message := testMessage(t)
		message.checkUserAgent()
		checkGenHeader(t, message, HeaderUserAgent, "checkUserAgent", 0, 1,
			fmt.Sprintf("go-mail v%s // https://github.com/wneessen/go-mail", VERSION))
		checkGenHeader(t, message, HeaderXMailer, "checkUserAgent", 0, 1,
			fmt.Sprintf("go-mail v%s // https://github.com/wneessen/go-mail", VERSION))
	})
	t.Run("noDefaultUserAgent should return empty string", func(t *testing.T) {
		message := testMessage(t)
		message.noDefaultUserAgent = true
		message.checkUserAgent()
		if len(message.genHeader[HeaderUserAgent]) != 0 {
			t.Error("user agent should be empty")
		}
		if len(message.genHeader[HeaderXMailer]) != 0 {
			t.Error("x-mailer should be empty")
		}
	})
}

func TestMsg_addDefaultHeader(t *testing.T) {
	t.Run("empty message should add defaults", func(t *testing.T) {
		message := NewMsg()
		if message == nil {
			t.Fatal("failed to create new message")
		}
		if _, ok := message.genHeader[HeaderDate]; ok {
			t.Error("empty message should not have date header")
		}
		if _, ok := message.genHeader[HeaderMessageID]; ok {
			t.Error("empty message should not have message-id header")
		}
		if _, ok := message.genHeader[HeaderMIMEVersion]; ok {
			t.Error("empty message should not have mime version header")
		}
		message.addDefaultHeader()
		if _, ok := message.genHeader[HeaderDate]; !ok {
			t.Error("message should now have date header")
		}
		if _, ok := message.genHeader[HeaderMessageID]; !ok {
			t.Error("message should now have message-id header")
		}
		if _, ok := message.genHeader[HeaderMIMEVersion]; !ok {
			t.Error("message should now have mime version header")
		}
	})
}

func TestMsg_fileFromIOFS(t *testing.T) {
	t.Run("file from fs.FS where fs is nil ", func(t *testing.T) {
		_, err := fileFromIOFS("testfile.txt", nil)
		if err == nil {
			t.Fatal("expected error for fs.FS that is nil")
		}
	})
}

func TestMsg_SignWithKeypair(t *testing.T) {
	rsaPrivKey, rsaCert, rsaIntermediate, err := getDummyRSACryptoMaterial()
	if err != nil {
		t.Fatalf("failed to load dummy crypto material: %s", err)
	}
	ecdsaPrivKey, ecdsaCert, ecdsaIntermediate, err := getDummyRSACryptoMaterial()
	if err != nil {
		t.Fatalf("failed to load dummy crypto material: %s", err)
	}

	t.Run("init signing with valid RSA keypair", func(t *testing.T) {
		msg := testMessage(t)
		if err = msg.SignWithKeypair(rsaPrivKey, rsaCert, rsaIntermediate); err != nil {
			t.Errorf("failed to initialize SMIME configuration: %s", err)
		}
		if msg.sMIME == nil {
			t.Errorf("failed to initialize SMIME configuration, SMIME is nil")
		}
		if msg.sMIME.privateKey == nil {
			t.Errorf("failed to initialize SMIME configuration, private key is nil")
		}
		if msg.sMIME.certificate == nil {
			t.Errorf("failed to initialize SMIME configuration, certificate is nil")
		}
		if msg.sMIME.intermediateCert == nil {
			t.Errorf("failed to initialize SMIME configuration, intermediate certificate is nil")
		}
	})
	t.Run("init signing with valid ECDSA keypair", func(t *testing.T) {
		msg := testMessage(t)
		if err = msg.SignWithKeypair(ecdsaPrivKey, ecdsaCert, ecdsaIntermediate); err != nil {
			t.Errorf("failed to initialize SMIME configuration: %s", err)
		}
		if msg.sMIME == nil {
			t.Errorf("failed to initialize SMIME configuration, SMIME is nil")
		}
		if msg.sMIME.privateKey == nil {
			t.Errorf("failed to initialize SMIME configuration, private key is nil")
		}
		if msg.sMIME.certificate == nil {
			t.Errorf("failed to initialize SMIME configuration, certificate is nil")
		}
		if msg.sMIME.intermediateCert == nil {
			t.Errorf("failed to initialize SMIME configuration, intermediate certificate is nil")
		}
	})
	t.Run("init signing with missing private key should fail", func(t *testing.T) {
		msg := testMessage(t)
		err = msg.SignWithKeypair(nil, rsaCert, rsaIntermediate)
		if err == nil {
			t.Errorf("SMIME init with missing private key should fail")
		}
		if !errors.Is(err, ErrPrivateKeyMissing) {
			t.Errorf("SMIME init with missing private key should fail with %s, but got: %s", ErrPrivateKeyMissing,
				err)
		}
		if msg.sMIME != nil {
			t.Errorf("SMIME init with missing private key should fail, but SMIME is not nil")
		}
	})
	t.Run("init signing with missing public key should fail", func(t *testing.T) {
		msg := testMessage(t)
		err = msg.SignWithKeypair(rsaPrivKey, nil, rsaIntermediate)
		if err == nil {
			t.Errorf("SMIME init with missing public key should fail")
		}
		if !errors.Is(err, ErrCertificateMissing) {
			t.Errorf("SMIME init with missing public key should fail with %s, but got: %s", ErrCertificateMissing,
				err)
		}
		if msg.sMIME != nil {
			t.Errorf("SMIME init with missing public key should fail, but SMIME is not nil")
		}
	})
	t.Run("init signing with missing intermediate cert should succeed", func(t *testing.T) {
		msg := testMessage(t)
		if err = msg.SignWithKeypair(rsaPrivKey, rsaCert, nil); err != nil {
			t.Errorf("failed to initialize SMIME configuration: %s", err)
		}
		if msg.sMIME == nil {
			t.Errorf("failed to initialize SMIME configuration, SMIME is nil")
		}
		if msg.sMIME.privateKey == nil {
			t.Errorf("failed to initialize SMIME configuration, private key is nil")
		}
		if msg.sMIME.certificate == nil {
			t.Errorf("failed to initialize SMIME configuration, certificate is nil")
		}
		if msg.sMIME.intermediateCert != nil {
			t.Errorf("failed to initialize SMIME configuration, intermediate certificate is not nil")
		}
	})
}

func TestMsg_SignWithTLSCertificate(t *testing.T) {
	keypair, err := getDummyKeyPairTLS()
	if err != nil {
		t.Fatalf("failed to load dummy crypto material: %s", err)
	}

	t.Run("init signing with valid TLS certificate", func(t *testing.T) {
		msg := testMessage(t)
		if err = msg.SignWithTLSCertificate(keypair); err != nil {
			t.Errorf("failed to initialize SMIME configuration: %s", err)
		}
		if msg.sMIME.privateKey == nil {
			t.Errorf("failed to initialize SMIME configuration, private key is nil")
		}
		if msg.sMIME.certificate == nil {
			t.Errorf("failed to initialize SMIME configuration, certificate is nil")
		}
		if msg.sMIME.intermediateCert == nil {
			t.Errorf("failed to initialize SMIME configuration, intermediate certificate is nil")
		}
	})

	// Before Go 1.23 Certificate.Leaf was left nil, and the parsed certificate was discarded. This behavior
	// can be re-enabled by setting "x509keypairleaf=0" in the GODEBUG environment variable.
	// See: https://go-review.googlesource.com/c/go/+/585856
	t.Run("init signing with valid TLS certificate with nil leaf", func(t *testing.T) {
		t.Setenv("GODEBUG", "x509keypairleaf=0")

		msg := testMessage(t)
		if err = msg.SignWithTLSCertificate(keypair); err != nil {
			t.Errorf("failed to initialize SMIME configuration: %s", err)
		}
		if msg.sMIME.privateKey == nil {
			t.Errorf("failed to initialize SMIME configuration, private key is nil")
		}
		if msg.sMIME.certificate == nil {
			t.Errorf("failed to initialize SMIME configuration, certificate is nil")
		}
		if msg.sMIME.intermediateCert == nil {
			t.Errorf("failed to initialize SMIME configuration, intermediate certificate is nil")
		}
	})
	t.Run("init signing with nil TLS certificate should fail", func(t *testing.T) {
		msg := testMessage(t)
		if err = msg.SignWithTLSCertificate(nil); err == nil {
			t.Errorf("SMIME initilization with nil TLS certificate should fail")
		}
	})
	t.Run("init signing with invalid intermediate certificate should fail", func(t *testing.T) {
		msg := testMessage(t)
		localpair := &tls.Certificate{
			Certificate:                  keypair.Certificate,
			PrivateKey:                   keypair.PrivateKey,
			Leaf:                         keypair.Leaf,
			SignedCertificateTimestamps:  keypair.SignedCertificateTimestamps,
			SupportedSignatureAlgorithms: keypair.SupportedSignatureAlgorithms,
		}
		if len(localpair.Certificate) != 2 {
			t.Fatal("expected certificate with intermediate certificate")
		}
		localpair.Certificate[1] = localpair.Certificate[1][:len(localpair.Certificate[1])-16]
		if err = msg.SignWithTLSCertificate(localpair); err == nil {
			t.Errorf("SMIME initilization with invalid intermediate certificate should fail")
		}
	})
	t.Run("init signing with empty tls.Certificate should fail on leaf certificate creation", func(t *testing.T) {
		msg := testMessage(t)
		localpair := &tls.Certificate{}
		if err = msg.SignWithTLSCertificate(localpair); err == nil {
			t.Errorf("SMIME initilization with invalid intermediate certificate should fail")
		}
	})
	t.Run("init signing with unsupported crypto.PrivateKey should fail", func(t *testing.T) {
		msg := testMessage(t)
		localpair := &tls.Certificate{
			Certificate:                  [][]byte{keypair.Certificate[0]},
			PrivateKey:                   unsupportedPrivKey{},
			Leaf:                         keypair.Leaf,
			SignedCertificateTimestamps:  keypair.SignedCertificateTimestamps,
			SupportedSignatureAlgorithms: keypair.SupportedSignatureAlgorithms,
		}
		if err = msg.SignWithTLSCertificate(localpair); err == nil {
			t.Errorf("SMIME initilization with invalid intermediate certificate should fail")
		}
		expErr := "unsupported private key type: mail.unsupportedPrivKey"
		if !strings.EqualFold(err.Error(), expErr) {
			t.Errorf("SMIME initilization with invalid intermediate certificate should fail with %s, but got: %s",
				expErr, err)
		}
	})
}

// TestMsg_signMessage tests the Msg.signMessage method
func TestMsg_signMessage(t *testing.T) {
	tests := []struct {
		name            string
		keyMaterialFunc func() (crypto.PrivateKey, *x509.Certificate, *x509.Certificate, error)
		asnSig          []byte
	}{
		{"RSA", getDummyRSACryptoMaterial, []byte{48, 130, 13}},
		{"ECDSA", getDummyECDSACryptoMaterial, []byte{48, 130, 5}},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("sign message with valid %s keypair", tt.name), func(t *testing.T) {
			privKey, cert, intermediate, err := tt.keyMaterialFunc()
			if err != nil {
				t.Fatalf("failed to load dummy crypto material: %s", err)
			}
			msg := testMessage(t)
			if err = msg.SignWithKeypair(privKey, cert, intermediate); err != nil {
				t.Errorf("failed to init smime configuration")
			}
			if err = msg.signMessage(); err != nil {
				t.Fatalf("failed to S/MIME sign message: %s", err)
			}

			parts := msg.GetParts()
			if len(parts) != 2 {
				t.Fatalf("failed to get message parts, expected 2 parts, got: %d", len(parts))
			}

			bodyPart := parts[0]
			if bodyPart.GetCharset() != CharsetUTF8 {
				t.Errorf("failed to get signed message bodyPart charset, expected %s, got: %s", CharsetUTF8,
					bodyPart.GetCharset())
			}
			if bodyPart.GetEncoding() != EncodingQP {
				t.Errorf("failed to get signed message bodyPart encoding, expected %s, got: %s", EncodingQP,
					bodyPart.GetEncoding())
			}
			if bodyPart.smime {
				t.Errorf("failed to get signed message bodyPart smime status, expected false, got: %t", bodyPart.smime)
			}
			body, err := bodyPart.GetContent()
			if err != nil {
				t.Fatalf("failed to get signed message body part content: %s", err)
			}
			if !bytes.Equal(body, []byte("Testmail")) {
				t.Errorf("signed body part content does not match, expected %s, got: %s", "Testmail", body)
			}

			signaturePart := parts[1]
			if signaturePart.GetCharset() != CharsetUTF8 {
				t.Errorf("failed to get signed message signaturePart charset, expected %s, got: %s", CharsetUTF8,
					signaturePart.GetCharset())
			}
			if signaturePart.GetEncoding() != EncodingB64 {
				t.Errorf("failed to get signed message signaturePart encoding, expected %s, got: %s", EncodingB64,
					signaturePart.GetEncoding())
			}
			if signaturePart.GetContentType() != TypeSMIMESigned {
				t.Errorf("failed to get signed message signaturePart content type, expected %s, got: %s",
					TypeSMIMESigned, signaturePart.GetContentType())
			}
			if !signaturePart.smime {
				t.Errorf("failed to get signed message signaturePart smime status, expected true, got: %t",
					signaturePart.smime)
			}
			signature, err := signaturePart.GetContent()
			if err != nil {
				t.Fatalf("failed to get signature content: %s", err)
			}
			if !bytes.Equal(signature[:3], tt.asnSig) {
				t.Errorf("signature ASN.1 signature does not match, expected: %x, got: %x", tt.asnSig, signature[:3])
			}
		})
	}

	t.Run("signing fails with invalid crypto.PrivateKey", func(t *testing.T) {
		keypair, err := getDummyKeyPairTLS()
		if err != nil {
			t.Fatalf("failed to load dummy crypto material: %s", err)
		}
		msg := testMessage(t)
		if err = msg.SignWithTLSCertificate(keypair); err != nil {
			t.Fatalf("failed to init SMIME configuration: %s", err)
		}
		msg.sMIME.privateKey = unsupportedPrivKey{}
		err = msg.signMessage()
		if err == nil {
			t.Error("SMIME signing with invalid private key is expected to fail")
		}
		expErr := "cannot convert encryption algorithm to oid, unknown private key type"
		if !strings.Contains(err.Error(), expErr) {
			t.Errorf("SMIME signing with invalid private key is expected to fail with %s, but got: %s", expErr, err)
		}
	})
	t.Run("signing fails with invalid header count", func(t *testing.T) {
		keypair, err := getDummyKeyPairTLS()
		if err != nil {
			t.Fatalf("failed to load dummy crypto material: %s", err)
		}
		msg := testMessage(t)
		if err = msg.SignWithTLSCertificate(keypair); err != nil {
			t.Fatalf("failed to init SMIME configuration: %s", err)
		}
		msg.headerCount = 1000
		err = msg.signMessage()
		if err == nil {
			t.Error("SMIME signing with invalid private key is expected to fail")
		}
		expErr := "unable to find message body starting index within rendered message"
		if !strings.EqualFold(err.Error(), expErr) {
			t.Errorf("SMIME signing with invalid header count is expected to fail with %s, but got: %s", expErr, err)
		}
	})
}

// uppercaseMiddleware is a middleware type that transforms the subject to uppercase.
type uppercaseMiddleware struct{}

// Handle satisfies the Middleware interface for the uppercaseMiddlware
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

// Type satisfies the Middleware interface for the uppercaseMiddlware
func (mw uppercaseMiddleware) Type() MiddlewareType {
	return "uppercase"
}

// encodeMiddleware is a middleware type that transforms an "a" in the subject to an "@"
type encodeMiddleware struct{}

// Handle satisfies the Middleware interface for the encodeMiddleware
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

// Type satisfies the Middleware interface for the encodeMiddleware
func (mw encodeMiddleware) Type() MiddlewareType {
	return "encode"
}

// failReadWriteSeekCloser is a type that always returns an error. It satisfies the io.Reader, io.Writer
// io.Closer, io.Seeker, io.WriteSeeker, io.ReadSeeker, io.ReadCloser and io.WriteCloser interfaces
type failReadWriteSeekCloser struct{}

// Write satisfies the io.Writer interface for the failReadWriteSeekCloser type
func (failReadWriteSeekCloser) Write([]byte) (int, error) {
	return 0, errors.New("intentional write failure")
}

// Read satisfies the io.Reader interface for the failReadWriteSeekCloser type
func (failReadWriteSeekCloser) Read([]byte) (int, error) {
	return 0, errors.New("intentional read failure")
}

// Seek satisfies the io.Seeker interface for the failReadWriteSeekCloser type
func (failReadWriteSeekCloser) Seek(int64, int) (int64, error) {
	return 0, errors.New("intentional seek failure")
}

// Close satisfies the io.Closer interface for the failReadWriteSeekCloser type
func (failReadWriteSeekCloser) Close() error {
	return errors.New("intentional close failure")
}

// checkAddrHeader verifies the correctness of an AddrHeader in a Msg based on the provided criteria.
// It checks whether the AddrHeader contains the correct address, name, and number of fields.
func checkAddrHeader(t *testing.T, message *Msg, header AddrHeader, fn string, field, wantFields int,
	wantMail, wantName string,
) {
	t.Helper()
	addresses, ok := message.addrHeader[header]
	if !ok {
		t.Fatalf("failed to exec %s, addrHeader field is not set", fn)
	}
	if len(addresses) != wantFields {
		t.Fatalf("failed to exec %s, addrHeader value count is: %d, want: %d", fn, len(addresses), field)
	}
	if addresses[field].Address != wantMail {
		t.Errorf("failed to exec %s, addrHeader value is %s, want: %s", fn, addresses[field].Address, wantMail)
	}
	wantString := fmt.Sprintf(`<%s>`, wantMail)
	if wantName != "" {
		wantString = fmt.Sprintf(`%q <%s>`, wantName, wantMail)
	}
	if addresses[field].String() != wantString {
		t.Errorf("failed to exec %s, addrHeader value is %s, want: %s", fn, addresses[field].String(), wantString)
	}
	if addresses[field].Name != wantName {
		t.Errorf("failed to exec %s, addrHeader name is %s, want: %s", fn, addresses[field].Name, wantName)
	}
}

// unsupportedPrivKey is a type that satisfies the crypto.PrivateKey interfaces but is not supported for signing
type unsupportedPrivKey struct{}

// Public implements the Public method of the crypto.PrivateKey interface for the unsupportedPrivKey type
func (u unsupportedPrivKey) Public() crypto.PublicKey {
	return nil
}

// Equal implements the Equal method of the crypto.PrivateKey interface for the unsupportedPrivKey type
func (u unsupportedPrivKey) Equal(_ crypto.PrivateKey) bool {
	return true
}

// checkGenHeader validates the generated header in an email message, verifying its presence and expected values.
func checkGenHeader(t *testing.T, message *Msg, header Header, fn string, field, wantFields int,
	wantVal string,
) {
	t.Helper()
	values, ok := message.genHeader[header]
	if !ok {
		t.Fatalf("failed to exec %s, genHeader field is not set", fn)
	}
	if len(values) != wantFields {
		t.Fatalf("failed to exec %s, genHeader value count is: %d, want: %d", fn, len(values), field)
	}
	if values[field] != wantVal {
		t.Errorf("failed to exec %s, genHeader value is %s, want: %s", fn, values[field], wantVal)
	}
}

// hasSendmail checks if the /usr/sbin/sendmail file exists and is executable. Returns true if conditions are met.
func hasSendmail() bool {
	sm, err := os.Stat(SendmailPath)
	if err == nil {
		if sm.Mode()&0o111 != 0 {
			return true
		}
	}
	return false
}

func checkMessageContent(t *testing.T, buffer *bytes.Buffer, wants []msgContentTest) {
	t.Helper()
	lines := strings.Split(buffer.String(), "\r\n")
	for _, want := range wants {
		if len(lines) <= want.line {
			t.Errorf("expected line %d to be present, got: %d lines in total", want.line, len(lines)-1)
			continue
		}
		if !strings.Contains(lines[want.line], want.data) {
			t.Errorf("expected line %d to contain %q, got: %q", want.line, want.data, lines[want.line])
		}
		if want.exact {
			if !strings.EqualFold(lines[want.line], want.data) {
				t.Errorf("expected line %d to be exactly %q, got: %q", want.line, want.data, lines[want.line])
			}
		}
		if want.dataIsPrefix {
			if !strings.HasPrefix(lines[want.line], want.data) {
				t.Errorf("expected line %d to start with %q, got: %q", want.line, want.data, lines[want.line])
			}
		}
		if want.dataIsSuffix {
			if !strings.HasSuffix(lines[want.line], want.data) {
				t.Errorf("expected line %d to end with %q, got: %q", want.line, want.data, lines[want.line])
			}
		}
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
