// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bufio"
	"bytes"
	"embed"
	"errors"
	"fmt"
	htpl "html/template"
	"io"
	"net/mail"
	"os"
	"sort"
	"strings"
	"testing"
	ttpl "text/template"
	"time"
)

//go:embed README.md
var efs embed.FS

// TestNewMsg tests the NewMsg method
func TestNewMsg(t *testing.T) {
	m := NewMsg()
	var err error
	if m.encoding != EncodingQP {
		err = fmt.Errorf("default encoding is not Quoted-Prinable")
	}
	if m.charset != CharsetUTF8 {
		err = fmt.Errorf("default charset is not UTF-8")
	}

	if err != nil {
		t.Errorf("NewMsg() failed: %s", err)
		return
	}
}

// TestNewMsgCharset tests WithCharset and Msg.SetCharset
func TestNewMsgCharset(t *testing.T) {
	tests := []struct {
		name  string
		value Charset
		want  Charset
	}{
		{"charset is UTF-7", CharsetUTF7, "UTF-7"},
		{"charset is UTF-8", CharsetUTF8, "UTF-8"},
		{"charset is US-ASCII", CharsetASCII, "US-ASCII"},
		{"charset is ISO-8859-1", CharsetISO88591, "ISO-8859-1"},
		{"charset is ISO-8859-2", CharsetISO88592, "ISO-8859-2"},
		{"charset is ISO-8859-3", CharsetISO88593, "ISO-8859-3"},
		{"charset is ISO-8859-4", CharsetISO88594, "ISO-8859-4"},
		{"charset is ISO-8859-5", CharsetISO88595, "ISO-8859-5"},
		{"charset is ISO-8859-6", CharsetISO88596, "ISO-8859-6"},
		{"charset is ISO-8859-7", CharsetISO88597, "ISO-8859-7"},
		{"charset is ISO-8859-9", CharsetISO88599, "ISO-8859-9"},
		{"charset is ISO-8859-13", CharsetISO885913, "ISO-8859-13"},
		{"charset is ISO-8859-14", CharsetISO885914, "ISO-8859-14"},
		{"charset is ISO-8859-15", CharsetISO885915, "ISO-8859-15"},
		{"charset is ISO-8859-16", CharsetISO885916, "ISO-8859-16"},
		{"charset is ISO-2022-JP", CharsetISO2022JP, "ISO-2022-JP"},
		{"charset is ISO-2022-KR", CharsetISO2022KR, "ISO-2022-KR"},
		{"charset is windows-1250", CharsetWindows1250, "windows-1250"},
		{"charset is windows-1251", CharsetWindows1251, "windows-1251"},
		{"charset is windows-1252", CharsetWindows1252, "windows-1252"},
		{"charset is windows-1255", CharsetWindows1255, "windows-1255"},
		{"charset is windows-1256", CharsetWindows1256, "windows-1256"},
		{"charset is KOI8-R", CharsetKOI8R, "KOI8-R"},
		{"charset is KOI8-U", CharsetKOI8U, "KOI8-U"},
		{"charset is Big5", CharsetBig5, "Big5"},
		{"charset is GB18030", CharsetGB18030, "GB18030"},
		{"charset is GB2312", CharsetGB2312, "GB2312"},
		{"charset is TIS-620", CharsetTIS620, "TIS-620"},
		{"charset is EUC-KR", CharsetEUCKR, "EUC-KR"},
		{"charset is Shift_JIS", CharsetShiftJIS, "Shift_JIS"},
		{"charset is GBK", CharsetGBK, "GBK"},
		{"charset is Unknown", CharsetUnknown, "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMsg(WithCharset(tt.value), nil)
			if m.charset != tt.want {
				t.Errorf("WithCharset() failed. Expected: %s, got: %s", tt.want, m.charset)
			}
			m.SetCharset(CharsetUTF8)
			if m.charset != CharsetUTF8 {
				t.Errorf("SetCharset() failed. Expected: %s, got: %s", CharsetUTF8, m.charset)
			}
			m.SetCharset(tt.value)
			if m.charset != tt.want {
				t.Errorf("SetCharset() failed. Expected: %s, got: %s", tt.want, m.charset)
			}
		})
	}
}

// TestNewMsgWithCharset tests WithEncoding and Msg.SetEncoding
func TestNewMsgWithEncoding(t *testing.T) {
	tests := []struct {
		name  string
		value Encoding
		want  Encoding
	}{
		{"encoding is Quoted-Printable", EncodingQP, "quoted-printable"},
		{"encoding is Base64", EncodingB64, "base64"},
		{"encoding is Unencoded 8-Bit", NoEncoding, "8bit"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMsg(WithEncoding(tt.value))
			if m.encoding != tt.want {
				t.Errorf("WithEncoding() failed. Expected: %s, got: %s", tt.want, m.encoding)
			}
			m.SetEncoding(NoEncoding)
			if m.encoding != NoEncoding {
				t.Errorf("SetEncoding() failed. Expected: %s, got: %s", NoEncoding, m.encoding)
			}
			m.SetEncoding(tt.want)
			if m.encoding != tt.want {
				t.Errorf("SetEncoding() failed. Expected: %s, got: %s", tt.want, m.encoding)
			}
		})
	}
}

// TestNewMsgWithMIMEVersion tests WithMIMEVersion and Msg.SetMIMEVersion
func TestNewMsgWithMIMEVersion(t *testing.T) {
	tests := []struct {
		name  string
		value MIMEVersion
		want  MIMEVersion
	}{
		{"MIME version is 1.0", Mime10, "1.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMsg(WithMIMEVersion(tt.value))
			if m.mimever != tt.want {
				t.Errorf("WithMIMEVersion() failed. Expected: %s, got: %s", tt.want, m.mimever)
			}
			m.mimever = ""
			m.SetMIMEVersion(tt.value)
			if m.mimever != tt.want {
				t.Errorf("SetMIMEVersion() failed. Expected: %s, got: %s", tt.want, m.mimever)
			}
		})
	}
}

// TestNewMsgWithBoundary tests WithBoundary and Msg.SetBoundary
func TestNewMsgWithBoundary(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		{"boundary is test123", "test123"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMsg(WithBoundary(tt.value))
			if m.boundary != tt.value {
				t.Errorf("WithBoundary() failed. Expected: %s, got: %s", tt.value, m.boundary)
			}
			m.boundary = ""
			m.SetBoundary(tt.value)
			if m.boundary != tt.value {
				t.Errorf("SetBoundary() failed. Expected: %s, got: %s", tt.value, m.boundary)
			}
		})
	}
}

// TestNewMsg_WithPGPType tests WithPGPType option
func TestNewMsg_WithPGPType(t *testing.T) {
	tests := []struct {
		name string
		pt   PGPType
		hpt  bool
	}{
		{"Not a PGP encoded message", NoPGP, false},
		{"PGP encrypted message", PGPEncrypt, true},
		{"PGP signed message", PGPSignature, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMsg(WithPGPType(tt.pt))
			if m.pgptype != tt.pt {
				t.Errorf("WithPGPType() failed. Expected: %d, got: %d", tt.pt, m.pgptype)
			}
			m.pgptype = 99
			m.SetPGPType(tt.pt)
			if m.pgptype != tt.pt {
				t.Errorf("SetPGPType() failed. Expected: %d, got: %d", tt.pt, m.pgptype)
			}
			if m.hasPGPType() != tt.hpt {
				t.Errorf("hasPGPType() failed. Expected %t, got: %t", tt.hpt, m.hasPGPType())
			}
		})
	}
}

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

// TestMsg_SetGenHeader tests Msg.SetGenHeader
func TestMsg_SetGenHeader(t *testing.T) {
	tests := []struct {
		name   string
		header Header
		values []string
	}{
		{"set subject", HeaderSubject, []string{"This is Subject"}},
		{"set content-language", HeaderContentLang, []string{"en", "de", "fr", "es"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMsg()
			m.SetGenHeader(tt.header, tt.values...)
			if m.genHeader[tt.header] == nil {
				t.Errorf("SetGenHeader() failed. Tried to set header %s, but it is empty", tt.header)
				return
			}
			for _, v := range tt.values {
				found := false
				for _, hv := range m.genHeader[tt.header] {
					if hv == v {
						found = true
					}
				}
				if !found {
					t.Errorf("SetGenHeader() failed. Value %s not found in header field", v)
				}
			}
		})
	}
}

// TestMsg_SetGenHeaderPreformatted tests Msg.SetGenHeaderPreformatted
func TestMsg_SetGenHeaderPreformatted(t *testing.T) {
	tests := []struct {
		name   string
		header Header
		value  string
	}{
		{"set subject", HeaderSubject, "This is Subject"},
		{"set content-language", HeaderContentLang, fmt.Sprintf("%s, %s, %s, %s",
			"en", "de", "fr", "es")},
		{"set subject with newline", HeaderSubject, "This is Subject\r\n with 2nd line"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &Msg{}
			m.SetGenHeaderPreformatted(tt.header, tt.value)
			m = NewMsg()
			m.SetGenHeaderPreformatted(tt.header, tt.value)
			if m.preformHeader[tt.header] == "" {
				t.Errorf("SetGenHeaderPreformatted() failed. Tried to set header %s, but it is empty", tt.header)
			}
			if m.preformHeader[tt.header] != tt.value {
				t.Errorf("SetGenHeaderPreformatted() failed. Expected: %q, got: %q", tt.value,
					m.preformHeader[tt.header])
			}
			buf := bytes.Buffer{}
			_, err := m.WriteTo(&buf)
			if err != nil {
				t.Errorf("failed to write message to memory: %s", err)
				return
			}
			if !strings.Contains(buf.String(), fmt.Sprintf("%s: %s%s", tt.header, tt.value, SingleNewLine)) {
				t.Errorf("SetGenHeaderPreformatted() failed. Unable to find correctly formated header in " +
					"mail message output")
			}
		})
	}
}

// TestMsg_AddTo tests the Msg.AddTo method
func TestMsg_AddTo(t *testing.T) {
	a := []string{"address1@example.com", "address2@example.com"}
	na := "address3@example.com"
	m := NewMsg()
	if err := m.To(a...); err != nil {
		t.Errorf("failed to set TO addresses: %s", err)
		return
	}
	if err := m.AddTo(na); err != nil {
		t.Errorf("AddTo failed: %s", err)
		return
	}

	atf := false
	for _, v := range m.addrHeader[HeaderTo] {
		if v.Address == na {
			atf = true
		}
	}
	if !atf {
		t.Errorf("AddTo() failed. Address %q not found in TO address slice.", na)
	}
}

// TestMsg_From tests the Msg.From and Msg.GetSender methods
func TestMsg_From(t *testing.T) {
	a := "toni@example.com"
	n := "Toni Tester"
	na := fmt.Sprintf(`"%s" <%s>`, n, a)
	m := NewMsg()

	_, err := m.GetSender(false)
	if err == nil {
		t.Errorf("GetSender(false) without a set From address succeeded but was expected to fail")
		return
	}

	if err := m.From(na); err != nil {
		t.Errorf("failed to set FROM addresses: %s", err)
		return
	}
	gs, err := m.GetSender(false)
	if err != nil {
		t.Errorf("GetSender(false) failed: %s", err)
		return
	}
	if gs != a {
		t.Errorf("From() failed. Expected: %s, got: %s", a, gs)
		return
	}

	gs, err = m.GetSender(true)
	if err != nil {
		t.Errorf("GetSender(true) failed: %s", err)
		return
	}
	if gs != na {
		t.Errorf("From() failed. Expected: %s, got: %s", na, gs)
		return
	}
}

// TestMsg_EnvelopeFrom tests the Msg.EnvelopeFrom and Msg.GetSender methods
func TestMsg_EnvelopeFrom(t *testing.T) {
	e := "envelope@example.com"
	a := "toni@example.com"
	n := "Toni Tester"
	na := fmt.Sprintf(`"%s" <%s>`, n, a)
	ne := fmt.Sprintf(`<%s>`, e)
	m := NewMsg()

	_, err := m.GetSender(false)
	if err == nil {
		t.Errorf("GetSender(false) without a set envelope From address succeeded but was expected to fail")
		return
	}

	if err := m.EnvelopeFrom(e); err != nil {
		t.Errorf("failed to set envelope FROM addresses: %s", err)
		return
	}
	gs, err := m.GetSender(false)
	if err != nil {
		t.Errorf("GetSender(false) failed: %s", err)
		return
	}
	if gs != e {
		t.Errorf("From() failed. Expected: %s, got: %s", e, gs)
		return
	}

	if err := m.From(na); err != nil {
		t.Errorf("failed to set FROM addresses: %s", err)
		return
	}
	gs, err = m.GetSender(false)
	if err != nil {
		t.Errorf("GetSender(false) failed: %s", err)
		return
	}
	if gs != e {
		t.Errorf("From() failed. Expected: %s, got: %s", e, gs)
		return
	}

	gs, err = m.GetSender(true)
	if err != nil {
		t.Errorf("GetSender(true) failed: %s", err)
		return
	}
	if gs != ne {
		t.Errorf("From() failed. Expected: %s, got: %s", ne, gs)
		return
	}
	m.Reset()

	if err := m.From(na); err != nil {
		t.Errorf("failed to set FROM addresses: %s", err)
		return
	}
	gs, err = m.GetSender(false)
	if err != nil {
		t.Errorf("GetSender(true) failed: %s", err)
		return
	}
	if gs != a {
		t.Errorf("From() failed. Expected: %s, got: %s", a, gs)
		return
	}
	gs, err = m.GetSender(true)
	if err != nil {
		t.Errorf("GetSender(true) failed: %s", err)
		return
	}
	if gs != na {
		t.Errorf("From() failed. Expected: %s, got: %s", na, gs)
		return
	}
}

// TestMsg_AddToFormat tests the Msg.AddToFormat method
func TestMsg_AddToFormat(t *testing.T) {
	a := []string{"address1@example.com", "address2@example.com"}
	nn := "Toni Tester"
	na := "address3@example.com"
	w := `"Toni Tester" <address3@example.com>`
	m := NewMsg()
	if err := m.To(a...); err != nil {
		t.Errorf("failed to set TO addresses: %s", err)
		return
	}
	if err := m.AddToFormat(nn, na); err != nil {
		t.Errorf("AddToFormat failed: %s", err)
		return
	}

	atf := false
	for _, v := range m.addrHeader[HeaderTo] {
		if v.String() == w {
			atf = true
		}
	}
	if !atf {
		t.Errorf("AddToFormat() failed. Address %q not found in TO address slice.", w)
	}
}

// TestMsg_ToIgnoreInvalid tests the Msg.ToIgnoreInvalid method
func TestMsg_ToIgnoreInvalid(t *testing.T) {
	a := []string{"address1@example.com", "address2@example.com"}
	fa := []string{"address1@example.com", "address2@example.com", "failedaddress.com"}
	m := NewMsg()

	m.ToIgnoreInvalid(a...)
	l := len(m.addrHeader[HeaderTo])
	if l != len(a) {
		t.Errorf("ToIgnoreInvalid() failed. Expected %d addresses, got: %d", len(a), l)
	}
	m.ToIgnoreInvalid(fa...)
	l = len(m.addrHeader[HeaderTo])
	if l != len(fa)-1 {
		t.Errorf("ToIgnoreInvalid() failed. Expected %d addresses, got: %d", len(fa)-1, l)
	}
}

// TestMsg_AddCc tests the Msg.AddCc method
func TestMsg_AddCc(t *testing.T) {
	a := []string{"address1@example.com", "address2@example.com"}
	na := "address3@example.com"
	m := NewMsg()
	if err := m.Cc(a...); err != nil {
		t.Errorf("failed to set CC addresses: %s", err)
		return
	}
	if err := m.AddCc(na); err != nil {
		t.Errorf("AddCc failed: %s", err)
		return
	}

	atf := false
	for _, v := range m.addrHeader[HeaderCc] {
		if v.Address == na {
			atf = true
		}
	}
	if !atf {
		t.Errorf("AddCc() failed. Address %q not found in CC address slice.", na)
	}
}

// TestMsg_AddCcFormat tests the Msg.AddCcFormat method
func TestMsg_AddCcFormat(t *testing.T) {
	a := []string{"address1@example.com", "address2@example.com"}
	nn := "Toni Tester"
	na := "address3@example.com"
	w := `"Toni Tester" <address3@example.com>`
	m := NewMsg()
	if err := m.Cc(a...); err != nil {
		t.Errorf("failed to set CC addresses: %s", err)
		return
	}
	if err := m.AddCcFormat(nn, na); err != nil {
		t.Errorf("AddCcFormat failed: %s", err)
		return
	}

	atf := false
	for _, v := range m.addrHeader[HeaderCc] {
		if v.String() == w {
			atf = true
		}
	}
	if !atf {
		t.Errorf("AddCcFormat() failed. Address %q not found in CC address slice.", w)
	}
}

// TestMsg_CcIgnoreInvalid tests the Msg.CcIgnoreInvalid method
func TestMsg_CcIgnoreInvalid(t *testing.T) {
	a := []string{"address1@example.com", "address2@example.com"}
	fa := []string{"address1@example.com", "address2@example.com", "failedaddress.com"}
	m := NewMsg()

	m.CcIgnoreInvalid(a...)
	l := len(m.addrHeader[HeaderCc])
	if l != len(a) {
		t.Errorf("CcIgnoreInvalid() failed. Expected %d addresses, got: %d", len(a), l)
	}
	m.CcIgnoreInvalid(fa...)
	l = len(m.addrHeader[HeaderCc])
	if l != len(fa)-1 {
		t.Errorf("CcIgnoreInvalid() failed. Expected %d addresses, got: %d", len(fa)-1, l)
	}
}

// TestMsg_AddBcc tests the Msg.AddBcc method
func TestMsg_AddBcc(t *testing.T) {
	a := []string{"address1@example.com", "address2@example.com"}
	na := "address3@example.com"
	m := NewMsg()
	if err := m.Bcc(a...); err != nil {
		t.Errorf("failed to set BCC addresses: %s", err)
		return
	}
	if err := m.AddBcc(na); err != nil {
		t.Errorf("AddBcc failed: %s", err)
		return
	}

	atf := false
	for _, v := range m.addrHeader[HeaderBcc] {
		if v.Address == na {
			atf = true
		}
	}
	if !atf {
		t.Errorf("AddBcc() failed. Address %q not found in BCC address slice.", na)
	}
}

// TestMsg_AddBccFormat tests the Msg.AddBccFormat method
func TestMsg_AddBccFormat(t *testing.T) {
	a := []string{"address1@example.com", "address2@example.com"}
	nn := "Toni Tester"
	na := "address3@example.com"
	w := `"Toni Tester" <address3@example.com>`
	m := NewMsg()
	if err := m.Bcc(a...); err != nil {
		t.Errorf("failed to set BCC addresses: %s", err)
		return
	}
	if err := m.AddBccFormat(nn, na); err != nil {
		t.Errorf("AddBccFormat failed: %s", err)
		return
	}

	atf := false
	for _, v := range m.addrHeader[HeaderBcc] {
		if v.String() == w {
			atf = true
		}
	}
	if !atf {
		t.Errorf("AddBccFormat() failed. Address %q not found in BCC address slice.", w)
	}
}

// TestMsg_BccIgnoreInvalid tests the Msg.BccIgnoreInvalid method
func TestMsg_BccIgnoreInvalid(t *testing.T) {
	a := []string{"address1@example.com", "address2@example.com"}
	fa := []string{"address1@example.com", "address2@example.com", "failedaddress.com"}
	m := NewMsg()

	m.BccIgnoreInvalid(a...)
	l := len(m.addrHeader[HeaderBcc])
	if l != len(a) {
		t.Errorf("BccIgnoreInvalid() failed. Expected %d addresses, got: %d", len(a), l)
	}
	m.BccIgnoreInvalid(fa...)
	l = len(m.addrHeader[HeaderBcc])
	if l != len(fa)-1 {
		t.Errorf("BccIgnoreInvalid() failed. Expected %d addresses, got: %d", len(fa)-1, l)
	}
}

// TestMsg_SetBulk tests the Msg.SetBulk method
func TestMsg_SetBulk(t *testing.T) {
	m := NewMsg()
	m.SetBulk()
	if m.genHeader[HeaderPrecedence] == nil {
		t.Errorf("SetBulk() failed. Precedence header is nil")
		return
	}
	if m.genHeader[HeaderPrecedence][0] != "bulk" {
		t.Errorf("SetBulk() failed. Expected Precedence header: %q, got: %q", "bulk",
			m.genHeader[HeaderPrecedence][0])
	}
	if m.genHeader[HeaderXAutoResponseSuppress] == nil {
		t.Errorf("SetBulk() failed. X-Auto-Response-Suppress header is nil")
		return
	}
	if m.genHeader[HeaderXAutoResponseSuppress][0] != "All" {
		t.Errorf("SetBulk() failed. Expected X-Auto-Response-Suppress header: %q, got: %q", "All",
			m.genHeader[HeaderXAutoResponseSuppress][0])
	}
}

// TestMsg_SetDate tests the Msg.SetDate and Msg.SetDateWithValue method
func TestMsg_SetDate(t *testing.T) {
	m := NewMsg()
	m.SetDate()
	if m.genHeader[HeaderDate] == nil {
		t.Errorf("SetDate() failed. Date header is nil")
		return
	}
	d, ok := m.genHeader[HeaderDate]
	if !ok {
		t.Errorf("failed to get date header")
		return
	}
	_, err := time.Parse(time.RFC1123Z, d[0])
	if err != nil {
		t.Errorf("failed to parse time in date header: %s", err)
	}
	m.genHeader = nil
	m.genHeader = make(map[Header][]string)

	now := time.Now()
	m.SetDateWithValue(now)
	if m.genHeader[HeaderDate] == nil {
		t.Errorf("SetDateWithValue() failed. Date header is nil")
		return
	}
	d, ok = m.genHeader[HeaderDate]
	if !ok {
		t.Errorf("failed to get date header")
		return
	}
	pt, err := time.Parse(time.RFC1123Z, d[0])
	if err != nil {
		t.Errorf("failed to parse time in date header: %s", err)
	}
	if pt.Unix() != now.Unix() {
		t.Errorf("SetDateWithValue() failed. Expected time: %d, got: %d", now.Unix(),
			pt.Unix())
	}
}

// TestMsg_SetMessageIDWIthValue tests the Msg.SetMessageIDWithValue and Msg.SetMessageID methods
func TestMsg_SetMessageIDWithValue(t *testing.T) {
	m := NewMsg()
	m.SetMessageID()
	if m.genHeader[HeaderMessageID] == nil {
		t.Errorf("SetMessageID() failed. MessageID header is nil")
		return
	}
	if m.genHeader[HeaderMessageID][0] == "" {
		t.Errorf("SetMessageID() failed. Expected value, got: empty")
		return
	}
	if _, ok := m.genHeader[HeaderMessageID]; ok {
		m.genHeader[HeaderMessageID] = nil
	}
	v := "This.is.a.message.id"
	vf := "<This.is.a.message.id>"
	m.SetMessageIDWithValue(v)
	if m.genHeader[HeaderMessageID] == nil {
		t.Errorf("SetMessageIDWithValue() failed. MessageID header is nil")
		return
	}
	if m.genHeader[HeaderMessageID][0] != vf {
		t.Errorf("SetMessageIDWithValue() failed. Expected: %s, got: %s", vf, m.genHeader[HeaderMessageID][0])
		return
	}
}

// TestMsg_SetMessageIDRandomness tests the randomness of Msg.SetMessageID methods
func TestMsg_SetMessageIDRandomness(t *testing.T) {
	var mids []string
	for i := 0; i < 100; i++ {
		m := NewMsg()
		m.SetMessageID()
		mid := m.GetGenHeader(HeaderMessageID)
		if len(mid) > 0 {
			mids = append(mids, mid[0])
		}
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
}

// TestMsg_FromFormat tests the FromFormat and EnvelopeFrom methods for the Msg object
func TestMsg_FromFormat(t *testing.T) {
	tests := []struct {
		tname string
		name  string
		addr  string
		want  string
		fail  bool
	}{
		{
			"valid name and addr", "Toni Tester", "tester@example.com",
			`"Toni Tester" <tester@example.com>`, false,
		},
		{
			"no name with valid addr", "", "tester@example.com",
			`<tester@example.com>`, false,
		},
		{
			"valid name with invalid addr", "Toni Tester", "@example.com",
			``, true,
		},
	}

	m := NewMsg()
	for _, tt := range tests {
		t.Run(tt.tname, func(t *testing.T) {
			if err := m.FromFormat(tt.name, tt.addr); err != nil && !tt.fail {
				t.Errorf("failed to FromFormat(): %s", err)
				return
			}
			if err := m.EnvelopeFromFormat(tt.name, tt.addr); err != nil && !tt.fail {
				t.Errorf("failed to EnvelopeFromFormat(): %s", err)
				return
			}

			var fa *mail.Address
			f, ok := m.addrHeader[HeaderFrom]
			if ok && len(f) > 0 {
				fa = f[0]
			}
			if (!ok || len(f) == 0) && !tt.fail {
				t.Errorf(`valid from address expected, but "From:" field is empty`)
				return
			}
			if tt.fail && len(f) > 0 {
				t.Errorf("FromFormat() was supposed to failed but got value: %s", fa.String())
				return
			}

			if !tt.fail && fa.String() != tt.want {
				t.Errorf("wrong result for FromFormat(). Want: %s, got: %s", tt.want, fa.String())
			}
			m.addrHeader[HeaderFrom] = nil
		})
	}
}

func TestMsg_GetRecipients(t *testing.T) {
	a := []string{"to@example.com", "cc@example.com", "bcc@example.com"}
	m := NewMsg()

	_, err := m.GetRecipients()
	if err == nil {
		t.Errorf("GetRecipients() succeeded but was expected to fail")
		return
	}

	if err := m.AddTo(a[0]); err != nil {
		t.Errorf("AddTo() failed: %s", err)
		return
	}
	if err := m.AddCc(a[1]); err != nil {
		t.Errorf("AddCc() failed: %s", err)
		return
	}
	if err := m.AddBcc(a[2]); err != nil {
		t.Errorf("AddBcc() failed: %s", err)
		return
	}

	al, err := m.GetRecipients()
	if err != nil {
		t.Errorf("GetRecipients() failed: %s", err)
		return
	}

	tf, cf, bf := false, false, false
	for _, r := range al {
		if r == a[0] {
			tf = true
		}
		if r == a[1] {
			cf = true
		}
		if r == a[2] {
			bf = true
		}
	}
	if !tf {
		t.Errorf("GetRecipients() failed. Expected to address %s but was not found", a[0])
		return
	}
	if !cf {
		t.Errorf("GetRecipients() failed. Expected cc address %s but was not found", a[1])
		return
	}
	if !bf {
		t.Errorf("GetRecipients() failed. Expected bcc address %s but was not found", a[2])
		return
	}
}

// TestMsg_ReplyTo tests the Msg.ReplyTo and Msg.ReplyToFormat methods
func TestMsg_ReplyTo(t *testing.T) {
	tests := []struct {
		tname string
		name  string
		addr  string
		want  string
		sf    bool
	}{
		{
			"valid name and addr", "Toni Tester", "tester@example.com",
			`"Toni Tester" <tester@example.com>`, false,
		},
		{
			"no name with valid addr", "", "tester@example.com",
			`<tester@example.com>`, false,
		},
		{
			"valid name with invalid addr", "Toni Tester", "@example.com",
			``, true,
		},
	}
	m := NewMsg()
	for _, tt := range tests {
		t.Run(tt.tname, func(t *testing.T) {
			if err := m.ReplyTo(tt.want); err != nil && !tt.sf {
				t.Errorf("ReplyTo() method failed: %s", err)
			}
			if !tt.sf {
				rt, ok := m.genHeader[HeaderReplyTo]
				if !ok {
					t.Errorf("ReplyTo() failed: ReplyTo generic header not set")
					return
				}
				if len(rt) <= 0 {
					t.Errorf("ReplyTo() failed: length of generic ReplyTo header is zero or less than zero")
					return
				}
				if rt[0] != tt.want {
					t.Errorf("ReplyTo() failed: expected value: %s, got: %s", tt.want, rt[0])
				}
			}
			m.genHeader = nil
			m.genHeader = make(map[Header][]string)
			if err := m.ReplyToFormat(tt.name, tt.addr); err != nil && !tt.sf {
				t.Errorf("ReplyToFormat() method failed: %s", err)
			}
			if !tt.sf {
				rt, ok := m.genHeader[HeaderReplyTo]
				if !ok {
					t.Errorf("ReplyTo() failed: ReplyTo generic header not set")
					return
				}
				if len(rt) <= 0 {
					t.Errorf("ReplyTo() failed: length of generic ReplyTo header is zero or less than zero")
					return
				}
				if rt[0] != tt.want {
					t.Errorf("ReplyTo() failed: expected value: %s, got: %s", tt.want, rt[0])
				}
			}
			m.genHeader = nil
			m.genHeader = make(map[Header][]string)
		})
	}
}

// TestMsg_Subject tests the Msg.Subject method
func TestMsg_Subject(t *testing.T) {
	tests := []struct {
		name string
		sub  string
		want string
	}{
		{"normal subject", "This is a test subject", "This is a test subject"},
		{
			"subject with umlauts", "This is a test subject with umlauts: üäöß",
			"=?UTF-8?q?This_is_a_test_subject_with_umlauts:_=C3=BC=C3=A4=C3=B6=C3=9F?=",
		},
		{
			"subject with emoji", "This is a test subject with emoji: 📧",
			"=?UTF-8?q?This_is_a_test_subject_with_emoji:_=F0=9F=93=A7?=",
		},
	}
	m := NewMsg()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.Subject(tt.sub)
			s, ok := m.genHeader[HeaderSubject]
			if !ok || len(s) <= 0 {
				t.Errorf("Subject() method failed. Generic header for Subject is empty")
				return
			}
			if s[0] != tt.want {
				t.Errorf("Subject() method failed. Expected: %s, got: %s", tt.want, s[0])
			}
		})
	}
}

// TestMsg_SetImportance tests the Msg.SetImportance method
func TestMsg_SetImportance(t *testing.T) {
	tests := []struct {
		name   string
		imp    Importance
		wantns string
		xprio  string
		want   string
		sf     bool
	}{
		{"Importance: Non-Urgent", ImportanceNonUrgent, "0", "5", "non-urgent", false},
		{"Importance: Low", ImportanceLow, "0", "5", "low", false},
		{"Importance: Normal", ImportanceNormal, "", "", "", true},
		{"Importance: High", ImportanceHigh, "1", "1", "high", false},
		{"Importance: Urgent", ImportanceUrgent, "1", "1", "urgent", false},
		{"Importance: Unknown", 9, "", "", "", true},
	}
	m := NewMsg()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.SetImportance(tt.imp)
			hi, ok := m.genHeader[HeaderImportance]
			if (!ok || len(hi) <= 0) && !tt.sf {
				t.Errorf("SetImportance() method failed. Generic header for Importance is empty")
			}
			hp, ok := m.genHeader[HeaderPriority]
			if (!ok || len(hp) <= 0) && !tt.sf {
				t.Errorf("SetImportance() method failed. Generic header for Priority is empty")
			}
			hx, ok := m.genHeader[HeaderXPriority]
			if (!ok || len(hx) <= 0) && !tt.sf {
				t.Errorf("SetImportance() method failed. Generic header for X-Priority is empty")
			}
			hm, ok := m.genHeader[HeaderXMSMailPriority]
			if (!ok || len(hm) <= 0) && !tt.sf {
				t.Errorf("SetImportance() method failed. Generic header for X-MS-XPriority is empty")
			}
			if !tt.sf {
				if hi[0] != tt.want {
					t.Errorf("SetImportance() method failed. Expected Imporance: %s, got: %s", tt.want, hi[0])
				}
				if hp[0] != tt.wantns {
					t.Errorf("SetImportance() method failed. Expected Priority: %s, got: %s", tt.want, hp[0])
				}
				if hx[0] != tt.xprio {
					t.Errorf("SetImportance() method failed. Expected X-Priority: %s, got: %s", tt.want, hx[0])
				}
				if hm[0] != tt.wantns {
					t.Errorf("SetImportance() method failed. Expected X-MS-Priority: %s, got: %s", tt.wantns, hm[0])
				}
			}
			m.genHeader = nil
			m.genHeader = make(map[Header][]string)
		})
	}
}

// TestMsg_SetOrganization tests the Msg.SetOrganization method
func TestMsg_SetOrganization(t *testing.T) {
	tests := []struct {
		name string
		org  string
	}{
		{"Org: testcorp", "testcorp"},
	}
	m := NewMsg()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.SetOrganization(tt.org)
			o, ok := m.genHeader[HeaderOrganization]
			if !ok || len(o) <= 0 {
				t.Errorf("SetOrganization() method failed. Generic header for Organization is empty")
				return
			}
			if o[0] != tt.org {
				t.Errorf("SetOrganization() method failed. Expected: %s, got: %s", tt.org, o[0])
			}
		})
	}
}

// TestMsg_SetUserAgent tests the Msg.SetUserAgent method
func TestMsg_SetUserAgent(t *testing.T) {
	tests := []struct {
		name string
		ua   string
	}{
		{"UA: Testmail 1.0", "Testmailer 1.0"},
	}
	m := NewMsg()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.SetUserAgent(tt.ua)
			xm, ok := m.genHeader[HeaderXMailer]
			if !ok || len(xm) <= 0 {
				t.Errorf("SetUserAgent() method failed. Generic header for X-Mailer is empty")
				return
			}
			ua, ok := m.genHeader[HeaderUserAgent]
			if !ok || len(ua) <= 0 {
				t.Errorf("SetUserAgent() method failed. Generic header for UserAgent is empty")
				return
			}
			if xm[0] != tt.ua {
				t.Errorf("SetUserAgent() method failed. Expected X-Mailer: %s, got: %s", tt.ua, xm[0])
			}
			if ua[0] != tt.ua {
				t.Errorf("SetUserAgent() method failed. Expected User-Agent: %s, got: %s", tt.ua, ua[0])
			}
		})
	}
}

// TestMsg_RequestMDN tests the different RequestMDN* related methods of Msg
func TestMsg_RequestMDN(t *testing.T) {
	n := "Toni Tester"
	n2 := "Melanie Tester"
	v := "toni.tester@example.com"
	v2 := "melanie.tester@example.com"
	iv := "testertest.tld"
	vl := []string{v, v2}
	m := NewMsg()

	// Single valid address
	if err := m.RequestMDNTo(v); err != nil {
		t.Errorf("RequestMDNTo with a single valid address failed: %s", err)
	}
	if val := m.genHeader[HeaderDispositionNotificationTo]; len(val) > 1 {
		if val[0] != fmt.Sprintf("<%s>", v) {
			t.Errorf("RequestMDNTo with a single valid address failed. Expected: %s, got: %s", v,
				val[0])
		}
	}
	m.Reset()

	// Multiples valid addresses
	if err := m.RequestMDNTo(vl...); err != nil {
		t.Errorf("RequestMDNTo with a multiple valid address failed: %s", err)
	}
	if val := m.genHeader[HeaderDispositionNotificationTo]; len(val) > 0 {
		if val[0] != fmt.Sprintf("<%s>", v) {
			t.Errorf("RequestMDNTo with a multiple valid addresses failed. Expected 0: %s, got 0: %s", v,
				val[0])
		}
	}
	if val := m.genHeader[HeaderDispositionNotificationTo]; len(val) > 1 {
		if val[1] != fmt.Sprintf("<%s>", v2) {
			t.Errorf("RequestMDNTo with a multiple valid addresses failed. Expected 1: %s, got 1: %s", v2,
				val[1])
		}
	}
	m.Reset()

	// Invalid address
	if err := m.RequestMDNTo(iv); err == nil {
		t.Errorf("RequestMDNTo with an invalid address was supposed to failed, but didn't")
	}
	m.Reset()

	// Single valid addresses + AddTo
	if err := m.RequestMDNTo(v); err != nil {
		t.Errorf("RequestMDNTo with a single valid address failed: %s", err)
	}
	if err := m.RequestMDNAddTo(v2); err != nil {
		t.Errorf("RequestMDNAddTo with a valid address failed: %s", err)
	}
	if val := m.genHeader[HeaderDispositionNotificationTo]; len(val) > 1 {
		if val[1] != fmt.Sprintf("<%s>", v2) {
			t.Errorf("RequestMDNTo with a multiple valid addresses failed. Expected 1: %s, got 1: %s", v2,
				val[1])
		}
	}
	m.Reset()

	// Single valid address formated + AddToFromat
	if err := m.RequestMDNToFormat(n, v); err != nil {
		t.Errorf("RequestMDNToFormat with a single valid address failed: %s", err)
	}
	if val := m.genHeader[HeaderDispositionNotificationTo]; len(val) > 0 {
		if val[0] != fmt.Sprintf(`"%s" <%s>`, n, v) {
			t.Errorf(`RequestMDNToFormat with a single valid address failed. Expected: "%s" <%s>, got: %s`, n, v,
				val[0])
		}
	}
	if err := m.RequestMDNAddToFormat(n2, v2); err != nil {
		t.Errorf("RequestMDNAddToFormat with a valid address failed: %s", err)
	}
	if val := m.genHeader[HeaderDispositionNotificationTo]; len(val) > 1 {
		if val[1] != fmt.Sprintf(`"%s" <%s>`, n2, v2) {
			t.Errorf(`RequestMDNAddToFormat with a single valid address failed. Expected: "%s" <%s>, got: %s`, n2, v2,
				val[1])
		}
	}
	m.Reset()

	// Invalid formated address
	if err := m.RequestMDNToFormat(n, iv); err == nil {
		t.Errorf("RequestMDNToFormat with an invalid address was supposed to failed, but didn't")
	}

	// Invalid address AddTo + AddToFormat
	if err := m.RequestMDNAddTo(iv); err == nil {
		t.Errorf("RequestMDNAddTo with an invalid address was supposed to failed, but didn't")
	}
	if err := m.RequestMDNAddToFormat(n, iv); err == nil {
		t.Errorf("RequestMDNAddToFormat with an invalid address was supposed to failed, but didn't")
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
			if _, err := part.w(&res); err != nil && !tt.sf {
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
			if _, err := apart.w(&res); err != nil && !tt.sf {
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

// TestMsg_GetAttachments tests the Msg.GetAttachments method
func TestMsg_GetAttachments(t *testing.T) {
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
				m.AttachFile(f, WithFileName(f), nil)
			}
			if len(m.attachments) != len(tt.files) {
				t.Errorf("AttachFile() failed. Number of attachments expected: %d, got: %d", len(tt.files),
					len(m.attachments))
				return
			}
			ff := m.GetAttachments()
			if len(m.attachments) != len(ff) {
				t.Errorf("GetAttachments() failed. Number of attachments expected: %d, got: %d", len(m.attachments),
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
					t.Errorf("GetAttachments() failed. Attachment name expected: %s, got: %s", f,
						fn[i])
					return
				}
			}
			m.Reset()
		})
	}
}

// TestMsg_SetAttachments tests the Msg.GetAttachments method
func TestMsg_SetAttachments(t *testing.T) {
	tests := []struct {
		name        string
		attachments []string
		files       []string
	}{
		{"File: replace README.md  with doc.go", []string{"README.md"}, []string{"doc.go"}},
		{"File: add README.md with doc.go ", []string{"doc.go"}, []string{"README.md", "doc.go"}},
		{"File: remove README.md and doc.go", []string{"README.md", "doc.go"}, nil},
		{"File: add README.md and doc.go", nil, []string{"README.md", "doc.go"}},
	}
	m := NewMsg()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sort.Strings(tt.attachments)
			sort.Strings(tt.files)
			for _, a := range tt.attachments {
				m.AttachFile(a, WithFileName(a), nil)
			}
			if len(m.attachments) != len(tt.attachments) {
				t.Errorf("AttachFile() failed. Number of attachments expected: %d, got: %d", len(tt.files),
					len(m.attachments))
				return
			}
			var files []*File
			for _, f := range tt.files {
				files = append(files, &File{Name: f})
			}
			m.SetAttachements(files)
			if len(m.attachments) != len(files) {
				t.Errorf("SetAttachements() failed. Number of attachments expected: %d, got: %d", len(files),
					len(m.attachments))
				return
			}
			for i, f := range tt.files {
				if f != m.attachments[i].Name {
					t.Errorf("SetAttachments() failed. Attachment name expected: %s, got: %s", f,
						m.attachments[i].Name)
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
			m.SetAttachements(files)

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
			m.SetAttachements(attachments)
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
			wantUserAgent:      "go-mail v0.4.1 // https://github.com/wneessen/go-mail",
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
