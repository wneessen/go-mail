package mail

import (
	"fmt"
	"net/mail"
	"testing"
)

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
			m := NewMsg(WithCharset(tt.value))
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

// TestMsg_SetHEader tests Msg.SetHeader
func TestMsg_SetHeader(t *testing.T) {
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
			m.SetHeader(tt.header, tt.values...)
			if m.genHeader[tt.header] == nil {
				t.Errorf("SetHeader() failed. Tried to set header %s, but it is empty", tt.header)
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
					t.Errorf("SetHeader() failed. Value %s not found in header field", v)
				}
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

// TestMsg_FromFormat tests the FromFormat() method for the Msg object
func TestMsg_FromFormat(t *testing.T) {
	tests := []struct {
		tname string
		name  string
		addr  string
		want  string
		fail  bool
	}{
		{"valid name and addr", "Toni Tester", "tester@example.com",
			`"Toni Tester" <tester@example.com>`, false},
		{"no name with valid addr", "", "tester@example.com",
			`<tester@example.com>`, false},
		{"valid name with invalid addr", "Toni Tester", "@example.com",
			``, true},
	}

	m := NewMsg()
	for _, tt := range tests {
		t.Run(tt.tname, func(t *testing.T) {
			if err := m.FromFormat(tt.name, tt.addr); err != nil && !tt.fail {
				t.Errorf("failed to FromFormat(): %s", err)
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
