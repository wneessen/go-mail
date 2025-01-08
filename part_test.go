// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

// TestPartEncoding tests the WithPartEncoding and Part.SetEncoding methods
func TestPartEncoding(t *testing.T) {
	tests := []struct {
		name string
		enc  Encoding
		want string
	}{
		{"Part encoding: Base64", EncodingB64, "base64"},
		{"Part encoding: Quoted-Printable", EncodingQP, "quoted-printable"},
		{"Part encoding: 8bit", NoEncoding, "8bit"},
	}
	for _, tt := range tests {
		m := NewMsg()
		t.Run(tt.name, func(t *testing.T) {
			part := m.newPart(TypeTextPlain, WithPartEncoding(tt.enc), nil)
			if part == nil {
				t.Errorf("newPart() WithPartEncoding() failed: no part returned")
				return
			}
			if part.encoding.String() != tt.want {
				t.Errorf("newPart() WithPartEncoding() failed: expected encoding: %s, got: %s", tt.want,
					part.encoding.String())
			}
			part.encoding = ""
			part.SetEncoding(tt.enc)
			if part.encoding.String() != tt.want {
				t.Errorf("newPart() SetEncoding() failed: expected encoding: %s, got: %s", tt.want,
					part.encoding.String())
			}
		})
	}
}

// TestWithPartCharset tests the WithPartCharset method
func TestWithPartCharset(t *testing.T) {
	tests := []struct {
		name string
		cs   Charset
		want string
	}{
		{"Part charset: UTF-8", CharsetUTF8, "UTF-8"},
		{"Part charset: ISO-8859-1", CharsetISO88591, "ISO-8859-1"},
		{"Part charset: empty", "", ""},
	}
	for _, tt := range tests {
		m := NewMsg()
		t.Run(tt.name, func(t *testing.T) {
			part := m.newPart(TypeTextPlain, WithPartCharset(tt.cs), nil)
			if part == nil {
				t.Errorf("newPart() WithPartCharset() failed: no part returned")
				return
			}
			if part.charset.String() != tt.want {
				t.Errorf("newPart() WithPartCharset() failed: expected charset: %s, got: %s",
					tt.want, part.charset.String())
			}
		})
	}
}

// TestPart_WithPartContentDescription tests the WithPartContentDescription method
func TestPart_WithPartContentDescription(t *testing.T) {
	tests := []struct {
		name string
		desc string
	}{
		{"Part description: test", "test"},
		{"Part description: empty", ""},
	}
	for _, tt := range tests {
		m := NewMsg()
		t.Run(tt.name, func(t *testing.T) {
			part := m.newPart(TypeTextPlain, WithPartContentDescription(tt.desc), nil)
			if part == nil {
				t.Errorf("newPart() WithPartContentDescription() failed: no part returned")
				return
			}
			if part.description != tt.desc {
				t.Errorf("newPart() WithPartContentDescription() failed: expected: %s, got: %s", tt.desc,
					part.description)
			}
			part.description = ""
			part.SetDescription(tt.desc)
			if part.description != tt.desc {
				t.Errorf("newPart() SetDescription() failed: expected: %s, got: %s", tt.desc, part.description)
			}
		})
	}
}

// TestPart_WithSMimeSinging tests the WithSMIMESigning method
func TestPart_WithSMimeSinging(t *testing.T) {
	m := NewMsg()
	part := m.newPart(TypeTextPlain, WithSMIMESigning())
	if part == nil {
		t.Errorf("newPart() WithSMIMESigning() failed: no part returned")
		return
	}
	if part.smime != true {
		t.Errorf("newPart() WithSMIMESigning() failed: expected: %v, got: %v", true, part.smime)
	}
	part.smime = true
	part.SetIsSMIMESigned(false)
	if part.smime != false {
		t.Errorf("newPart() SetIsSMIMESigned() failed: expected: %v, got: %v", false, part.smime)
	}
}

// TestPartContentType tests Part.SetContentType
func TestPart_SetContentType(t *testing.T) {
	tests := []struct {
		name string
		ct   ContentType
		want string
	}{
		{"ContentType: text/plain", TypeTextPlain, "text/plain"},
		{"ContentType: text/html", TypeTextHTML, "text/html"},
		{"ContentType: application/json", "application/json", "application/json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMsg()
			m.SetBodyString(TypeTextPlain, "This is a test with ümläutß")
			pl, err := getPartList(m)
			if err != nil {
				t.Errorf("failed: %s", err)
				return
			}
			pl[0].SetContentType(tt.ct)
			ct := pl[0].GetContentType()
			if string(ct) != tt.want {
				t.Errorf("SetContentType failed. Got: %s, expected: %s", string(ct), tt.want)
			}
		})
	}
}

// TestPartEncoding tests Part.GetEncoding
func TestPart_GetEncoding(t *testing.T) {
	tests := []struct {
		name string
		enc  Encoding
		want string
	}{
		{"Part encoding: Base64", EncodingB64, "base64"},
		{"Part encoding: Quoted-Printable", EncodingQP, "quoted-printable"},
		{"Part encoding: 8bit", NoEncoding, "8bit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMsg()
			m.SetBodyString(TypeTextPlain, "This is a test with ümläutß", WithPartEncoding(tt.enc))
			pl, err := getPartList(m)
			if err != nil {
				t.Errorf("failed: %s", err)
				return
			}
			e := pl[0].GetEncoding()
			if e.String() != tt.want {
				t.Errorf("Part.GetEncoding failed. Expected: %s, got: %s", tt.want, e.String())
			}
		})
	}
}

// TestPart_GetContentType tests Part.GetContentType
func TestPart_GetContentType(t *testing.T) {
	tests := []struct {
		name string
		ct   ContentType
		want string
	}{
		{"ContentType: text/plain", TypeTextPlain, "text/plain"},
		{"ContentType: text/html", TypeTextHTML, "text/html"},
		{"ContentType: application/json", "application/json", "application/json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMsg()
			m.SetBodyString(tt.ct, "This is a test with ümläutß")
			pl, err := getPartList(m)
			if err != nil {
				t.Errorf("failed: %s", err)
				return
			}
			c := pl[0].GetContentType()
			if string(c) != tt.want {
				t.Errorf("Part.GetContentType failed. Expected: %s, got: %s", tt.want, string(c))
			}
		})
	}
}

// TestPart_GetWriteFunc tests Part.GetWriteFunc
func TestPart_GetWriteFunc(t *testing.T) {
	c := "This is a test with ümläutß"
	m := NewMsg()
	m.SetBodyString(TypeTextPlain, c)
	pl, err := getPartList(m)
	if err != nil {
		t.Errorf("failed: %s", err)
		return
	}
	wf := pl[0].GetWriteFunc()
	var b bytes.Buffer
	if _, err := wf(&b); err != nil {
		t.Errorf("failed to execute writefunc: %s", err)
	}
	if b.String() != c {
		t.Errorf("GetWriteFunc failed. Expected: %s, got: %s", c, b.String())
	}
}

// TestPart_GetContent tests Part.GetContent
func TestPart_GetContent(t *testing.T) {
	c := "This is a test with ümläutß"
	m := NewMsg()
	m.SetBodyString(TypeTextPlain, c)
	pl, err := getPartList(m)
	if err != nil {
		t.Errorf("failed: %s", err)
		return
	}
	cb, err := pl[0].GetContent()
	if err != nil {
		t.Errorf("Part.GetContent failed: %s", err)
	}
	if string(cb) != c {
		t.Errorf("Part.GetContent failed. Expected: %s, got: %s", c, string(cb))
	}
}

// TestPart_GetContentBroken tests Part.GetContent
func TestPart_GetContentBroken(t *testing.T) {
	c := "This is a test with ümläutß"
	m := NewMsg()
	m.SetBodyString(TypeTextPlain, c)
	pl, err := getPartList(m)
	if err != nil {
		t.Errorf("failed: %s", err)
		return
	}
	pl[0].writeFunc = func(io.Writer) (int64, error) {
		return 0, fmt.Errorf("broken")
	}
	_, err = pl[0].GetContent()
	if err == nil {
		t.Errorf("Part.GetContent was supposed to failed, but didn't")
	}
}

// TestPart_IsSMimeSigned tests Part.IsSMIMESigned
func TestPart_IsSMimeSigned(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"smime:", true},
		{"smime:", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMsg()
			m.SetBodyString(TypeTextPlain, "This is a body!")
			pl, err := getPartList(m)
			if err != nil {
				t.Errorf("failed: %s", err)
				return
			}
			pl[0].SetIsSMIMESigned(tt.want)
			smime := pl[0].smime
			if smime != tt.want {
				t.Errorf("SetContentType failed. Got: %v, expected: %v", smime, tt.want)
			}
		})
	}
}

// TestPart_SetWriteFunc tests Part.SetWriteFunc
func TestPart_SetWriteFunc(t *testing.T) {
	c := "This is a test with ümläutß"
	m := NewMsg()
	m.SetBodyString(TypeTextPlain, c)
	pl, err := getPartList(m)
	if err != nil {
		t.Errorf("failed: %s", err)
		return
	}
	cb, err := pl[0].GetContent()
	if err != nil {
		t.Errorf("Part.GetContent failed: %s", err)
	}
	pl[0].SetWriteFunc(func(w io.Writer) (int64, error) {
		ns := strings.ToUpper(string(cb))
		buf := bytes.NewBufferString(ns)
		nb, err := w.Write(buf.Bytes())
		return int64(nb), err
	})
	nc, err := pl[0].GetContent()
	if err != nil {
		t.Errorf("Part.GetContent failed: %s", err)
	}
	if string(nc) != strings.ToUpper(c) {
		t.Errorf("SetWriteFunc failed. Expected: %s, got: %s", strings.ToUpper(c), string(nc))
	}
}

// TestPart_SetContent tests Part.SetContent
func TestPart_SetContent(t *testing.T) {
	c := "This is a test with ümläutß"
	m := NewMsg()
	m.SetBodyString(TypeTextPlain, c)
	pl, err := getPartList(m)
	if err != nil {
		t.Errorf("failed: %s", err)
		return
	}
	cb, err := pl[0].GetContent()
	if err != nil {
		t.Errorf("Part.GetContent failed: %s", err)
	}
	pl[0].SetContent(strings.ToUpper(string(cb)))
	nc, err := pl[0].GetContent()
	if err != nil {
		t.Errorf("Part.GetContent failed: %s", err)
	}
	if string(nc) != strings.ToUpper(c) {
		t.Errorf("SetContent failed. Expected: %s, got: %s", strings.ToUpper(c), string(nc))
	}
}

// TestPart_SetDescription tests Part.SetDescription
func TestPart_SetDescription(t *testing.T) {
	c := "This is a test"
	d := "test-description"
	m := NewMsg()
	m.SetBodyString(TypeTextPlain, c)
	pl, err := getPartList(m)
	if err != nil {
		t.Errorf("failed: %s", err)
		return
	}
	pd := pl[0].GetDescription()
	if pd != "" {
		t.Errorf("Part.GetDescription failed. Expected empty description but got: %s", pd)
	}
	pl[0].SetDescription(d)
	if pl[0].description != d {
		t.Errorf("Part.SetDescription failed. Expected description to be: %s, got: %s", d, pd)
	}
	pd = pl[0].GetDescription()
	if pd != d {
		t.Errorf("Part.GetDescription failed. Expected: %s, got: %s", d, pd)
	}
}

// TestPart_Delete tests Part.Delete
func TestPart_Delete(t *testing.T) {
	c := "This is a test with ümläutß"
	m := NewMsg()
	m.SetBodyString(TypeTextPlain, c)
	pl, err := getPartList(m)
	if err != nil {
		t.Errorf("failed: %s", err)
		return
	}
	pl[0].Delete()
	if !pl[0].isDeleted {
		t.Errorf("Delete failed. Expected: %t, got: %t", true, pl[0].isDeleted)
	}
}

// getPartList is a helper function
func getPartList(m *Msg) ([]*Part, error) {
	pl := m.GetParts()
	if len(pl) <= 0 {
		return nil, fmt.Errorf("Msg.GetParts failed. Part list is empty")
	}
	return pl, nil
}

// TestPart_SetCharset tests Part.SetCharset method
func TestPart_SetCharset(t *testing.T) {
	tests := []struct {
		name string
		cs   Charset
		want string
	}{
		{"Charset: UTF-8", CharsetUTF8, "UTF-8"},
		{"Charset: ISO-8859-1", CharsetISO88591, "ISO-8859-1"},
		{"Charset: empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMsg()
			m.SetBodyString(TypeTextPlain, "This is a test with ümläutß")
			pl, err := getPartList(m)
			if err != nil {
				t.Errorf("failed: %s", err)
				return
			}
			pl[0].SetCharset(tt.cs)
			cs := pl[0].GetCharset()
			if string(cs) != tt.want {
				t.Errorf("SetCharset failed. Got: %s, expected: %s", string(cs), tt.want)
			}
		})
	}
}
