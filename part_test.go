// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"fmt"
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
			if part.enc.String() != tt.want {
				t.Errorf("newPart() WithPartEncoding() failed: expected encoding: %s, got: %s", tt.want,
					part.enc.String())
			}
			part.enc = ""
			part.SetEncoding(tt.enc)
			if part.enc.String() != tt.want {
				t.Errorf("newPart() SetEncoding() failed: expected encoding: %s, got: %s", tt.want,
					part.enc.String())
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

// getPartList is a helper function
func getPartList(m *Msg) ([]*Part, error) {
	pl := m.GetParts()
	if len(pl) <= 0 {
		return nil, fmt.Errorf("Msg.GetParts failed. Part list is empty")
	}
	return pl, nil
}
