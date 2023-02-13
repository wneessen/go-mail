// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import "testing"

// TestFile_SetGetHeader tests the set-/getHeader method of the File object
func TestFile_SetGetHeader(t *testing.T) {
	f := File{
		Name:   "testfile.txt",
		Header: make(map[string][]string),
	}
	f.setHeader(HeaderContentType, "text/plain")
	fi, ok := f.getHeader(HeaderContentType)
	if !ok {
		t.Errorf("getHeader method of File did not return a value")
		return
	}
	if fi != "text/plain" {
		t.Errorf("getHeader returned wrong value. Expected: %s, got: %s", "text/plain", fi)
	}
	fi, ok = f.getHeader(HeaderContentTransferEnc)
	if ok {
		t.Errorf("getHeader method of File did return a value, but wasn't supposed to")
		return
	}
	if fi != "" {
		t.Errorf("getHeader returned wrong value. Expected: %s, got: %s", "", fi)
	}
}

// TestFile_WithFileDescription tests the WithFileDescription option
func TestFile_WithFileDescription(t *testing.T) {
	tests := []struct {
		name string
		desc string
	}{
		{"File description: test", "test"},
		{"File description: empty", ""},
	}
	for _, tt := range tests {
		m := NewMsg()
		t.Run(tt.name, func(t *testing.T) {
			m.AttachFile("file.go", WithFileDescription(tt.desc))
			al := m.GetAttachments()
			if len(al) <= 0 {
				t.Errorf("AttachFile() failed. Attachment list is empty")
			}
			a := al[0]
			if a.Desc != tt.desc {
				t.Errorf("WithFileDescription() failed. Expected: %s, got: %s", tt.desc, a.Desc)
			}
		})
	}
}

// TestFile_WithFileEncoding tests the WithFileEncoding option
func TestFile_WithFileEncoding(t *testing.T) {
	tests := []struct {
		name string
		enc  Encoding
		want Encoding
	}{
		{"File encoding: 8bit raw", NoEncoding, NoEncoding},
		{"File encoding: Base64", EncodingB64, EncodingB64},
		{"File encoding: quoted-printable (not allowed)", EncodingQP, ""},
	}
	for _, tt := range tests {
		m := NewMsg()
		t.Run(tt.name, func(t *testing.T) {
			m.AttachFile("file.go", WithFileEncoding(tt.enc))
			al := m.GetAttachments()
			if len(al) <= 0 {
				t.Errorf("AttachFile() failed. Attachment list is empty")
			}
			a := al[0]
			if a.Enc != tt.want {
				t.Errorf("WithFileEncoding() failed. Expected: %s, got: %s", tt.enc, a.Enc)
			}
		})
	}
}

// TestFile_WithFileContentType tests the WithFileContentType option
func TestFile_WithFileContentType(t *testing.T) {
	tests := []struct {
		name string
		ct   ContentType
		want string
	}{
		{"File content-type: text/plain", TypeTextPlain, "text/plain"},
		{"File content-type: html/html", TypeTextHTML, "text/html"},
		{"File content-type: application/octet-stream", TypeAppOctetStream, "application/octet-stream"},
		{"File content-type: application/pgp-encrypted", TypePGPEncrypted, "application/pgp-encrypted"},
		{"File content-type: application/pgp-signature", TypePGPSignature, "application/pgp-signature"},
	}
	for _, tt := range tests {
		m := NewMsg()
		t.Run(tt.name, func(t *testing.T) {
			m.AttachFile("file.go", WithFileContentType(tt.ct))
			al := m.GetAttachments()
			if len(al) <= 0 {
				t.Errorf("AttachFile() failed. Attachment list is empty")
			}
			a := al[0]
			if a.ContentType != ContentType(tt.want) {
				t.Errorf("WithFileContentType() failed. Expected: %s, got: %s", tt.want, a.ContentType)
			}
		})
	}
}
