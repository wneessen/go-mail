// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import "testing"

func TestFile(t *testing.T) {
	t.Run("setHeader", func(t *testing.T) {
		f := File{
			Name:   "testfile.txt",
			Header: make(map[string][]string),
		}
		f.setHeader(HeaderContentType, "text/plain")
		contentType, ok := f.Header[HeaderContentType.String()]
		if !ok {
			t.Fatalf("setHeader failed. Expected header %s to be set", HeaderContentType)
		}
		if len(contentType) != 1 {
			t.Fatalf("setHeader failed. Expected header %s to have one value, got: %d", HeaderContentType,
				len(contentType))
		}
		if contentType[0] != "text/plain" {
			t.Fatalf("setHeader failed. Expected header %s to have value %s, got: %s",
				HeaderContentType.String(), "text/plain", contentType[0])
		}
	})
	t.Run("getHeader", func(t *testing.T) {
		f := File{
			Name:   "testfile.txt",
			Header: make(map[string][]string),
		}
		f.setHeader(HeaderContentType, "text/plain")
		contentType, ok := f.getHeader(HeaderContentType)
		if !ok {
			t.Fatalf("setHeader failed. Expected header %s to be set", HeaderContentType)
		}
		if contentType != "text/plain" {
			t.Fatalf("setHeader failed. Expected header %s to have value %s, got: %s",
				HeaderContentType.String(), "text/plain", contentType)
		}
	})
	t.Run("WithFileDescription", func(t *testing.T) {
		tests := []struct {
			name string
			desc string
		}{
			{"File description: test", "test"},
			{"File description: with newline", "test\n"},
			{"File description: empty", ""},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				message.AttachFile("file.go", WithFileDescription(tt.desc))
				attachments := message.GetAttachments()
				if len(attachments) <= 0 {
					t.Fatalf("failed to retrieve attachments list")
				}
				firstAttachment := attachments[0]
				if firstAttachment == nil {
					t.Fatalf("failed to retrieve first attachment, got nil")
				}
				if firstAttachment.Desc != tt.desc {
					t.Errorf("WithFileDescription() failed. Expected: %s, got: %s", tt.desc,
						firstAttachment.Desc)
				}
			})
		}
	})
	t.Run("WithFileContentID", func(t *testing.T) {
		tests := []struct {
			name string
			id   string
		}{
			{"Content-ID: test", "test"},
			{"Content-ID: with newline", "test\n"},
			{"Content-ID: empty", ""},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				message.AttachFile("file.go", WithFileContentID(tt.id))
				attachments := message.GetAttachments()
				if len(attachments) <= 0 {
					t.Fatalf("failed to retrieve attachments list")
				}
				firstAttachment := attachments[0]
				if firstAttachment == nil {
					t.Fatalf("failed to retrieve first attachment, got nil")
				}
				contentID := firstAttachment.Header.Get(HeaderContentID.String())
				if contentID != tt.id {
					t.Errorf("WithFileContentID() failed. Expected: %s, got: %s", tt.id,
						contentID)
				}
			})
		}
	})
	t.Run("WithFileEncoding", func(t *testing.T) {
		tests := []struct {
			name     string
			encoding Encoding
			want     Encoding
		}{
			{"File encoding: US-ASCII", EncodingUSASCII, EncodingUSASCII},
			{"File encoding: 8bit raw", NoEncoding, NoEncoding},
			{"File encoding: Base64", EncodingB64, EncodingB64},
			{"File encoding: quoted-printable (not allowed)", EncodingQP, ""},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				message.AttachFile("file.go", WithFileEncoding(tt.encoding))
				attachments := message.GetAttachments()
				if len(attachments) <= 0 {
					t.Fatalf("failed to retrieve attachments list")
				}
				firstAttachment := attachments[0]
				if firstAttachment == nil {
					t.Fatalf("failed to retrieve first attachment, got nil")
				}
				if firstAttachment.Enc != tt.want {
					t.Errorf("WithFileEncoding() failed. Expected: %s, got: %s", tt.want, firstAttachment.Enc)
				}
			})
		}
	})
	t.Run("WithFileName", func(t *testing.T) {
		tests := []struct {
			name     string
			fileName string
		}{
			{"File name: test", "test"},
			{"File name: with newline", "test\n"},
			{"File name: empty", ""},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				message.AttachFile("file.go", WithFileName(tt.fileName))
				attachments := message.GetAttachments()
				if len(attachments) <= 0 {
					t.Fatalf("failed to retrieve attachments list")
				}
				firstAttachment := attachments[0]
				if firstAttachment == nil {
					t.Fatalf("failed to retrieve first attachment, got nil")
				}
				if firstAttachment.Name != tt.fileName {
					t.Errorf("WithFileName() failed. Expected: %s, got: %s", tt.fileName,
						firstAttachment.Name)
				}
			})
		}
	})
	t.Run("WithFileContentType", func(t *testing.T) {
		tests := []struct {
			name        string
			contentType ContentType
		}{
			{"File content-type: text/plain", TypeTextPlain},
			{"File content-type: html/html", TypeTextHTML},
			{"File content-type: application/octet-stream", TypeAppOctetStream},
			{"File content-type: application/pgp-encrypted", TypePGPEncrypted},
			{"File content-type: application/pgp-signature", TypePGPSignature},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				message := NewMsg()
				message.AttachFile("file.go", WithFileContentType(tt.contentType))
				attachments := message.GetAttachments()
				if len(attachments) <= 0 {
					t.Fatalf("failed to retrieve attachments list")
				}
				firstAttachment := attachments[0]
				if firstAttachment == nil {
					t.Fatalf("failed to retrieve first attachment, got nil")
				}
				if firstAttachment.ContentType != tt.contentType {
					t.Errorf("WithFileContentType() failed. Expected: %s, got: %s", tt.contentType,
						firstAttachment.ContentType)
				}
			})
		}
	})
}
