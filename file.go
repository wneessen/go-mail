// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"io"
	"net/textproto"
)

// FileOption is a function type used to modify properties of a File
type FileOption func(*File)

// File represents a file with properties like content type, description, encoding, headers, name, and
// writer function. This can either be an attachment or an embedded file for a Msg.
type File struct {
	ContentType ContentType
	Desc        string
	Enc         Encoding
	Header      textproto.MIMEHeader
	Name        string
	Writer      func(w io.Writer) (int64, error)
}

// WithFileContentID sets the "Content-ID" header in the File's MIME headers to the specified id.
func WithFileContentID(id string) FileOption {
	return func(f *File) {
		f.Header.Set(HeaderContentID.String(), id)
	}
}

// WithFileName sets the name of a File to the provided value.
func WithFileName(name string) FileOption {
	return func(f *File) {
		f.Name = name
	}
}

// WithFileDescription sets an optional file description for the File. The description is used in the
// Content-Description header of the MIME output.
func WithFileDescription(description string) FileOption {
	return func(f *File) {
		f.Desc = description
	}
}

// WithFileEncoding sets the encoding type for a file.
//
// By default one should always use Base64 encoding for attachments and embeds, but there might be exceptions in
// which this might come handy.
//
// Note: that quoted-printable must never be used for attachments or embeds. If EncodingQP is provided as encoding
// to this method, it will be automatically overwritten with EncodingB64.
func WithFileEncoding(encoding Encoding) FileOption {
	return func(f *File) {
		if encoding == EncodingQP {
			return
		}
		f.Enc = encoding
	}
}

// WithFileContentType sets the content type of the File.
//
// By default we will try to guess the file type and its corresponding content type and fall back to
// application/octet-stream if the file type, if no matching type could be guessed. This FileOption can
// be used to override this type, in case a specific type is required.
func WithFileContentType(contentType ContentType) FileOption {
	return func(f *File) {
		f.ContentType = contentType
	}
}

// setHeader sets the value of a given MIME header field for the File.
func (f *File) setHeader(header Header, value string) {
	f.Header.Set(string(header), value)
}

// getHeader retrieves the value of the specified MIME header field. It returns the header value and a boolean
// indicating whether the header was present or not.
func (f *File) getHeader(header Header) (string, bool) {
	v := f.Header.Get(string(header))
	return v, v != ""
}
