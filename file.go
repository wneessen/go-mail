// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"io"
	"net/textproto"
)

// FileOption returns a function that can be used for grouping File options
type FileOption func(*File)

// File is an attachment or embedded file of the Msg
type File struct {
	ContentType ContentType
	Desc        string
	Enc         Encoding
	Header      textproto.MIMEHeader
	Name        string
	Writer      func(w io.Writer) (int64, error)
}

// WithContentID sets the Content-ID header for the File
func WithContentID(id string) FileOption {
	return func(f *File) {
		f.Header.Set(HeaderContentID.String(), id)
	}
}

// WithFileName sets the filename of the File
func WithFileName(name string) FileOption {
	return func(f *File) {
		f.Name = name
	}
}

// WithFileDescription sets an optional file description of the File that will be
// added as Content-Description part
func WithFileDescription(description string) FileOption {
	return func(f *File) {
		f.Desc = description
	}
}

// WithFileEncoding sets the encoding of the File. By default we should always use
// Base64 encoding but there might be exceptions, where this might come handy.
// Please note that quoted-printable should never be used for attachments/embeds. If this
// is provided as argument, the function will automatically override back to Base64
func WithFileEncoding(encoding Encoding) FileOption {
	return func(f *File) {
		if encoding == EncodingQP {
			return
		}
		f.Enc = encoding
	}
}

// WithFileContentType sets the content type of the File.
// By default go-mail will try to guess the file type and its corresponding
// content type and fall back to application/octet-stream if the file type
// could not be guessed. In some cases, however, it might be needed to force
// this to a specific type. For such situations this override method can
// be used
func WithFileContentType(contentType ContentType) FileOption {
	return func(f *File) {
		f.ContentType = contentType
	}
}

// setHeader sets header fields to a File
func (f *File) setHeader(header Header, value string) {
	f.Header.Set(string(header), value)
}

// getHeader return header fields of a File
func (f *File) getHeader(header Header) (string, bool) {
	v := f.Header.Get(string(header))
	return v, v != ""
}
