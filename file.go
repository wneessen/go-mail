// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
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
	Name   string
	Header textproto.MIMEHeader
	Writer func(w io.Writer) (int64, error)
}

// WithFileName sets the filename of the File
func WithFileName(n string) FileOption {
	return func(f *File) {
		f.Name = n
	}
}

// setHeader sets header fields to a File
func (f *File) setHeader(h Header, v string) {
	f.Header.Set(string(h), v)
}

func (f *File) getHeader(h Header) (string, bool) {
	v := f.Header.Get(string(h))
	return v, v != ""
}
