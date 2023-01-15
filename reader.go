// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"io"
)

// Reader is a type that implements the io.Reader interface for a Msg
type Reader struct {
	buf []byte // contents are the bytes buf[off : len(buf)]
	off int    // read at &buf[off], write at &buf[len(buf)]
	err error  // initalization error
}

// Error returns an error if the Reader err field is not nil
func (r *Reader) Error() error {
	return r.err
}

// Read reads the length of p of the Msg buffer to satisfy the io.Reader interface
func (r *Reader) Read(p []byte) (n int, err error) {
	if r.err != nil {
		return 0, r.err
	}
	if r.empty() {
		r.Reset()
		if len(p) == 0 {
			return 0, nil
		}
		return 0, io.EOF
	}
	n = copy(p, r.buf[r.off:])
	r.off += n
	return n, err
}

// Reset resets the Reader buffer to be empty, but it retains the underlying storage
// for use by future writes.
func (r *Reader) Reset() {
	r.buf = r.buf[:0]
	r.off = 0
}

// empty reports whether the unread portion of the Reader buffer is empty.
func (r *Reader) empty() bool { return len(r.buf) <= r.off }
