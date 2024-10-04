// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"errors"
	"io"
)

// newlineBytes is a byte slice representation of the SingleNewLine constant used for line breaking
// in encoding processes.
var newlineBytes = []byte(SingleNewLine)

// ErrNoOutWriter is the error message returned when no io.Writer is set for Base64LineBreaker.
const ErrNoOutWriter = "no io.Writer set for Base64LineBreaker"

// Base64LineBreaker is used to handle base64 encoding with the insertion of new lines after a certain
// number of characters.
//
// It satisfies the io.WriteCloser interface.
type Base64LineBreaker struct {
	line [MaxBodyLength]byte
	used int
	out  io.Writer
}

// Write writes data to the Base64LineBreaker, ensuring lines do not exceed MaxBodyLength.
// It handles continuation if data length exceeds the limit and writes new lines accordingly.
func (l *Base64LineBreaker) Write(data []byte) (numBytes int, err error) {
	if l.out == nil {
		err = errors.New(ErrNoOutWriter)
		return
	}
	if l.used+len(data) < MaxBodyLength {
		copy(l.line[l.used:], data)
		l.used += len(data)
		return len(data), nil
	}

	numBytes, err = l.out.Write(l.line[0:l.used])
	if err != nil {
		return
	}
	excess := MaxBodyLength - l.used
	l.used = 0

	numBytes, err = l.out.Write(data[0:excess])
	if err != nil {
		return
	}

	numBytes, err = l.out.Write(newlineBytes)
	if err != nil {
		return
	}

	return l.Write(data[excess:])
}

// Close finalizes the Base64LineBreaker, writing any remaining buffered data and appending a newline.
func (l *Base64LineBreaker) Close() (err error) {
	if l.used > 0 {
		_, err = l.out.Write(l.line[0:l.used])
		if err != nil {
			return
		}
		_, err = l.out.Write(newlineBytes)
	}

	return
}
