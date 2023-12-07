// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"
)

// TestReader_Read tests the Reader.Read method that implements the io.Reader interface
func TestReader_Read(t *testing.T) {
	tests := []struct {
		name string
		plen int
	}{
		{"P length is bigger than the mail", 3200000},
		{"P length is smaller than the mail", 128},
	}

	m := NewMsg()
	m.SetBodyString(TypeTextPlain, "TEST123")
	wbuf := bytes.Buffer{}
	_, err := m.Write(&wbuf)
	if err != nil {
		t.Errorf("failed to write message into temporary buffer: %s", err)
	}
	elen := wbuf.Len()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := make([]byte, tt.plen)
			mr := m.NewReader()
			n, err := mr.Read(p)
			if err != nil {
				t.Errorf("failed to Read(): %s", err)
			}
			if n == 0 {
				t.Errorf("failed to Read() - received 0 bytes of data")
			}
			if tt.plen >= elen && n != elen {
				t.Errorf("failed to Read() - not all data received. Expected: %d, got: %d", elen, n)
			}
			if tt.plen < elen && n != tt.plen {
				t.Errorf("failed to Read() - full length of p wasn't filled with data. Expected: %d, got: %d",
					tt.plen, n)
			}
		})
	}
}

// TestReader_Read_error tests the Reader.Read method with an intentional error
func TestReader_Read_error(t *testing.T) {
	r := Reader{err: fmt.Errorf("FAILED")}
	var p []byte
	_, err := r.Read(p)
	if err == nil {
		t.Errorf("Reader was supposed to fail, but didn't")
	}
}

// TestReader_Read_empty tests the Reader.Read method with an empty buffer
func TestReader_Read_empty(t *testing.T) {
	r := Reader{buf: []byte{}}
	p := make([]byte, 1)
	p[0] = 'a'
	_, err := r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Errorf("Reader failed: %s", err)
	}
}

// TestReader_Read_nil tests the Reader.Read method with a nil buffer
func TestReader_Read_nil(t *testing.T) {
	r := Reader{buf: nil, off: -10}
	p := make([]byte, 0)
	_, err := r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Errorf("Reader failed: %s", err)
	}
}
