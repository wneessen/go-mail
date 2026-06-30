// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

package ntlm

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

func Test_ntlmv2Hash(t *testing.T) {
	want := []byte{23, 76, 33, 13, 99, 39, 31, 213, 150, 111, 98, 90, 105, 122, 255, 91}
	hash := ntlmv2Hash("user", "password", "domain")
	if !bytes.Equal(hash, want) {
		t.Errorf("ntlmv2 hash mismatch, got: %x, want: %x", hash, want)
	}
}

func Test_timeToWindowsFileTime(t *testing.T) {
	want := []byte{0x00, 0x00, 0x81, 0x92, 0xb1, 0x7a, 0xdc, 0x01}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	filetime := timeToWindowsFileTime(now)
	if !bytes.Equal(filetime, want) {
		t.Errorf("timeToWindowsFileTime mismatch, got: %x, want: %x", filetime, want)
	}
}

func Test_utf16FromString(t *testing.T) {
	value := "teststring"
	want := []byte{0x74, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x73, 0x00, 0x74, 0x00, 0x72, 0x00, 0x69, 0x00, 0x6e, 0x00, 0x67, 0x00}
	got := utf16FromString(value)
	if !bytes.Equal(got, want) {
		t.Errorf("utf16FromString mismatch, got: %x, want: %x", got, want)
	}
}

func Test_randomBytes(t *testing.T) {
	lengths := []int{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47}
	for _, length := range lengths {
		t.Run(fmt.Sprintf("generating %d random bytes", length), func(t *testing.T) {
			val := randomBytes(length)
			if len(val) != length {
				t.Errorf("randomBytes length mismatch, got: %d, want: %d", len(val), length)
			}
		})
	}
}
