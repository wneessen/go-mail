// Package ntlm provides a very basic implementation of the NTLMv2 protocol. It provides everything needed to
// authenticate a SMTP authentication request. This package is not feature complete and is intented to only
// provide the means required for go-mail to perform NTLM via SMTP authentication.
package ntlm

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

const (
	// windowsFileTime is the number of 100-nanosecond intervals since January 1, 1601 (UTC).
	// This magic number is used as base for the Windows FILETIME representation.
	windowsFileTime = 116444736000000000
)

// ntlmv2Hash computes the NT One-Way Function (OWF) for the given user, password,
// and user domain. It only implements the OWF v2 as described in the NTLMv2 spec.
//
// See: https://curl.se/rfc/ntlm.html#appendixD
func ntlmv2Hash(user, passwd, userDom string) []byte {
	hasher := md4.New()
	hasher.Write(utf16FromString(passwd))
	mac := hmac.New(md5.New, hasher.Sum(nil))
	mac.Write(utf16FromString(strings.ToUpper(user) + userDom))
	return mac.Sum(nil)
}

// timeToWindowsFileTime converts a time.Time to a Windows FILETIME (little-endian) byte slice.
//
// See:      https://learn.microsoft.com/en-us/windows/win32/sysinfo/converting-a-time-t-value-to-a-file-time
// See also: https://curl.se/rfc/ntlm.html#appendixD
func timeToWindowsFileTime(t time.Time) []byte {
	fileTime := uint64(t.UnixNano()/100 + windowsFileTime)
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, fileTime)
	return buf
}

// utf16FromString converts a string to a UTF-16 (little-endian) byte slice.
func utf16FromString(payload string) []byte {
	encoded := utf16.Encode([]rune(payload))
	result := make([]byte, len(encoded)*2)

	for i, u := range encoded {
		binary.LittleEndian.PutUint16(result[i*2:], u)
	}
	return result
}

// randomBytes returns a slice of random bytes of the given length.
func randomBytes(length int) []byte {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return b
}
