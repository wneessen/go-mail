// Package ntlm provides a very basic implementation of the NTLMv2 protocol. It provides everything needed to
// authenticate a SMTP authentication request. This package is not feature complete and is intented to only
// provide the means required for go-mail to perform NTLM via SMTP authentication.
package ntlm

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"strings"
	"time"
	"unicode/utf16"

	"golang.org/x/crypto/md4"
)

// NT One-Way Function, version 2.
func ntowfv2(user, passwd, userDom string) []byte {
	hasher := md4.New()
	hasher.Write(utf16FromString(passwd))
	mac := hmac.New(md5.New, hasher.Sum(nil))
	mac.Write(utf16FromString(strings.ToUpper(user) + userDom))
	return mac.Sum(nil)
}

func utf16FromString(payload string) []byte {
	encoded := utf16.Encode([]rune(payload))
	result := make([]byte, len(encoded)*2)

	for i := 0; i < len(encoded); i++ {
		result[i*2] = byte(encoded[i])
		result[i*2+1] = byte(encoded[i] << 8)
	}
	return result
}

// See: https://learn.microsoft.com/en-us/windows/win32/sysinfo/converting-a-time-t-value-to-a-file-time
func timeToWindowsFileTime(t time.Time) []byte {
	fileTime := (t.Unix() * 10000000) + WindowsFileTime
	buffer := bytes.NewBuffer(make([]byte, 0, 8))
	binary.Write(buffer, binary.LittleEndian, fileTime)
	return buffer.Bytes()
}

func randomBytes(length int) []byte {
	b := make([]byte, length)
	_, _ = rand.Read(b)
	return b
}

func zeroBytes(length int) []byte     { return make([]byte, length) }
func concatBytes(ar ...[]byte) []byte { return bytes.Join(ar, nil) }
