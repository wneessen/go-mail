// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"crypto/rand"
	"encoding/binary"
	"strings"
)

// Range of characters for the secure string generation
const cr = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

// Bitmask sizes for the string generators (based on 93 chars total)
const (
	letterIdxBits = 7                    // 7 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

// randomStringSecure returns a random, string of length characters. This method uses the
// crypto/random package and therfore is cryptographically secure
func randomStringSecure(length int) (string, error) {
	randString := strings.Builder{}
	randString.Grow(length)
	charRangeLength := len(cr)

	randPool := make([]byte, 8)
	_, err := rand.Read(randPool)
	if err != nil {
		return randString.String(), err
	}
	for idx, char, rest := length-1, binary.BigEndian.Uint64(randPool), letterIdxMax; idx >= 0; {
		if rest == 0 {
			_, err = rand.Read(randPool)
			if err != nil {
				return randString.String(), err
			}
			char, rest = binary.BigEndian.Uint64(randPool), letterIdxMax
		}
		if i := int(char & letterIdxMask); i < charRangeLength {
			randString.WriteByte(cr[i])
			idx--
		}
		char >>= letterIdxBits
		rest--
	}

	return randString.String(), nil
}
