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
//
// These constants define bitmask-related values used for efficient random string generation.
// The bitmask operates over 93 possible characters, and the constants help determine the
// number of bits and indices used in the process.
const (
	// letterIdxBits: Number of bits (7) needed to represent a letter index.
	letterIdxBits = 7
	// letterIdxMask: Bitmask to extract letter indices (all 1-bits for letterIdxBits).
	letterIdxMask = 1<<letterIdxBits - 1
	// letterIdxMax: The maximum number of letter indices that fit in 63 bits.
	letterIdxMax = 63 / letterIdxBits
)

// randomStringSecure returns a random string of the specified length.
//
// This function generates a cryptographically secure random string of the given length using
// the crypto/rand package. It ensures that the randomness is secure and suitable for
// cryptographic purposes. The function reads random bytes, converts them to indices within
// a character range, and builds the string. If an error occurs while reading from the random
// pool, it returns the error.
//
// Parameters:
//   - length: The length of the random string to be generated.
//
// Returns:
//   - A randomly generated string.
//   - An error if the random generation fails.
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
