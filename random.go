// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
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

// randomStringSecure returns a random, n long string of characters. The character set is based
// on the s (special chars) and h (human readable) boolean arguments. This method uses the
// crypto/random package and therfore is cryptographically secure
func randomStringSecure(n int) (string, error) {
	rs := strings.Builder{}
	rs.Grow(n)
	crl := len(cr)

	rp := make([]byte, 8)
	_, err := rand.Read(rp)
	if err != nil {
		return rs.String(), err
	}
	for i, c, r := n-1, binary.BigEndian.Uint64(rp), letterIdxMax; i >= 0; {
		if r == 0 {
			_, err := rand.Read(rp)
			if err != nil {
				return rs.String(), err
			}
			c, r = binary.BigEndian.Uint64(rp), letterIdxMax
		}
		if idx := int(c & letterIdxMask); idx < crl {
			rs.WriteByte(cr[idx])
			i--
		}
		c >>= letterIdxBits
		r--
	}

	return rs.String(), nil
}

// randNum returns a random number with a maximum value of n
func randNum(n int) (int, error) {
	if n <= 0 {
		return 0, fmt.Errorf("provided number is <= 0: %d", n)
	}
	mbi := big.NewInt(int64(n))
	if !mbi.IsUint64() {
		return 0, fmt.Errorf("big.NewInt() generation returned negative value: %d", mbi)
	}
	rn64, err := rand.Int(rand.Reader, mbi)
	if err != nil {
		return 0, err
	}
	rn := int(rn64.Int64())
	if rn < 0 {
		return 0, fmt.Errorf("generated random number does not fit as int64: %d", rn64)
	}
	return rn, nil
}
