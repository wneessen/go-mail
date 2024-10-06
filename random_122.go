// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build go1.22
// +build go1.22

package mail

import (
	"math/rand/v2"
)

// randNum returns a random number with a maximum value of maxval.
//
// This function generates a random integer between 0 and maxval (exclusive). It utilizes
// the math/rand/v2 interface for Go 1.22+ and will default to math/rand for older Go versions.
// If maxval is less than or equal to 0, it returns 0.
//
// Parameters:
//   - maxval: The upper bound for the random number generation (exclusive).
//
// Returns:
//   - A random integer between 0 and maxval. If maxval is less than or equal to 0, it returns 0.
func randNum(maxval int) int {
	if maxval <= 0 {
		return 0
	}
	return rand.IntN(maxval)
}
