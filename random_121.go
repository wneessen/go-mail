// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build go1.20 && !go1.22
// +build go1.20,!go1.22

package mail

import (
	"math/rand"
)

// randNum returns a random number with a maximum value of maxval.
//
// This function generates a random integer between 0 and maxval (exclusive). If maxval is less
// than or equal to 0, it returns 0. The random number generator uses the default seed provided
// by the rand package.
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
	return rand.Intn(maxval)
}
