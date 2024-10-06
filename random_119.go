// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build !go1.20
// +build !go1.20

package mail

import (
	"math/rand"
	"time"
)

// randNum returns a random number with a maximum value of maxval.
//
// This function generates a random integer between 0 and maxval (exclusive). It seeds the
// random number generator with the current time in nanoseconds to ensure different results
// each time the function is called.
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
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(maxval)
}
