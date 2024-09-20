// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build go1.20 && !go1.22
// +build go1.20,!go1.22

package mail

import (
	"math/rand"
)

// randNum returns a random number with a maximum value of length
func randNum(maxval int) int {
	if maxval <= 0 {
		return 0
	}
	return rand.Intn(maxval)
}
