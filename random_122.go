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
// go-mail compiled with Go 1.22+ will make use of the novel math/rand/v2 interface
// Older versions of Go will use math/rand
func randNum(maxval int) int {
	if maxval <= 0 {
		return 0
	}
	return rand.IntN(maxval)
}
