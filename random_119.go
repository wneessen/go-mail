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

// randNum returns a random number with a maximum value of length
func randNum(maxval int) int {
	if maxval <= 0 {
		return 0
	}
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(maxval)
}
