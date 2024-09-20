// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"strings"
	"testing"
)

// TestRandomStringSecure tests the randomStringSecure method
func TestRandomStringSecure(t *testing.T) {
	tt := []struct {
		testName     string
		length       int
		mustNotMatch string
	}{
		{"20 chars", 20, "'"},
		{"100 chars", 100, "'"},
		{"1000 chars", 1000, "'"},
	}

	for _, tc := range tt {
		t.Run(tc.testName, func(t *testing.T) {
			rs, err := randomStringSecure(tc.length)
			if err != nil {
				t.Errorf("random string generation failed: %s", err)
			}
			if strings.Contains(rs, tc.mustNotMatch) {
				t.Errorf("random string contains unexpected character. got: %s, not-expected: %s",
					rs, tc.mustNotMatch)
			}
			if len(rs) != tc.length {
				t.Errorf("random string length does not match. expected: %d, got: %d", tc.length, len(rs))
			}
		})
	}
}

// TestRandomNum tests the randomNum method
func TestRandomNum(t *testing.T) {
	tt := []struct {
		testName string
		max      int
	}{
		{"Max: 1", 1},
		{"Max: 20", 20},
		{"Max: 50", 50},
		{"Max: 100", 100},
		{"Max: 1000", 1000},
		{"Max: 10000", 10000},
		{"Max: 100000000", 100000000},
	}

	for _, tc := range tt {
		t.Run(tc.testName, func(t *testing.T) {
			rn := randNum(tc.max)
			if rn > tc.max {
				t.Errorf("random number generation failed: %d is bigger than given value %d", rn, tc.max)
			}
		})
	}
}

func TestRandomNumZero(t *testing.T) {
	rn := randNum(0)
	if rn != 0 {
		t.Errorf("random number generation failed: %d is not zero", rn)
	}
}
