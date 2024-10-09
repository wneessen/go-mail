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

func BenchmarkGenerator_RandomStringSecure(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := randomStringSecure(22)
		if err != nil {
			b.Errorf("RandomStringFromCharRange() failed: %s", err)
		}
	}
}
