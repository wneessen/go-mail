// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
)

// TestRandomStringSecure tests the randomStringSecure method
func TestRandomStringSecure(t *testing.T) {
	t.Run("randomStringSecure with varying length", func(t *testing.T) {
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
	})
	t.Run("randomStringSecure fails on broken rand Reader (first read)", func(t *testing.T) {
		defaultRandReader := rand.Reader
		t.Cleanup(func() { rand.Reader = defaultRandReader })
		rand.Reader = &randReader{failon: 1}
		if _, err := randomStringSecure(22); err == nil {
			t.Fatalf("expected failure on broken rand Reader")
		}
	})
	t.Run("randomStringSecure fails on broken rand Reader (second read)", func(t *testing.T) {
		defaultRandReader := rand.Reader
		t.Cleanup(func() { rand.Reader = defaultRandReader })
		rand.Reader = &randReader{failon: 0}
		if _, err := randomStringSecure(22); err == nil {
			t.Fatalf("expected failure on broken rand Reader")
		}
	})
}

func TestRandomBoundary(t *testing.T) {
	t.Run("randomBoundary returning valid values", func(t *testing.T) {
		boundary, err := randomBoundary()
		if err != nil {
			t.Errorf("random boundary generation failed: %s", err)
		}
		if len(boundary) < 30 {
			t.Errorf("random boundary length mismatch. got: %d, expected: %d", len(boundary), 30)
		}
	})
	t.Run("randomBoundary fails on broken rand Reader", func(t *testing.T) {
		defaultRandReader := rand.Reader
		t.Cleanup(func() { rand.Reader = defaultRandReader })
		rand.Reader = &randReader{failon: 1}
		if _, err := randomBoundary(); err == nil {
			t.Fatalf("expected random boundary generation to fail on broken rand.Reader")
		}
	})
}

func BenchmarkGenerator_RandomStringSecure(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := randomStringSecure(10)
		if err != nil {
			b.Errorf("RandomStringFromCharRange() failed: %s", err)
		}
	}
}

// randReader is type that satisfies the io.Reader interface. It can fail on a specific read
// operations and is therefore useful to test consecutive reads with errors
type randReader struct {
	failon uint8
	call   uint8
}

// Read implements the io.Reader interface for the randReader type
func (r *randReader) Read(p []byte) (int, error) {
	if r.call == r.failon {
		r.call++
		return len(p), nil
	}
	return 0, errors.New("broken reader")
}
