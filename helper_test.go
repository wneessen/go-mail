// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// getGoVersion returns the current Go runtime version as a float64. It fails the test if the version
// parsing encounters an error.
func getGoVersion(t *testing.T) float64 {
	t.Helper()
	version := runtime.Version()
	version = version[2:]
	version = version[:strings.LastIndex(version, ".")]
	vernum, err := strconv.ParseFloat(version, 64)
	if err != nil {
		t.Fatalf("failed to parse Go version: %s", err)
	}
	return vernum
}
