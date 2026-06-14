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
func getGoVersion(t *testing.T, incMinorVer bool) float64 {
	t.Helper()
	version := runtime.Version()
	parts := strings.Split(version[2:], ".")
	majorVerNum, err := strconv.ParseFloat(parts[0]+"."+parts[1], 64)
	if err != nil {
		t.Fatalf("failed to parse Go version: %s", err)
	}
	minorVerNum, err := strconv.ParseFloat(parts[0]+"."+parts[1]+parts[2], 64)
	if err != nil {
		t.Fatalf("failed to parse Go version: %s", err)
	}
	if incMinorVer {
		return minorVerNum
	}
	return majorVerNum
}
