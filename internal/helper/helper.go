// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

package helper

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

// curVersion holds the current Go runtime version as a string.
var curVersion = runtime.Version()

// GetGoVersion returns the current Go runtime version as a float64. It fails the test if the version
// parsing encounters an error. If wantMinorVer is true, the minor version is included in the result.
func GetGoVersion(wantMinorVer bool) (float64, error) {
	parts := strings.Split(curVersion[2:], ".")
	if len(parts) < 2 {
		return 0, fmt.Errorf("invalid Go version: %s", curVersion)
	}
	verNumMajorOnly, err := strconv.ParseFloat(parts[0]+"."+parts[1], 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse Go major version: %w", err)
	}
	if !wantMinorVer {
		return verNumMajorOnly, nil
	}

	if len(parts) < 3 {
		return 0, fmt.Errorf("invalid Go version: %s", curVersion)
	}
	if len(parts[2]) == 1 {
		parts[2] = "0" + parts[2]
	}
	verNumWithMinor, err := strconv.ParseFloat(parts[0]+"."+parts[1]+parts[2], 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse Go minor version: %w", err)
	}
	return verNumWithMinor, nil
}
