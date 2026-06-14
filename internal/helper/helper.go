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

// GetGoVersion returns the current Go runtime version as a float64. It fails the test if the version
// parsing encounters an error. If wantMinorVer is true, the minor version is included in the result.
func GetGoVersion(wantMinorVer bool) (float64, error) {
	version := runtime.Version()
	parts := strings.Split(version[2:], ".")
	verNumMajorOnly, err := strconv.ParseFloat(parts[0]+"."+parts[1], 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse Go major version: %w", err)
	}
	if !wantMinorVer {
		return verNumMajorOnly, nil
	}

	verNumWithMinor, err := strconv.ParseFloat(parts[0]+"."+parts[1]+parts[2], 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse Go minor version: %w", err)
	}
	return verNumWithMinor, nil
}
