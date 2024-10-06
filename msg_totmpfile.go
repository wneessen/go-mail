// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build go1.17
// +build go1.17

package mail

import (
	"fmt"
	"os"
)

// WriteToTempFile creates a temporary file and writes the Msg content to this file.
//
// This method generates a temporary file with a ".eml" extension, writes the Msg to it, and returns the
// filename of the created temporary file.
//
// Returns:
//   - A string representing the filename of the temporary file.
//   - An error if the file creation or writing process fails.
func (m *Msg) WriteToTempFile() (string, error) {
	f, err := os.CreateTemp("", "go-mail_*.eml")
	if err != nil {
		return "", fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() { _ = f.Close() }()
	return f.Name(), m.WriteToFile(f.Name())
}
