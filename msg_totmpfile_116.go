// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build !go1.17
// +build !go1.17

package mail

import (
	"fmt"
	"io/ioutil"
)

// WriteToTempFile will create a temporary file and output the Msg to this file
// The method will return the filename of the temporary file
func (m *Msg) WriteToTempFile() (string, error) {
	f, err := ioutil.TempFile("", "go-mail_*.eml")
	if err != nil {
		return "", fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() { _ = f.Close() }()
	return f.Name(), m.WriteToFile(f.Name())
}
