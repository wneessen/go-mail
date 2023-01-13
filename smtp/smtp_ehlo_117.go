// SPDX-FileCopyrightText: Copyright 2010 The Go Authors. All rights reserved.
// SPDX-FileCopyrightText: Copyright (c) 2022-2023 The go-mail Authors
//
// Original net/smtp code from the Go stdlib by the Go Authors.
// Use of this source code is governed by a BSD-style
// LICENSE file that can be found in this directory.
//
// go-mail specific modifications by the go-mail Authors.
// Licensed under the MIT License.
// See [PROJECT ROOT]/LICENSES directory for more information.
//
// SPDX-License-Identifier: BSD-3-Clause AND MIT

//go:build !go1.18
// +build !go1.18

package smtp

import "strings"

// ehlo sends the EHLO (extended hello) greeting to the server. It
// should be the preferred greeting for servers that support it.
//
// Backport of: https://github.com/golang/go/commit/4d8db00641cc9ff4f44de7df9b8c4f4a4f9416ee#diff-4f6f6bdb9891d4dd271f9f31430420a2e44018fe4ee539576faf458bebb3cee4
// to guarantee backwards compatiblity with Go 1.16/1.17:w
func (c *Client) ehlo() error {
	_, msg, err := c.cmd(250, "EHLO %s", c.localName)
	if err != nil {
		return err
	}
	ext := make(map[string]string)
	extList := strings.Split(msg, "\n")
	if len(extList) > 1 {
		extList = extList[1:]
		for _, line := range extList {
			args := strings.SplitN(line, " ", 2)
			if len(args) > 1 {
				ext[args[0]] = args[1]
			} else {
				ext[args[0]] = ""
			}
		}
	}
	if mechs, ok := ext["AUTH"]; ok {
		c.auth = strings.Split(mechs, " ")
	}
	c.ext = ext
	return err
}
