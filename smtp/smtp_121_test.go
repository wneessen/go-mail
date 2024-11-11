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

//go:build go1.21
// +build go1.21

package smtp

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/wneessen/go-mail/log"
)

func TestClient_SetDebugLog_JSON(t *testing.T) {
	t.Run("set debug loggging to on should not override logger", func(t *testing.T) {
		client := &Client{logger: log.NewJSON(os.Stderr, log.LevelDebug)}
		client.SetDebugLog(true)
		if !client.debug {
			t.Fatalf("expected debug log to be true")
		}
		if client.logger == nil {
			t.Fatalf("expected logger to be defined")
		}
		if !strings.EqualFold(fmt.Sprintf("%T", client.logger), "*log.JSONlog") {
			t.Errorf("expected logger to be of type *log.JSONlog, got: %T", client.logger)
		}
	})
}

func TestClient_SetLogger_JSON(t *testing.T) {
	t.Run("set logger to JSONlog logger", func(t *testing.T) {
		client := &Client{}
		client.SetLogger(log.NewJSON(os.Stderr, log.LevelDebug))
		if !strings.EqualFold(fmt.Sprintf("%T", client.logger), "*log.JSONlog") {
			t.Errorf("expected logger to be of type *log.JSONlog, got: %T", client.logger)
		}
	})
	t.Run("nil logger should just return and not set/override", func(t *testing.T) {
		client := &Client{logger: log.NewJSON(os.Stderr, log.LevelDebug)}
		client.SetLogger(nil)
		if !strings.EqualFold(fmt.Sprintf("%T", client.logger), "*log.JSONlog") {
			t.Errorf("expected logger to be of type *log.JSONlog, got: %T", client.logger)
		}
	})
}
