// SPDX-FileCopyrightText: Copyright (c) 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

// Package log implements a logger interface that can be used within the go-mail package
package log

// Logger is the log interface for go-mail
type Logger interface {
	Errorf(format string, v ...interface{})
	Warnf(format string, v ...interface{})
	Infof(format string, v ...interface{})
	Debugf(format string, v ...interface{})
}
