// SPDX-FileCopyrightText: Copyright (c) 2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package log

import (
	"fmt"
	"io"
	"log"
)

// Level is a type wrapper for an int
type Level int

// Stdlog is the default logger that satisfies the Logger interface
type Stdlog struct {
	l     Level
	err   *log.Logger
	warn  *log.Logger
	info  *log.Logger
	debug *log.Logger
}

const (
	// LevelError is the Level for only ERROR log messages
	LevelError Level = iota
	// LevelWarn is the Level for WARN and higher log messages
	LevelWarn
	// LevelInfo is the Level for INFO and higher log messages
	LevelInfo
	// LevelDebug is the Level for DEBUG and higher log messages
	LevelDebug
)

// CallDepth is the call depth value for the log.Logger's Output method
// This defaults to 2 and is only here for better readablity of the code
const CallDepth = 2

// New returns a new Stdlog type that satisfies the Logger interface
func New(o io.Writer, l Level) *Stdlog {
	lf := log.Lmsgprefix | log.LstdFlags
	return &Stdlog{
		l:     l,
		err:   log.New(o, "ERROR: ", lf),
		warn:  log.New(o, " WARN: ", lf),
		info:  log.New(o, " INFO: ", lf),
		debug: log.New(o, "DEBUG: ", lf),
	}
}

// Debugf performs a Printf() on the debug logger
func (l *Stdlog) Debugf(f string, v ...interface{}) {
	if l.l >= LevelDebug {
		_ = l.debug.Output(CallDepth, fmt.Sprintf(f, v...))
	}
}

// Infof performs a Printf() on the info logger
func (l *Stdlog) Infof(f string, v ...interface{}) {
	if l.l >= LevelInfo {
		_ = l.info.Output(CallDepth, fmt.Sprintf(f, v...))
	}
}

// Warnf performs a Printf() on the warn logger
func (l *Stdlog) Warnf(f string, v ...interface{}) {
	if l.l >= LevelWarn {
		_ = l.warn.Output(CallDepth, fmt.Sprintf(f, v...))
	}
}

// Errorf performs a Printf() on the error logger
func (l *Stdlog) Errorf(f string, v ...interface{}) {
	if l.l >= LevelError {
		_ = l.err.Output(CallDepth, fmt.Sprintf(f, v...))
	}
}
