// SPDX-FileCopyrightText: Copyright (c) 2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package log

import (
	"fmt"
	"io"
	"log"
)

// Stdlog is the default logger that satisfies the Logger interface
type Stdlog struct {
	l     Level
	err   *log.Logger
	warn  *log.Logger
	info  *log.Logger
	debug *log.Logger
}

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
func (l *Stdlog) Debugf(lo Log) {
	if l.l >= LevelDebug {
		f := fmt.Sprintf("%s %s", lo.directionPrefix(), lo.Format)
		_ = l.debug.Output(CallDepth, fmt.Sprintf(f, lo.Messages...))
	}
}

// Infof performs a Printf() on the info logger
func (l *Stdlog) Infof(lo Log) {
	if l.l >= LevelInfo {
		f := fmt.Sprintf("%s %s", lo.directionPrefix(), lo.Format)
		_ = l.info.Output(CallDepth, fmt.Sprintf(f, lo.Messages...))
	}
}

// Warnf performs a Printf() on the warn logger
func (l *Stdlog) Warnf(lo Log) {
	if l.l >= LevelWarn {
		f := fmt.Sprintf("%s %s", lo.directionPrefix(), lo.Format)
		_ = l.warn.Output(CallDepth, fmt.Sprintf(f, lo.Messages...))
	}
}

// Errorf performs a Printf() on the error logger
func (l *Stdlog) Errorf(lo Log) {
	if l.l >= LevelError {
		f := fmt.Sprintf("%s %s", lo.directionPrefix(), lo.Format)
		_ = l.err.Output(CallDepth, fmt.Sprintf(f, lo.Messages...))
	}
}
