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
	level Level
	err   *log.Logger
	warn  *log.Logger
	info  *log.Logger
	debug *log.Logger
}

// CallDepth is the call depth value for the log.Logger's Output method
// This defaults to 2 and is only here for better readablity of the code
const CallDepth = 2

// New returns a new Stdlog type that satisfies the Logger interface
func New(output io.Writer, level Level) *Stdlog {
	lf := log.Lmsgprefix | log.LstdFlags
	return &Stdlog{
		level: level,
		err:   log.New(output, "ERROR: ", lf),
		warn:  log.New(output, " WARN: ", lf),
		info:  log.New(output, " INFO: ", lf),
		debug: log.New(output, "DEBUG: ", lf),
	}
}

// Debugf performs a Printf() on the debug logger
func (l *Stdlog) Debugf(log Log) {
	if l.level >= LevelDebug {
		format := fmt.Sprintf("%s %s", log.directionPrefix(), log.Format)
		_ = l.debug.Output(CallDepth, fmt.Sprintf(format, log.Messages...))
	}
}

// Infof performs a Printf() on the info logger
func (l *Stdlog) Infof(log Log) {
	if l.level >= LevelInfo {
		format := fmt.Sprintf("%s %s", log.directionPrefix(), log.Format)
		_ = l.info.Output(CallDepth, fmt.Sprintf(format, log.Messages...))
	}
}

// Warnf performs a Printf() on the warn logger
func (l *Stdlog) Warnf(log Log) {
	if l.level >= LevelWarn {
		format := fmt.Sprintf("%s %s", log.directionPrefix(), log.Format)
		_ = l.warn.Output(CallDepth, fmt.Sprintf(format, log.Messages...))
	}
}

// Errorf performs a Printf() on the error logger
func (l *Stdlog) Errorf(log Log) {
	if l.level >= LevelError {
		format := fmt.Sprintf("%s %s", log.directionPrefix(), log.Format)
		_ = l.err.Output(CallDepth, fmt.Sprintf(format, log.Messages...))
	}
}
