// SPDX-FileCopyrightText: Copyright (c) 2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build go1.21
// +build go1.21

package log

import (
	"fmt"
	"io"
	"log/slog"
)

// JSONlog is the default structured JSON logger that satisfies the Logger interface
type JSONlog struct {
	level Level
	log   *slog.Logger
}

// NewJSON returns a new JSONlog type that satisfies the Logger interface
func NewJSON(output io.Writer, level Level) *JSONlog {
	logOpts := slog.HandlerOptions{}
	switch level {
	case LevelDebug:
		logOpts.Level = slog.LevelDebug
	case LevelInfo:
		logOpts.Level = slog.LevelInfo
	case LevelWarn:
		logOpts.Level = slog.LevelWarn
	case LevelError:
		logOpts.Level = slog.LevelError
	default:
		logOpts.Level = slog.LevelDebug
	}
	logHandler := slog.NewJSONHandler(output, &logOpts)
	return &JSONlog{
		level: level,
		log:   slog.New(logHandler),
	}
}

// Debugf logs a debug message via the structured JSON logger
func (l *JSONlog) Debugf(log Log) {
	if l.level >= LevelDebug {
		l.log.WithGroup(DirString).With(
			slog.String(DirFromString, log.directionFrom()),
			slog.String(DirToString, log.directionTo()),
		).Debug(fmt.Sprintf(log.Format, log.Messages...))
	}
}

// Infof logs a info message via the structured JSON logger
func (l *JSONlog) Infof(log Log) {
	if l.level >= LevelInfo {
		l.log.WithGroup(DirString).With(
			slog.String(DirFromString, log.directionFrom()),
			slog.String(DirToString, log.directionTo()),
		).Info(fmt.Sprintf(log.Format, log.Messages...))
	}
}

// Warnf logs a warn message via the structured JSON logger
func (l *JSONlog) Warnf(log Log) {
	if l.level >= LevelWarn {
		l.log.WithGroup(DirString).With(
			slog.String(DirFromString, log.directionFrom()),
			slog.String(DirToString, log.directionTo()),
		).Warn(fmt.Sprintf(log.Format, log.Messages...))
	}
}

// Errorf logs a warn message via the structured JSON logger
func (l *JSONlog) Errorf(log Log) {
	if l.level >= LevelError {
		l.log.WithGroup(DirString).With(
			slog.String(DirFromString, log.directionFrom()),
			slog.String(DirToString, log.directionTo()),
		).Error(fmt.Sprintf(log.Format, log.Messages...))
	}
}
