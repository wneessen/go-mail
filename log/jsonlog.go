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
	l   Level
	log *slog.Logger
}

// NewJSON returns a new JSONlog type that satisfies the Logger interface
func NewJSON(o io.Writer, l Level) *JSONlog {
	lo := slog.HandlerOptions{}
	switch l {
	case LevelDebug:
		lo.Level = slog.LevelDebug
	case LevelInfo:
		lo.Level = slog.LevelInfo
	case LevelWarn:
		lo.Level = slog.LevelWarn
	case LevelError:
		lo.Level = slog.LevelError
	default:
		lo.Level = slog.LevelDebug
	}
	lh := slog.NewJSONHandler(o, &lo)
	return &JSONlog{
		l:   l,
		log: slog.New(lh),
	}
}

// Debugf logs a debug message via the structured JSON logger
func (l *JSONlog) Debugf(lo Log) {
	if l.l >= LevelDebug {
		l.log.WithGroup(DirString).With(
			slog.String(DirFromString, lo.directionFrom()),
			slog.String(DirToString, lo.directionTo()),
		).Debug(fmt.Sprintf(lo.Format, lo.Messages...))
	}
}

// Infof logs a info message via the structured JSON logger
func (l *JSONlog) Infof(lo Log) {
	if l.l >= LevelInfo {
		l.log.WithGroup(DirString).With(
			slog.String(DirFromString, lo.directionFrom()),
			slog.String(DirToString, lo.directionTo()),
		).Info(fmt.Sprintf(lo.Format, lo.Messages...))
	}
}

// Warnf logs a warn message via the structured JSON logger
func (l *JSONlog) Warnf(lo Log) {
	if l.l >= LevelWarn {
		l.log.WithGroup(DirString).With(
			slog.String(DirFromString, lo.directionFrom()),
			slog.String(DirToString, lo.directionTo()),
		).Warn(fmt.Sprintf(lo.Format, lo.Messages...))
	}
}

// Errorf logs a warn message via the structured JSON logger
func (l *JSONlog) Errorf(lo Log) {
	if l.l >= LevelError {
		l.log.WithGroup(DirString).With(
			slog.String(DirFromString, lo.directionFrom()),
			slog.String(DirToString, lo.directionTo()),
		).Error(fmt.Sprintf(lo.Format, lo.Messages...))
	}
}
