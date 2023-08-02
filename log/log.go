// SPDX-FileCopyrightText: Copyright (c) 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

// Package log implements a logger interface that can be used within the go-mail package
package log

const (
	DirServerToClient Direction = iota // Server to Client communication
	DirClientToServer                  // Client to Server communication
)

// Direction is a type wrapper for the direction a debug log message goes
type Direction int

// Log represents a log message type that holds a log Direction, a Format string
// and a slice of Messages
type Log struct {
	Direction Direction
	Format    string
	Messages  []interface{}
}

// Logger is the log interface for go-mail
type Logger interface {
	Debugf(Log)
	Infof(Log)
	Warnf(Log)
	Errorf(Log)
}
