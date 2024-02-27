// SPDX-FileCopyrightText: Copyright (c) 2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build go1.21
// +build go1.21

package log

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

type jsonLog struct {
	Direction jsonDir   `json:"direction"`
	Level     string    `json:"level"`
	Message   string    `json:"msg"`
	Time      time.Time `json:"time"`
}

type jsonDir struct {
	From string `json:"from"`
	To   string `json:"to"`
}

func TestNewJSON(t *testing.T) {
	var b bytes.Buffer
	l := NewJSON(&b, LevelDebug)
	if l.level != LevelDebug {
		t.Error("Expected level to be LevelDebug, got ", l.level)
	}
	if l.log == nil {
		t.Error("logger not initialized")
	}
}

func TestJSONDebugf(t *testing.T) {
	var b bytes.Buffer
	l := NewJSON(&b, LevelDebug)
	f := "test %s"
	msg := "foo"
	msg2 := "bar"

	l.Debugf(Log{Direction: DirServerToClient, Format: f, Messages: []interface{}{msg}})
	exFrom := "server"
	exTo := "client"
	jl, err := unmarshalLog(b.Bytes())
	if err != nil {
		t.Errorf("Debugf() failed, unmarshal json log message failed: %s", err)
	}
	if jl.Direction.To != exTo {
		t.Errorf("Debugf() failed, expected message to: %s, got: %s", exTo, jl.Direction.To)
	}
	if jl.Direction.From != exFrom {
		t.Errorf("Debugf() failed, expected message to: %s, got: %s", exFrom, jl.Direction.From)
	}
	if jl.Message != fmt.Sprintf(f, msg) {
		t.Errorf("Debugf() failed, expected message: %s, got %s", msg, jl.Message)
	}

	b.Reset()
	l.Debugf(Log{Direction: DirClientToServer, Format: f, Messages: []interface{}{msg2}})
	exFrom = "client"
	exTo = "server"
	jl, err = unmarshalLog(b.Bytes())
	if err != nil {
		t.Errorf("Debugf() failed, unmarshal json log message failed: %s", err)
	}
	if jl.Direction.To != exTo {
		t.Errorf("Debugf() failed, expected message to: %s, got: %s", exTo, jl.Direction.To)
	}
	if jl.Direction.From != exFrom {
		t.Errorf("Debugf() failed, expected message to: %s, got: %s", exFrom, jl.Direction.From)
	}
	if jl.Message != fmt.Sprintf(f, msg2) {
		t.Errorf("Debugf() failed, expected message: %s, got %s", msg2, jl.Message)
	}

	b.Reset()
	l.level = LevelInfo
	l.Debugf(Log{Direction: DirServerToClient, Format: "test %s", Messages: []interface{}{"foo"}})
	if b.String() != "" {
		t.Error("Debug message was not expected to be logged")
	}
}

func TestJSONDebugf_WithDefault(t *testing.T) {
	var b bytes.Buffer
	l := NewJSON(&b, 999)
	f := "test %s"
	msg := "foo"
	msg2 := "bar"

	l.Debugf(Log{Direction: DirServerToClient, Format: f, Messages: []interface{}{msg}})
	exFrom := "server"
	exTo := "client"
	jl, err := unmarshalLog(b.Bytes())
	if err != nil {
		t.Errorf("Debugf() failed, unmarshal json log message failed: %s", err)
	}
	if jl.Direction.To != exTo {
		t.Errorf("Debugf() failed, expected message to: %s, got: %s", exTo, jl.Direction.To)
	}
	if jl.Direction.From != exFrom {
		t.Errorf("Debugf() failed, expected message to: %s, got: %s", exFrom, jl.Direction.From)
	}
	if jl.Message != fmt.Sprintf(f, msg) {
		t.Errorf("Debugf() failed, expected message: %s, got %s", msg, jl.Message)
	}

	b.Reset()
	l.Debugf(Log{Direction: DirClientToServer, Format: f, Messages: []interface{}{msg2}})
	exFrom = "client"
	exTo = "server"
	jl, err = unmarshalLog(b.Bytes())
	if err != nil {
		t.Errorf("Debugf() failed, unmarshal json log message failed: %s", err)
	}
	if jl.Direction.To != exTo {
		t.Errorf("Debugf() failed, expected message to: %s, got: %s", exTo, jl.Direction.To)
	}
	if jl.Direction.From != exFrom {
		t.Errorf("Debugf() failed, expected message to: %s, got: %s", exFrom, jl.Direction.From)
	}
	if jl.Message != fmt.Sprintf(f, msg2) {
		t.Errorf("Debugf() failed, expected message: %s, got %s", msg2, jl.Message)
	}

	b.Reset()
	l.level = LevelInfo
	l.Debugf(Log{Direction: DirServerToClient, Format: "test %s", Messages: []interface{}{"foo"}})
	if b.String() != "" {
		t.Error("Debug message was not expected to be logged")
	}
}

func TestJSONInfof(t *testing.T) {
	var b bytes.Buffer
	l := NewJSON(&b, LevelInfo)
	f := "test %s"
	msg := "foo"
	msg2 := "bar"

	l.Infof(Log{Direction: DirServerToClient, Format: f, Messages: []interface{}{msg}})
	exFrom := "server"
	exTo := "client"
	jl, err := unmarshalLog(b.Bytes())
	if err != nil {
		t.Errorf("Debugf() failed, unmarshal json log message failed: %s", err)
	}
	if jl.Direction.To != exTo {
		t.Errorf("Debugf() failed, expected message to: %s, got: %s", exTo, jl.Direction.To)
	}
	if jl.Direction.From != exFrom {
		t.Errorf("Debugf() failed, expected message to: %s, got: %s", exFrom, jl.Direction.From)
	}
	if jl.Message != fmt.Sprintf(f, msg) {
		t.Errorf("Debugf() failed, expected message: %s, got %s", msg, jl.Message)
	}

	b.Reset()
	l.Infof(Log{Direction: DirClientToServer, Format: f, Messages: []interface{}{msg2}})
	exFrom = "client"
	exTo = "server"
	jl, err = unmarshalLog(b.Bytes())
	if err != nil {
		t.Errorf("Debugf() failed, unmarshal json log message failed: %s", err)
	}
	if jl.Direction.To != exTo {
		t.Errorf("Debugf() failed, expected message to: %s, got: %s", exTo, jl.Direction.To)
	}
	if jl.Direction.From != exFrom {
		t.Errorf("Debugf() failed, expected message to: %s, got: %s", exFrom, jl.Direction.From)
	}
	if jl.Message != fmt.Sprintf(f, msg2) {
		t.Errorf("Debugf() failed, expected message: %s, got %s", msg2, jl.Message)
	}

	b.Reset()
	l.level = LevelWarn
	l.Infof(Log{Direction: DirServerToClient, Format: "test %s", Messages: []interface{}{"foo"}})
	if b.String() != "" {
		t.Error("Info message was not expected to be logged")
	}
}

func TestJSONWarnf(t *testing.T) {
	var b bytes.Buffer
	l := NewJSON(&b, LevelWarn)
	f := "test %s"
	msg := "foo"
	msg2 := "bar"

	l.Warnf(Log{Direction: DirServerToClient, Format: f, Messages: []interface{}{msg}})
	exFrom := "server"
	exTo := "client"
	jl, err := unmarshalLog(b.Bytes())
	if err != nil {
		t.Errorf("Debugf() failed, unmarshal json log message failed: %s", err)
	}
	if jl.Direction.To != exTo {
		t.Errorf("Debugf() failed, expected message to: %s, got: %s", exTo, jl.Direction.To)
	}
	if jl.Direction.From != exFrom {
		t.Errorf("Debugf() failed, expected message to: %s, got: %s", exFrom, jl.Direction.From)
	}
	if jl.Message != fmt.Sprintf(f, msg) {
		t.Errorf("Debugf() failed, expected message: %s, got %s", msg, jl.Message)
	}

	b.Reset()
	l.Warnf(Log{Direction: DirClientToServer, Format: f, Messages: []interface{}{msg2}})
	exFrom = "client"
	exTo = "server"
	jl, err = unmarshalLog(b.Bytes())
	if err != nil {
		t.Errorf("Debugf() failed, unmarshal json log message failed: %s", err)
	}
	if jl.Direction.To != exTo {
		t.Errorf("Debugf() failed, expected message to: %s, got: %s", exTo, jl.Direction.To)
	}
	if jl.Direction.From != exFrom {
		t.Errorf("Debugf() failed, expected message to: %s, got: %s", exFrom, jl.Direction.From)
	}
	if jl.Message != fmt.Sprintf(f, msg2) {
		t.Errorf("Debugf() failed, expected message: %s, got %s", msg2, jl.Message)
	}

	b.Reset()
	l.level = LevelError
	l.Warnf(Log{Direction: DirServerToClient, Format: "test %s", Messages: []interface{}{"foo"}})
	if b.String() != "" {
		t.Error("Warn message was not expected to be logged")
	}
}

func TestJSONErrorf(t *testing.T) {
	var b bytes.Buffer
	l := NewJSON(&b, LevelError)
	f := "test %s"
	msg := "foo"
	msg2 := "bar"

	l.Errorf(Log{Direction: DirServerToClient, Format: f, Messages: []interface{}{msg}})
	exFrom := "server"
	exTo := "client"
	jl, err := unmarshalLog(b.Bytes())
	if err != nil {
		t.Errorf("Debugf() failed, unmarshal json log message failed: %s", err)
	}
	if jl.Direction.To != exTo {
		t.Errorf("Debugf() failed, expected message to: %s, got: %s", exTo, jl.Direction.To)
	}
	if jl.Direction.From != exFrom {
		t.Errorf("Debugf() failed, expected message to: %s, got: %s", exFrom, jl.Direction.From)
	}
	if jl.Message != fmt.Sprintf(f, msg) {
		t.Errorf("Debugf() failed, expected message: %s, got %s", msg, jl.Message)
	}

	b.Reset()
	l.Errorf(Log{Direction: DirClientToServer, Format: f, Messages: []interface{}{msg2}})
	exFrom = "client"
	exTo = "server"
	jl, err = unmarshalLog(b.Bytes())
	if err != nil {
		t.Errorf("Debugf() failed, unmarshal json log message failed: %s", err)
	}
	if jl.Direction.To != exTo {
		t.Errorf("Debugf() failed, expected message to: %s, got: %s", exTo, jl.Direction.To)
	}
	if jl.Direction.From != exFrom {
		t.Errorf("Debugf() failed, expected message to: %s, got: %s", exFrom, jl.Direction.From)
	}
	if jl.Message != fmt.Sprintf(f, msg2) {
		t.Errorf("Debugf() failed, expected message: %s, got %s", msg2, jl.Message)
	}

	b.Reset()
	l.level = -99
	l.Errorf(Log{Direction: DirServerToClient, Format: "test %s", Messages: []interface{}{"foo"}})
	if b.String() != "" {
		t.Error("Error message was not expected to be logged")
	}
}

func unmarshalLog(j []byte) (jsonLog, error) {
	var jl jsonLog
	if err := json.Unmarshal(j, &jl); err != nil {
		return jl, err
	}
	return jl, nil
}
