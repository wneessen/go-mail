// SPDX-FileCopyrightText: Copyright (c) The go-mail Authors
//
// SPDX-License-Identifier: MIT

package log

import (
	"bytes"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, LevelDebug)
	if l.level != LevelDebug {
		t.Error("Expected level to be LevelDebug, got ", l.level)
	}
	if l.err == nil || l.warn == nil || l.info == nil || l.debug == nil {
		t.Error("Loggers not initialized")
	}
}

func TestDebugf(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, LevelDebug)

	l.Debugf(Log{Direction: DirServerToClient, Format: "test %s", Messages: []interface{}{"foo"}})
	expected := "DEBUG: C <-- S: test foo\n"
	if !strings.HasSuffix(b.String(), expected) {
		t.Errorf("Expected %q, got %q", expected, b.String())
	}
	l.Debugf(Log{Direction: DirClientToServer, Format: "test %s", Messages: []interface{}{"foo"}})
	expected = "DEBUG: C --> S: test foo\n"
	if !strings.HasSuffix(b.String(), expected) {
		t.Errorf("Expected %q, got %q", expected, b.String())
	}

	b.Reset()
	l.level = LevelInfo
	l.Debugf(Log{Direction: DirServerToClient, Format: "test %s", Messages: []interface{}{"foo"}})
	if b.String() != "" {
		t.Error("Debug message was not expected to be logged")
	}
}

func TestInfof(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, LevelInfo)

	l.Infof(Log{Direction: DirServerToClient, Format: "test %s", Messages: []interface{}{"foo"}})
	expected := " INFO: C <-- S: test foo\n"
	if !strings.HasSuffix(b.String(), expected) {
		t.Errorf("Expected %q, got %q", expected, b.String())
	}
	l.Infof(Log{Direction: DirClientToServer, Format: "test %s", Messages: []interface{}{"foo"}})
	expected = " INFO: C --> S: test foo\n"
	if !strings.HasSuffix(b.String(), expected) {
		t.Errorf("Expected %q, got %q", expected, b.String())
	}

	b.Reset()
	l.level = LevelWarn
	l.Infof(Log{Direction: DirServerToClient, Format: "test %s", Messages: []interface{}{"foo"}})
	if b.String() != "" {
		t.Error("Info message was not expected to be logged")
	}
}

func TestWarnf(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, LevelWarn)

	l.Warnf(Log{Direction: DirServerToClient, Format: "test %s", Messages: []interface{}{"foo"}})
	expected := " WARN: C <-- S: test foo\n"
	if !strings.HasSuffix(b.String(), expected) {
		t.Errorf("Expected %q, got %q", expected, b.String())
	}
	l.Warnf(Log{Direction: DirClientToServer, Format: "test %s", Messages: []interface{}{"foo"}})
	expected = " WARN: C --> S: test foo\n"
	if !strings.HasSuffix(b.String(), expected) {
		t.Errorf("Expected %q, got %q", expected, b.String())
	}

	b.Reset()
	l.level = LevelError
	l.Warnf(Log{Direction: DirServerToClient, Format: "test %s", Messages: []interface{}{"foo"}})
	if b.String() != "" {
		t.Error("Warn message was not expected to be logged")
	}
}

func TestErrorf(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, LevelError)

	l.Errorf(Log{Direction: DirServerToClient, Format: "test %s", Messages: []interface{}{"foo"}})
	expected := "ERROR: C <-- S: test foo\n"
	if !strings.HasSuffix(b.String(), expected) {
		t.Errorf("Expected %q, got %q", expected, b.String())
	}
	l.Errorf(Log{Direction: DirClientToServer, Format: "test %s", Messages: []interface{}{"foo"}})
	expected = "ERROR: C --> S: test foo\n"
	if !strings.HasSuffix(b.String(), expected) {
		t.Errorf("Expected %q, got %q", expected, b.String())
	}

	b.Reset()
	l.level = LevelError - 1
	l.Errorf(Log{Direction: DirServerToClient, Format: "test %s", Messages: []interface{}{"foo"}})
	if b.String() != "" {
		t.Error("Error message was not expected to be logged")
	}
}
