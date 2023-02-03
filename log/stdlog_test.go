// SPDX-FileCopyrightText: Copyright (c) 2023 The go-mail Authors
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
	if l.l != LevelDebug {
		t.Error("Expected level to be LevelDebug, got ", l.l)
	}
	if l.err == nil || l.warn == nil || l.info == nil || l.debug == nil {
		t.Error("Loggers not initialized")
	}
}

func TestDebugf(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, LevelDebug)

	l.Debugf("test %s", "foo")
	expected := "DEBUG: test foo\n"
	if !strings.HasSuffix(b.String(), expected) {
		t.Errorf("Expected %q, got %q", expected, b.String())
	}

	b.Reset()
	l.l = LevelInfo
	l.Debugf("test %s", "foo")
	if b.String() != "" {
		t.Error("Debug message was not expected to be logged")
	}
}

func TestInfof(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, LevelInfo)

	l.Infof("test %s", "foo")
	expected := " INFO: test foo\n"
	if !strings.HasSuffix(b.String(), expected) {
		t.Errorf("Expected %q, got %q", expected, b.String())
	}

	b.Reset()
	l.l = LevelWarn
	l.Infof("test %s", "foo")
	if b.String() != "" {
		t.Error("Info message was not expected to be logged")
	}
}

func TestWarnf(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, LevelWarn)

	l.Warnf("test %s", "foo")
	expected := " WARN: test foo\n"
	if !strings.HasSuffix(b.String(), expected) {
		t.Errorf("Expected %q, got %q", expected, b.String())
	}

	b.Reset()
	l.l = LevelError
	l.Warnf("test %s", "foo")
	if b.String() != "" {
		t.Error("Warn message was not expected to be logged")
	}
}

func TestErrorf(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, LevelError)

	l.Errorf("test %s", "foo")
	expected := "ERROR: test foo\n"
	if !strings.HasSuffix(b.String(), expected) {
		t.Errorf("Expected %q, got %q", expected, b.String())
	}
	b.Reset()
	l.l = LevelError - 1
	l.Warnf("test %s", "foo")
	if b.String() != "" {
		t.Error("Error message was not expected to be logged")
	}
}
