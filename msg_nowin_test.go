// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build !windows
// +build !windows

package mail

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestMsg_WriteToSendmailWithContext tests the WriteToSendmailWithContext() method of the Msg
func TestMsg_WriteToSendmailWithContext(t *testing.T) {
	if os.Getenv("TEST_SENDMAIL") != "true" {
		t.Skipf("TEST_SENDMAIL variable is not set. Skipping sendmail test")
	}
	tests := []struct {
		name string
		sp   string
		sf   bool
	}{
		{"Sendmail path: /dev/null", "/dev/null", true},
		{"Sendmail path: /bin/cat", "/bin/cat", true},
		{"Sendmail path: /is/invalid", "/is/invalid", true},
		{"Sendmail path: /bin/echo", "/bin/echo", false},
	}
	m := NewMsg()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cfn := context.WithTimeout(context.Background(), time.Second*10)
			defer cfn()
			m.SetBodyString(TypeTextPlain, "Plain")
			if err := m.WriteToSendmailWithContext(ctx, tt.sp); err != nil && !tt.sf {
				t.Errorf("WriteToSendmailWithCommand() failed: %s", err)
			}
			m.Reset()
		})
	}
}

// TestMsg_WriteToSendmail will test the output to the local sendmail command
func TestMsg_WriteToSendmail(t *testing.T) {
	if os.Getenv("TEST_SENDMAIL") != "true" {
		t.Skipf("TEST_SENDMAIL variable is not set. Skipping sendmail test")
	}
	_, err := os.Stat(SendmailPath)
	if err != nil {
		t.Skipf("local sendmail command not found in expected path. Skipping")
	}

	m := NewMsg()
	_ = m.From("Toni Tester <tester@example.com>")
	_ = m.To(TestRcpt)
	m.SetBodyString(TypeTextPlain, "This is a test")
	if err := m.WriteToSendmail(); err != nil {
		t.Errorf("WriteToSendmail failed: %s", err)
	}
}

func TestMsg_WriteToTempFileFailed(t *testing.T) {
	m := NewMsg()
	_ = m.From("Toni Tester <tester@example.com>")
	_ = m.To("Ellenor Tester <ellinor@example.com>")
	m.SetBodyString(TypeTextPlain, "This is a test")

	curTmpDir := os.Getenv("TMPDIR")
	defer func() {
		if err := os.Setenv("TMPDIR", curTmpDir); err != nil {
			t.Errorf("failed to set TMPDIR environment variable: %s", err)
		}
	}()

	if err := os.Setenv("TMPDIR", "/invalid/directory/that/does/not/exist"); err != nil {
		t.Errorf("failed to set TMPDIR environment variable: %s", err)
	}
	_, err := m.WriteToTempFile()
	if err == nil {
		t.Errorf("WriteToTempFile() did not fail as expected")
	}
}
