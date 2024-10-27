// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build !windows
// +build !windows

package mail

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestMsg_AttachFile_unixOnly(t *testing.T) {
	t.Run("AttachFile with fileFromFS fails on open", func(t *testing.T) {
		tempfile, err := os.CreateTemp("", "attachfile-unable-to-open.*.txt")
		if err != nil {
			t.Fatalf("failed to create temp file: %s", err)
		}
		t.Cleanup(func() {
			if err := os.Remove(tempfile.Name()); err != nil {
				t.Errorf("failed to remove temp file: %s", err)
			}
		})
		if err = os.Chmod(tempfile.Name(), 0o000); err != nil {
			t.Fatalf("failed to chmod temp file to 0000: %s", err)
		}
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.AttachFile(tempfile.Name())
		attachments := message.GetAttachments()
		if len(attachments) != 1 {
			t.Fatalf("failed to get attachments, expected 1, got: %d", len(attachments))
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = attachments[0].Writer(messageBuf)
		if err == nil {
			t.Error("writer func expected to fail, but didn't")
		}
		if !errors.Is(err, os.ErrPermission) {
			t.Errorf("expected error to be %s, got: %s", os.ErrPermission, err)
		}
	})
	t.Run("AttachFile with fileFromFS fails on copy", func(t *testing.T) {
		tempfile, err := os.CreateTemp("", "attachfile-close-early.*.txt")
		if err != nil {
			t.Fatalf("failed to create temp file: %s", err)
		}
		t.Cleanup(func() {
			if err := os.Remove(tempfile.Name()); err != nil {
				t.Errorf("failed to remove temp file: %s", err)
			}
		})
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.AttachFile("testdata/attachment.txt")
		attachments := message.GetAttachments()
		if len(attachments) != 1 {
			t.Fatalf("failed to get attachments, expected 1, got: %d", len(attachments))
		}
		messageBuf, err := os.Open(tempfile.Name())
		if err != nil {
			t.Fatalf("failed to open temp file: %s", err)
		}
		// We close early to cause an error during io.Copy
		if err = messageBuf.Close(); err != nil {
			t.Fatalf("failed to close temp file: %s", err)
		}
		_, err = attachments[0].Writer(messageBuf)
		if err == nil {
			t.Error("writer func expected to fail, but didn't")
		}
		if !errors.Is(err, os.ErrClosed) {
			t.Errorf("expected error to be %s, got: %s", os.ErrClosed, err)
		}
	})
}

func TestMsg_AttachReader_unixOnly(t *testing.T) {
	t.Run("AttachReader with fileFromReader fails on copy", func(t *testing.T) {
		tempfile, err := os.CreateTemp("", "attachfile-close-early.*.txt")
		if err != nil {
			t.Fatalf("failed to create temp file: %s", err)
		}
		t.Cleanup(func() {
			if err := os.Remove(tempfile.Name()); err != nil {
				t.Errorf("failed to remove temp file: %s", err)
			}
		})
		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		file, err := os.Open("testdata/attachment.txt")
		if err != nil {
			t.Fatalf("failed to open file: %s", err)
		}
		t.Cleanup(func() {
			if err := file.Close(); err != nil {
				t.Errorf("failed to close file: %s", err)
			}
		})
		if err = message.AttachReader("attachment.txt", file); err != nil {
			t.Fatalf("failed to attach reader: %s", err)
		}
		attachments := message.GetAttachments()
		if len(attachments) != 1 {
			t.Fatalf("failed to get attachments, expected 1, got: %d", len(attachments))
		}
		messageBuf, err := os.Open(tempfile.Name())
		if err != nil {
			t.Fatalf("failed to open temp file: %s", err)
		}
		// We close early to cause an error during io.Copy
		if err = messageBuf.Close(); err != nil {
			t.Fatalf("failed to close temp file: %s", err)
		}
		_, err = attachments[0].Writer(messageBuf)
		if err == nil {
			t.Error("writer func expected to fail, but didn't")
		}
		if !errors.Is(err, os.ErrClosed) {
			t.Errorf("expected error to be %s, got: %s", os.ErrClosed, err)
		}
	})
}

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
