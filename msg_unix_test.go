// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build linux || freebsd
// +build linux freebsd

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
		if os.Getenv("PERFORM_UNIX_OPEN_WRITE_TESTS") != "true" {
			t.Skipf("PERFORM_UNIX_OPEN_WRITE_TESTS variable is not set. Skipping unix open/write tests")
		}

		tempFile, err := os.CreateTemp("", "attachfile-open-write-test.*.txt")
		if err != nil {
			t.Fatalf("failed to create temp file: %s", err)
		}
		t.Cleanup(func() {
			if err := os.Remove(tempFile.Name()); err != nil {
				t.Errorf("failed to remove temp file: %s", err)
			}
		})
		if err = os.Chmod(tempFile.Name(), 0o000); err != nil {
			t.Fatalf("failed to chmod temp file: %s", err)
		}

		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.AttachFile(tempFile.Name())
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
}

func TestMsg_EmbedFile_unixOnly(t *testing.T) {
	t.Run("EmbedFile with fileFromFS fails on open", func(t *testing.T) {
		if os.Getenv("PERFORM_UNIX_OPEN_WRITE_TESTS") != "true" {
			t.Skipf("PERFORM_UNIX_OPEN_WRITE_TESTS variable is not set. Skipping unix open/write tests")
		}

		tempFile, err := os.CreateTemp("", "embedfile-open-write-test.*.txt")
		if err != nil {
			t.Fatalf("failed to create temp file: %s", err)
		}
		t.Cleanup(func() {
			if err := os.Remove(tempFile.Name()); err != nil {
				t.Errorf("failed to remove temp file: %s", err)
			}
		})
		if err = os.Chmod(tempFile.Name(), 0o000); err != nil {
			t.Fatalf("failed to chmod temp file: %s", err)
		}

		message := NewMsg()
		if message == nil {
			t.Fatal("message is nil")
		}
		message.EmbedFile(tempFile.Name())
		embeds := message.GetEmbeds()
		if len(embeds) != 1 {
			t.Fatalf("failed to get embeds, expected 1, got: %d", len(embeds))
		}
		messageBuf := bytes.NewBuffer(nil)
		_, err = embeds[0].Writer(messageBuf)
		if err == nil {
			t.Error("writer func expected to fail, but didn't")
		}
		if !errors.Is(err, os.ErrPermission) {
			t.Errorf("expected error to be %s, got: %s", os.ErrPermission, err)
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
