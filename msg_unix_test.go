// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build linux || freebsd
// +build linux freebsd

package mail

import (
	"bytes"
	"errors"
	"os"
	"testing"
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

func TestMsg_WriteToFile_unixOnly(t *testing.T) {
	t.Run("WriteToFile fails on create", func(t *testing.T) {
		if os.Getenv("PERFORM_UNIX_OPEN_WRITE_TESTS") != "true" {
			t.Skipf("PERFORM_UNIX_OPEN_WRITE_TESTS variable is not set. Skipping unix open/write tests")
		}

		tempfile, err := os.CreateTemp("", "testmail-create.*.eml")
		if err != nil {
			t.Fatalf("failed to create temp file: %s", err)
		}
		if err = os.Chmod(tempfile.Name(), 0o000); err != nil {
			t.Fatalf("failed to chmod temp file: %s", err)
		}
		t.Cleanup(func() {
			if err = tempfile.Close(); err != nil {
				t.Fatalf("failed to close temp file: %s", err)
			}
			if err = os.Remove(tempfile.Name()); err != nil {
				t.Fatalf("failed to remove temp file: %s", err)
			}
		})
		message := testMessage(t)
		if err = message.WriteToFile(tempfile.Name()); err == nil {
			t.Errorf("expected error, got nil")
		}
	})
}

func TestMsg_WriteToTempFile_unixOnly(t *testing.T) {
	if os.Getenv("PERFORM_UNIX_OPEN_WRITE_TESTS") != "true" {
		t.Skipf("PERFORM_UNIX_OPEN_WRITE_TESTS variable is not set. Skipping unix open/write tests")
	}

	t.Run("WriteToTempFile fails on invalid TMPDIR", func(t *testing.T) {
		// We store the current TMPDIR variable so we can set it back when the test is over
		curTmpDir := os.Getenv("TMPDIR")
		t.Cleanup(func() {
			if err := os.Setenv("TMPDIR", curTmpDir); err != nil {
				t.Errorf("failed to set TMPDIR environment variable: %s", err)
			}
		})

		if err := os.Setenv("TMPDIR", "/invalid/directory/that/does/not/exist"); err != nil {
			t.Fatalf("failed to set TMPDIR environment variable: %s", err)
		}
		message := testMessage(t)
		_, err := message.WriteToTempFile()
		if err == nil {
			t.Errorf("expected writing to invalid TMPDIR to fail, got: %s", err)
		}
	})
}
