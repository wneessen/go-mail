// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"errors"
	"fmt"
	"mime"
	"strings"
	"testing"
	"time"
)

func TestMsgWriter_Write(t *testing.T) {
	t.Run("msgWriter writes to memory for all charsets", func(t *testing.T) {
		for _, tt := range charsetTests {
			t.Run(tt.name, func(t *testing.T) {
				buffer := bytes.NewBuffer(nil)
				msgwriter := &msgWriter{
					writer:  buffer,
					charset: tt.value,
					encoder: mime.QEncoding,
				}
				_, err := msgwriter.Write([]byte("test"))
				if err != nil {
					t.Errorf("msgWriter failed to write: %s", err)
				}
			})
		}
	})
	t.Run("msgWriter writes to memory for all encodings", func(t *testing.T) {
		for _, tt := range encodingTests {
			t.Run(tt.name, func(t *testing.T) {
				buffer := bytes.NewBuffer(nil)
				msgwriter := &msgWriter{
					writer:  buffer,
					charset: CharsetUTF8,
					encoder: getEncoder(tt.value),
				}
				_, err := msgwriter.Write([]byte("test"))
				if err != nil {
					t.Errorf("msgWriter failed to write: %s", err)
				}
			})
		}
	})
	t.Run("msgWriter should fail on write", func(t *testing.T) {
		msgwriter := &msgWriter{
			writer:  failReadWriteSeekCloser{},
			charset: CharsetUTF8,
			encoder: getEncoder(EncodingQP),
		}
		_, err := msgwriter.Write([]byte("test"))
		if err == nil {
			t.Fatalf("msgWriter was supposed to fail on write")
		}
	})
	t.Run("msgWriter should fail on previous error", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		msgwriter := &msgWriter{
			writer:  buffer,
			charset: CharsetUTF8,
			encoder: getEncoder(EncodingQP),
		}
		_, err := msgwriter.Write([]byte("test"))
		if err != nil {
			t.Errorf("msgWriter failed to write: %s", err)
		}
		msgwriter.err = errors.New("intentionally failed")
		_, err = msgwriter.Write([]byte("test2"))
		if err == nil {
			t.Fatalf("msgWriter was supposed to fail on second write")
		}
	})
}

func TestMsgWriter_writeMsg(t *testing.T) {
	msgwriter := &msgWriter{
		charset: CharsetUTF8,
		encoder: getEncoder(EncodingQP),
	}
	t.Run("msgWriter writes a simple message", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		now := time.Now()
		msgwriter.writer = buffer
		message := testMessage(t)
		message.SetDateWithValue(now)
		message.SetMessageIDWithValue("message@id.com")
		message.SetBulk()
		msgwriter.writeMsg(message)
		if msgwriter.err != nil {
			t.Errorf("msgWriter failed to write: %s", msgwriter.err)
		}

		var incorrectFields []string
		if !strings.Contains(buffer.String(), "MIME-Version: 1.0\r\n") {
			incorrectFields = append(incorrectFields, "MIME-Version")
		}
		if !strings.Contains(buffer.String(), fmt.Sprintf("Date: %s\r\n", now.Format(time.RFC1123Z))) {
			incorrectFields = append(incorrectFields, "Date")
		}
		if !strings.Contains(buffer.String(), "Message-ID: <message@id.com>\r\n") {
			incorrectFields = append(incorrectFields, "Message-ID")
		}
		if !strings.Contains(buffer.String(), "Precedence: bulk\r\n") {
			incorrectFields = append(incorrectFields, "Precedence")
		}
		if !strings.Contains(buffer.String(), "X-Auto-Response-Suppress: All\r\n") {
			incorrectFields = append(incorrectFields, "X-Auto-Response-Suppress")
		}
		if !strings.Contains(buffer.String(), "Subject: Testmail\r\n") {
			incorrectFields = append(incorrectFields, "Subject")
		}
		if !strings.Contains(buffer.String(), "User-Agent: go-mail v") {
			incorrectFields = append(incorrectFields, "User-Agent")
		}
		if !strings.Contains(buffer.String(), "X-Mailer: go-mail v") {
			incorrectFields = append(incorrectFields, "X-Mailer")
		}
		if !strings.Contains(buffer.String(), `From: <`+TestSenderValid+`>`) {
			incorrectFields = append(incorrectFields, "From")
		}
		if !strings.Contains(buffer.String(), `To: <`+TestRcptValid+`>`) {
			incorrectFields = append(incorrectFields, "From")
		}
		if !strings.Contains(buffer.String(), "Content-Type: text/plain; charset=UTF-8\r\n") {
			incorrectFields = append(incorrectFields, "Content-Type")
		}
		if !strings.Contains(buffer.String(), "Content-Transfer-Encoding: quoted-printable\r\n") {
			incorrectFields = append(incorrectFields, "Content-Transfer-Encoding")
		}
		if !strings.HasSuffix(buffer.String(), "\r\n\r\nTestmail") {
			incorrectFields = append(incorrectFields, "Message body")
		}
		if len(incorrectFields) > 0 {
			t.Fatalf("msgWriter failed to write correct fields: %s - mail: %s",
				strings.Join(incorrectFields, ", "), buffer.String())
		}
	})
	t.Run("msgWriter with no from address uses envelope from", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		msgwriter.writer = buffer
		message := NewMsg()
		if message == nil {
			t.Fatal("failed to create new message")
		}
		if err := message.EnvelopeFrom(TestSenderValid); err != nil {
			t.Errorf("failed to set sender address: %s", err)
		}
		if err := message.To(TestRcptValid); err != nil {
			t.Errorf("failed to set recipient address: %s", err)
		}
		message.Subject("Testmail")
		message.SetBodyString(TypeTextPlain, "Testmail")
		msgwriter.writeMsg(message)
		if msgwriter.err != nil {
			t.Errorf("msgWriter failed to write: %s", msgwriter.err)
		}
		if !strings.Contains(buffer.String(), "From: <"+TestSenderValid+">") {
			t.Errorf("expected envelope from address as from address, got: %s", buffer.String())
		}
	})
	t.Run("msgWriter with no from address or envelope from", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		msgwriter.writer = buffer
		message := NewMsg()
		if message == nil {
			t.Fatal("failed to create new message")
		}
		msgwriter.writeMsg(message)
		if msgwriter.err != nil {
			t.Errorf("msgWriter failed to write: %s", msgwriter.err)
		}
		if strings.Contains(buffer.String(), "From:") {
			t.Errorf("expected no from address, got: %s", buffer.String())
		}
	})
	t.Run("msgWriter writes a multipart/mixed message", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		msgwriter.writer = buffer
		message := testMessage(t, WithBoundary("testboundary"))
		message.AttachFile("testdata/attachment.txt")
		msgwriter.writeMsg(message)
		if msgwriter.err != nil {
			t.Errorf("msgWriter failed to write: %s", msgwriter.err)
		}
		if !strings.Contains(buffer.String(), "Content-Type: multipart/mixed") {
			t.Errorf("expected multipart/mixed, got: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), "--testboundary\r\n") {
			t.Errorf("expected boundary, got: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), "--testboundary--") {
			t.Errorf("expected end boundary, got: %s", buffer.String())
		}
	})
	t.Run("msgWriter writes a multipart/related message", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		msgwriter.writer = buffer
		message := testMessage(t, WithBoundary("testboundary"))
		message.EmbedFile("testdata/embed.txt")
		msgwriter.writeMsg(message)
		if msgwriter.err != nil {
			t.Errorf("msgWriter failed to write: %s", msgwriter.err)
		}
		if !strings.Contains(buffer.String(), "Content-Type: multipart/related") {
			t.Errorf("expected multipart/related, got: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), "--testboundary\r\n") {
			t.Errorf("expected boundary, got: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), "--testboundary--") {
			t.Errorf("expected end boundary, got: %s", buffer.String())
		}
	})
	t.Run("msgWriter writes a multipart/alternative message", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		msgwriter.writer = buffer
		message := testMessage(t, WithBoundary("testboundary"))
		message.AddAlternativeString(TypeTextHTML, "<html><body><h1>Testmail</h1></body></html>")
		msgwriter.writeMsg(message)
		if msgwriter.err != nil {
			t.Errorf("msgWriter failed to write: %s", msgwriter.err)
		}
		if !strings.Contains(buffer.String(), "Content-Type: multipart/alternative") {
			t.Errorf("expected multipart/alternative, got: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), "--testboundary\r\n") {
			t.Errorf("expected boundary, got: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), "--testboundary--") {
			t.Errorf("expected end boundary, got: %s", buffer.String())
		}
	})
	t.Run("msgWriter writes a application/pgp-encrypted message", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		msgwriter.writer = buffer
		message := testMessage(t, WithPGPType(PGPEncrypt), WithBoundary("testboundary"))
		msgwriter.writeMsg(message)
		if msgwriter.err != nil {
			t.Errorf("msgWriter failed to write: %s", msgwriter.err)
		}
		if !strings.Contains(buffer.String(), "Content-Type: multipart/encrypted") {
			t.Errorf("expected multipart/encrypted, got: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), "--testboundary\r\n") {
			t.Errorf("expected boundary, got: %s", buffer.String())
		}
	})
	t.Run("msgWriter writes a application/pgp-signature message", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		msgwriter.writer = buffer
		message := testMessage(t, WithPGPType(PGPSignature), WithBoundary("testboundary"))
		msgwriter.writeMsg(message)
		if msgwriter.err != nil {
			t.Errorf("msgWriter failed to write: %s", msgwriter.err)
		}
		if !strings.Contains(buffer.String(), "Content-Type: multipart/signed") {
			t.Errorf("expected multipart/signed, got: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), "--testboundary\r\n") {
			t.Errorf("expected boundary, got: %s", buffer.String())
		}
	})
	t.Run("msgWriter should ignore NoPGP", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		msgwriter.writer = buffer
		message := testMessage(t, WithBoundary("testboundary"))
		message.pgptype = 9
		msgwriter.writeMsg(message)
		if msgwriter.err != nil {
			t.Errorf("msgWriter failed to write: %s", msgwriter.err)
		}
		if !strings.Contains(buffer.String(), "--testboundary\r\n") {
			t.Errorf("expected boundary, got: %s", buffer.String())
		}
	})
}

func TestMsgWriter_writePreformattedGenHeader(t *testing.T) {
	t.Run("message with no preformatted headerset", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		msgwriter := &msgWriter{
			writer:  buffer,
			charset: CharsetUTF8,
			encoder: getEncoder(EncodingQP),
		}
		message := testMessage(t)
		message.SetGenHeaderPreformatted(HeaderContentID, "This is a content id")
		msgwriter.writeMsg(message)
		if !strings.Contains(buffer.String(), "Content-ID: This is a content id\r\n") {
			t.Errorf("expected preformatted header, got: %s", buffer.String())
		}
	})
}

func TestMsgWriter_addFiles(t *testing.T) {
	msgwriter := &msgWriter{
		charset: CharsetUTF8,
		encoder: getEncoder(EncodingQP),
	}
	t.Run("message with a single file attached", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		msgwriter.writer = buffer
		message := testMessage(t)
		message.AttachFile("testdata/attachment.txt")
		msgwriter.writeMsg(message)
		if msgwriter.err != nil {
			t.Errorf("msgWriter failed to write: %s", msgwriter.err)
		}
		if !strings.Contains(buffer.String(), "VGhpcyBpcyBhIHRlc3QgYXR0YWNobWVudAo=") {
			t.Errorf("attachment not found in mail message. Mail: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), `Content-Disposition: attachment; filename="attachment.txt"`) {
			t.Errorf("Content-Dispositon header not found for attachment. Mail: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), `Content-Type: text/plain; charset=utf-8; name="attachment.txt"`) {
			t.Errorf("Content-Type header not found for attachment. Mail: %s", buffer.String())
		}
	})
	t.Run("message with a single file attached no extension", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		msgwriter.writer = buffer
		message := testMessage(t)
		message.AttachFile("testdata/attachment")
		msgwriter.writeMsg(message)
		if msgwriter.err != nil {
			t.Errorf("msgWriter failed to write: %s", msgwriter.err)
		}
		if !strings.Contains(buffer.String(), "VGhpcyBpcyBhIHRlc3QgYXR0YWNobWVudAo=") {
			t.Errorf("attachment not found in mail message. Mail: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), `Content-Disposition: attachment; filename="attachment"`) {
			t.Errorf("Content-Dispositon header not found for attachment. Mail: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), `Content-Type: application/octet-stream; name="attachment"`) {
			t.Errorf("Content-Type header not found for attachment. Mail: %s", buffer.String())
		}
	})
	t.Run("message with a single file attached custom content-type", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		msgwriter.writer = buffer
		message := testMessage(t)
		message.AttachFile("testdata/attachment.txt", WithFileContentType(TypeAppOctetStream))
		msgwriter.writeMsg(message)
		if msgwriter.err != nil {
			t.Errorf("msgWriter failed to write: %s", msgwriter.err)
		}
		if !strings.Contains(buffer.String(), "VGhpcyBpcyBhIHRlc3QgYXR0YWNobWVudAo=") {
			t.Errorf("attachment not found in mail message. Mail: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), `Content-Disposition: attachment; filename="attachment.txt"`) {
			t.Errorf("Content-Dispositon header not found for attachment. Mail: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), `Content-Type: application/octet-stream; name="attachment.txt"`) {
			t.Errorf("Content-Type header not found for attachment. Mail: %s", buffer.String())
		}
	})
	t.Run("message with a single file attached custom transfer-encoding", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		msgwriter.writer = buffer
		message := testMessage(t)
		message.AttachFile("testdata/attachment.txt", WithFileEncoding(EncodingUSASCII))
		msgwriter.writeMsg(message)
		if msgwriter.err != nil {
			t.Errorf("msgWriter failed to write: %s", msgwriter.err)
		}
		if !strings.Contains(buffer.String(), "\r\n\r\nThis is a test attachment") {
			t.Errorf("attachment not found in mail message. Mail: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), `Content-Disposition: attachment; filename="attachment.txt"`) {
			t.Errorf("Content-Dispositon header not found for attachment. Mail: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), `text/plain; charset=utf-8; name="attachment.txt"`) {
			t.Errorf("Content-Type header not found for attachment. Mail: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), `Content-Transfer-Encoding: 7bit`) {
			t.Errorf("Content-Transfer-Encoding header not found for attachment. Mail: %s", buffer.String())
		}
	})
	t.Run("message with a single file attached custom description", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		msgwriter.writer = buffer
		message := testMessage(t)
		message.AttachFile("testdata/attachment.txt", WithFileDescription("Testdescription"))
		msgwriter.writeMsg(message)
		if msgwriter.err != nil {
			t.Errorf("msgWriter failed to write: %s", msgwriter.err)
		}
		if !strings.Contains(buffer.String(), "\r\n\r\nVGhpcyBpcyBhIHRlc3QgYXR0YWNobWVudAo=") {
			t.Errorf("attachment not found in mail message. Mail: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), `Content-Disposition: attachment; filename="attachment.txt"`) {
			t.Errorf("Content-Dispositon header not found for attachment. Mail: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), `text/plain; charset=utf-8; name="attachment.txt"`) {
			t.Errorf("Content-Type header not found for attachment. Mail: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), `Content-Transfer-Encoding: base64`) {
			t.Errorf("Content-Transfer-Encoding header not found for attachment. Mail: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), `Content-Description: Testdescription`) {
			t.Errorf("Content-Description header not found for attachment. Mail: %s", buffer.String())
		}
	})
	t.Run("message with attachment but no body part", func(t *testing.T) {
		buffer := bytes.NewBuffer(nil)
		msgwriter.writer = buffer
		message := testMessage(t)
		message.parts = nil
		message.AttachFile("testdata/attachment.txt")
		msgwriter.writeMsg(message)
		if msgwriter.err != nil {
			t.Errorf("msgWriter failed to write: %s", msgwriter.err)
		}
		if !strings.Contains(buffer.String(), "\r\n\r\nVGhpcyBpcyBhIHRlc3QgYXR0YWNobWVudAo=") {
			t.Errorf("attachment not found in mail message. Mail: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), `Content-Disposition: attachment; filename="attachment.txt"`) {
			t.Errorf("Content-Dispositon header not found for attachment. Mail: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), `text/plain; charset=utf-8; name="attachment.txt"`) {
			t.Errorf("Content-Type header not found for attachment. Mail: %s", buffer.String())
		}
		if !strings.Contains(buffer.String(), `Content-Transfer-Encoding: base64`) {
			t.Errorf("Content-Transfer-Encoding header not found for attachment. Mail: %s", buffer.String())
		}
	})
}
