// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"strings"
	"testing"
	"time"
)

// brokenWriter implements a broken writer for io.Writer testing
type brokenWriter struct {
	io.Writer
}

// Write implements the io.Writer interface but intentionally returns an error at
// any time
func (bw *brokenWriter) Write([]byte) (int, error) {
	return 0, fmt.Errorf("intentionally failed")
}

// TestMsgWriter_Write tests the WriteTo() method of the msgWriter
func TestMsgWriter_Write(t *testing.T) {
	bw := &brokenWriter{}
	mw := &msgWriter{writer: bw, charset: CharsetUTF8, encoder: mime.QEncoding}
	_, err := mw.Write([]byte("test"))
	if err == nil {
		t.Errorf("msgWriter WriteTo() with brokenWriter should fail, but didn't")
	}

	// Also test the part when a previous error happened
	mw.err = fmt.Errorf("broken")
	_, err = mw.Write([]byte("test"))
	if err == nil {
		t.Errorf("msgWriter WriteTo() with brokenWriter should fail, but didn't")
	}
}

// TestMsgWriter_writeMsg tests the writeMsg method of the msgWriter
func TestMsgWriter_writeMsg(t *testing.T) {
	m := NewMsg()
	_ = m.From(`"Toni Tester" <test@example.com>`)
	_ = m.To(`"Toni Receiver" <receiver@example.com>`)
	m.Subject("This is a subject")
	m.SetBulk()
	now := time.Now()
	m.SetDateWithValue(now)
	m.SetMessageIDWithValue("message@id.com")
	m.SetBodyString(TypeTextPlain, "This is the body")
	m.AddAlternativeString(TypeTextHTML, "This is the alternative body")
	buf := bytes.Buffer{}
	mw := &msgWriter{writer: &buf, charset: CharsetUTF8, encoder: mime.QEncoding}
	mw.writeMsg(m)
	ms := buf.String()

	var ea []string
	if !strings.Contains(ms, `MIME-Version: 1.0`) {
		ea = append(ea, "MIME-Version")
	}
	if !strings.Contains(ms, fmt.Sprintf("Date: %s", now.Format(time.RFC1123Z))) {
		ea = append(ea, "Date")
	}
	if !strings.Contains(ms, `Message-ID: <message@id.com>`) {
		ea = append(ea, "Message-ID")
	}
	if !strings.Contains(ms, `Precedence: bulk`) {
		ea = append(ea, "Precedence")
	}
	if !strings.Contains(ms, `Subject: This is a subject`) {
		ea = append(ea, "Subject")
	}
	if !strings.Contains(ms, `User-Agent: go-mail v`) {
		ea = append(ea, "User-Agent")
	}
	if !strings.Contains(ms, `X-Mailer: go-mail v`) {
		ea = append(ea, "X-Mailer")
	}
	if !strings.Contains(ms, `From: "Toni Tester" <test@example.com>`) {
		ea = append(ea, "From")
	}
	if !strings.Contains(ms, `To: "Toni Receiver" <receiver@example.com>`) {
		ea = append(ea, "To")
	}
	if !strings.Contains(ms, `Content-Type: text/plain; charset=UTF-8`) {
		ea = append(ea, "Content-Type")
	}
	if !strings.Contains(ms, `Content-Transfer-Encoding: quoted-printable`) {
		ea = append(ea, "Content-Transfer-Encoding")
	}
	if !strings.Contains(ms, "\r\n\r\nThis is the body") {
		ea = append(ea, "Message body")
	}

	pl := m.GetParts()
	if len(pl) <= 0 {
		t.Errorf("expected multiple parts but got none")
		return
	}
	if len(pl) == 2 {
		ap := pl[1]
		ap.SetCharset(CharsetISO88591)
	}
	buf.Reset()
	mw.writeMsg(m)
	ms = buf.String()
	if !strings.Contains(ms, "\r\n\r\nThis is the alternative body") {
		ea = append(ea, "Message alternative body")
	}
	if !strings.Contains(ms, `Content-Type: text/html; charset=ISO-8859-1`) {
		ea = append(ea, "alternative body charset")
	}

	if len(ea) > 0 {
		em := "writeMsg() failed. The following errors occurred:\n"
		for e := range ea {
			em += fmt.Sprintf("* incorrect %q field", ea[e])
		}
		em += fmt.Sprintf("\n\nFull message:\n%s", ms)
		t.Error(em)
	}
}

// TestMsgWriter_writeMsg_PGP tests the writeMsg method of the msgWriter with PGP types set
func TestMsgWriter_writeMsg_PGP(t *testing.T) {
	m := NewMsg(WithPGPType(PGPEncrypt))
	_ = m.From(`"Toni Tester" <test@example.com>`)
	_ = m.To(`"Toni Receiver" <receiver@example.com>`)
	m.Subject("This is a subject")
	m.SetBodyString(TypeTextPlain, "This is the body")
	buf := bytes.Buffer{}
	mw := &msgWriter{writer: &buf, charset: CharsetUTF8, encoder: mime.QEncoding}
	mw.writeMsg(m)
	ms := buf.String()
	if !strings.Contains(ms, `encrypted; protocol="application/pgp-encrypted"`) {
		t.Errorf("writeMsg failed. Expected PGP encoding header but didn't find it in message output")
	}

	m = NewMsg(WithPGPType(PGPSignature))
	_ = m.From(`"Toni Tester" <test@example.com>`)
	_ = m.To(`"Toni Receiver" <receiver@example.com>`)
	m.Subject("This is a subject")
	m.SetBodyString(TypeTextPlain, "This is the body")
	buf = bytes.Buffer{}
	mw = &msgWriter{writer: &buf, charset: CharsetUTF8, encoder: mime.QEncoding}
	mw.writeMsg(m)
	ms = buf.String()
	if !strings.Contains(ms, `signed; protocol="application/pgp-signature"`) {
		t.Errorf("writeMsg failed. Expected PGP encoding header but didn't find it in message output")
	}
}

// TestMsgWriter_writeMsg_SMime tests the writeMsg method of the msgWriter with S/MIME types set
func TestMsgWriter_writeMsg_SMime(t *testing.T) {
	privateKey, certificate, intermediateCertificate, err := getDummyCryptoMaterial()
	if err != nil {
		t.Errorf("failed to laod dummy crypto material. Cause: %v", err)
	}

	m := NewMsg()
	if err := m.SignWithSMime(privateKey, certificate, intermediateCertificate); err != nil {
		t.Errorf("failed to init smime configuration")
	}
	_ = m.From(`"Toni Tester" <test@example.com>`)
	_ = m.To(`"Toni Receiver" <receiver@example.com>`)
	m.Subject("This is a subject")
	m.SetBodyString(TypeTextPlain, "This is the body")
	buf := bytes.Buffer{}
	mw := &msgWriter{writer: &buf, charset: CharsetUTF8, encoder: mime.QEncoding}
	mw.writeMsg(m)
	ms := buf.String()

	if !strings.Contains(ms, "MIME-Version: 1.0") {
		t.Errorf("writeMsg failed. Unable to find MIME-Version")
	}
	if !strings.Contains(ms, "Subject: This is a subject") {
		t.Errorf("writeMsg failed. Unable to find subject")
	}
	if !strings.Contains(ms, "From: \"Toni Tester\" <test@example.com>") {
		t.Errorf("writeMsg failed. Unable to find transmitter")
	}
	if !strings.Contains(ms, "To: \"Toni Receiver\" <receiver@example.com>") {
		t.Errorf("writeMsg failed. Unable to find receiver")
	}

	boundary := ms[strings.LastIndex(ms, "--")-60 : strings.LastIndex(ms, "--")]
	if !strings.Contains(ms, fmt.Sprintf("Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256;\r\n boundary=%s", boundary)) {
		t.Errorf("writeMsg failed. Unable to find Content-Type")
	}
}
