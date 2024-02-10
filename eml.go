// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	nm "net/mail"
	"os"
	"strings"
)

// EMLToMsgFromString will parse a given EML string and returns a pre-filled Msg pointer
func EMLToMsgFromString(es string) (*Msg, error) {
	eb := bytes.NewBufferString(es)
	return EMLToMsgFromReader(eb)
}

// EMLToMsgFromReader will parse a reader that holds EML content and returns a pre-filled
// Msg pointer
func EMLToMsgFromReader(r io.Reader) (*Msg, error) {
	m := &Msg{
		addrHeader:    make(map[AddrHeader][]*nm.Address),
		genHeader:     make(map[Header][]string),
		preformHeader: make(map[Header]string),
		mimever:       MIME10,
	}

	pm, bodybuf, err := readEMLFromReader(r)
	if err != nil || pm == nil {
		return m, fmt.Errorf("failed to parse EML from reader: %w", err)
	}

	if err = parseEMLHeaders(&pm.Header, m); err != nil {
		return m, fmt.Errorf("failed to parse EML headers: %w", err)
	}
	if err = parseEMLBodyParts(pm, bodybuf, m); err != nil {
		return m, fmt.Errorf("failed to parse EML body parts: %w", err)
	}

	return m, nil
}

// EMLToMsgFromFile will open and parse a .eml file at a provided file path and returns a
// pre-filled Msg pointer
func EMLToMsgFromFile(fp string) (*Msg, error) {
	m := &Msg{
		addrHeader:    make(map[AddrHeader][]*nm.Address),
		genHeader:     make(map[Header][]string),
		preformHeader: make(map[Header]string),
		mimever:       MIME10,
	}

	pm, bodybuf, err := readEML(fp)
	if err != nil || pm == nil {
		return m, fmt.Errorf("failed to parse EML file: %w", err)
	}

	if err = parseEMLHeaders(&pm.Header, m); err != nil {
		return m, fmt.Errorf("failed to parse EML headers: %w", err)
	}
	if err = parseEMLBodyParts(pm, bodybuf, m); err != nil {
		return m, fmt.Errorf("failed to parse EML body parts: %w", err)
	}

	return m, nil
}

// readEML opens an EML file and uses net/mail to parse the header and body
func readEML(fp string) (*nm.Message, *bytes.Buffer, error) {
	fh, err := os.Open(fp)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open EML file: %w", err)
	}
	defer func() {
		_ = fh.Close()
	}()
	return readEMLFromReader(fh)
}

// readEMLFromReader uses net/mail to parse the header and body from a given io.Reader
func readEMLFromReader(r io.Reader) (*nm.Message, *bytes.Buffer, error) {
	pm, err := nm.ReadMessage(r)
	if err != nil {
		return pm, nil, fmt.Errorf("failed to parse EML: %w", err)
	}

	buf := bytes.Buffer{}
	if _, err = buf.ReadFrom(pm.Body); err != nil {
		return nil, nil, err
	}

	return pm, &buf, nil
}

// parseEMLHeaders will check the EML headers for the most common headers and set the
// according settings in the Msg
func parseEMLHeaders(mh *nm.Header, m *Msg) error {
	commonHeaders := []Header{
		HeaderContentType, HeaderImportance, HeaderInReplyTo, HeaderListUnsubscribe,
		HeaderListUnsubscribePost, HeaderMessageID, HeaderMIMEVersion, HeaderOrganization,
		HeaderPrecedence, HeaderPriority, HeaderReferences, HeaderSubject, HeaderUserAgent,
		HeaderXMailer, HeaderXMSMailPriority, HeaderXPriority,
	}

	// Extract content type, charset and encoding first
	if v := mh.Get(HeaderContentTransferEnc.String()); v != "" {
		switch {
		case strings.EqualFold(v, EncodingQP.String()):
			m.SetEncoding(EncodingQP)
		case strings.EqualFold(v, EncodingB64.String()):
			m.SetEncoding(EncodingB64)
		default:
			m.SetEncoding(NoEncoding)
		}
	}
	if v := mh.Get(HeaderContentType.String()); v != "" {
		ct, cs := parseContentType(v)
		if cs != "" {
			m.SetCharset(Charset(cs))
		}
		m.setEncoder()
		if ct != "" {
			m.SetGenHeader(HeaderContentType, ct)
		}
	}

	// Extract address headers
	if v := mh.Get(HeaderFrom.String()); v != "" {
		if err := m.From(v); err != nil {
			return fmt.Errorf(`failed to parse %q header: %w`, HeaderFrom, err)
		}
	}
	ahl := map[AddrHeader]func(...string) error{
		HeaderTo:  m.To,
		HeaderCc:  m.Cc,
		HeaderBcc: m.Bcc,
	}
	for h, f := range ahl {
		if v := mh.Get(h.String()); v != "" {
			var als []string
			pal, err := nm.ParseAddressList(v)
			if err != nil {
				return fmt.Errorf(`failed to parse address list: %w`, err)
			}
			for _, a := range pal {
				als = append(als, a.String())
			}
			if err := f(als...); err != nil {
				return fmt.Errorf(`failed to parse %q header: %w`, HeaderTo, err)
			}
		}
	}

	// Extract date from message
	d, err := mh.Date()
	if err != nil {
		switch {
		case errors.Is(err, nm.ErrHeaderNotPresent):
			m.SetDate()
		default:
			return fmt.Errorf("failed to parse EML date: %w", err)
		}
	}
	if err == nil {
		m.SetDateWithValue(d)
	}

	// Extract common headers
	for _, h := range commonHeaders {
		if v := mh.Get(h.String()); v != "" {
			m.SetGenHeader(h, v)
		}
	}

	return nil
}

// parseEMLBodyParts parses the body of a EML based on the different content types and encodings
func parseEMLBodyParts(pm *nm.Message, bodybuf *bytes.Buffer, m *Msg) error {
	// Extract the transfer encoding of the body
	mediatype, params, err := mime.ParseMediaType(pm.Header.Get(HeaderContentType.String()))
	if err != nil {
		return fmt.Errorf("failed to extract content type: %w", err)
	}
	if v, ok := params["charset"]; ok {
		m.SetCharset(Charset(v))
	}

	switch {
	case strings.EqualFold(mediatype, TypeTextPlain.String()),
		strings.EqualFold(mediatype, TypeTextHTML.String()):
		if err := parseEMLBodyPlain(mediatype, pm, bodybuf, m); err != nil {
			return fmt.Errorf("failed to parse plain body: %w", err)
		}
	case strings.EqualFold(mediatype, TypeMultipartAlternative.String()),
		strings.EqualFold(mediatype, "multipart/mixed"):
		if err := parseEMLMultipartAlternative(params, bodybuf, m); err != nil {
			return fmt.Errorf("failed to parse multipart/alternative body: %w", err)
		}
	default:
	}
	return nil
}

// parseEMLBodyPlain parses the mail body of plain type mails
func parseEMLBodyPlain(mediatype string, pm *nm.Message, bodybuf *bytes.Buffer, m *Msg) error {
	cte := pm.Header.Get(HeaderContentTransferEnc.String())
	if strings.EqualFold(cte, NoEncoding.String()) {
		m.SetEncoding(NoEncoding)
		m.SetBodyString(ContentType(mediatype), bodybuf.String())
		return nil
	}
	if strings.EqualFold(cte, EncodingQP.String()) {
		m.SetEncoding(EncodingQP)
		qpr := quotedprintable.NewReader(bodybuf)
		qpbuf := bytes.Buffer{}
		if _, err := qpbuf.ReadFrom(qpr); err != nil {
			return fmt.Errorf("failed to read quoted-printable body: %w", err)
		}
		m.SetBodyString(ContentType(mediatype), qpbuf.String())
		return nil
	}
	if strings.EqualFold(cte, EncodingB64.String()) {
		m.SetEncoding(EncodingB64)
		b64d := base64.NewDecoder(base64.StdEncoding, bodybuf)
		b64buf := bytes.Buffer{}
		if _, err := b64buf.ReadFrom(b64d); err != nil {
			return fmt.Errorf("failed to read base64 body: %w", err)
		}
		m.SetBodyString(ContentType(mediatype), b64buf.String())
		return nil
	}
	return fmt.Errorf("unsupported Content-Transfer-Encoding")
}

// parseEMLMultipartAlternative parses a multipart/alternative body part of a EML
func parseEMLMultipartAlternative(params map[string]string, bodybuf *bytes.Buffer, m *Msg) error {
	boundary, ok := params["boundary"]
	if !ok {
		return fmt.Errorf("no boundary tag found in multipart body")
	}
	mpreader := multipart.NewReader(bodybuf, boundary)
	mpart, err := mpreader.NextPart()
	if err != nil {
		return fmt.Errorf("failed to get next part of multipart message: %w", err)
	}
	for err == nil {
		mpdata, mperr := io.ReadAll(mpart)
		if mperr != nil {
			_ = mpart.Close()
			return fmt.Errorf("failed to read multipart: %w", err)
		}

		mpContentType, ok := mpart.Header[HeaderContentType.String()]
		if !ok {
			return fmt.Errorf("failed to get content-type from part")
		}
		conType, charSet := parseContentType(mpContentType[0])
		p := m.newPart(ContentType(conType))
		p.SetCharset(Charset(charSet))

		mpTransferEnc, ok := mpart.Header[HeaderContentTransferEnc.String()]
		if !ok {
			// If CTE is empty we can assume that it's a quoted-printable CTE since the
			// GO stdlib multipart packages deletes that header
			// See: https://cs.opensource.google/go/go/+/refs/tags/go1.22.0:src/mime/multipart/multipart.go;l=161
			mpTransferEnc = []string{EncodingQP.String()}
		}

		switch {
		case strings.EqualFold(mpTransferEnc[0], EncodingB64.String()):
			if err := handleEMLMultiPartBase64Encoding(mpdata, p); err != nil {
				return fmt.Errorf("failed to handle multipart base64 transfer-encoding: %w", err)
			}
		case strings.EqualFold(mpTransferEnc[0], EncodingQP.String()):
			p.SetContent(string(mpdata))
		default:
			return fmt.Errorf("unsupported Content-Transfer-Encoding")
		}

		m.parts = append(m.parts, p)
		mpart, err = mpreader.NextPart()
	}
	if !errors.Is(err, io.EOF) {
		_ = mpart.Close()
		return fmt.Errorf("failed to read multipart: %w", err)
	}
	return nil
}

// handleEMLMultiPartBase64Encoding sets the content body of a base64 encoded Part
func handleEMLMultiPartBase64Encoding(mpdata []byte, p *Part) error {
	p.SetEncoding(EncodingB64)
	cont, err := base64.StdEncoding.DecodeString(string(mpdata))
	if err != nil {
		return fmt.Errorf("failed to decode base64 part: %w", err)
	}
	p.SetContent(string(cont))
	return nil
}

// parseContentType parses the Content-Type header and returns the type and charse as
// separate string values
func parseContentType(cth string) (ct string, cs string) {
	cts := strings.SplitN(cth, "; ", 2)
	if len(cts) != 2 {
		return
	}
	ct = cts[0]
	if strings.HasPrefix(strings.ToLower(cts[1]), "charset=") {
		css := strings.SplitN(cts[1], "=", 2)
		if len(css) == 2 {
			cs = css[1]
		}
	}
	return
}
