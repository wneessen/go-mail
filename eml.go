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

	pm, mbbuf, err := readEMLFromReader(r)
	if err != nil || pm == nil {
		return m, fmt.Errorf("failed to parse EML from reader: %w", err)
	}

	if err = parseEMLHeaders(&pm.Header, m); err != nil {
		return m, fmt.Errorf("failed to parse EML headers: %w", err)
	}
	if err = parseEMLBodyParts(pm, mbbuf, m); err != nil {
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

	pm, mbbuf, err := readEML(fp)
	if err != nil || pm == nil {
		return m, fmt.Errorf("failed to parse EML file: %w", err)
	}

	if err = parseEMLHeaders(&pm.Header, m); err != nil {
		return m, fmt.Errorf("failed to parse EML headers: %w", err)
	}
	if err = parseEMLBodyParts(pm, mbbuf, m); err != nil {
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
func parseEMLBodyParts(pm *nm.Message, mbbuf *bytes.Buffer, m *Msg) error {
	// Extract the transfer encoding of the body
	mt, par, err := mime.ParseMediaType(pm.Header.Get(HeaderContentType.String()))
	if err != nil {
		return fmt.Errorf("failed to extract content type: %w", err)
	}
	if v, ok := par["charset"]; ok {
		m.SetCharset(Charset(v))
	}

	cte := pm.Header.Get(HeaderContentTransferEnc.String())
	switch strings.ToLower(mt) {
	case TypeTextPlain.String():
		if strings.EqualFold(cte, NoEncoding.String()) {
			m.SetEncoding(NoEncoding)
			m.SetBodyString(TypeTextPlain, mbbuf.String())
			break
		}
		if strings.EqualFold(cte, EncodingQP.String()) {
			m.SetEncoding(EncodingQP)
			qpr := quotedprintable.NewReader(mbbuf)
			qpbuf := bytes.Buffer{}
			if _, err = qpbuf.ReadFrom(qpr); err != nil {
				return fmt.Errorf("failed to read quoted-printable body: %w", err)
			}
			m.SetBodyString(TypeTextPlain, qpbuf.String())
			break
		}
		if strings.EqualFold(cte, EncodingB64.String()) {
			m.SetEncoding(EncodingB64)
			b64d := base64.NewDecoder(base64.StdEncoding, mbbuf)
			b64buf := bytes.Buffer{}
			if _, err = b64buf.ReadFrom(b64d); err != nil {
				return fmt.Errorf("failed to read base64 body: %w", err)
			}
			m.SetBodyString(TypeTextPlain, b64buf.String())
			break
		}
	case TypeMultipartAlternative.String():
		// TODO: Refactor in its own function
		b, ok := par["boundary"]
		if !ok {
			return fmt.Errorf("no boundary tag found in multipart body")
		}
		mpr := multipart.NewReader(mbbuf, b)
		mp, err := mpr.NextPart()
		if err != nil {
			return fmt.Errorf("failed to get next part of multipart message: %w", err)
		}
		for err == nil {
			// TODO: Clean up code
			mpd, mperr := io.ReadAll(mp)
			if mperr != nil {
				_ = mp.Close()
				return fmt.Errorf("failed to read multipart: %w", err)
			}
			mpctc, ok := mp.Header[HeaderContentType.String()]
			if !ok {
				return fmt.Errorf("failed to get content-type from part")
			}
			mpcts := strings.Split(mpctc[0], "; ")
			if len(mpcts) > 1 && strings.HasPrefix(strings.ToLower(mpcts[1]), "charset=") {
				vs := strings.Split(mpcts[1], "=")
				if len(vs) > 1 {
					// TODO: We probably want per-part charset instead
					m.SetCharset(Charset(vs[1]))
				}
			}
			mpcte, ok := mp.Header[HeaderContentTransferEnc.String()]
			if !ok {
				return fmt.Errorf("failed to get content-transfer-encoding from part")
			}
			m.SetCharset(Charset(mpcts[1]))
			p := m.newPart(ContentType(mpcts[0]))
			switch {
			case strings.EqualFold(mpcte[0], EncodingB64.String()):
				p.SetEncoding(EncodingB64)
				cont, err := base64.StdEncoding.DecodeString(string(mpd))
				if err != nil {
					return fmt.Errorf("failed to decode base64 part: %w", err)
				}
				p.SetContent(string(cont))
			}
			m.parts = append(m.parts, p)
			mp, err = mpr.NextPart()
		}
		if err != io.EOF {
			_ = mp.Close()
			return fmt.Errorf("failed to read multipart: %w", err)
		}

	default:
	}
	return nil
}
