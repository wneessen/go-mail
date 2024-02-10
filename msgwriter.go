// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/textproto"
	"path/filepath"
	"sort"
	"strings"
)

// MaxHeaderLength defines the maximum line length for a mail header
// RFC 2047 suggests 76 characters
const MaxHeaderLength = 76

// MaxBodyLength defines the maximum line length for the mail body
// RFC 2047 suggests 76 characters
const MaxBodyLength = 76

// SingleNewLine represents a new line that can be used by the msgWriter to issue a carriage return
const SingleNewLine = "\r\n"

// DoubleNewLine represents a double new line that can be used by the msgWriter to
// indicate a new segement of the mail
const DoubleNewLine = "\r\n\r\n"

// msgWriter handles the I/O to the io.WriteCloser of the SMTP client
type msgWriter struct {
	c   Charset
	d   int8
	en  mime.WordEncoder
	err error
	mpw [3]*multipart.Writer
	n   int64
	pw  io.Writer
	w   io.Writer
}

// Write implements the io.Writer interface for msgWriter
func (mw *msgWriter) Write(p []byte) (int, error) {
	if mw.err != nil {
		return 0, fmt.Errorf("failed to write due to previous error: %w", mw.err)
	}

	var n int
	n, mw.err = mw.w.Write(p)
	mw.n += int64(n)
	return n, mw.err
}

// writeMsg formats the message and sends it to its io.Writer
func (mw *msgWriter) writeMsg(m *Msg) {
	m.addDefaultHeader()
	m.checkUserAgent()
	mw.writeGenHeader(m)
	mw.writePreformattedGenHeader(m)

	// Set the FROM header (or envelope FROM if FROM is empty)
	hf := true
	f, ok := m.addrHeader[HeaderFrom]
	if !ok || (len(f) == 0 || f == nil) {
		f, ok = m.addrHeader[HeaderEnvelopeFrom]
		if !ok || (len(f) == 0 || f == nil) {
			hf = false
		}
	}
	if hf && (len(f) > 0 && f[0] != nil) {
		mw.writeHeader(Header(HeaderFrom), f[0].String())
	}

	// Set the rest of the address headers
	for _, t := range []AddrHeader{HeaderTo, HeaderCc} {
		if al, ok := m.addrHeader[t]; ok {
			var v []string
			for _, a := range al {
				v = append(v, a.String())
			}
			mw.writeHeader(Header(t), v...)
		}
	}

	if m.hasMixed() {
		mw.startMP(MIMEMixed, m.boundary)
		mw.writeString(DoubleNewLine)
	}
	if m.hasRelated() {
		mw.startMP(MIMERelated, m.boundary)
		mw.writeString(DoubleNewLine)
	}
	if m.hasAlt() {
		mw.startMP(MIMEAlternative, m.boundary)
		mw.writeString(DoubleNewLine)
	}
	if m.hasPGPType() {
		switch m.pgptype {
		case PGPEncrypt:
			mw.startMP(`encrypted; protocol="application/pgp-encrypted"`, m.boundary)
		case PGPSignature:
			mw.startMP(`signed; protocol="application/pgp-signature";`, m.boundary)
		}
		mw.writeString(DoubleNewLine)
	}

	for _, p := range m.parts {
		if !p.del {
			mw.writePart(p, m.charset)
		}
	}

	if m.hasAlt() {
		mw.stopMP()
	}

	// Add embeds
	mw.addFiles(m.embeds, false)
	if m.hasRelated() {
		mw.stopMP()
	}

	// Add attachments
	mw.addFiles(m.attachments, true)
	if m.hasMixed() {
		mw.stopMP()
	}
}

// writeGenHeader writes out all generic headers to the msgWriter
func (mw *msgWriter) writeGenHeader(m *Msg) {
	gk := make([]string, 0, len(m.genHeader))
	for k := range m.genHeader {
		gk = append(gk, string(k))
	}
	sort.Strings(gk)
	for _, k := range gk {
		mw.writeHeader(Header(k), m.genHeader[Header(k)]...)
	}
}

// writePreformatedHeader writes out all preformated generic headers to the msgWriter
func (mw *msgWriter) writePreformattedGenHeader(m *Msg) {
	for k, v := range m.preformHeader {
		mw.writeString(fmt.Sprintf("%s: %s%s", k, v, SingleNewLine))
	}
}

// startMP writes a multipart beginning
func (mw *msgWriter) startMP(mt MIMEType, b string) {
	mp := multipart.NewWriter(mw)
	if b != "" {
		mw.err = mp.SetBoundary(b)
	}

	ct := fmt.Sprintf("multipart/%s;\r\n boundary=%s", mt, mp.Boundary())
	mw.mpw[mw.d] = mp

	if mw.d == 0 {
		mw.writeString(fmt.Sprintf("%s: %s", HeaderContentType, ct))
	}
	if mw.d > 0 {
		mw.newPart(map[string][]string{"Content-Type": {ct}})
	}
	mw.d++
}

// stopMP closes the multipart
func (mw *msgWriter) stopMP() {
	if mw.d > 0 {
		mw.err = mw.mpw[mw.d-1].Close()
		mw.d--
	}
}

// addFiles adds the attachments/embeds file content to the mail body
func (mw *msgWriter) addFiles(fl []*File, a bool) {
	for _, f := range fl {
		e := EncodingB64
		if _, ok := f.getHeader(HeaderContentType); !ok {
			mt := mime.TypeByExtension(filepath.Ext(f.Name))
			if mt == "" {
				mt = "application/octet-stream"
			}
			if f.ContentType != "" {
				mt = string(f.ContentType)
			}
			f.setHeader(HeaderContentType, fmt.Sprintf(`%s; name="%s"`, mt,
				mw.en.Encode(mw.c.String(), f.Name)))
		}

		if _, ok := f.getHeader(HeaderContentTransferEnc); !ok {
			if f.Enc != "" {
				e = f.Enc
			}
			f.setHeader(HeaderContentTransferEnc, string(e))
		}

		if f.Desc != "" {
			if _, ok := f.getHeader(HeaderContentDescription); !ok {
				f.setHeader(HeaderContentDescription, f.Desc)
			}
		}

		if _, ok := f.getHeader(HeaderContentDisposition); !ok {
			d := "inline"
			if a {
				d = "attachment"
			}
			f.setHeader(HeaderContentDisposition, fmt.Sprintf(`%s; filename="%s"`, d,
				mw.en.Encode(mw.c.String(), f.Name)))
		}

		if !a {
			if _, ok := f.getHeader(HeaderContentID); !ok {
				f.setHeader(HeaderContentID, fmt.Sprintf("<%s>", f.Name))
			}
		}
		if mw.d == 0 {
			for h, v := range f.Header {
				mw.writeHeader(Header(h), v...)
			}
			mw.writeString(SingleNewLine)
		}
		if mw.d > 0 {
			mw.newPart(f.Header)
		}

		if mw.err == nil {
			mw.writeBody(f.Writer, e)
		}
	}
}

// newPart creates a new MIME multipart io.Writer and sets the partwriter to it
func (mw *msgWriter) newPart(h map[string][]string) {
	mw.pw, mw.err = mw.mpw[mw.d-1].CreatePart(h)
}

// writePart writes the corresponding part to the Msg body
func (mw *msgWriter) writePart(p *Part, cs Charset) {
	pcs := p.cset
	if pcs.String() == "" {
		pcs = cs
	}
	ct := fmt.Sprintf("%s; charset=%s", p.ctype, pcs)
	cte := p.enc.String()
	if mw.d == 0 {
		mw.writeHeader(HeaderContentType, ct)
		mw.writeHeader(HeaderContentTransferEnc, cte)
		mw.writeString(SingleNewLine)
	}
	if mw.d > 0 {
		mh := textproto.MIMEHeader{}
		if p.desc != "" {
			mh.Add(string(HeaderContentDescription), p.desc)
		}
		mh.Add(string(HeaderContentType), ct)
		mh.Add(string(HeaderContentTransferEnc), cte)
		mw.newPart(mh)
	}
	mw.writeBody(p.w, p.enc)
}

// writeString writes a string into the msgWriter's io.Writer interface
func (mw *msgWriter) writeString(s string) {
	if mw.err != nil {
		return
	}
	var n int
	n, mw.err = io.WriteString(mw.w, s)
	mw.n += int64(n)
}

// writeHeader writes a header into the msgWriter's io.Writer
func (mw *msgWriter) writeHeader(k Header, vl ...string) {
	wbuf := bytes.Buffer{}
	cl := MaxHeaderLength - 2
	wbuf.WriteString(string(k))
	cl -= len(k)
	if len(vl) == 0 {
		wbuf.WriteString(":\r\n")
		return
	}
	wbuf.WriteString(": ")
	cl -= 2

	fs := strings.Join(vl, ", ")
	sfs := strings.Split(fs, " ")
	for i, v := range sfs {
		if cl-len(v) <= 1 {
			wbuf.WriteString(fmt.Sprintf("%s ", SingleNewLine))
			cl = MaxHeaderLength - 3
		}
		wbuf.WriteString(v)
		if i < len(sfs)-1 {
			wbuf.WriteString(" ")
			cl -= 1
		}
		cl -= len(v)
	}

	bufs := wbuf.String()
	bufs = strings.ReplaceAll(bufs, fmt.Sprintf(" %s", SingleNewLine), SingleNewLine)
	mw.writeString(bufs)
	mw.writeString("\r\n")
}

// writeBody writes an io.Reader into an io.Writer using provided Encoding
func (mw *msgWriter) writeBody(f func(io.Writer) (int64, error), e Encoding) {
	var w io.Writer
	var ew io.WriteCloser
	var n int64
	var err error
	if mw.d == 0 {
		w = mw.w
	}
	if mw.d > 0 {
		w = mw.pw
	}
	wbuf := bytes.Buffer{}
	lb := Base64LineBreaker{}
	lb.out = &wbuf

	switch e {
	case EncodingQP:
		ew = quotedprintable.NewWriter(&wbuf)
	case EncodingB64:
		ew = base64.NewEncoder(base64.StdEncoding, &lb)
	case NoEncoding:
		_, err = f(&wbuf)
		if err != nil {
			mw.err = fmt.Errorf("bodyWriter function: %w", err)
		}
		n, err = io.Copy(w, &wbuf)
		if err != nil && mw.err == nil {
			mw.err = fmt.Errorf("bodyWriter io.Copy: %w", err)
		}
		if mw.d == 0 {
			mw.n += n
		}
		return
	default:
		ew = quotedprintable.NewWriter(w)
	}

	_, err = f(ew)
	if err != nil {
		mw.err = fmt.Errorf("bodyWriter function: %w", err)
	}
	err = ew.Close()
	if err != nil && mw.err == nil {
		mw.err = fmt.Errorf("bodyWriter close encoded writer: %w", err)
	}
	err = lb.Close()
	if err != nil && mw.err == nil {
		mw.err = fmt.Errorf("bodyWriter close linebreaker: %w", err)
	}
	n, err = io.Copy(w, &wbuf)
	if err != nil && mw.err == nil {
		mw.err = fmt.Errorf("bodyWriter io.Copy: %w", err)
	}

	// Since the part writer uses the WriteTo() method, we don't need to add the
	// bytes twice
	if mw.d == 0 {
		mw.n += n
	}
}
