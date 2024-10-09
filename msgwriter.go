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
	bytesWritten    int64
	charset         Charset
	depth           int8
	encoder         mime.WordEncoder
	err             error
	multiPartWriter [3]*multipart.Writer
	partWriter      io.Writer
	writer          io.Writer
}

// Write implements the io.Writer interface for msgWriter
func (mw *msgWriter) Write(payload []byte) (int, error) {
	if mw.err != nil {
		return 0, fmt.Errorf("failed to write due to previous error: %w", mw.err)
	}

	var n int
	n, mw.err = mw.writer.Write(payload)
	mw.bytesWritten += int64(n)
	return n, mw.err
}

// writeMsg formats the message and sends it to its io.Writer
func (mw *msgWriter) writeMsg(msg *Msg) {
	msg.addDefaultHeader()
	msg.checkUserAgent()
	mw.writeGenHeader(msg)
	mw.writePreformattedGenHeader(msg)

	// Set the FROM header (or envelope FROM if FROM is empty)
	hasFrom := true
	from, ok := msg.addrHeader[HeaderFrom]
	if !ok || (len(from) == 0 || from == nil) {
		from, ok = msg.addrHeader[HeaderEnvelopeFrom]
		if !ok || (len(from) == 0 || from == nil) {
			hasFrom = false
		}
	}
	if hasFrom && (len(from) > 0 && from[0] != nil) {
		mw.writeHeader(Header(HeaderFrom), from[0].String())
	}

	// Set the rest of the address headers
	for _, to := range []AddrHeader{HeaderTo, HeaderCc} {
		if addresses, ok := msg.addrHeader[to]; ok {
			var val []string
			for _, addr := range addresses {
				val = append(val, addr.String())
			}
			mw.writeHeader(Header(to), val...)
		}
	}

	if msg.hasSMime() {
		mw.startMP(MIMESMime, msg.boundary)
		mw.writeString(DoubleNewLine)
	}
	if msg.hasMixed() {
		mw.startMP(MIMEMixed, msg.boundary)
		mw.writeString(DoubleNewLine)
	}
	if msg.hasRelated() {
		mw.startMP(MIMERelated, msg.boundary)
		mw.writeString(DoubleNewLine)
	}
	if msg.hasAlt() {
		mw.startMP(MIMEAlternative, msg.boundary)
		mw.writeString(DoubleNewLine)
	}
	if msg.hasPGPType() {
		switch msg.pgptype {
		case PGPEncrypt:
			mw.startMP(`encrypted; protocol="application/pgp-encrypted"`,
				msg.boundary)
		case PGPSignature:
			mw.startMP(`signed; protocol="application/pgp-signature";`,
				msg.boundary)
		default:
		}
		mw.writeString(DoubleNewLine)
	}

	for _, part := range msg.parts {
		if !part.isDeleted {
			mw.writePart(part, msg.charset)
		}
	}

	if msg.hasAlt() {
		mw.stopMP()
	}

	// Add embeds
	mw.addFiles(msg.embeds, false)
	if msg.hasRelated() {
		mw.stopMP()
	}

	// Add attachments
	mw.addFiles(msg.attachments, true)
	if msg.hasMixed() {
		mw.stopMP()
	}

	if msg.hasSMime() {
		mw.stopMP()
	}
}

// writeGenHeader writes out all generic headers to the msgWriter
func (mw *msgWriter) writeGenHeader(msg *Msg) {
	keys := make([]string, 0, len(msg.genHeader))
	for key := range msg.genHeader {
		keys = append(keys, string(key))
	}
	sort.Strings(keys)
	for _, key := range keys {
		mw.writeHeader(Header(key), msg.genHeader[Header(key)]...)
	}
}

// writePreformatedHeader writes out all preformated generic headers to the msgWriter
func (mw *msgWriter) writePreformattedGenHeader(msg *Msg) {
	for key, val := range msg.preformHeader {
		mw.writeString(fmt.Sprintf("%s: %s%s", key, val, SingleNewLine))
	}
}

// startMP writes a multipart beginning
func (mw *msgWriter) startMP(mimeType MIMEType, boundary string) {
	multiPartWriter := multipart.NewWriter(mw)
	if boundary != "" {
		mw.err = multiPartWriter.SetBoundary(boundary)
	}

	contentType := fmt.Sprintf("multipart/%s;\r\n boundary=%s", mimeType,
		multiPartWriter.Boundary())
	mw.multiPartWriter[mw.depth] = multiPartWriter

	if mw.depth == 0 {
		mw.writeString(fmt.Sprintf("%s: %s", HeaderContentType, contentType))
	}
	if mw.depth > 0 {
		mw.newPart(map[string][]string{"Content-Type": {contentType}})
	}
	mw.depth++
}

// stopMP closes the multipart
func (mw *msgWriter) stopMP() {
	if mw.depth > 0 {
		mw.err = mw.multiPartWriter[mw.depth-1].Close()
		mw.depth--
	}
}

// addFiles adds the attachments/embeds file content to the mail body
func (mw *msgWriter) addFiles(files []*File, isAttachment bool) {
	for _, file := range files {
		encoding := EncodingB64
		if _, ok := file.getHeader(HeaderContentType); !ok {
			mimeType := mime.TypeByExtension(filepath.Ext(file.Name))
			if mimeType == "" {
				mimeType = "application/octet-stream"
			}
			if file.ContentType != "" {
				mimeType = string(file.ContentType)
			}
			file.setHeader(HeaderContentType, fmt.Sprintf(`%s; name="%s"`, mimeType,
				mw.encoder.Encode(mw.charset.String(), file.Name)))
		}

		if _, ok := file.getHeader(HeaderContentTransferEnc); !ok {
			if file.Enc != "" {
				encoding = file.Enc
			}
			file.setHeader(HeaderContentTransferEnc, string(encoding))
		}

		if file.Desc != "" {
			if _, ok := file.getHeader(HeaderContentDescription); !ok {
				file.setHeader(HeaderContentDescription, file.Desc)
			}
		}

		if _, ok := file.getHeader(HeaderContentDisposition); !ok {
			disposition := "inline"
			if isAttachment {
				disposition = "attachment"
			}
			file.setHeader(HeaderContentDisposition, fmt.Sprintf(`%s; filename="%s"`,
				disposition, mw.encoder.Encode(mw.charset.String(), file.Name)))
		}

		if !isAttachment {
			if _, ok := file.getHeader(HeaderContentID); !ok {
				file.setHeader(HeaderContentID, fmt.Sprintf("<%s>", file.Name))
			}
		}
		if mw.depth == 0 {
			for header, val := range file.Header {
				mw.writeHeader(Header(header), val...)
			}
			mw.writeString(SingleNewLine)
		}
		if mw.depth > 0 {
			mw.newPart(file.Header)
		}

		if mw.err == nil {
			mw.writeBody(file.Writer, encoding, false)
		}
	}
}

// newPart creates a new MIME multipart io.Writer and sets the partwriter to it
func (mw *msgWriter) newPart(header map[string][]string) {
	mw.partWriter, mw.err = mw.multiPartWriter[mw.depth-1].CreatePart(header)
}

// writePart writes the corresponding part to the Msg body
func (mw *msgWriter) writePart(part *Part, charset Charset) {
	partCharset := part.charset
	if partCharset.String() == "" {
		partCharset = charset
	}

	contentType := part.contentType.String()
	if !part.IsSMimeSigned() {
		contentType = strings.Join([]string{contentType, "; charset=", partCharset.String()}, "")
	}

	contentTransferEnc := part.encoding.String()
	if mw.depth == 0 {
		mw.writeHeader(HeaderContentType, contentType)
		mw.writeHeader(HeaderContentTransferEnc, contentTransferEnc)
		mw.writeString(SingleNewLine)
	}
	if mw.depth > 0 {
		mimeHeader := textproto.MIMEHeader{}
		if part.description != "" {
			mimeHeader.Add(string(HeaderContentDescription), part.description)
		}
		mimeHeader.Add(string(HeaderContentType), contentType)
		mimeHeader.Add(string(HeaderContentTransferEnc), contentTransferEnc)
		mw.newPart(mimeHeader)
	}
	mw.writeBody(part.writeFunc, part.encoding, part.smime)
}

// writeString writes a string into the msgWriter's io.Writer interface
func (mw *msgWriter) writeString(s string) {
	if mw.err != nil {
		return
	}
	var n int
	n, mw.err = io.WriteString(mw.writer, s)
	mw.bytesWritten += int64(n)
}

// writeHeader writes a header into the msgWriter's io.Writer
func (mw *msgWriter) writeHeader(key Header, values ...string) {
	buffer := strings.Builder{}
	charLength := MaxHeaderLength - 2
	buffer.WriteString(string(key))
	charLength -= len(key)
	if len(values) == 0 {
		buffer.WriteString(":\r\n")
		return
	}
	buffer.WriteString(": ")
	charLength -= 2

	fullValueStr := strings.Join(values, ", ")
	words := strings.Split(fullValueStr, " ")
	for i, val := range words {
		if charLength-len(val) <= 1 {
			buffer.WriteString(fmt.Sprintf("%s ", SingleNewLine))
			charLength = MaxHeaderLength - 3
		}
		buffer.WriteString(val)
		if i < len(words)-1 {
			buffer.WriteString(" ")
			charLength -= 1
		}
		charLength -= len(val)
	}

	bufferString := buffer.String()
	bufferString = strings.ReplaceAll(bufferString, fmt.Sprintf(" %s", SingleNewLine),
		SingleNewLine)
	mw.writeString(bufferString)
	mw.writeString("\r\n")
}

// writeBody writes an io.Reader into an io.Writer using provided Encoding
func (mw *msgWriter) writeBody(writeFunc func(io.Writer) (int64, error), encoding Encoding, singingWithSMime bool) {
	var writer io.Writer
	var encodedWriter io.WriteCloser
	var n int64
	var err error
	if mw.depth == 0 {
		writer = mw.writer
	}
	if mw.depth > 0 {
		writer = mw.partWriter
	}
	writeBuffer := bytes.Buffer{}
	lineBreaker := Base64LineBreaker{}
	lineBreaker.out = &writeBuffer

	if encoding == EncodingQP {
		encodedWriter = quotedprintable.NewWriter(&writeBuffer)
	} else if encoding == EncodingB64 && !singingWithSMime {
		encodedWriter = base64.NewEncoder(base64.StdEncoding, &lineBreaker)
	} else if encoding == NoEncoding || singingWithSMime {
		_, err = writeFunc(&writeBuffer)
		if err != nil {
			mw.err = fmt.Errorf("bodyWriter function: %w", err)
		}
		n, err = io.Copy(writer, &writeBuffer)
		if err != nil && mw.err == nil {
			mw.err = fmt.Errorf("bodyWriter io.Copy: %w", err)
		}
		if mw.depth == 0 {
			mw.bytesWritten += n
		}
		return
	} else {
		encodedWriter = quotedprintable.NewWriter(writer)
	}

	_, err = writeFunc(encodedWriter)
	if err != nil {
		mw.err = fmt.Errorf("bodyWriter function: %w", err)
	}
	err = encodedWriter.Close()
	if err != nil && mw.err == nil {
		mw.err = fmt.Errorf("bodyWriter close encoded writer: %w", err)
	}
	err = lineBreaker.Close()
	if err != nil && mw.err == nil {
		mw.err = fmt.Errorf("bodyWriter close linebreaker: %w", err)
	}
	n, err = io.Copy(writer, &writeBuffer)
	if err != nil && mw.err == nil {
		mw.err = fmt.Errorf("bodyWriter io.Copy: %w", err)
	}

	// Since the part writer uses the WriteTo() method, we don't need to add the
	// bytes twice
	if mw.depth == 0 {
		mw.bytesWritten += n
	}
}
