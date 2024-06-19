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
	netmail "net/mail"
	"os"
	"strings"
)

// EMLToMsgFromString will parse a given EML string and returns a pre-filled Msg pointer
func EMLToMsgFromString(emlString string) (*Msg, error) {
	eb := bytes.NewBufferString(emlString)
	return EMLToMsgFromReader(eb)
}

// EMLToMsgFromReader will parse a reader that holds EML content and returns a pre-filled
// Msg pointer
func EMLToMsgFromReader(reader io.Reader) (*Msg, error) {
	msg := &Msg{
		addrHeader:    make(map[AddrHeader][]*netmail.Address),
		genHeader:     make(map[Header][]string),
		preformHeader: make(map[Header]string),
		mimever:       MIME10,
	}

	parsedMsg, bodybuf, err := readEMLFromReader(reader)
	if err != nil || parsedMsg == nil {
		return msg, fmt.Errorf("failed to parse EML from reader: %w", err)
	}

	if err = parseEMLHeaders(&parsedMsg.Header, msg); err != nil {
		return msg, fmt.Errorf("failed to parse EML headers: %w", err)
	}
	if err = parseEMLBodyParts(parsedMsg, bodybuf, msg); err != nil {
		return msg, fmt.Errorf("failed to parse EML body parts: %w", err)
	}

	return msg, nil
}

// EMLToMsgFromFile will open and parse a .eml file at a provided file path and returns a
// pre-filled Msg pointer
func EMLToMsgFromFile(filePath string) (*Msg, error) {
	msg := &Msg{
		addrHeader:    make(map[AddrHeader][]*netmail.Address),
		genHeader:     make(map[Header][]string),
		preformHeader: make(map[Header]string),
		mimever:       MIME10,
	}

	parsedMsg, bodybuf, err := readEML(filePath)
	if err != nil || parsedMsg == nil {
		return msg, fmt.Errorf("failed to parse EML file: %w", err)
	}

	if err = parseEMLHeaders(&parsedMsg.Header, msg); err != nil {
		return msg, fmt.Errorf("failed to parse EML headers: %w", err)
	}
	if err = parseEMLBodyParts(parsedMsg, bodybuf, msg); err != nil {
		return msg, fmt.Errorf("failed to parse EML body parts: %w", err)
	}

	return msg, nil
}

// readEML opens an EML file and uses net/mail to parse the header and body
func readEML(filePath string) (*netmail.Message, *bytes.Buffer, error) {
	fileHandle, err := os.Open(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open EML file: %w", err)
	}
	defer func() {
		_ = fileHandle.Close()
	}()
	return readEMLFromReader(fileHandle)
}

// readEMLFromReader uses net/mail to parse the header and body from a given io.Reader
func readEMLFromReader(reader io.Reader) (*netmail.Message, *bytes.Buffer, error) {
	parsedMsg, err := netmail.ReadMessage(reader)
	if err != nil {
		return parsedMsg, nil, fmt.Errorf("failed to parse EML: %w", err)
	}

	buf := bytes.Buffer{}
	if _, err = buf.ReadFrom(parsedMsg.Body); err != nil {
		return nil, nil, err
	}

	return parsedMsg, &buf, nil
}

// parseEMLHeaders will check the EML headers for the most common headers and set the
// according settings in the Msg
func parseEMLHeaders(mailHeader *netmail.Header, msg *Msg) error {
	commonHeaders := []Header{
		HeaderContentType, HeaderImportance, HeaderInReplyTo, HeaderListUnsubscribe,
		HeaderListUnsubscribePost, HeaderMessageID, HeaderMIMEVersion, HeaderOrganization,
		HeaderPrecedence, HeaderPriority, HeaderReferences, HeaderSubject, HeaderUserAgent,
		HeaderXMailer, HeaderXMSMailPriority, HeaderXPriority,
	}

	// Extract content type, charset and encoding first
	parseEMLEncoding(mailHeader, msg)
	parseEMLContentTypeCharset(mailHeader, msg)

	// Extract address headers
	if value := mailHeader.Get(HeaderFrom.String()); value != "" {
		if err := msg.From(value); err != nil {
			return fmt.Errorf(`failed to parse %q header: %w`, HeaderFrom, err)
		}
	}
	addrHeaders := map[AddrHeader]func(...string) error{
		HeaderTo:  msg.To,
		HeaderCc:  msg.Cc,
		HeaderBcc: msg.Bcc,
	}
	for addrHeader, addrFunc := range addrHeaders {
		if v := mailHeader.Get(addrHeader.String()); v != "" {
			var addrStrings []string
			parsedAddrs, err := netmail.ParseAddressList(v)
			if err != nil {
				return fmt.Errorf(`failed to parse address list: %w`, err)
			}
			for _, addr := range parsedAddrs {
				addrStrings = append(addrStrings, addr.String())
			}
			if err = addrFunc(addrStrings...); err != nil {
				return fmt.Errorf(`failed to parse %q header: %w`, HeaderTo, err)
			}
		}
	}

	// Extract date from message
	date, err := mailHeader.Date()
	if err != nil {
		switch {
		case errors.Is(err, netmail.ErrHeaderNotPresent):
			msg.SetDate()
		default:
			return fmt.Errorf("failed to parse EML date: %w", err)
		}
	}
	if err == nil {
		msg.SetDateWithValue(date)
	}

	// Extract common headers
	for _, header := range commonHeaders {
		if value := mailHeader.Get(header.String()); value != "" {
			msg.SetGenHeader(header, value)
		}
	}

	return nil
}

// parseEMLBodyParts parses the body of a EML based on the different content types and encodings
func parseEMLBodyParts(parsedMsg *netmail.Message, bodybuf *bytes.Buffer, msg *Msg) error {
	// Extract the transfer encoding of the body
	mediatype, params, err := mime.ParseMediaType(parsedMsg.Header.Get(HeaderContentType.String()))
	if err != nil {
		return fmt.Errorf("failed to extract content type: %w", err)
	}
	if value, ok := params["charset"]; ok {
		msg.SetCharset(Charset(value))
	}

	switch {
	case strings.EqualFold(mediatype, TypeTextPlain.String()),
		strings.EqualFold(mediatype, TypeTextHTML.String()):
		if err = parseEMLBodyPlain(mediatype, parsedMsg, bodybuf, msg); err != nil {
			return fmt.Errorf("failed to parse plain body: %w", err)
		}
	case strings.EqualFold(mediatype, TypeMultipartAlternative.String()),
		strings.EqualFold(mediatype, TypeMultipartMixed.String()):
		if err = parseEMLMultipart(params, bodybuf, msg); err != nil {
			return fmt.Errorf("failed to parse multipart/alternative body: %w", err)
		}
	default:
	}
	return nil
}

// parseEMLBodyPlain parses the mail body of plain type mails
func parseEMLBodyPlain(mediatype string, parsedMsg *netmail.Message, bodybuf *bytes.Buffer, msg *Msg) error {
	contentTransferEnc := parsedMsg.Header.Get(HeaderContentTransferEnc.String())
	if strings.EqualFold(contentTransferEnc, NoEncoding.String()) {
		msg.SetEncoding(NoEncoding)
		msg.SetBodyString(ContentType(mediatype), bodybuf.String())
		return nil
	}
	if strings.EqualFold(contentTransferEnc, EncodingQP.String()) {
		msg.SetEncoding(EncodingQP)
		qpReader := quotedprintable.NewReader(bodybuf)
		qpBuffer := bytes.Buffer{}
		if _, err := qpBuffer.ReadFrom(qpReader); err != nil {
			return fmt.Errorf("failed to read quoted-printable body: %w", err)
		}
		msg.SetBodyString(ContentType(mediatype), qpBuffer.String())
		return nil
	}
	if strings.EqualFold(contentTransferEnc, EncodingB64.String()) {
		msg.SetEncoding(EncodingB64)
		b64Decoder := base64.NewDecoder(base64.StdEncoding, bodybuf)
		b64Buffer := bytes.Buffer{}
		if _, err := b64Buffer.ReadFrom(b64Decoder); err != nil {
			return fmt.Errorf("failed to read base64 body: %w", err)
		}
		msg.SetBodyString(ContentType(mediatype), b64Buffer.String())
		return nil
	}
	return fmt.Errorf("unsupported Content-Transfer-Encoding")
}

// parseEMLMultipart parses a multipart body part of a EML
func parseEMLMultipart(params map[string]string, bodybuf *bytes.Buffer, msg *Msg) error {
	boundary, ok := params["boundary"]
	if !ok {
		return fmt.Errorf("no boundary tag found in multipart body")
	}
	multipartReader := multipart.NewReader(bodybuf, boundary)
	multiPart, err := multipartReader.NextPart()
	if err != nil {
		return fmt.Errorf("failed to get next part of multipart message: %w", err)
	}
	for err == nil {
		if contentDisposition, ok := multiPart.Header[HeaderContentDisposition.String()]; ok {
			cdType, optional := parseMultiPartHeader(contentDisposition[0])
			fmt.Println("CTD:", cdType)
			fmt.Printf("optional: %+v\n", optional)
			if err = msg.AttachReader("", multiPart); err != nil {
				return fmt.Errorf("failed to attach multipart body: %w", err)
			}
			return nil
		}

		multiPartData, mperr := io.ReadAll(multiPart)
		if mperr != nil {
			_ = multiPart.Close()
			return fmt.Errorf("failed to read multipart: %w", err)
		}

		multiPartContentType, ok := multiPart.Header[HeaderContentType.String()]
		if !ok {
			return fmt.Errorf("failed to get content-type from part")
		}
		contentType, optional := parseMultiPartHeader(multiPartContentType[0])
		part := msg.newPart(ContentType(contentType))
		if charset, ok := optional["charset"]; ok {
			part.SetCharset(Charset(charset))
		}

		mutliPartTransferEnc, ok := multiPart.Header[HeaderContentTransferEnc.String()]
		if !ok {
			// If CTE is empty we can assume that it's a quoted-printable CTE since the
			// GO stdlib multipart packages deletes that header
			// See: https://cs.opensource.google/go/go/+/refs/tags/go1.22.0:src/mime/multipart/multipart.go;l=161
			mutliPartTransferEnc = []string{EncodingQP.String()}
		}

		switch {
		case strings.EqualFold(mutliPartTransferEnc[0], EncodingB64.String()):
			if err := handleEMLMultiPartBase64Encoding(multiPartData, part); err != nil {
				return fmt.Errorf("failed to handle multipart base64 transfer-encoding: %w", err)
			}
		case strings.EqualFold(mutliPartTransferEnc[0], EncodingQP.String()):
			part.SetContent(string(multiPartData))
		default:
			return fmt.Errorf("unsupported Content-Transfer-Encoding")
		}

		msg.parts = append(msg.parts, part)
		multiPart, err = multipartReader.NextPart()
	}
	if !errors.Is(err, io.EOF) {
		_ = multiPart.Close()
		return fmt.Errorf("failed to read multipart: %w", err)
	}
	return nil
}

// parseEMLEncoding parses and determines the encoding of the message
func parseEMLEncoding(mailHeader *netmail.Header, msg *Msg) {
	if value := mailHeader.Get(HeaderContentTransferEnc.String()); value != "" {
		switch {
		case strings.EqualFold(value, EncodingQP.String()):
			msg.SetEncoding(EncodingQP)
		case strings.EqualFold(value, EncodingB64.String()):
			msg.SetEncoding(EncodingB64)
		default:
			msg.SetEncoding(NoEncoding)
		}
	}
}

// parseEMLContentTypeCharset parses and determines the charset and content type of the message
func parseEMLContentTypeCharset(mailHeader *netmail.Header, msg *Msg) {
	if value := mailHeader.Get(HeaderContentType.String()); value != "" {
		contentType, optional := parseMultiPartHeader(value)
		if charset, ok := optional["charset"]; ok {
			msg.SetCharset(Charset(charset))
		}
		msg.setEncoder()
		if contentType != "" {
			msg.SetGenHeader(HeaderContentType, contentType)
		}
	}
}

// handleEMLMultiPartBase64Encoding sets the content body of a base64 encoded Part
func handleEMLMultiPartBase64Encoding(multiPartData []byte, part *Part) error {
	part.SetEncoding(EncodingB64)
	content, err := base64.StdEncoding.DecodeString(string(multiPartData))
	if err != nil {
		return fmt.Errorf("failed to decode base64 part: %w", err)
	}
	part.SetContent(string(content))
	return nil
}

// parseMultiPartHeader parses a multipart header and returns the value and optional parts as
// separate map
func parseMultiPartHeader(multiPartHeader string) (header string, optional map[string]string) {
	optional = make(map[string]string)
	headerSplit := strings.SplitN(multiPartHeader, "; ", 2)
	header = headerSplit[0]
	if len(headerSplit) == 2 {
		optSplit := strings.SplitN(headerSplit[1], "=", 2)
		if len(optSplit) == 2 {
			optional[optSplit[0]] = optSplit[1]
		}
	}
	return
}
