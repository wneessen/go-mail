// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"io"
)

// PartOption returns a function that can be used for grouping Part options
type PartOption func(*Part)

// Part is a part of the Msg
type Part struct {
	contentType ContentType
	charset     Charset
	description string
	encoding    Encoding
	isDeleted   bool
	writeFunc   func(io.Writer) (int64, error)
	smime       bool
}

// GetContent executes the WriteFunc of the Part and returns the content as byte slice
func (p *Part) GetContent() ([]byte, error) {
	var b bytes.Buffer
	if _, err := p.writeFunc(&b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// GetCharset returns the currently set Charset of the Part
func (p *Part) GetCharset() Charset {
	return p.charset
}

// GetContentType returns the currently set ContentType of the Part
func (p *Part) GetContentType() ContentType {
	return p.contentType
}

// GetEncoding returns the currently set Encoding of the Part
func (p *Part) GetEncoding() Encoding {
	return p.encoding
}

// GetWriteFunc returns the currently set WriterFunc of the Part
func (p *Part) GetWriteFunc() func(io.Writer) (int64, error) {
	return p.writeFunc
}

// GetDescription returns the currently set Content-Description of the Part
func (p *Part) GetDescription() string {
	return p.description
}

// IsSMimeSigned returns true if the Part should be singed with S/MIME
func (p *Part) IsSMimeSigned() bool {
	return p.smime
}

// SetContent overrides the content of the Part with the given string
func (p *Part) SetContent(content string) {
	buffer := bytes.NewBufferString(content)
	p.writeFunc = writeFuncFromBuffer(buffer)
}

// SetContentType overrides the ContentType of the Part
func (p *Part) SetContentType(contentType ContentType) {
	p.contentType = contentType
}

// SetCharset overrides the Charset of the Part
func (p *Part) SetCharset(charset Charset) {
	p.charset = charset
}

// SetEncoding creates a new mime.WordEncoder based on the encoding setting of the message
func (p *Part) SetEncoding(encoding Encoding) {
	p.encoding = encoding
}

// SetDescription overrides the Content-Description of the Part
func (p *Part) SetDescription(description string) {
	p.description = description
}

// SetIsSMimeSigned sets the flag for signing the Part with S/MIME
func (p *Part) SetIsSMimeSigned(smime bool) {
	p.smime = smime
}

// SetWriteFunc overrides the WriteFunc of the Part
func (p *Part) SetWriteFunc(writeFunc func(io.Writer) (int64, error)) {
	p.writeFunc = writeFunc
}

// Delete removes the current part from the parts list of the Msg by setting the
// isDeleted flag to true. The msgWriter will skip it then
func (p *Part) Delete() {
	p.isDeleted = true
}

// WithPartCharset overrides the default Part charset
func WithPartCharset(charset Charset) PartOption {
	return func(p *Part) {
		p.charset = charset
	}
}

// WithPartEncoding overrides the default Part encoding
func WithPartEncoding(encoding Encoding) PartOption {
	return func(p *Part) {
		p.encoding = encoding
	}
}

// WithPartContentDescription overrides the default Part Content-Description
func WithPartContentDescription(description string) PartOption {
	return func(p *Part) {
		p.description = description
	}
}

// WithSMimeSinging overrides the flag for signing the Part with S/MIME
func WithSMimeSinging() PartOption {
	return func(p *Part) {
		p.smime = true
	}
}
