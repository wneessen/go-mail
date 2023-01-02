// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	ht "html/template"
	"io"
	"mime"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	tt "text/template"
	"time"
)

var (
	// ErrNoFromAddress should be used when a FROM address is requrested but not set
	ErrNoFromAddress = errors.New("no FROM address set")

	// ErrNoRcptAddresses should be used when the list of RCPTs is empty
	ErrNoRcptAddresses = errors.New("no recipient addresses set")
)

const (
	// errTplExecuteFailed is issued when the template execution was not successful
	errTplExecuteFailed = "failed to execute template: %w"

	// errTplPointerNil is issued when a template pointer is expected but it is nil
	errTplPointerNil = "template pointer is nil"

	// errParseMailAddr is used when a mail address could not be validated
	errParseMailAddr = "failed to parse mail address %q: %w"
)

// MiddlewareType is the type description of the Middleware and needs to be returned
// in the Middleware interface by the Type method
type MiddlewareType string

// Middleware is an interface to define a function to apply to Msg before sending
type Middleware interface {
	Handle(*Msg) *Msg
	Type() MiddlewareType
}

// Msg is the mail message struct
type Msg struct {
	// addrHeader is a slice of strings that the different mail AddrHeader fields
	addrHeader map[AddrHeader][]*mail.Address

	// attachments represent the different attachment File of the Msg
	attachments []*File

	// boundary is the MIME content boundary
	boundary string

	// charset represents the charset of the mail (defaults to UTF-8)
	charset Charset

	// embeds represent the different embedded File of the Msg
	embeds []*File

	// encoder represents a mime.WordEncoder from the std lib
	encoder mime.WordEncoder

	// encoding represents the message encoding (the encoder will be a corresponding WordEncoder)
	encoding Encoding

	// genHeader is a slice of strings that the different generic mail Header fields
	genHeader map[Header][]string

	// preformHeader is a slice of strings that the different generic mail Header fields
	// of which content is already preformated and will not be affected by the automatic line
	// breaks
	preformHeader map[Header]string

	// mimever represents the MIME version
	mimever MIMEVersion

	// parts represent the different parts of the Msg
	parts []*Part

	// middlewares is the list of middlewares to apply to the Msg before sending in FIFO order
	middlewares []Middleware

	// sendError holds the SendError in case a Msg could not be delivered during the Client.Send operation
	sendError error
}

// SendmailPath is the default system path to the sendmail binary
const SendmailPath = "/usr/sbin/sendmail"

// MsgOption returns a function that can be used for grouping Msg options
type MsgOption func(*Msg)

// NewMsg returns a new Msg pointer
func NewMsg(o ...MsgOption) *Msg {
	m := &Msg{
		addrHeader:    make(map[AddrHeader][]*mail.Address),
		charset:       CharsetUTF8,
		encoding:      EncodingQP,
		genHeader:     make(map[Header][]string),
		preformHeader: make(map[Header]string),
		mimever:       Mime10,
	}

	// Override defaults with optionally provided MsgOption functions
	for _, co := range o {
		if co == nil {
			continue
		}
		co(m)
	}

	// Set the matcing mime.WordEncoder for the Msg
	m.setEncoder()

	return m
}

// WithCharset overrides the default message charset
func WithCharset(c Charset) MsgOption {
	return func(m *Msg) {
		m.charset = c
	}
}

// WithEncoding overrides the default message encoding
func WithEncoding(e Encoding) MsgOption {
	return func(m *Msg) {
		m.encoding = e
	}
}

// WithMIMEVersion overrides the default MIME version
func WithMIMEVersion(mv MIMEVersion) MsgOption {
	return func(m *Msg) {
		m.mimever = mv
	}
}

// WithBoundary overrides the default MIME boundary
func WithBoundary(b string) MsgOption {
	return func(m *Msg) {
		m.boundary = b
	}
}

// WithMiddleware add the given middleware in the end of the list of the client middlewares
func WithMiddleware(mw Middleware) MsgOption {
	return func(m *Msg) {
		m.middlewares = append(m.middlewares, mw)
	}
}

// SetCharset sets the encoding charset of the Msg
func (m *Msg) SetCharset(c Charset) {
	m.charset = c
}

// SetEncoding sets the encoding of the Msg
func (m *Msg) SetEncoding(e Encoding) {
	m.encoding = e
	m.setEncoder()
}

// SetBoundary sets the boundary of the Msg
func (m *Msg) SetBoundary(b string) {
	m.boundary = b
}

// SetMIMEVersion sets the MIME version of the Msg
func (m *Msg) SetMIMEVersion(mv MIMEVersion) {
	m.mimever = mv
}

// Encoding returns the currently set encoding of the Msg
func (m *Msg) Encoding() string {
	return m.encoding.String()
}

// Charset returns the currently set charset of the Msg
func (m *Msg) Charset() string {
	return m.charset.String()
}

// SetHeader sets a generic header field of the Msg
// For adding address headers like "To:" or "From", see SetAddrHeader
//
// Deprecated: This method only exists for compatibility reason. Please use SetGenHeader instead
func (m *Msg) SetHeader(h Header, v ...string) {
	m.SetGenHeader(h, v...)
}

// SetGenHeader sets a generic header field of the Msg
// For adding address headers like "To:" or "From", see SetAddrHeader
func (m *Msg) SetGenHeader(h Header, v ...string) {
	if m.genHeader == nil {
		m.genHeader = make(map[Header][]string)
	}
	for i, hv := range v {
		v[i] = m.encodeString(hv)
	}
	m.genHeader[h] = v
}

// SetHeaderPreformatted sets a generic header field of the Msg which content is
// already preformated.
//
// Deprecated: This method only exists for compatibility reason. Please use
// SetGenHeaderPreformatted instead
func (m *Msg) SetHeaderPreformatted(h Header, v string) {
	m.SetGenHeaderPreformatted(h, v)
}

// SetGenHeaderPreformatted sets a generic header field of the Msg which content is
// already preformated.
//
// This method does not take a slice of values but only a single value. This is
// due to the fact, that we do not perform any content alteration and expect the
// user has already done so
//
// **Please note:** This method should be used only as a last resort. Since the
// user is respondible for the formating of the message header, go-mail cannot
// guarantee the fully compliance with the RFC 2822. It is recommended to use
// SetGenHeader instead.
func (m *Msg) SetGenHeaderPreformatted(h Header, v string) {
	if m.preformHeader == nil {
		m.preformHeader = make(map[Header]string)
	}
	m.preformHeader[h] = v
}

// SetAddrHeader sets an address related header field of the Msg
func (m *Msg) SetAddrHeader(h AddrHeader, v ...string) error {
	if m.addrHeader == nil {
		m.addrHeader = make(map[AddrHeader][]*mail.Address)
	}
	var al []*mail.Address
	for _, av := range v {
		a, err := mail.ParseAddress(av)
		if err != nil {
			return fmt.Errorf(errParseMailAddr, av, err)
		}
		al = append(al, a)
	}
	switch h {
	case HeaderFrom:
		m.addrHeader[h] = []*mail.Address{al[0]}
	default:
		m.addrHeader[h] = al
	}
	return nil
}

// SetAddrHeaderIgnoreInvalid sets an address related header field of the Msg and ignores invalid address
// in the validation process
func (m *Msg) SetAddrHeaderIgnoreInvalid(h AddrHeader, v ...string) {
	var al []*mail.Address
	for _, av := range v {
		a, err := mail.ParseAddress(m.encodeString(av))
		if err != nil {
			continue
		}
		al = append(al, a)
	}
	m.addrHeader[h] = al
}

// EnvelopeFrom takes and validates a given mail address and sets it as envelope "FROM"
// addrHeader of the Msg
func (m *Msg) EnvelopeFrom(f string) error {
	return m.SetAddrHeader(HeaderEnvelopeFrom, f)
}

// EnvelopeFromFormat takes a name and address, formats them RFC5322 compliant and stores them as
// the envelope FROM address header field
func (m *Msg) EnvelopeFromFormat(n, a string) error {
	return m.SetAddrHeader(HeaderEnvelopeFrom, fmt.Sprintf(`"%s" <%s>`, n, a))
}

// From takes and validates a given mail address and sets it as "From" genHeader of the Msg
func (m *Msg) From(f string) error {
	return m.SetAddrHeader(HeaderFrom, f)
}

// FromFormat takes a name and address, formats them RFC5322 compliant and stores them as
// the From address header field
func (m *Msg) FromFormat(n, a string) error {
	return m.SetAddrHeader(HeaderFrom, fmt.Sprintf(`"%s" <%s>`, n, a))
}

// To takes and validates a given mail address list sets the To: addresses of the Msg
func (m *Msg) To(t ...string) error {
	return m.SetAddrHeader(HeaderTo, t...)
}

// AddTo adds an additional address to the To address header field
func (m *Msg) AddTo(t string) error {
	return m.addAddr(HeaderTo, t)
}

// AddToFormat takes a name and address, formats them RFC5322 compliant and stores them as
// as additional To address header field
func (m *Msg) AddToFormat(n, a string) error {
	return m.addAddr(HeaderTo, fmt.Sprintf(`"%s" <%s>`, n, a))
}

// ToIgnoreInvalid takes and validates a given mail address list sets the To: addresses of the Msg
// Any provided address that is not RFC5322 compliant, will be ignored
func (m *Msg) ToIgnoreInvalid(t ...string) {
	m.SetAddrHeaderIgnoreInvalid(HeaderTo, t...)
}

// Cc takes and validates a given mail address list sets the Cc: addresses of the Msg
func (m *Msg) Cc(c ...string) error {
	return m.SetAddrHeader(HeaderCc, c...)
}

// AddCc adds an additional address to the Cc address header field
func (m *Msg) AddCc(t string) error {
	return m.addAddr(HeaderCc, t)
}

// AddCcFormat takes a name and address, formats them RFC5322 compliant and stores them as
// as additional Cc address header field
func (m *Msg) AddCcFormat(n, a string) error {
	return m.addAddr(HeaderCc, fmt.Sprintf(`"%s" <%s>`, n, a))
}

// CcIgnoreInvalid takes and validates a given mail address list sets the Cc: addresses of the Msg
// Any provided address that is not RFC5322 compliant, will be ignored
func (m *Msg) CcIgnoreInvalid(c ...string) {
	m.SetAddrHeaderIgnoreInvalid(HeaderCc, c...)
}

// Bcc takes and validates a given mail address list sets the Bcc: addresses of the Msg
func (m *Msg) Bcc(b ...string) error {
	return m.SetAddrHeader(HeaderBcc, b...)
}

// AddBcc adds an additional address to the Bcc address header field
func (m *Msg) AddBcc(t string) error {
	return m.addAddr(HeaderBcc, t)
}

// AddBccFormat takes a name and address, formats them RFC5322 compliant and stores them as
// as additional Bcc address header field
func (m *Msg) AddBccFormat(n, a string) error {
	return m.addAddr(HeaderBcc, fmt.Sprintf(`"%s" <%s>`, n, a))
}

// BccIgnoreInvalid takes and validates a given mail address list sets the Bcc: addresses of the Msg
// Any provided address that is not RFC5322 compliant, will be ignored
func (m *Msg) BccIgnoreInvalid(b ...string) {
	m.SetAddrHeaderIgnoreInvalid(HeaderBcc, b...)
}

// ReplyTo takes and validates a given mail address and sets it as "Reply-To" addrHeader of the Msg
func (m *Msg) ReplyTo(r string) error {
	rt, err := mail.ParseAddress(m.encodeString(r))
	if err != nil {
		return fmt.Errorf("failed to parse reply-to address: %w", err)
	}
	m.SetGenHeader(HeaderReplyTo, rt.String())
	return nil
}

// ReplyToFormat takes a name and address, formats them RFC5322 compliant and stores them as
// the Reply-To header field
func (m *Msg) ReplyToFormat(n, a string) error {
	return m.ReplyTo(fmt.Sprintf(`"%s" <%s>`, n, a))
}

// addAddr adds an additional address to the given addrHeader of the Msg
func (m *Msg) addAddr(h AddrHeader, a string) error {
	var al []string
	for _, ca := range m.addrHeader[h] {
		al = append(al, ca.String())
	}
	al = append(al, a)
	return m.SetAddrHeader(h, al...)
}

// Subject sets the "Subject" header field of the Msg
func (m *Msg) Subject(s string) {
	m.SetGenHeader(HeaderSubject, s)
}

// SetMessageID generates a random message id for the mail
func (m *Msg) SetMessageID() {
	hn, err := os.Hostname()
	if err != nil {
		hn = "localhost.localdomain"
	}
	rn, _ := randNum(100000000)
	rm, _ := randNum(10000)
	rs, _ := randomStringSecure(17)
	pid := os.Getpid() * rm
	mid := fmt.Sprintf("%d.%d%d.%s@%s", pid, rn, rm, rs, hn)
	m.SetMessageIDWithValue(mid)
}

// SetMessageIDWithValue sets the message id for the mail
func (m *Msg) SetMessageIDWithValue(v string) {
	m.SetGenHeader(HeaderMessageID, fmt.Sprintf("<%s>", v))
}

// SetBulk sets the "Precedence: bulk" genHeader which is recommended for
// automated mails like OOO replies
// See: https://www.rfc-editor.org/rfc/rfc2076#section-3.9
func (m *Msg) SetBulk() {
	m.SetGenHeader(HeaderPrecedence, "bulk")
}

// SetDate sets the Date genHeader field to the current time in a valid format
func (m *Msg) SetDate() {
	ts := time.Now().Format(time.RFC1123Z)
	m.SetGenHeader(HeaderDate, ts)
}

// SetDateWithValue sets the Date genHeader field to the provided time in a valid format
func (m *Msg) SetDateWithValue(t time.Time) {
	m.SetGenHeader(HeaderDate, t.Format(time.RFC1123Z))
}

// SetImportance sets the Msg Importance/Priority header to given Importance
func (m *Msg) SetImportance(i Importance) {
	if i == ImportanceNormal {
		return
	}
	m.SetGenHeader(HeaderImportance, i.String())
	m.SetGenHeader(HeaderPriority, i.NumString())
	m.SetGenHeader(HeaderXPriority, i.XPrioString())
	m.SetGenHeader(HeaderXMSMailPriority, i.NumString())
}

// SetOrganization sets the provided string as Organization header for the Msg
func (m *Msg) SetOrganization(o string) {
	m.SetGenHeader(HeaderOrganization, o)
}

// SetUserAgent sets the User-Agent/X-Mailer header for the Msg
func (m *Msg) SetUserAgent(a string) {
	m.SetGenHeader(HeaderUserAgent, a)
	m.SetGenHeader(HeaderXMailer, a)
}

// RequestMDNTo adds the Disposition-Notification-To header to request a MDN from the receiving end
// as described in RFC8098. It allows to provide a list recipient addresses.
// Address validation is performed
// See: https://www.rfc-editor.org/rfc/rfc8098.html
func (m *Msg) RequestMDNTo(t ...string) error {
	var tl []string
	for _, at := range t {
		a, err := mail.ParseAddress(at)
		if err != nil {
			return fmt.Errorf(errParseMailAddr, at, err)
		}
		tl = append(tl, a.String())
	}
	m.genHeader[HeaderDispositionNotificationTo] = tl
	return nil
}

// RequestMDNToFormat adds the Disposition-Notification-To header to request a MDN from the receiving end
// as described in RFC8098. It allows to provide a recipient address with name and address and will format
// accordingly. Address validation is performed
// See: https://www.rfc-editor.org/rfc/rfc8098.html
func (m *Msg) RequestMDNToFormat(n, a string) error {
	return m.RequestMDNTo(fmt.Sprintf(`%s <%s>`, n, a))
}

// RequestMDNAddTo adds an additional recipient to the recipient list of the MDN
func (m *Msg) RequestMDNAddTo(t string) error {
	a, err := mail.ParseAddress(t)
	if err != nil {
		return fmt.Errorf(errParseMailAddr, t, err)
	}
	var tl []string
	tl = append(tl, m.genHeader[HeaderDispositionNotificationTo]...)
	tl = append(tl, a.String())
	m.genHeader[HeaderDispositionNotificationTo] = tl
	return nil
}

// RequestMDNAddToFormat adds an additional formated recipient to the recipient list of the MDN
func (m *Msg) RequestMDNAddToFormat(n, a string) error {
	return m.RequestMDNAddTo(fmt.Sprintf(`"%s" <%s>`, n, a))
}

// GetSender returns the currently set envelope FROM address. If no envelope FROM is set it will use
// the first mail body FROM address. If ff is true, it will return the full address string including
// the address name, if set
func (m *Msg) GetSender(ff bool) (string, error) {
	f, ok := m.addrHeader[HeaderEnvelopeFrom]
	if !ok || len(f) == 0 {
		f, ok = m.addrHeader[HeaderFrom]
		if !ok || len(f) == 0 {
			return "", ErrNoFromAddress
		}
	}
	if ff {
		return f[0].String(), nil
	}
	return f[0].Address, nil
}

// GetRecipients returns a list of the currently set TO/CC/BCC addresses.
func (m *Msg) GetRecipients() ([]string, error) {
	var rl []string
	for _, t := range []AddrHeader{HeaderTo, HeaderCc, HeaderBcc} {
		al, ok := m.addrHeader[t]
		if !ok || len(al) == 0 {
			continue
		}
		for _, r := range al {
			rl = append(rl, r.Address)
		}
	}
	if len(rl) <= 0 {
		return rl, ErrNoRcptAddresses
	}
	return rl, nil
}

// GetAddrHeader returns the content of the requested address header of the Msg
func (m *Msg) GetAddrHeader(h AddrHeader) []*mail.Address {
	return m.addrHeader[h]
}

// GetAddrHeaderString returns the address string of the requested address header of the Msg
func (m *Msg) GetAddrHeaderString(h AddrHeader) []string {
	var al []string
	for i := range m.addrHeader[h] {
		al = append(al, m.addrHeader[h][i].String())
	}
	return al
}

// GetFrom returns the content of the From address header of the Msg
func (m *Msg) GetFrom() []*mail.Address {
	return m.GetAddrHeader(HeaderFrom)
}

// GetFromString returns the content of the From address header of the Msg as string slice
func (m *Msg) GetFromString() []string {
	return m.GetAddrHeaderString(HeaderFrom)
}

// GetTo returns the content of the To address header of the Msg
func (m *Msg) GetTo() []*mail.Address {
	return m.GetAddrHeader(HeaderTo)
}

// GetToString returns the content of the To address header of the Msg as string slice
func (m *Msg) GetToString() []string {
	return m.GetAddrHeaderString(HeaderTo)
}

// GetCc returns the content of the Cc address header of the Msg
func (m *Msg) GetCc() []*mail.Address {
	return m.GetAddrHeader(HeaderCc)
}

// GetCcString returns the content of the Cc address header of the Msg as string slice
func (m *Msg) GetCcString() []string {
	return m.GetAddrHeaderString(HeaderCc)
}

// GetBcc returns the content of the Bcc address header of the Msg
func (m *Msg) GetBcc() []*mail.Address {
	return m.GetAddrHeader(HeaderBcc)
}

// GetBccString returns the content of the Bcc address header of the Msg as string slice
func (m *Msg) GetBccString() []string {
	return m.GetAddrHeaderString(HeaderBcc)
}

// GetGenHeader returns the content of the requested generic header of the Msg
func (m *Msg) GetGenHeader(h Header) []string {
	return m.genHeader[h]
}

// GetParts returns the message parts of the Msg
func (m *Msg) GetParts() []*Part {
	return m.parts
}

// GetAttachments returns the attachments of the Msg
func (m *Msg) GetAttachments() []*File {
	return m.attachments
}

// SetAttachements sets the attachements of the message.
func (m *Msg) SetAttachements(ff []*File) {
	m.attachments = ff
}

// SetBodyString sets the body of the message.
func (m *Msg) SetBodyString(ct ContentType, b string, o ...PartOption) {
	buf := bytes.NewBufferString(b)
	w := writeFuncFromBuffer(buf)
	m.SetBodyWriter(ct, w, o...)
}

// SetBodyWriter sets the body of the message.
func (m *Msg) SetBodyWriter(ct ContentType, w func(io.Writer) (int64, error), o ...PartOption) {
	p := m.newPart(ct, o...)
	p.w = w
	m.parts = []*Part{p}
}

// SetBodyHTMLTemplate sets the body of the message from a given html/template.Template pointer
// The content type will be set to text/html automatically
func (m *Msg) SetBodyHTMLTemplate(t *ht.Template, d interface{}, o ...PartOption) error {
	if t == nil {
		return fmt.Errorf(errTplPointerNil)
	}
	buf := bytes.Buffer{}
	if err := t.Execute(&buf, d); err != nil {
		return fmt.Errorf(errTplExecuteFailed, err)
	}
	w := writeFuncFromBuffer(&buf)
	m.SetBodyWriter(TypeTextHTML, w, o...)
	return nil
}

// SetBodyTextTemplate sets the body of the message from a given text/template.Template pointer
// The content type will be set to text/plain automatically
func (m *Msg) SetBodyTextTemplate(t *tt.Template, d interface{}, o ...PartOption) error {
	if t == nil {
		return fmt.Errorf(errTplPointerNil)
	}
	buf := bytes.Buffer{}
	if err := t.Execute(&buf, d); err != nil {
		return fmt.Errorf(errTplExecuteFailed, err)
	}
	w := writeFuncFromBuffer(&buf)
	m.SetBodyWriter(TypeTextPlain, w, o...)
	return nil
}

// AddAlternativeString sets the alternative body of the message.
func (m *Msg) AddAlternativeString(ct ContentType, b string, o ...PartOption) {
	buf := bytes.NewBufferString(b)
	w := writeFuncFromBuffer(buf)
	m.AddAlternativeWriter(ct, w, o...)
}

// AddAlternativeWriter sets the body of the message.
func (m *Msg) AddAlternativeWriter(ct ContentType, w func(io.Writer) (int64, error), o ...PartOption) {
	p := m.newPart(ct, o...)
	p.w = w
	m.parts = append(m.parts, p)
}

// AddAlternativeHTMLTemplate sets the alternative body of the message to a html/template.Template output
// The content type will be set to text/html automatically
func (m *Msg) AddAlternativeHTMLTemplate(t *ht.Template, d interface{}, o ...PartOption) error {
	if t == nil {
		return fmt.Errorf(errTplPointerNil)
	}
	buf := bytes.Buffer{}
	if err := t.Execute(&buf, d); err != nil {
		return fmt.Errorf(errTplExecuteFailed, err)
	}
	w := writeFuncFromBuffer(&buf)
	m.AddAlternativeWriter(TypeTextHTML, w, o...)
	return nil
}

// AddAlternativeTextTemplate sets the alternative body of the message to a text/template.Template output
// The content type will be set to text/plain automatically
func (m *Msg) AddAlternativeTextTemplate(t *tt.Template, d interface{}, o ...PartOption) error {
	if t == nil {
		return fmt.Errorf(errTplPointerNil)
	}
	buf := bytes.Buffer{}
	if err := t.Execute(&buf, d); err != nil {
		return fmt.Errorf(errTplExecuteFailed, err)
	}
	w := writeFuncFromBuffer(&buf)
	m.AddAlternativeWriter(TypeTextPlain, w, o...)
	return nil
}

// AttachFile adds an attachment File to the Msg
func (m *Msg) AttachFile(n string, o ...FileOption) {
	f := fileFromFS(n)
	if f == nil {
		return
	}
	m.attachments = m.appendFile(m.attachments, f, o...)
}

// AttachReader adds an attachment File via io.Reader to the Msg
func (m *Msg) AttachReader(n string, r io.Reader, o ...FileOption) {
	f := fileFromReader(n, r)
	m.attachments = m.appendFile(m.attachments, f, o...)
}

// AttachHTMLTemplate adds the output of a html/template.Template pointer as File attachment to the Msg
func (m *Msg) AttachHTMLTemplate(n string, t *ht.Template, d interface{}, o ...FileOption) error {
	f, err := fileFromHTMLTemplate(n, t, d)
	if err != nil {
		return fmt.Errorf("failed to attach template: %w", err)
	}
	m.attachments = m.appendFile(m.attachments, f, o...)
	return nil
}

// AttachTextTemplate adds the output of a text/template.Template pointer as File attachment to the Msg
func (m *Msg) AttachTextTemplate(n string, t *tt.Template, d interface{}, o ...FileOption) error {
	f, err := fileFromTextTemplate(n, t, d)
	if err != nil {
		return fmt.Errorf("failed to attach template: %w", err)
	}
	m.attachments = m.appendFile(m.attachments, f, o...)
	return nil
}

// AttachFromEmbedFS adds an attachment File from an embed.FS to the Msg
func (m *Msg) AttachFromEmbedFS(n string, f *embed.FS, o ...FileOption) error {
	if f == nil {
		return fmt.Errorf("embed.FS must not be nil")
	}
	ef, err := fileFromEmbedFS(n, f)
	if err != nil {
		return err
	}
	m.attachments = m.appendFile(m.attachments, ef, o...)
	return nil
}

// EmbedFile adds an embedded File to the Msg
func (m *Msg) EmbedFile(n string, o ...FileOption) {
	f := fileFromFS(n)
	if f == nil {
		return
	}
	m.embeds = m.appendFile(m.embeds, f, o...)
}

// EmbedReader adds an embedded File from an io.Reader to the Msg
func (m *Msg) EmbedReader(n string, r io.Reader, o ...FileOption) {
	f := fileFromReader(n, r)
	m.embeds = m.appendFile(m.embeds, f, o...)
}

// EmbedHTMLTemplate adds the output of a html/template.Template pointer as embedded File to the Msg
func (m *Msg) EmbedHTMLTemplate(n string, t *ht.Template, d interface{}, o ...FileOption) error {
	f, err := fileFromHTMLTemplate(n, t, d)
	if err != nil {
		return fmt.Errorf("failed to embed template: %w", err)
	}
	m.embeds = m.appendFile(m.embeds, f, o...)
	return nil
}

// EmbedTextTemplate adds the output of a text/template.Template pointer as embedded File to the Msg
func (m *Msg) EmbedTextTemplate(n string, t *tt.Template, d interface{}, o ...FileOption) error {
	f, err := fileFromTextTemplate(n, t, d)
	if err != nil {
		return fmt.Errorf("failed to embed template: %w", err)
	}
	m.embeds = m.appendFile(m.embeds, f, o...)
	return nil
}

// EmbedFromEmbedFS adds an embedded File from an embed.FS to the Msg
func (m *Msg) EmbedFromEmbedFS(n string, f *embed.FS, o ...FileOption) error {
	if f == nil {
		return fmt.Errorf("embed.FS must not be nil")
	}
	ef, err := fileFromEmbedFS(n, f)
	if err != nil {
		return err
	}
	m.embeds = m.appendFile(m.embeds, ef, o...)
	return nil
}

// Reset resets all headers, body parts and attachments/embeds of the Msg
// It leaves already set encodings, charsets, boundaries, etc. as is
func (m *Msg) Reset() {
	m.addrHeader = make(map[AddrHeader][]*mail.Address)
	m.attachments = nil
	m.embeds = nil
	m.genHeader = make(map[Header][]string)
	m.parts = nil
}

// ApplyMiddlewares apply the list of middlewares to a Msg
func (m *Msg) applyMiddlewares(ms *Msg) *Msg {
	for _, mw := range m.middlewares {
		ms = mw.Handle(ms)
	}
	return ms
}

// WriteTo writes the formated Msg into a give io.Writer and satisfies the io.WriteTo interface
func (m *Msg) WriteTo(w io.Writer) (int64, error) {
	mw := &msgWriter{w: w, c: m.charset, en: m.encoder}
	mw.writeMsg(m.applyMiddlewares(m))
	return mw.n, mw.err
}

// WriteToSkipMiddleware writes the formated Msg into a give io.Writer and satisfies
// the io.WriteTo interface but will skip the given Middleware
func (m *Msg) WriteToSkipMiddleware(w io.Writer, mt MiddlewareType) (int64, error) {
	var omwl, mwl []Middleware
	omwl = m.middlewares
	for i := range m.middlewares {
		if m.middlewares[i].Type() == mt {
			continue
		}
		mwl = append(mwl, m.middlewares[i])
	}
	m.middlewares = mwl
	mw := &msgWriter{w: w, c: m.charset, en: m.encoder}
	mw.writeMsg(m.applyMiddlewares(m))
	m.middlewares = omwl
	return mw.n, mw.err
}

// Write is an alias method to WriteTo due to compatibility reasons
func (m *Msg) Write(w io.Writer) (int64, error) {
	return m.WriteTo(w)
}

// appendFile adds a File to the Msg (as attachment or embed)
func (m *Msg) appendFile(c []*File, f *File, o ...FileOption) []*File {
	// Override defaults with optionally provided FileOption functions
	for _, co := range o {
		if co == nil {
			continue
		}
		co(f)
	}

	if c == nil {
		return []*File{f}
	}

	return append(c, f)
}

// WriteToFile stores the Msg as file on disk. It will try to create the given filename
// Already existing files will be overwritten
func (m *Msg) WriteToFile(n string) error {
	f, err := os.Create(n)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() { _ = f.Close() }()
	_, err = m.WriteTo(f)
	if err != nil {
		return fmt.Errorf("failed to write to output file: %w", err)
	}
	return f.Close()
}

// WriteToSendmail returns WriteToSendmailWithCommand with a default sendmail path
func (m *Msg) WriteToSendmail() error {
	return m.WriteToSendmailWithCommand(SendmailPath)
}

// WriteToSendmailWithCommand returns WriteToSendmailWithContext with a default timeout
// of 5 seconds and a given sendmail path
func (m *Msg) WriteToSendmailWithCommand(sp string) error {
	tctx, tcfn := context.WithTimeout(context.Background(), time.Second*5)
	defer tcfn()
	return m.WriteToSendmailWithContext(tctx, sp)
}

// WriteToSendmailWithContext opens an pipe to the local sendmail binary and tries to send the
// mail though that. It takes a context.Context, the path to the sendmail binary and additional
// arguments for the sendmail binary as parameters
func (m *Msg) WriteToSendmailWithContext(ctx context.Context, sp string, a ...string) error {
	ec := exec.CommandContext(ctx, sp)
	ec.Args = append(ec.Args, "-oi", "-t")
	ec.Args = append(ec.Args, a...)

	se, err := ec.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to set STDERR pipe: %w", err)
	}

	si, err := ec.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to set STDIN pipe: %w", err)
	}

	// Start the execution and write to STDIN
	if err := ec.Start(); err != nil {
		return fmt.Errorf("could not start sendmail execution: %w", err)
	}
	_, err = m.WriteTo(si)
	if err != nil {
		if !errors.Is(err, syscall.EPIPE) {
			return fmt.Errorf("failed to write mail to buffer: %w", err)
		}
	}

	// Close STDIN and wait for completion or cancellation of the sendmail executable
	if err := si.Close(); err != nil {
		return fmt.Errorf("failed to close STDIN pipe: %w", err)
	}

	// Read the stderr pipe for possible errors
	serr, err := io.ReadAll(se)
	if err != nil {
		return fmt.Errorf("failed to read STDERR pipe: %w", err)
	}
	if len(serr) > 0 {
		return fmt.Errorf("sendmail command failed: %s", string(serr))
	}

	if err := ec.Wait(); err != nil {
		return fmt.Errorf("sendmail command execution failed: %w", err)
	}

	return nil
}

// NewReader returns a Reader type that satisfies the io.Reader interface.
//
// IMPORTANT: when creating a new Reader, the current state of the Msg is taken, as
// basis for the Reader. If you perform changes on Msg after creating the Reader, these
// changes will not be reflected in the Reader. You will have to use Msg.UpdateReader
// first to update the Reader's buffer with the current Msg content
func (m *Msg) NewReader() *Reader {
	r := &Reader{}
	wbuf := bytes.Buffer{}
	_, err := m.Write(&wbuf)
	if err != nil {
		r.err = fmt.Errorf("failed to write Msg to Reader buffer: %w", err)
	}
	r.buf = wbuf.Bytes()
	return r
}

// UpdateReader will update a Reader with the content of the given Msg and reset the
// Reader position to the start
func (m *Msg) UpdateReader(r *Reader) {
	wbuf := bytes.Buffer{}
	_, err := m.Write(&wbuf)
	r.Reset()
	r.buf = wbuf.Bytes()
	r.err = err
}

// HasSendError returns true if the Msg experienced an error during the message delivery and the
// sendError field of the Msg is not nil
func (m *Msg) HasSendError() bool {
	return m.sendError != nil
}

// SendErrorIsTemp returns true if the Msg experienced an error during the message delivery and the
// corresponding error was of temporary nature and should be retried later
func (m *Msg) SendErrorIsTemp() bool {
	var e *SendError
	if errors.As(m.sendError, &e) {
		return e.isTemp
	}
	return false
}

// SendError returns the senderror field of the Msg
func (m *Msg) SendError() error {
	return m.sendError
}

// encodeString encodes a string based on the configured message encoder and the corresponding
// charset for the Msg
func (m *Msg) encodeString(s string) string {
	return m.encoder.Encode(string(m.charset), s)
}

// hasAlt returns true if the Msg has more than one part
func (m *Msg) hasAlt() bool {
	return len(m.parts) > 1
}

// hasMixed returns true if the Msg has mixed parts
func (m *Msg) hasMixed() bool {
	return (len(m.parts) > 0 && len(m.attachments) > 0) || len(m.attachments) > 1
}

// hasRelated returns true if the Msg has related parts
func (m *Msg) hasRelated() bool {
	return (len(m.parts) > 0 && len(m.embeds) > 0) || len(m.embeds) > 1
}

// newPart returns a new Part for the Msg
func (m *Msg) newPart(ct ContentType, o ...PartOption) *Part {
	p := &Part{
		ctype: ct,
		enc:   m.encoding,
	}

	// Override defaults with optionally provided MsgOption functions
	for _, co := range o {
		if co == nil {
			continue
		}
		co(p)
	}

	return p
}

// setEncoder creates a new mime.WordEncoder based on the encoding setting of the message
func (m *Msg) setEncoder() {
	m.encoder = getEncoder(m.encoding)
}

// checkUserAgent checks if a useragent/x-mailer is set and if not will set a default
// version string
func (m *Msg) checkUserAgent() {
	_, uaok := m.genHeader[HeaderUserAgent]
	_, xmok := m.genHeader[HeaderXMailer]
	if !uaok && !xmok {
		m.SetUserAgent(fmt.Sprintf("go-mail v%s // https://github.com/wneessen/go-mail",
			VERSION))
	}
}

// addDefaultHeader sets some default headers, if they haven't been set before
func (m *Msg) addDefaultHeader() {
	if _, ok := m.genHeader[HeaderDate]; !ok {
		m.SetDate()
	}
	if _, ok := m.genHeader[HeaderMessageID]; !ok {
		m.SetMessageID()
	}
	m.SetGenHeader(HeaderMIMEVersion, string(m.mimever))
}

// fileFromEmbedFS returns a File pointer from a given file in the provided embed.FS
func fileFromEmbedFS(n string, f *embed.FS) (*File, error) {
	_, err := f.Open(n)
	if err != nil {
		return nil, fmt.Errorf("failed to open file from embed.FS: %w", err)
	}
	return &File{
		Name:   filepath.Base(n),
		Header: make(map[string][]string),
		Writer: func(w io.Writer) (int64, error) {
			h, err := f.Open(n)
			if err != nil {
				return 0, err
			}
			nb, err := io.Copy(w, h)
			if err != nil {
				_ = h.Close()
				return nb, fmt.Errorf("failed to copy file to io.Writer: %w", err)
			}
			return nb, h.Close()
		},
	}, nil
}

// fileFromFS returns a File pointer from a given file in the system's file system
func fileFromFS(n string) *File {
	_, err := os.Stat(n)
	if err != nil {
		return nil
	}

	return &File{
		Name:   filepath.Base(n),
		Header: make(map[string][]string),
		Writer: func(w io.Writer) (int64, error) {
			h, err := os.Open(n)
			if err != nil {
				return 0, err
			}
			nb, err := io.Copy(w, h)
			if err != nil {
				_ = h.Close()
				return nb, fmt.Errorf("failed to copy file to io.Writer: %w", err)
			}
			return nb, h.Close()
		},
	}
}

// fileFromReader returns a File pointer from a given io.Reader
func fileFromReader(n string, r io.Reader) *File {
	return &File{
		Name:   filepath.Base(n),
		Header: make(map[string][]string),
		Writer: func(w io.Writer) (int64, error) {
			nb, err := io.Copy(w, r)
			if err != nil {
				return nb, err
			}
			return nb, nil
		},
	}
}

// fileFromHTMLTemplate returns a File pointer form a given html/template.Template
func fileFromHTMLTemplate(n string, t *ht.Template, d interface{}) (*File, error) {
	if t == nil {
		return nil, fmt.Errorf(errTplPointerNil)
	}
	buf := bytes.Buffer{}
	if err := t.Execute(&buf, d); err != nil {
		return nil, fmt.Errorf(errTplExecuteFailed, err)
	}
	f := fileFromReader(n, &buf)
	return f, nil
}

// fileFromTextTemplate returns a File pointer form a given text/template.Template
func fileFromTextTemplate(n string, t *tt.Template, d interface{}) (*File, error) {
	if t == nil {
		return nil, fmt.Errorf(errTplPointerNil)
	}
	buf := bytes.Buffer{}
	if err := t.Execute(&buf, d); err != nil {
		return nil, fmt.Errorf(errTplExecuteFailed, err)
	}
	f := fileFromReader(n, &buf)
	return f, nil
}

// getEncoder creates a new mime.WordEncoder based on the encoding setting of the message
func getEncoder(e Encoding) mime.WordEncoder {
	switch e {
	case EncodingQP:
		return mime.QEncoding
	case EncodingB64:
		return mime.BEncoding
	default:
		return mime.QEncoding
	}
}

// writeFuncFromBuffer is a common method to convert a byte buffer into a writeFunc as
// often required by this library
func writeFuncFromBuffer(buf *bytes.Buffer) func(io.Writer) (int64, error) {
	w := func(w io.Writer) (int64, error) {
		nb, err := w.Write(buf.Bytes())
		return int64(nb), err
	}
	return w
}
