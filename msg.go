// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
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
	"strings"
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

const (
	// NoPGP indicates that a message should not be treated as PGP encrypted
	// or signed and is the default value for a message
	NoPGP PGPType = iota
	// PGPEncrypt indicates that a message should be treated as PGP encrypted
	// This works closely together with the corresponding go-mail-middleware
	PGPEncrypt
	// PGPSignature indicates that a message should be treated as PGP signed
	// This works closely together with the corresponding go-mail-middleware
	PGPSignature
)

// MiddlewareType is the type description of the Middleware and needs to be returned
// in the Middleware interface by the Type method
type MiddlewareType string

// Middleware is an interface to define a function to apply to Msg before sending
type Middleware interface {
	Handle(*Msg) *Msg
	Type() MiddlewareType
}

// PGPType is a type alias for a int representing a type of PGP encryption
// or signature
type PGPType int

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

	// isDelivered signals if a message has been delivered or not
	isDelivered bool

	// middlewares is the list of middlewares to apply to the Msg before sending in FIFO order
	middlewares []Middleware

	// mimever represents the MIME version
	mimever MIMEVersion

	// parts represent the different parts of the Msg
	parts []*Part

	// preformHeader is a slice of strings that the different generic mail Header fields
	// of which content is already preformated and will not be affected by the automatic line
	// breaks
	preformHeader map[Header]string

	// pgptype indicates that a message has a PGPType assigned and therefore will generate
	// different Content-Type settings in the msgWriter
	pgptype PGPType

	// sendError holds the SendError in case a Msg could not be delivered during the Client.Send operation
	sendError error

	// noDefaultUserAgent indicates whether the default User Agent will be excluded for the Msg when it's sent.
	noDefaultUserAgent bool
}

// SendmailPath is the default system path to the sendmail binary
const SendmailPath = "/usr/sbin/sendmail"

// MsgOption returns a function that can be used for grouping Msg options
type MsgOption func(*Msg)

// NewMsg returns a new Msg pointer
func NewMsg(opts ...MsgOption) *Msg {
	msg := &Msg{
		addrHeader:    make(map[AddrHeader][]*mail.Address),
		charset:       CharsetUTF8,
		encoding:      EncodingQP,
		genHeader:     make(map[Header][]string),
		preformHeader: make(map[Header]string),
		mimever:       MIME10,
	}

	// Override defaults with optionally provided MsgOption functions
	for _, option := range opts {
		if option == nil {
			continue
		}
		option(msg)
	}

	// Set the matcing mime.WordEncoder for the Msg
	msg.setEncoder()

	return msg
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

// WithPGPType overrides the default PGPType of the message
func WithPGPType(pt PGPType) MsgOption {
	return func(m *Msg) {
		m.pgptype = pt
	}
}

// WithNoDefaultUserAgent configures the Msg to not use the default User Agent
func WithNoDefaultUserAgent() MsgOption {
	return func(m *Msg) {
		m.noDefaultUserAgent = true
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

// SetPGPType sets the PGPType of the Msg
func (m *Msg) SetPGPType(t PGPType) {
	m.pgptype = t
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
func (m *Msg) SetHeader(header Header, values ...string) {
	m.SetGenHeader(header, values...)
}

// SetGenHeader sets a generic header field of the Msg
// For adding address headers like "To:" or "From", see SetAddrHeader
func (m *Msg) SetGenHeader(header Header, values ...string) {
	if m.genHeader == nil {
		m.genHeader = make(map[Header][]string)
	}
	for i, val := range values {
		values[i] = m.encodeString(val)
	}
	m.genHeader[header] = values
}

// SetHeaderPreformatted sets a generic header field of the Msg which content is
// already preformated.
//
// Deprecated: This method only exists for compatibility reason. Please use
// SetGenHeaderPreformatted instead
func (m *Msg) SetHeaderPreformatted(header Header, value string) {
	m.SetGenHeaderPreformatted(header, value)
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
func (m *Msg) SetGenHeaderPreformatted(header Header, value string) {
	if m.preformHeader == nil {
		m.preformHeader = make(map[Header]string)
	}
	m.preformHeader[header] = value
}

// SetAddrHeader sets an address related header field of the Msg
func (m *Msg) SetAddrHeader(header AddrHeader, values ...string) error {
	if m.addrHeader == nil {
		m.addrHeader = make(map[AddrHeader][]*mail.Address)
	}
	var addresses []*mail.Address
	for _, addrVal := range values {
		address, err := mail.ParseAddress(addrVal)
		if err != nil {
			return fmt.Errorf(errParseMailAddr, addrVal, err)
		}
		addresses = append(addresses, address)
	}
	switch header {
	case HeaderFrom:
		if len(addresses) > 0 {
			m.addrHeader[header] = []*mail.Address{addresses[0]}
		}
	default:
		m.addrHeader[header] = addresses
	}
	return nil
}

// SetAddrHeaderIgnoreInvalid sets an address related header field of the Msg and ignores invalid address
// in the validation process
func (m *Msg) SetAddrHeaderIgnoreInvalid(header AddrHeader, values ...string) {
	var addresses []*mail.Address
	for _, addrVal := range values {
		address, err := mail.ParseAddress(m.encodeString(addrVal))
		if err != nil {
			continue
		}
		addresses = append(addresses, address)
	}
	m.addrHeader[header] = addresses
}

// EnvelopeFrom takes and validates a given mail address and sets it as envelope "FROM"
// addrHeader of the Msg
func (m *Msg) EnvelopeFrom(from string) error {
	return m.SetAddrHeader(HeaderEnvelopeFrom, from)
}

// EnvelopeFromFormat takes a name and address, formats them RFC5322 compliant and stores them as
// the envelope FROM address header field
func (m *Msg) EnvelopeFromFormat(name, addr string) error {
	return m.SetAddrHeader(HeaderEnvelopeFrom, fmt.Sprintf(`"%s" <%s>`, name, addr))
}

// From takes and validates a given mail address and sets it as "From" genHeader of the Msg
func (m *Msg) From(from string) error {
	return m.SetAddrHeader(HeaderFrom, from)
}

// FromFormat takes a name and address, formats them RFC5322 compliant and stores them as
// the From address header field
func (m *Msg) FromFormat(name, addr string) error {
	return m.SetAddrHeader(HeaderFrom, fmt.Sprintf(`"%s" <%s>`, name, addr))
}

// To takes and validates a given mail address list sets the To: addresses of the Msg
func (m *Msg) To(rcpts ...string) error {
	return m.SetAddrHeader(HeaderTo, rcpts...)
}

// AddTo adds an additional address to the To address header field
func (m *Msg) AddTo(rcpt string) error {
	return m.addAddr(HeaderTo, rcpt)
}

// AddToFormat takes a name and address, formats them RFC5322 compliant and stores them as
// as additional To address header field
func (m *Msg) AddToFormat(name, addr string) error {
	return m.addAddr(HeaderTo, fmt.Sprintf(`"%s" <%s>`, name, addr))
}

// ToIgnoreInvalid takes and validates a given mail address list sets the To: addresses of the Msg
// Any provided address that is not RFC5322 compliant, will be ignored
func (m *Msg) ToIgnoreInvalid(rcpts ...string) {
	m.SetAddrHeaderIgnoreInvalid(HeaderTo, rcpts...)
}

// ToFromString takes and validates a given string of comma separted
// mail address and sets them as To: addresses of the Msg
func (m *Msg) ToFromString(rcpts string) error {
	return m.To(strings.Split(rcpts, ",")...)
}

// Cc takes and validates a given mail address list sets the Cc: addresses of the Msg
func (m *Msg) Cc(rcpts ...string) error {
	return m.SetAddrHeader(HeaderCc, rcpts...)
}

// AddCc adds an additional address to the Cc address header field
func (m *Msg) AddCc(rcpt string) error {
	return m.addAddr(HeaderCc, rcpt)
}

// AddCcFormat takes a name and address, formats them RFC5322 compliant and stores them as
// as additional Cc address header field
func (m *Msg) AddCcFormat(name, addr string) error {
	return m.addAddr(HeaderCc, fmt.Sprintf(`"%s" <%s>`, name, addr))
}

// CcIgnoreInvalid takes and validates a given mail address list sets the Cc: addresses of the Msg
// Any provided address that is not RFC5322 compliant, will be ignored
func (m *Msg) CcIgnoreInvalid(rcpts ...string) {
	m.SetAddrHeaderIgnoreInvalid(HeaderCc, rcpts...)
}

// CcFromString takes and validates a given string of comma separted
// mail address and sets them as Cc: addresses of the Msg
func (m *Msg) CcFromString(rcpts string) error {
	return m.Cc(strings.Split(rcpts, ",")...)
}

// Bcc takes and validates a given mail address list sets the Bcc: addresses of the Msg
func (m *Msg) Bcc(rcpts ...string) error {
	return m.SetAddrHeader(HeaderBcc, rcpts...)
}

// AddBcc adds an additional address to the Bcc address header field
func (m *Msg) AddBcc(rcpt string) error {
	return m.addAddr(HeaderBcc, rcpt)
}

// AddBccFormat takes a name and address, formats them RFC5322 compliant and stores them as
// as additional Bcc address header field
func (m *Msg) AddBccFormat(name, addr string) error {
	return m.addAddr(HeaderBcc, fmt.Sprintf(`"%s" <%s>`, name, addr))
}

// BccIgnoreInvalid takes and validates a given mail address list sets the Bcc: addresses of the Msg
// Any provided address that is not RFC5322 compliant, will be ignored
func (m *Msg) BccIgnoreInvalid(rcpts ...string) {
	m.SetAddrHeaderIgnoreInvalid(HeaderBcc, rcpts...)
}

// BccFromString takes and validates a given string of comma separted
// mail address and sets them as Bcc: addresses of the Msg
func (m *Msg) BccFromString(rcpts string) error {
	return m.Bcc(strings.Split(rcpts, ",")...)
}

// ReplyTo takes and validates a given mail address and sets it as "Reply-To" addrHeader of the Msg
func (m *Msg) ReplyTo(addr string) error {
	replyTo, err := mail.ParseAddress(addr)
	if err != nil {
		return fmt.Errorf("failed to parse reply-to address: %w", err)
	}
	m.SetGenHeader(HeaderReplyTo, replyTo.String())
	return nil
}

// ReplyToFormat takes a name and address, formats them RFC5322 compliant and stores them as
// the Reply-To header field
func (m *Msg) ReplyToFormat(name, addr string) error {
	return m.ReplyTo(fmt.Sprintf(`"%s" <%s>`, name, addr))
}

// addAddr adds an additional address to the given addrHeader of the Msg
func (m *Msg) addAddr(header AddrHeader, addr string) error {
	var addresses []string
	for _, address := range m.addrHeader[header] {
		addresses = append(addresses, address.String())
	}
	addresses = append(addresses, addr)
	return m.SetAddrHeader(header, addresses...)
}

// Subject sets the "Subject" header field of the Msg
func (m *Msg) Subject(subj string) {
	m.SetGenHeader(HeaderSubject, subj)
}

// SetMessageID generates a random message id for the mail
func (m *Msg) SetMessageID() {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost.localdomain"
	}
	randNumPrimary, _ := randNum(100000000)
	randNumSecondary, _ := randNum(10000)
	randString, _ := randomStringSecure(17)
	procID := os.Getpid() * randNumSecondary
	messageID := fmt.Sprintf("%d.%d%d.%s@%s", procID, randNumPrimary, randNumSecondary,
		randString, hostname)
	m.SetMessageIDWithValue(messageID)
}

// SetMessageIDWithValue sets the message id for the mail
func (m *Msg) SetMessageIDWithValue(messageID string) {
	m.SetGenHeader(HeaderMessageID, fmt.Sprintf("<%s>", messageID))
}

// SetBulk sets the "Precedence: bulk" and "X-Auto-Response-Suppress: All" genHeaders which are
// recommended for automated mails like OOO replies
// See: https://www.rfc-editor.org/rfc/rfc2076#section-3.9
// See also: https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmail/ced68690-498a-4567-9d14-5c01f974d8b1#Appendix_A_Target_51
func (m *Msg) SetBulk() {
	m.SetGenHeader(HeaderPrecedence, "bulk")
	m.SetGenHeader(HeaderXAutoResponseSuppress, "All")
}

// SetDate sets the Date genHeader field to the current time in a valid format
func (m *Msg) SetDate() {
	now := time.Now().Format(time.RFC1123Z)
	m.SetGenHeader(HeaderDate, now)
}

// SetDateWithValue sets the Date genHeader field to the provided time in a valid format
func (m *Msg) SetDateWithValue(timeVal time.Time) {
	m.SetGenHeader(HeaderDate, timeVal.Format(time.RFC1123Z))
}

// SetImportance sets the Msg Importance/Priority header to given Importance
func (m *Msg) SetImportance(importance Importance) {
	if importance == ImportanceNormal {
		return
	}
	m.SetGenHeader(HeaderImportance, importance.String())
	m.SetGenHeader(HeaderPriority, importance.NumString())
	m.SetGenHeader(HeaderXPriority, importance.XPrioString())
	m.SetGenHeader(HeaderXMSMailPriority, importance.NumString())
}

// SetOrganization sets the provided string as Organization header for the Msg
func (m *Msg) SetOrganization(org string) {
	m.SetGenHeader(HeaderOrganization, org)
}

// SetUserAgent sets the User-Agent/X-Mailer header for the Msg
func (m *Msg) SetUserAgent(userAgent string) {
	m.SetGenHeader(HeaderUserAgent, userAgent)
	m.SetGenHeader(HeaderXMailer, userAgent)
}

// IsDelivered will return true if the Msg has been successfully delivered
func (m *Msg) IsDelivered() bool {
	return m.isDelivered
}

// RequestMDNTo adds the Disposition-Notification-To header to request a MDN from the receiving end
// as described in RFC8098. It allows to provide a list recipient addresses.
// Address validation is performed
// See: https://www.rfc-editor.org/rfc/rfc8098.html
func (m *Msg) RequestMDNTo(rcpts ...string) error {
	var addresses []string
	for _, addrVal := range rcpts {
		address, err := mail.ParseAddress(addrVal)
		if err != nil {
			return fmt.Errorf(errParseMailAddr, addrVal, err)
		}
		addresses = append(addresses, address.String())
	}
	if _, ok := m.genHeader[HeaderDispositionNotificationTo]; ok {
		m.genHeader[HeaderDispositionNotificationTo] = addresses
	}
	return nil
}

// RequestMDNToFormat adds the Disposition-Notification-To header to request a MDN from the receiving end
// as described in RFC8098. It allows to provide a recipient address with name and address and will format
// accordingly. Address validation is performed
// See: https://www.rfc-editor.org/rfc/rfc8098.html
func (m *Msg) RequestMDNToFormat(name, addr string) error {
	return m.RequestMDNTo(fmt.Sprintf(`%s <%s>`, name, addr))
}

// RequestMDNAddTo adds an additional recipient to the recipient list of the MDN
func (m *Msg) RequestMDNAddTo(rcpt string) error {
	address, err := mail.ParseAddress(rcpt)
	if err != nil {
		return fmt.Errorf(errParseMailAddr, rcpt, err)
	}
	var addresses []string
	addresses = append(addresses, m.genHeader[HeaderDispositionNotificationTo]...)
	addresses = append(addresses, address.String())
	if _, ok := m.genHeader[HeaderDispositionNotificationTo]; ok {
		m.genHeader[HeaderDispositionNotificationTo] = addresses
	}
	return nil
}

// RequestMDNAddToFormat adds an additional formated recipient to the recipient list of the MDN
func (m *Msg) RequestMDNAddToFormat(name, addr string) error {
	return m.RequestMDNAddTo(fmt.Sprintf(`"%s" <%s>`, name, addr))
}

// GetSender returns the currently set envelope FROM address. If no envelope FROM is set it will use
// the first mail body FROM address. If useFullAddr is true, it will return the full address string
// including the address name, if set
func (m *Msg) GetSender(useFullAddr bool) (string, error) {
	from, ok := m.addrHeader[HeaderEnvelopeFrom]
	if !ok || len(from) == 0 {
		from, ok = m.addrHeader[HeaderFrom]
		if !ok || len(from) == 0 {
			return "", ErrNoFromAddress
		}
	}
	if useFullAddr {
		return from[0].String(), nil
	}
	return from[0].Address, nil
}

// GetRecipients returns a list of the currently set TO/CC/BCC addresses.
func (m *Msg) GetRecipients() ([]string, error) {
	var rcpts []string
	for _, addressType := range []AddrHeader{HeaderTo, HeaderCc, HeaderBcc} {
		addresses, ok := m.addrHeader[addressType]
		if !ok || len(addresses) == 0 {
			continue
		}
		for _, r := range addresses {
			rcpts = append(rcpts, r.Address)
		}
	}
	if len(rcpts) <= 0 {
		return rcpts, ErrNoRcptAddresses
	}
	return rcpts, nil
}

// GetAddrHeader returns the content of the requested address header of the Msg
func (m *Msg) GetAddrHeader(header AddrHeader) []*mail.Address {
	return m.addrHeader[header]
}

// GetAddrHeaderString returns the address string of the requested address header of the Msg
func (m *Msg) GetAddrHeaderString(header AddrHeader) []string {
	var addresses []string
	for _, mh := range m.addrHeader[header] {
		addresses = append(addresses, mh.String())
	}
	return addresses
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
func (m *Msg) GetGenHeader(header Header) []string {
	return m.genHeader[header]
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
func (m *Msg) SetAttachements(files []*File) {
	m.attachments = files
}

// UnsetAllAttachments unset the attachments of the message.
func (m *Msg) UnsetAllAttachments() {
	m.attachments = nil
}

// GetEmbeds returns the embeds of the Msg
func (m *Msg) GetEmbeds() []*File {
	return m.embeds
}

// SetEmbeds sets the embeds of the message.
func (m *Msg) SetEmbeds(files []*File) {
	m.embeds = files
}

// UnsetAllEmbeds unset the embeds of the message.
func (m *Msg) UnsetAllEmbeds() {
	m.embeds = nil
}

// UnsetAllParts unset the embeds and attachments of the message.
func (m *Msg) UnsetAllParts() {
	m.UnsetAllAttachments()
	m.UnsetAllEmbeds()
}

// SetBodyString sets the body of the message.
func (m *Msg) SetBodyString(contentType ContentType, content string, opts ...PartOption) {
	buffer := bytes.NewBufferString(content)
	writeFunc := writeFuncFromBuffer(buffer)
	m.SetBodyWriter(contentType, writeFunc, opts...)
}

// SetBodyWriter sets the body of the message.
func (m *Msg) SetBodyWriter(
	contentType ContentType, writeFunc func(io.Writer) (int64, error),
	opts ...PartOption,
) {
	p := m.newPart(contentType, opts...)
	p.writeFunc = writeFunc
	m.parts = []*Part{p}
}

// SetBodyHTMLTemplate sets the body of the message from a given html/template.Template pointer
// The content type will be set to text/html automatically
func (m *Msg) SetBodyHTMLTemplate(tpl *ht.Template, data interface{}, opts ...PartOption) error {
	if tpl == nil {
		return fmt.Errorf(errTplPointerNil)
	}
	buffer := bytes.Buffer{}
	if err := tpl.Execute(&buffer, data); err != nil {
		return fmt.Errorf(errTplExecuteFailed, err)
	}
	writeFunc := writeFuncFromBuffer(&buffer)
	m.SetBodyWriter(TypeTextHTML, writeFunc, opts...)
	return nil
}

// SetBodyTextTemplate sets the body of the message from a given text/template.Template pointer
// The content type will be set to text/plain automatically
func (m *Msg) SetBodyTextTemplate(tpl *tt.Template, data interface{}, opts ...PartOption) error {
	if tpl == nil {
		return fmt.Errorf(errTplPointerNil)
	}
	buf := bytes.Buffer{}
	if err := tpl.Execute(&buf, data); err != nil {
		return fmt.Errorf(errTplExecuteFailed, err)
	}
	writeFunc := writeFuncFromBuffer(&buf)
	m.SetBodyWriter(TypeTextPlain, writeFunc, opts...)
	return nil
}

// AddAlternativeString sets the alternative body of the message.
func (m *Msg) AddAlternativeString(contentType ContentType, content string, opts ...PartOption) {
	buffer := bytes.NewBufferString(content)
	writeFunc := writeFuncFromBuffer(buffer)
	m.AddAlternativeWriter(contentType, writeFunc, opts...)
}

// AddAlternativeWriter sets the body of the message.
func (m *Msg) AddAlternativeWriter(
	contentType ContentType, writeFunc func(io.Writer) (int64, error),
	opts ...PartOption,
) {
	part := m.newPart(contentType, opts...)
	part.writeFunc = writeFunc
	m.parts = append(m.parts, part)
}

// AddAlternativeHTMLTemplate sets the alternative body of the message to a html/template.Template output
// The content type will be set to text/html automatically
func (m *Msg) AddAlternativeHTMLTemplate(tpl *ht.Template, data interface{}, opts ...PartOption) error {
	if tpl == nil {
		return fmt.Errorf(errTplPointerNil)
	}
	buffer := bytes.Buffer{}
	if err := tpl.Execute(&buffer, data); err != nil {
		return fmt.Errorf(errTplExecuteFailed, err)
	}
	writeFunc := writeFuncFromBuffer(&buffer)
	m.AddAlternativeWriter(TypeTextHTML, writeFunc, opts...)
	return nil
}

// AddAlternativeTextTemplate sets the alternative body of the message to a text/template.Template output
// The content type will be set to text/plain automatically
func (m *Msg) AddAlternativeTextTemplate(tpl *tt.Template, data interface{}, opts ...PartOption) error {
	if tpl == nil {
		return fmt.Errorf(errTplPointerNil)
	}
	buffer := bytes.Buffer{}
	if err := tpl.Execute(&buffer, data); err != nil {
		return fmt.Errorf(errTplExecuteFailed, err)
	}
	writeFunc := writeFuncFromBuffer(&buffer)
	m.AddAlternativeWriter(TypeTextPlain, writeFunc, opts...)
	return nil
}

// AttachFile adds an attachment File to the Msg
func (m *Msg) AttachFile(name string, opts ...FileOption) {
	file := fileFromFS(name)
	if file == nil {
		return
	}
	m.attachments = m.appendFile(m.attachments, file, opts...)
}

// AttachReader adds an attachment File via io.Reader to the Msg
//
// CAVEAT: For AttachReader to work it has to read all data of the io.Reader
// into memory first, so it can seek through it. Using larger amounts of
// data on the io.Reader should be avoided. For such, it is recommended to
// either use AttachFile or AttachReadSeeker instead
func (m *Msg) AttachReader(name string, reader io.Reader, opts ...FileOption) error {
	file, err := fileFromReader(name, reader)
	if err != nil {
		return err
	}
	m.attachments = m.appendFile(m.attachments, file, opts...)
	return nil
}

// AttachReadSeeker adds an attachment File via io.ReadSeeker to the Msg
func (m *Msg) AttachReadSeeker(name string, reader io.ReadSeeker, opts ...FileOption) {
	file := fileFromReadSeeker(name, reader)
	m.attachments = m.appendFile(m.attachments, file, opts...)
}

// AttachHTMLTemplate adds the output of a html/template.Template pointer as File attachment to the Msg
func (m *Msg) AttachHTMLTemplate(
	name string, tpl *ht.Template, data interface{}, opts ...FileOption,
) error {
	file, err := fileFromHTMLTemplate(name, tpl, data)
	if err != nil {
		return fmt.Errorf("failed to attach template: %w", err)
	}
	m.attachments = m.appendFile(m.attachments, file, opts...)
	return nil
}

// AttachTextTemplate adds the output of a text/template.Template pointer as File attachment to the Msg
func (m *Msg) AttachTextTemplate(
	name string, tpl *tt.Template, data interface{}, opts ...FileOption,
) error {
	file, err := fileFromTextTemplate(name, tpl, data)
	if err != nil {
		return fmt.Errorf("failed to attach template: %w", err)
	}
	m.attachments = m.appendFile(m.attachments, file, opts...)
	return nil
}

// AttachFromEmbedFS adds an attachment File from an embed.FS to the Msg
func (m *Msg) AttachFromEmbedFS(name string, fs *embed.FS, opts ...FileOption) error {
	if fs == nil {
		return fmt.Errorf("embed.FS must not be nil")
	}
	file, err := fileFromEmbedFS(name, fs)
	if err != nil {
		return err
	}
	m.attachments = m.appendFile(m.attachments, file, opts...)
	return nil
}

// EmbedFile adds an embedded File to the Msg
func (m *Msg) EmbedFile(name string, opts ...FileOption) {
	file := fileFromFS(name)
	if file == nil {
		return
	}
	m.embeds = m.appendFile(m.embeds, file, opts...)
}

// EmbedReader adds an embedded File from an io.Reader to the Msg
//
// CAVEAT: For EmbedReader to work it has to read all data of the io.Reader
// into memory first, so it can seek through it. Using larger amounts of
// data on the io.Reader should be avoided. For such, it is recommended to
// either use EmbedFile or EmbedReadSeeker instead
func (m *Msg) EmbedReader(name string, reader io.Reader, opts ...FileOption) error {
	file, err := fileFromReader(name, reader)
	if err != nil {
		return err
	}
	m.embeds = m.appendFile(m.embeds, file, opts...)
	return nil
}

// EmbedReadSeeker adds an embedded File from an io.ReadSeeker to the Msg
func (m *Msg) EmbedReadSeeker(name string, reader io.ReadSeeker, opts ...FileOption) {
	file := fileFromReadSeeker(name, reader)
	m.embeds = m.appendFile(m.embeds, file, opts...)
}

// EmbedHTMLTemplate adds the output of a html/template.Template pointer as embedded File to the Msg
func (m *Msg) EmbedHTMLTemplate(
	name string, tpl *ht.Template, data interface{}, opts ...FileOption,
) error {
	file, err := fileFromHTMLTemplate(name, tpl, data)
	if err != nil {
		return fmt.Errorf("failed to embed template: %w", err)
	}
	m.embeds = m.appendFile(m.embeds, file, opts...)
	return nil
}

// EmbedTextTemplate adds the output of a text/template.Template pointer as embedded File to the Msg
func (m *Msg) EmbedTextTemplate(
	name string, tpl *tt.Template, data interface{}, opts ...FileOption,
) error {
	file, err := fileFromTextTemplate(name, tpl, data)
	if err != nil {
		return fmt.Errorf("failed to embed template: %w", err)
	}
	m.embeds = m.appendFile(m.embeds, file, opts...)
	return nil
}

// EmbedFromEmbedFS adds an embedded File from an embed.FS to the Msg
func (m *Msg) EmbedFromEmbedFS(name string, fs *embed.FS, opts ...FileOption) error {
	if fs == nil {
		return fmt.Errorf("embed.FS must not be nil")
	}
	file, err := fileFromEmbedFS(name, fs)
	if err != nil {
		return err
	}
	m.embeds = m.appendFile(m.embeds, file, opts...)
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
func (m *Msg) applyMiddlewares(msg *Msg) *Msg {
	for _, middleware := range m.middlewares {
		msg = middleware.Handle(msg)
	}
	return msg
}

// WriteTo writes the formated Msg into a give io.Writer and satisfies the io.WriteTo interface
func (m *Msg) WriteTo(writer io.Writer) (int64, error) {
	mw := &msgWriter{writer: writer, charset: m.charset, encoder: m.encoder}
	mw.writeMsg(m.applyMiddlewares(m))
	return mw.bytesWritten, mw.err
}

// WriteToSkipMiddleware writes the formated Msg into a give io.Writer and satisfies
// the io.WriteTo interface but will skip the given Middleware
func (m *Msg) WriteToSkipMiddleware(writer io.Writer, middleWareType MiddlewareType) (int64, error) {
	var origMiddlewares, middlewares []Middleware
	origMiddlewares = m.middlewares
	for i := range m.middlewares {
		if m.middlewares[i].Type() == middleWareType {
			continue
		}
		middlewares = append(middlewares, m.middlewares[i])
	}
	m.middlewares = middlewares
	mw := &msgWriter{writer: writer, charset: m.charset, encoder: m.encoder}
	mw.writeMsg(m.applyMiddlewares(m))
	m.middlewares = origMiddlewares
	return mw.bytesWritten, mw.err
}

// Write is an alias method to WriteTo due to compatibility reasons
func (m *Msg) Write(writer io.Writer) (int64, error) {
	return m.WriteTo(writer)
}

// appendFile adds a File to the Msg (as attachment or embed)
func (m *Msg) appendFile(files []*File, file *File, opts ...FileOption) []*File {
	// Override defaults with optionally provided FileOption functions
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(file)
	}

	if files == nil {
		return []*File{file}
	}

	return append(files, file)
}

// WriteToFile stores the Msg as file on disk. It will try to create the given filename
// Already existing files will be overwritten
func (m *Msg) WriteToFile(name string) error {
	file, err := os.Create(name)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() { _ = file.Close() }()
	_, err = m.WriteTo(file)
	if err != nil {
		return fmt.Errorf("failed to write to output file: %w", err)
	}
	return file.Close()
}

// WriteToSendmail returns WriteToSendmailWithCommand with a default sendmail path
func (m *Msg) WriteToSendmail() error {
	return m.WriteToSendmailWithCommand(SendmailPath)
}

// WriteToSendmailWithCommand returns WriteToSendmailWithContext with a default timeout
// of 5 seconds and a given sendmail path
func (m *Msg) WriteToSendmailWithCommand(sendmailPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	return m.WriteToSendmailWithContext(ctx, sendmailPath)
}

// WriteToSendmailWithContext opens an pipe to the local sendmail binary and tries to send the
// mail though that. It takes a context.Context, the path to the sendmail binary and additional
// arguments for the sendmail binary as parameters
func (m *Msg) WriteToSendmailWithContext(ctx context.Context, sendmailPath string, args ...string) error {
	cmdCtx := exec.CommandContext(ctx, sendmailPath)
	cmdCtx.Args = append(cmdCtx.Args, "-oi", "-t")
	cmdCtx.Args = append(cmdCtx.Args, args...)

	stdErr, err := cmdCtx.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to set STDERR pipe: %w", err)
	}

	stdIn, err := cmdCtx.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to set STDIN pipe: %w", err)
	}
	if stdErr == nil || stdIn == nil {
		return fmt.Errorf("received nil for STDERR or STDIN pipe")
	}

	// Start the execution and write to STDIN
	if err = cmdCtx.Start(); err != nil {
		return fmt.Errorf("could not start sendmail execution: %w", err)
	}
	_, err = m.WriteTo(stdIn)
	if err != nil {
		if !errors.Is(err, syscall.EPIPE) {
			return fmt.Errorf("failed to write mail to buffer: %w", err)
		}
	}

	// Close STDIN and wait for completion or cancellation of the sendmail executable
	if err = stdIn.Close(); err != nil {
		return fmt.Errorf("failed to close STDIN pipe: %w", err)
	}

	// Read the stderr pipe for possible errors
	sendmailErr, err := io.ReadAll(stdErr)
	if err != nil {
		return fmt.Errorf("failed to read STDERR pipe: %w", err)
	}
	if len(sendmailErr) > 0 {
		return fmt.Errorf("sendmail command failed: %s", string(sendmailErr))
	}

	if err = cmdCtx.Wait(); err != nil {
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
	reader := &Reader{}
	buffer := bytes.Buffer{}
	_, err := m.Write(&buffer)
	if err != nil {
		reader.err = fmt.Errorf("failed to write Msg to Reader buffer: %w", err)
	}
	reader.buffer = buffer.Bytes()
	return reader
}

// UpdateReader will update a Reader with the content of the given Msg and reset the
// Reader position to the start
func (m *Msg) UpdateReader(reader *Reader) {
	buffer := bytes.Buffer{}
	_, err := m.Write(&buffer)
	reader.Reset()
	reader.buffer = buffer.Bytes()
	reader.err = err
}

// HasSendError returns true if the Msg experienced an error during the message delivery and the
// sendError field of the Msg is not nil
func (m *Msg) HasSendError() bool {
	return m.sendError != nil
}

// SendErrorIsTemp returns true if the Msg experienced an error during the message delivery and the
// corresponding error was of temporary nature and should be retried later
func (m *Msg) SendErrorIsTemp() bool {
	var err *SendError
	if errors.As(m.sendError, &err) && err != nil {
		return err.isTemp
	}
	return false
}

// SendError returns the sendError field of the Msg
func (m *Msg) SendError() error {
	return m.sendError
}

// encodeString encodes a string based on the configured message encoder and the corresponding
// charset for the Msg
func (m *Msg) encodeString(str string) string {
	return m.encoder.Encode(string(m.charset), str)
}

// hasAlt returns true if the Msg has more than one part
func (m *Msg) hasAlt() bool {
	count := 0
	for _, part := range m.parts {
		if !part.isDeleted {
			count++
		}
	}
	return count > 1 && m.pgptype == 0
}

// hasMixed returns true if the Msg has mixed parts
func (m *Msg) hasMixed() bool {
	return m.pgptype == 0 && ((len(m.parts) > 0 && len(m.attachments) > 0) || len(m.attachments) > 1)
}

// hasRelated returns true if the Msg has related parts
func (m *Msg) hasRelated() bool {
	return m.pgptype == 0 && ((len(m.parts) > 0 && len(m.embeds) > 0) || len(m.embeds) > 1)
}

// hasPGPType returns true if the Msg should be treated as PGP encoded message
func (m *Msg) hasPGPType() bool {
	return m.pgptype > 0
}

// newPart returns a new Part for the Msg
func (m *Msg) newPart(contentType ContentType, opts ...PartOption) *Part {
	p := &Part{
		contentType: contentType,
		charset:     m.charset,
		encoding:    m.encoding,
	}

	// Override defaults with optionally provided MsgOption functions
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(p)
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
	if m.noDefaultUserAgent {
		return
	}
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
func fileFromEmbedFS(name string, fs *embed.FS) (*File, error) {
	_, err := fs.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open file from embed.FS: %w", err)
	}
	return &File{
		Name:   filepath.Base(name),
		Header: make(map[string][]string),
		Writer: func(writer io.Writer) (int64, error) {
			file, err := fs.Open(name)
			if err != nil {
				return 0, err
			}
			numBytes, err := io.Copy(writer, file)
			if err != nil {
				_ = file.Close()
				return numBytes, fmt.Errorf("failed to copy file to io.Writer: %w", err)
			}
			return numBytes, file.Close()
		},
	}, nil
}

// fileFromFS returns a File pointer from a given file in the system's file system
func fileFromFS(name string) *File {
	_, err := os.Stat(name)
	if err != nil {
		return nil
	}

	return &File{
		Name:   filepath.Base(name),
		Header: make(map[string][]string),
		Writer: func(writer io.Writer) (int64, error) {
			file, err := os.Open(name)
			if err != nil {
				return 0, err
			}
			numBytes, err := io.Copy(writer, file)
			if err != nil {
				_ = file.Close()
				return numBytes, fmt.Errorf("failed to copy file to io.Writer: %w", err)
			}
			return numBytes, file.Close()
		},
	}
}

// fileFromReader returns a File pointer from a given io.Reader
func fileFromReader(name string, reader io.Reader) (*File, error) {
	d, err := io.ReadAll(reader)
	if err != nil {
		return &File{}, err
	}
	byteReader := bytes.NewReader(d)
	return &File{
		Name:   name,
		Header: make(map[string][]string),
		Writer: func(writer io.Writer) (int64, error) {
			readBytes, copyErr := io.Copy(writer, byteReader)
			if copyErr != nil {
				return readBytes, copyErr
			}
			_, copyErr = byteReader.Seek(0, io.SeekStart)
			return readBytes, copyErr
		},
	}, nil
}

// fileFromReadSeeker returns a File pointer from a given io.ReadSeeker
func fileFromReadSeeker(name string, reader io.ReadSeeker) *File {
	return &File{
		Name:   name,
		Header: make(map[string][]string),
		Writer: func(writer io.Writer) (int64, error) {
			readBytes, err := io.Copy(writer, reader)
			if err != nil {
				return readBytes, err
			}
			_, err = reader.Seek(0, io.SeekStart)
			return readBytes, err
		},
	}
}

// fileFromHTMLTemplate returns a File pointer form a given html/template.Template
func fileFromHTMLTemplate(name string, tpl *ht.Template, data interface{}) (*File, error) {
	if tpl == nil {
		return nil, fmt.Errorf(errTplPointerNil)
	}
	buffer := bytes.Buffer{}
	if err := tpl.Execute(&buffer, data); err != nil {
		return nil, fmt.Errorf(errTplExecuteFailed, err)
	}
	return fileFromReader(name, &buffer)
}

// fileFromTextTemplate returns a File pointer form a given text/template.Template
func fileFromTextTemplate(name string, tpl *tt.Template, data interface{}) (*File, error) {
	if tpl == nil {
		return nil, fmt.Errorf(errTplPointerNil)
	}
	buffer := bytes.Buffer{}
	if err := tpl.Execute(&buffer, data); err != nil {
		return nil, fmt.Errorf(errTplExecuteFailed, err)
	}
	return fileFromReader(name, &buffer)
}

// getEncoder creates a new mime.WordEncoder based on the encoding setting of the message
func getEncoder(enc Encoding) mime.WordEncoder {
	switch enc {
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
func writeFuncFromBuffer(buffer *bytes.Buffer) func(io.Writer) (int64, error) {
	writeFunc := func(w io.Writer) (int64, error) {
		numBytes, err := w.Write(buffer.Bytes())
		return int64(numBytes), err
	}
	return writeFunc
}
