package mail

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"mime"
	"net/mail"
	"os"
	"time"
)

var (
	// ErrNoFromAddress should be used when a FROM address is requrested but not set
	ErrNoFromAddress = errors.New("no FROM address set")

	// ErrNoRcptAddresses should be used when the list of RCPTs is empty
	ErrNoRcptAddresses = errors.New("no recipient addresses set")
)

// Msg is the mail message struct
type Msg struct {
	// addrHeader is a slice of strings that the different mail AddrHeader fields
	addrHeader map[AddrHeader][]*mail.Address

	// boundary is the MIME content boundary
	boundary string

	// charset represents the charset of the mail (defaults to UTF-8)
	charset Charset

	// encoding represents the message encoding (the encoder will be a corresponding WordEncoder)
	encoding Encoding

	// encoder represents a mime.WordEncoder from the std lib
	encoder mime.WordEncoder

	// genHeader is a slice of strings that the different generic mail Header fields
	genHeader map[Header][]string

	// mimever represents the MIME version
	mimever MIMEVersion

	// parts represent the different parts of the Msg
	parts []*Part
}

// Part is a part of the Msg
type Part struct {
	w     func(io.Writer) error
	ctype ContentType
	enc   Encoding
}

// PartOption returns a function that can be used for grouping Part options
type PartOption func(*Part)

// MsgOption returns a function that can be used for grouping Msg options
type MsgOption func(*Msg)

// NewMsg returns a new Msg pointer
func NewMsg(o ...MsgOption) *Msg {
	m := &Msg{
		addrHeader: make(map[AddrHeader][]*mail.Address),
		charset:    CharsetUTF8,
		encoding:   EncodingQP,
		genHeader:  make(map[Header][]string),
		mimever:    Mime10,
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

// SetCharset sets the encoding charset of the Msg
func (m *Msg) SetCharset(c Charset) {
	m.charset = c
}

// SetEncoding sets the encoding of the Msg
func (m *Msg) SetEncoding(e Encoding) {
	m.encoding = e
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
func (m *Msg) SetHeader(h Header, v ...string) {
	for i, hv := range v {
		v[i] = m.encodeString(hv)
	}
	m.genHeader[h] = v
}

// SetAddrHeader sets an address related header field of the Msg
func (m *Msg) SetAddrHeader(h AddrHeader, v ...string) error {
	var al []*mail.Address
	for _, av := range v {
		a, err := mail.ParseAddress(m.encodeString(av))
		if err != nil {
			return fmt.Errorf("failed to parse mail address header %q: %w", av, err)
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
	m.SetHeader(HeaderSubject, s)
}

// SetMessageID generates a random message id for the mail
func (m *Msg) SetMessageID() {
	hn, err := os.Hostname()
	if err != nil {
		hn = "localhost.localdomain"
	}
	ct := time.Now().Unix()
	r := rand.New(rand.NewSource(ct))
	rn := r.Int()
	pid := os.Getpid()

	mid := fmt.Sprintf("%d.%d.%d@%s", pid, rn, ct, hn)
	m.SetMessageIDWithValue(mid)
}

// SetMessageIDWithValue sets the message id for the mail
func (m *Msg) SetMessageIDWithValue(v string) {
	m.SetHeader(HeaderMessageID, fmt.Sprintf("<%s>", v))
}

// SetBulk sets the "Precedence: bulk" genHeader which is recommended for
// automated mails like OOO replies
// See: https://www.rfc-editor.org/rfc/rfc2076#section-3.9
func (m *Msg) SetBulk() {
	m.SetHeader(HeaderPrecedence, "bulk")
}

// SetDate sets the Date genHeader field to the current time in a valid format
func (m *Msg) SetDate() {
	ts := time.Now().Format(time.RFC1123Z)
	m.SetHeader(HeaderDate, ts)
}

// SetImportance sets the Msg Importance/Priority header to given Importance
func (m *Msg) SetImportance(i Importance) {
	if i == ImportanceNormal {
		return
	}
	m.SetHeader(HeaderImportance, i.String())
	m.SetHeader(HeaderPriority, i.NumString())
	m.SetHeader(HeaderXPriority, i.NumString())
	m.SetHeader(HeaderXMSMailPriority, i.NumString())
}

// GetSender returns the currently set FROM address. If f is true, it will return the full
// address string including the address name, if set
func (m *Msg) GetSender(ff bool) (string, error) {
	f, ok := m.addrHeader[HeaderFrom]
	if !ok || len(f) == 0 {
		return "", ErrNoFromAddress
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

// SetBodyString sets the body of the message.
func (m *Msg) SetBodyString(ct ContentType, b string, o ...PartOption) {
	buf := bytes.NewBufferString(b)
	w := func(w io.Writer) error {
		_, err := io.Copy(w, buf)
		return err
	}
	m.SetBodyWriter(ct, w, o...)
}

// SetBodyWriter sets the body of the message.
func (m *Msg) SetBodyWriter(ct ContentType, w func(io.Writer) error, o ...PartOption) {
	p := m.NewPart(ct, o...)
	p.w = w
	m.parts = []*Part{p}
}

// AddAlternativeString sets the alternative body of the message.
func (m *Msg) AddAlternativeString(ct ContentType, b string, o ...PartOption) {
	buf := bytes.NewBufferString(b)
	w := func(w io.Writer) error {
		_, err := io.Copy(w, buf)
		return err
	}
	m.AddAlternativeWriter(ct, w, o...)
}

// AddAlternativeWriter sets the body of the message.
func (m *Msg) AddAlternativeWriter(ct ContentType, w func(io.Writer) error, o ...PartOption) {
	p := m.NewPart(ct, o...)
	p.w = w
	m.parts = append(m.parts, p)
}

// Write writes the formated Msg into a give io.Writer
func (m *Msg) Write(w io.Writer) (int64, error) {
	mw := &msgWriter{w: w}
	mw.writeMsg(m)
	return mw.n, mw.err
}

// NewPart returns a new Part for the Msg
func (m *Msg) NewPart(ct ContentType, o ...PartOption) *Part {
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

// WithPartEncoding overrides the default Part encoding
func WithPartEncoding(e Encoding) PartOption {
	return func(p *Part) {
		p.enc = e
	}
}

// SetEncoding creates a new mime.WordEncoder based on the encoding setting of the message
func (p *Part) SetEncoding(e Encoding) {
	p.enc = e
}

// setEncoder creates a new mime.WordEncoder based on the encoding setting of the message
func (m *Msg) setEncoder() {
	m.encoder = getEncoder(m.encoding)
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

// encodeString encodes a string based on the configured message encoder and the corresponding
// charset for the Msg
func (m *Msg) encodeString(s string) string {
	return m.encoder.Encode(string(m.charset), s)
}

// hasAlt returns true if the Msg has more than one part
func (m *Msg) hasAlt() bool {
	return len(m.parts) > 1
}
