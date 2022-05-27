package mail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"mime"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
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

	// mimever represents the MIME version
	mimever MIMEVersion

	// parts represent the different parts of the Msg
	parts []*Part
}

// SendmailPath is the default system path to the sendmail binary
const SendmailPath = "/usr/sbin/sendmail"

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

// WithBoundary overrides the default MIME boundary
func WithBoundary(b string) MsgOption {
	return func(m *Msg) {
		m.boundary = b
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
		a, err := mail.ParseAddress(av)
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

// ReplyTo takes and validates a given mail address and sets it as "Reply-To" addrHeader of the Msg
func (m *Msg) ReplyTo(r string) error {
	rt, err := mail.ParseAddress(m.encodeString(r))
	if err != nil {
		return fmt.Errorf("failed to parse reply-to address: %w", err)
	}
	m.SetHeader(HeaderReplyTo, rt.String())
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

// SetDateWithValue sets the Date genHeader field to the provided time in a valid format
func (m *Msg) SetDateWithValue(t time.Time) {
	m.SetHeader(HeaderDate, t.Format(time.RFC1123Z))
}

// SetImportance sets the Msg Importance/Priority header to given Importance
func (m *Msg) SetImportance(i Importance) {
	if i == ImportanceNormal {
		return
	}
	m.SetHeader(HeaderImportance, i.String())
	m.SetHeader(HeaderPriority, i.NumString())
	m.SetHeader(HeaderXPriority, i.XPrioString())
	m.SetHeader(HeaderXMSMailPriority, i.NumString())
}

// SetOrganization sets the provided string as Organization header for the Msg
func (m *Msg) SetOrganization(o string) {
	m.SetHeader(HeaderOrganization, o)
}

// SetUserAgent sets the User-Agent/X-Mailer header for the Msg
func (m *Msg) SetUserAgent(a string) {
	m.SetHeader(HeaderUserAgent, a)
	m.SetHeader(HeaderXMailer, a)
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
	w := func(w io.Writer) (int64, error) {
		nb, err := w.Write(buf.Bytes())
		return int64(nb), err
	}
	m.SetBodyWriter(ct, w, o...)
}

// SetBodyWriter sets the body of the message.
func (m *Msg) SetBodyWriter(ct ContentType, w func(io.Writer) (int64, error), o ...PartOption) {
	p := m.newPart(ct, o...)
	p.w = w
	m.parts = []*Part{p}
}

// AddAlternativeString sets the alternative body of the message.
func (m *Msg) AddAlternativeString(ct ContentType, b string, o ...PartOption) {
	buf := bytes.NewBufferString(b)
	w := func(w io.Writer) (int64, error) {
		nb, err := w.Write(buf.Bytes())
		return int64(nb), err
	}
	m.AddAlternativeWriter(ct, w, o...)
}

// AddAlternativeWriter sets the body of the message.
func (m *Msg) AddAlternativeWriter(ct ContentType, w func(io.Writer) (int64, error), o ...PartOption) {
	p := m.newPart(ct, o...)
	p.w = w
	m.parts = append(m.parts, p)
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

// Reset resets all headers, body parts and attachments/embeds of the Msg
// It leaves already set encodings, charsets, boundaries, etc. as is
func (m *Msg) Reset() {
	m.addrHeader = make(map[AddrHeader][]*mail.Address)
	m.attachments = nil
	m.embeds = nil
	m.genHeader = make(map[Header][]string)
	m.parts = nil
}

// WriteTo writes the formated Msg into a give io.Writer and satisfies the io.WriteTo interface
func (m *Msg) WriteTo(w io.Writer) (int64, error) {
	mw := &msgWriter{w: w, c: m.charset, en: m.encoder}
	mw.writeMsg(m)
	return mw.n, mw.err
}

// Write is an alias method to WriteTo due to compatiblity reasons
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
	m.SetHeader(HeaderMIMEVersion, string(m.mimever))
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
