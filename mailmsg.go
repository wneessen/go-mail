package mail

import (
	"fmt"
	"math/rand"
	"net/mail"
	"os"
	"time"
)

// Msg is the mail message struct
type Msg struct {
	// charset represents the charset of the mail (defaults to UTF-8)
	charset string

	// encoder represents a mime.WordEncoder from the std lib
	//encoder mime.WordEncoder

	// genHeader is a slice of strings that the different generic mail Header fields
	genHeader map[Header][]string

	// addrHeader is a slice of strings that the different mail AddrHeader fields
	addrHeader map[AddrHeader][]*mail.Address
}

// NewMsg returns a new Msg pointer
func NewMsg() *Msg {
	m := &Msg{
		charset:    "UTF-8",
		genHeader:  make(map[Header][]string),
		addrHeader: make(map[AddrHeader][]*mail.Address),
	}
	return m
}

// SetHeader sets a generic header field of the Msg
func (m *Msg) SetHeader(h Header, v ...string) {
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
		a, err := mail.ParseAddress(av)
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

// To takes and validates a given mail address list sets the To: addresses of the Msg
func (m *Msg) To(t ...string) error {
	return m.SetAddrHeader(HeaderTo, t...)
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

// CcIgnoreInvalid takes and validates a given mail address list sets the Cc: addresses of the Msg
// Any provided address that is not RFC5322 compliant, will be ignored
func (m *Msg) CcIgnoreInvalid(c ...string) {
	m.SetAddrHeaderIgnoreInvalid(HeaderCc, c...)
}

// Bcc takes and validates a given mail address list sets the Bcc: addresses of the Msg
func (m *Msg) Bcc(b ...string) error {
	return m.SetAddrHeader(HeaderBcc, b...)
}

// BccIgnoreInvalid takes and validates a given mail address list sets the Bcc: addresses of the Msg
// Any provided address that is not RFC5322 compliant, will be ignored
func (m *Msg) BccIgnoreInvalid(b ...string) {
	m.SetAddrHeaderIgnoreInvalid(HeaderBcc, b...)
}

// SetMessageID generates a random message id for the mail
func (m *Msg) SetMessageID() {
	hn, err := os.Hostname()
	if err != nil {
		hn = "localhost.localdomain"
	}
	ct := time.Now().UnixMicro()
	r := rand.New(rand.NewSource(ct))
	rn := r.Int()
	pid := os.Getpid()

	mid := fmt.Sprintf("%d.%d.%d@%s", pid, rn, ct, hn)
	m.SetMessageIDWithValue(mid)
}

// SetMessageIDWithValue sets the message id for the mail
func (m *Msg) SetMessageIDWithValue(v string) {
	m.SetHeader(HeaderMessageID, v)
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

// Header does something
// FIXME: This is only here to quickly show the set headers for debugging purpose. Remove me later
func (m *Msg) Header() {
	fmt.Printf("Address header: %+v\n", m.addrHeader)
	fmt.Printf("Generic header: %+v\n", m.genHeader)

}
