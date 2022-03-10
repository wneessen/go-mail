package mail

import (
	"fmt"
	"math/rand"
	"os"
	"time"
)

// Msg is the mail message struct
type Msg struct {
	// charset represents the charset of the mail (defaults to UTF-8)
	charset string

	// encoder represents a mime.WordEncoder from the std lib
	//encoder mime.WordEncoder

	// header is a slice of strings that the different mail header fields
	header map[Header][]string
}

// NewMsg returns a new Msg pointer
func NewMsg() *Msg {
	m := &Msg{
		charset: "UTF-8",
		header:  make(map[Header][]string),
	}
	return m
}

// SetHeader sets a header field of the Msg
func (m *Msg) SetHeader(h Header, v ...string) {
	switch h {
	case HeaderFrom:
		m.header[h] = []string{v[0]}
	default:
		m.header[h] = v
	}
}

// From sets the From: address of the Msg
func (m *Msg) From(f string) {
	m.SetHeader(HeaderFrom, f)
}

// To sets the To: addresses of the Msg
func (m *Msg) To(t ...string) {
	m.SetHeader(HeaderTo, t...)
}

// Cc sets the Cc: addresses of the Msg
func (m *Msg) Cc(c ...string) {
	m.SetHeader(HeaderCc, c...)
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

// SetBulk sets the "Precedence: bulk" header which is recommended for
// automated mails like OOO replies
// See: https://www.rfc-editor.org/rfc/rfc2076#section-3.9
func (m *Msg) SetBulk() {
	m.SetHeader(HeaderPrecedence, "bulk")
}

// Header does something
// FIXME: This is only here to quickly show the set headers for debugging purpose. Remove me later
func (m *Msg) Header() {
	fmt.Printf("%+v\n", m.header)

}
