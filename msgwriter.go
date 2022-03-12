package mail

import (
	"io"
	"strings"
)

// MaxHeaderLength defines the maximum line length for a mail header
// RFC 2047 suggests 76 characters
const MaxHeaderLength = 76

// msgWriter handles the I/O to the io.WriteCloser of the SMTP client
type msgWriter struct {
	w io.Writer
	n int64
	//writers    [3]*multipart.Writer
	//partWriter io.Writer
	//depth      uint8
	err error
}

// writeMsg formats the message and sends it to its io.Writer
func (mw *msgWriter) writeMsg(m *Msg) {
	if _, ok := m.genHeader["Date"]; !ok {
		m.SetDate()
	}
	for k, v := range m.genHeader {
		mw.writeHeader(k, v...)
	}
	for _, t := range []AddrHeader{HeaderFrom, HeaderTo, HeaderCc} {
		if al, ok := m.addrHeader[t]; ok {
			var v []string
			for _, a := range al {
				v = append(v, a.String())
			}
			mw.writeHeader(Header(t), v...)
		}
	}
	mw.writeString("\r\n")
	mw.writeString("This is a test mail")
}

// writeHeader writes a header into the msgWriter's io.Writer
func (mw *msgWriter) writeHeader(k Header, v ...string) {
	mw.writeString(string(k))
	if len(v) == 0 {
		mw.writeString(":\r\n")
		return
	}
	mw.writeString(": ")

	// Chars left: MaxHeaderLength - "<Headername>: " - "CRLF"
	cl := MaxHeaderLength - len(k) - 4
	for i, s := range v {
		nfl := 0
		if i < len(v) {
			nfl = len(v[i])
		}
		if cl-len(s) < 1 {
			if p := strings.IndexByte(s, ' '); p != -1 {
				mw.writeString(s[:p])
				mw.writeString("\r\n ")
				mw.writeString(s[p:])
				cl -= len(s[p:])
				continue
			}
		}
		if cl < 1 || cl-nfl < 1 {
			mw.writeString("\r\n")
			cl = MaxHeaderLength - 4
			if i != len(v) {
				mw.writeString(" ")
				cl -= 1
			}
		}
		mw.writeString(s)
		cl -= len(s)

		if i != len(v)-1 {
			mw.writeString(", ")
			cl -= 2
		}

	}
	mw.writeString("\r\n")
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
