package mail

import "io"

// reader is a type that implements the io.Reader interface for a Msg
type reader struct {
	buf []byte // contents are the bytes buf[off : len(buf)]
	off int    // read at &buf[off], write at &buf[len(buf)]
}

// Read reads the length of p of the Msg buffer to satisfy the io.Reader interface
func (r *reader) Read(p []byte) (n int, err error) {
	if r.empty() {
		r.Reset()
		if len(p) == 0 {
			return 0, nil
		}
		return 0, io.EOF
	}
	n = copy(p, r.buf[r.off:])
	r.off += n
	return n, nil
}

// Reset resets the Reader buffer to be empty, but it retains the underlying storage
// for use by future writes.
func (r *reader) Reset() {
	r.buf = r.buf[:0]
	r.off = 0
}

// empty reports whether the unread portion of the Reader buffer is empty.
func (r *reader) empty() bool { return len(r.buf) <= r.off }
