package mail

import "io"

// PartOption returns a function that can be used for grouping Part options
type PartOption func(*Part)

// Part is a part of the Msg
type Part struct {
	ctype ContentType
	enc   Encoding
	w     func(io.Writer) error
}

// SetEncoding creates a new mime.WordEncoder based on the encoding setting of the message
func (p *Part) SetEncoding(e Encoding) {
	p.enc = e
}

// WithPartEncoding overrides the default Part encoding
func WithPartEncoding(e Encoding) PartOption {
	return func(p *Part) {
		p.enc = e
	}
}
