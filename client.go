package mail

import (
	"context"
	"time"
)

// DefaultPort is the default connection port to the SMTP server
const DefaultPort = 25

// DefaultTimeout is the default connection timeout
const DefaultTimeout = time.Second * 30

// Client is the SMTP client struct
type Client struct {
	h   string          // Hostname of the target SMTP server to connect to
	p   int             // Port of the SMTP server to connect to
	s   bool            // Use SSL/TLS or not
	ctx context.Context // The context for the connection handling
}

// Option returns a function that can be used for grouping Client options
type Option func(*Client)

// NewClient returns a new Session client object
func NewClient(o ...Option) Client {
	c := Client{
		p: DefaultPort,
	}

	// Override defaults with optionally provided Option functions
	for _, co := range o {
		if co == nil {
			continue
		}
		co(&c)
	}

	return c
}

// WithHost overrides the default connection port
func WithHost(h string) Option {
	return func(c *Client) {
		c.h = h
	}
}

// WithPort overrides the default connection port
func WithPort(p int) Option {
	return func(c *Client) {
		c.p = p
	}
}

func (c Client) Dial() {

}
