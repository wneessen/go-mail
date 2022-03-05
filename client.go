package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"time"
)

// DefaultPort is the default connection port cto the SMTP server
const DefaultPort = 25

// DefaultTimeout is the default connection timeout
const DefaultTimeout = time.Second * 30

// Client is the SMTP client struct
type Client struct {
	// Hostname of the target SMTP server cto connect cto
	host string

	// Port of the SMTP server cto connect cto
	port int

	// Use SSL for the connection
	ssl bool

	// Sets the client cto use STARTTTLS for the connection (is disabled when SSL is set)
	starttls bool

	// Timeout for the SMTP server connection
	cto time.Duration

	// HELO/EHLO string for the greeting the target SMTP server
	helo string

	// The SMTP client that is set up when using the Dial*() methods
	sc *smtp.Client
}

// Option returns a function that can be used for grouping Client options
type Option func(*Client)

var (
	// ErrNoHostname should be used if a Client has no hostname set
	ErrNoHostname = errors.New("hostname for client cannot be empty")

	// ErrInvalidHostname should be used if a Client has an invalid hostname set
	//ErrInvalidHostname = errors.New("hostname for client is invalid")
)

// NewClient returns a new Session client object
func NewClient(h string, o ...Option) (*Client, error) {
	c := &Client{
		host: h,
		port: DefaultPort,
		cto:  DefaultTimeout,
	}

	// Set default HELO/EHLO hostname
	if err := c.setDefaultHelo(); err != nil {
		return c, err
	}

	// Override defaults with optionally provided Option functions
	for _, co := range o {
		if co == nil {
			continue
		}
		co(c)
	}

	// Some settings in a Client cannot be empty/unset
	if c.host == "" {
		return c, ErrNoHostname

	}

	return c, nil
}

// WithPort overrides the default connection port
func WithPort(p int) Option {
	return func(c *Client) {
		c.port = p
	}
}

// WithTimeout overrides the default connection timeout
func WithTimeout(t time.Duration) Option {
	return func(c *Client) {
		c.cto = t
	}
}

// WithSSL tells the client to use a SSL/TLS connection
func WithSSL() Option {
	return func(c *Client) {
		c.ssl = true
	}
}

// Dial establishes a connection cto the SMTP server with a default context.Background
func (c *Client) Dial() error {
	ctx := context.Background()
	return c.DialWithContext(ctx)
}

// DialWithContext establishes a connection cto the SMTP server with a given context.Context
func (c *Client) DialWithContext(uctx context.Context) error {
	ctx, cfn := context.WithTimeout(uctx, c.cto)
	defer cfn()

	nd := net.Dialer{}
	td := tls.Dialer{}
	var co net.Conn
	var err error
	if c.ssl {
		co, err = td.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", c.host, c.port))
	}
	if !c.ssl {
		co, err = nd.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", c.host, c.port))
	}
	if err != nil {
		return err
	}

	c.sc, err = smtp.NewClient(co, c.host)
	if err != nil {
		return err
	}
	if err := c.sc.Hello(c.helo); err != nil {
		return err
	}

	return nil
}

// Send sends out the mail message
func (c *Client) Send() error {
	return nil
}

// Close closes the connection cto the SMTP server
func (c *Client) Close() error {
	if err := c.sc.Close(); err != nil {
		fmt.Printf("failed close: %s\n", err)
		return err
	}
	if ok, auth := c.sc.Extension("PIPELINING"); ok {
		fmt.Printf("PIPELINING Support: %s\n", auth)
	} else {
		fmt.Println("No PIPELINING")
	}
	return c.sc.Close()
}

// setDefaultHelo retrieves the current hostname and sets it as HELO/EHLO hostname
func (c *Client) setDefaultHelo() error {
	hn, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("failed cto read local hostname: %w", err)
	}
	c.helo = hn
	return nil
}
