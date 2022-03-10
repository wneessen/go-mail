package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"strings"
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

	// tlspolicy sets the client to use the provided TLSPolicy for the STARTTLS protocol
	tlspolicy TLSPolicy

	// tlsconfig represents the tls.Config setting for the STARTTLS connection
	tlsconfig *tls.Config

	// Timeout for the SMTP server connection
	cto time.Duration

	// HELO/EHLO string for the greeting the target SMTP server
	helo string

	// enc indicates if a Client connection is encrypted or not
	enc bool

	// user is the SMTP AUTH username
	user string

	// pass is the corresponding SMTP AUTH password
	pass string

	// satype represents the authentication type for SMTP AUTH
	satype SMTPAuthType

	// co is the net.Conn that the smtp.Client is based on
	co net.Conn

	// sa is a pointer to smtp.Auth
	sa smtp.Auth

	// sc is the smtp.Client that is set up when using the Dial*() methods
	sc *smtp.Client
}

// Option returns a function that can be used for grouping Client options
type Option func(*Client)

var (
	// ErrNoHostname should be used if a Client has no hostname set
	ErrNoHostname = errors.New("hostname for client cannot be empty")

	// ErrDeadlineExtendFailed should be used if the extension of the connection deadline fails
	ErrDeadlineExtendFailed = errors.New("connection deadline extension failed")

	// ErrNoActiveConnection should be used when a method is used that requies a server connection
	// but is not yet connected
	ErrNoActiveConnection = errors.New("not connected to SMTP server")
)

// NewClient returns a new Session client object
func NewClient(h string, o ...Option) (*Client, error) {
	c := &Client{
		cto:       DefaultTimeout,
		host:      h,
		port:      DefaultPort,
		tlspolicy: TLSMandatory,
		tlsconfig: &tls.Config{ServerName: h},
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

// WithHELO tells the client to use the provided string as HELO/EHLO greeting host
func WithHELO(h string) Option {
	return func(c *Client) {
		c.helo = h
	}
}

// WithTLSPolicy tells the client to use the provided TLSPolicy
func WithTLSPolicy(p TLSPolicy) Option {
	return func(c *Client) {
		c.tlspolicy = p
	}
}

// WithTLSConfig tells the client to use the provided *tls.Config
func WithTLSConfig(co *tls.Config) Option {
	return func(c *Client) {
		c.tlsconfig = co
	}
}

// WithSMTPAuth tells the client to use the provided SMTPAuthType for authentication
func WithSMTPAuth(t SMTPAuthType) Option {
	return func(c *Client) {
		c.satype = t
	}
}

// WithSMTPAuthCustom tells the client to use the provided smtp.Auth for SMTP authentication
func WithSMTPAuthCustom(a smtp.Auth) Option {
	return func(c *Client) {
		c.sa = a
	}
}

// WithUsername tells the client to use the provided string as username for authentication
func WithUsername(u string) Option {
	return func(c *Client) {
		c.user = u
	}
}

// WithPassword tells the client to use the provided string as password/secret for authentication
func WithPassword(p string) Option {
	return func(c *Client) {
		c.pass = p
	}
}

// TLSPolicy returns the currently set TLSPolicy as string
func (c *Client) TLSPolicy() string {
	return c.tlspolicy.String()
}

// ServerAddr returns the currently set combination of hostname and port
func (c *Client) ServerAddr() string {
	return fmt.Sprintf("%s:%d", c.host, c.port)
}

// SetTLSPolicy overrides the current TLSPolicy with the given TLSPolicy value
func (c *Client) SetTLSPolicy(p TLSPolicy) {
	c.tlspolicy = p
}

// SetTLSConfig overrides the current *tls.Config with the given *tls.Config value
func (c *Client) SetTLSConfig(co *tls.Config) {
	c.tlsconfig = co
}

// SetUsername overrides the current username string with the given value
func (c *Client) SetUsername(u string) {
	c.user = u
}

// SetPassword overrides the current password string with the given value
func (c *Client) SetPassword(p string) {
	c.pass = p
}

// SetSMTPAuth overrides the current SMTP AUTH type setting with the given value
func (c *Client) SetSMTPAuth(a SMTPAuthType) {
	c.satype = a
}

// SetSMTPAuthCustom overrides the current SMTP AUTH setting with the given custom smtp.Auth
func (c *Client) SetSMTPAuthCustom(sa smtp.Auth) {
	c.sa = sa
}

// Close closes the connection cto the SMTP server
func (c *Client) Close() error {
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

// DialWithContext establishes a connection cto the SMTP server with a given context.Context
func (c *Client) DialWithContext(pc context.Context) error {
	ctx, cfn := context.WithDeadline(pc, time.Now().Add(c.cto))
	defer cfn()

	nd := net.Dialer{}
	td := tls.Dialer{}
	var err error
	if c.ssl {
		c.enc = true
		c.co, err = td.DialContext(ctx, "tcp", c.ServerAddr())
	}
	if !c.ssl {
		c.co, err = nd.DialContext(ctx, "tcp", c.ServerAddr())
	}
	if err != nil {
		return err
	}

	c.sc, err = smtp.NewClient(c.co, c.host)
	if err != nil {
		return err
	}
	if err := c.sc.Hello(c.helo); err != nil {
		return err
	}

	if !c.ssl && c.tlspolicy != NoTLS {
		est := false
		st, _ := c.sc.Extension("STARTTLS")
		if c.tlspolicy == TLSMandatory {
			est = true
			if !st {
				return fmt.Errorf("STARTTLS mode set to: %q, but target host does not support STARTTLS",
					c.tlspolicy)
			}
		}
		if c.tlspolicy == TLSOpportunistic {
			if st {
				est = true
			}
		}
		if est {
			if err := c.sc.StartTLS(c.tlsconfig); err != nil {
				return err
			}
		}
		_, c.enc = c.sc.TLSConnectionState()
	}

	if err := c.auth(); err != nil {
		return err
	}

	return nil
}

// Send sends out the mail message
func (c *Client) Send() error {
	if err := c.checkConn(); err != nil {
		return fmt.Errorf("failed to send mail: %w", err)
	}

	return nil
}

// DialAndSend establishes a connection to the SMTP server with a
// default context.Background and sends the mail
func (c *Client) DialAndSend() error {
	ctx := context.Background()
	if err := c.DialWithContext(ctx); err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	if err := c.Send(); err != nil {
		return fmt.Errorf("send failed: %w", err)
	}
	return nil
}

// checkConn makes sure that a required server connection is available and extends the
// connection deadline
func (c *Client) checkConn() error {
	if c.co == nil {
		return ErrNoActiveConnection
	}
	if err := c.co.SetDeadline(time.Now().Add(c.cto)); err != nil {
		return ErrDeadlineExtendFailed
	}
	return nil
}

// auth will try to perform SMTP AUTH if requested
func (c *Client) auth() error {
	if err := c.checkConn(); err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}
	if c.sa == nil && c.satype != "" {
		sa, sat := c.sc.Extension("AUTH")
		if !sa {
			return fmt.Errorf("server does not support SMTP AUTH")
		}

		switch c.satype {
		case SMTPAuthPlain:
			if !strings.Contains(sat, string(SMTPAuthPlain)) {
				return ErrPlainAuthNotSupported
			}
			c.sa = smtp.PlainAuth("", c.user, c.pass, c.host)
		case SMTPAuthLogin:
			if !strings.Contains(sat, string(SMTPAuthLogin)) {
				return ErrLoginAuthNotSupported
			}
			c.sa = smtp.PlainAuth("", c.user, c.pass, c.host)
		case SMTPAuthCramMD5:
			if !strings.Contains(sat, string(SMTPAuthCramMD5)) {
				return ErrCramMD5AuthNotSupported
			}
			c.sa = smtp.CRAMMD5Auth(c.user, c.pass)
		case SMTPAuthDigestMD5:
			if !strings.Contains(sat, string(SMTPAuthDigestMD5)) {
				return ErrDigestMD5AuthNotSupported
			}
			c.sa = smtp.CRAMMD5Auth(c.user, c.pass)
		default:
			return fmt.Errorf("unsupported SMTP AUTH type %q", c.satype)
		}
	}

	if c.sa != nil {
		if err := c.sc.Auth(c.sa); err != nil {
			return fmt.Errorf("SMTP AUTH failed: %w", err)
		}
	}
	return nil
}
