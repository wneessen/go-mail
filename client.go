package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/wneessen/go-mail/auth"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// Defaults
const (
	// DefaultPort is the default connection port cto the SMTP server
	DefaultPort = 25

	// DefaultTimeout is the default connection timeout
	DefaultTimeout = time.Second * 15

	// DefaultTLSPolicy is the default STARTTLS policy
	DefaultTLSPolicy = TLSMandatory

	// DefaultTLSMinVersion is the minimum TLS version required for the connection
	// Nowadays TLS1.2 should be the sane default
	DefaultTLSMinVersion = tls.VersionTLS12
)

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
type Option func(*Client) error

var (
	// ErrInvalidPort should be used if a port is specified that is not valid
	ErrInvalidPort = errors.New("invalid port number")

	// ErrInvalidTimeout should be used if a timeout is set that is zero or negative
	ErrInvalidTimeout = errors.New("timeout cannot be zero or negative")

	// ErrInvalidHELO should be used if an empty HELO sting is provided
	ErrInvalidHELO = errors.New("invalid HELO/EHLO value - must not be empty")

	// ErrInvalidTLSConfig should be used if an empty tls.Config is provided
	ErrInvalidTLSConfig = errors.New("invalid TLS config")

	// ErrNoHostname should be used if a Client has no hostname set
	ErrNoHostname = errors.New("hostname for client cannot be empty")

	// ErrDeadlineExtendFailed should be used if the extension of the connection deadline fails
	ErrDeadlineExtendFailed = errors.New("connection deadline extension failed")

	// ErrNoActiveConnection should be used when a method is used that requies a server connection
	// but is not yet connected
	ErrNoActiveConnection = errors.New("not connected to SMTP server")

	// ErrServerNoUnencoded should be used when 8BIT encoding is selected for a message, but
	// the server does not offer 8BITMIME mode
	ErrServerNoUnencoded = errors.New("message is 8bit unencoded, but server does not support 8BITMIME")
)

// NewClient returns a new Session client object
func NewClient(h string, o ...Option) (*Client, error) {
	c := &Client{
		cto:       DefaultTimeout,
		host:      h,
		port:      DefaultPort,
		tlsconfig: &tls.Config{ServerName: h, MinVersion: DefaultTLSMinVersion},
		tlspolicy: DefaultTLSPolicy,
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
		if err := co(c); err != nil {
			return c, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	// Some settings in a Client cannot be empty/unset
	if c.host == "" {
		return c, ErrNoHostname
	}

	return c, nil
}

// WithPort overrides the default connection port
func WithPort(p int) Option {
	return func(c *Client) error {
		if p < 1 || p > 65535 {
			return ErrInvalidPort
		}
		c.port = p
		return nil
	}
}

// WithTimeout overrides the default connection timeout
func WithTimeout(t time.Duration) Option {
	return func(c *Client) error {
		if t <= 0 {
			return ErrInvalidTimeout
		}
		c.cto = t
		return nil
	}
}

// WithSSL tells the client to use a SSL/TLS connection
func WithSSL() Option {
	return func(c *Client) error {
		c.ssl = true
		return nil
	}
}

// WithHELO tells the client to use the provided string as HELO/EHLO greeting host
func WithHELO(h string) Option {
	return func(c *Client) error {
		if h == "" {
			return ErrInvalidHELO
		}
		c.helo = h
		return nil
	}
}

// WithTLSPolicy tells the client to use the provided TLSPolicy
func WithTLSPolicy(p TLSPolicy) Option {
	return func(c *Client) error {
		c.tlspolicy = p
		return nil
	}
}

// WithTLSConfig tells the client to use the provided *tls.Config
func WithTLSConfig(co *tls.Config) Option {
	return func(c *Client) error {
		if co == nil {
			return ErrInvalidTLSConfig
		}
		c.tlsconfig = co
		return nil
	}
}

// WithSMTPAuth tells the client to use the provided SMTPAuthType for authentication
func WithSMTPAuth(t SMTPAuthType) Option {
	return func(c *Client) error {
		c.satype = t
		return nil
	}
}

// WithSMTPAuthCustom tells the client to use the provided smtp.Auth for SMTP authentication
func WithSMTPAuthCustom(a smtp.Auth) Option {
	return func(c *Client) error {
		c.sa = a
		return nil
	}
}

// WithUsername tells the client to use the provided string as username for authentication
func WithUsername(u string) Option {
	return func(c *Client) error {
		c.user = u
		return nil
	}
}

// WithPassword tells the client to use the provided string as password/secret for authentication
func WithPassword(p string) Option {
	return func(c *Client) error {
		c.pass = p
		return nil
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

	if err := c.tls(); err != nil {
		return err
	}

	if err := c.auth(); err != nil {
		return err
	}

	return nil
}

// Send sends out the mail message
func (c *Client) Send(ml ...*Msg) error {
	if err := c.checkConn(); err != nil {
		return fmt.Errorf("failed to send mail: %w", err)
	}
	for _, m := range ml {
		if m.encoding == NoEncoding {
			if ok, _ := c.sc.Extension("8BITMIME"); !ok {
				return ErrServerNoUnencoded
			}
		}
		f, err := m.GetSender(false)
		if err != nil {
			return err
		}
		rl, err := m.GetRecipients()
		if err != nil {
			return err
		}

		if err := c.sc.Mail(f); err != nil {
			return fmt.Errorf("sending MAIL FROM command failed: %w", err)
		}
		for _, r := range rl {
			if err := c.sc.Rcpt(r); err != nil {
				return fmt.Errorf("sending RCPT TO command failed: %w", err)
			}
		}
		w, err := c.sc.Data()
		if err != nil {
			return fmt.Errorf("sending DATA command failed: %w", err)
		}
		_, err = m.Write(w)
		if err != nil {
			return fmt.Errorf("sending mail content failed: %w", err)
		}

		if err := w.Close(); err != nil {
			return fmt.Errorf("failed to close DATA writer: %w", err)
		}

		if err := c.Reset(); err != nil {
			return fmt.Errorf("sending RSET command failed: %s", err)
		}
		if err := c.checkConn(); err != nil {
			return fmt.Errorf("failed to check server connection: %w", err)
		}
	}

	return nil
}

// Close closes the Client connection
func (c *Client) Close() error {
	if err := c.checkConn(); err != nil {
		return err
	}
	if err := c.sc.Quit(); err != nil {
		return fmt.Errorf("failed to close SMTP client: %w", err)
	}

	return nil
}

// Reset sends the RSET command to the SMTP client
func (c *Client) Reset() error {
	if err := c.checkConn(); err != nil {
		return err
	}
	if err := c.sc.Reset(); err != nil {
		return fmt.Errorf("failed to send RSET to SMTP client: %w", err)
	}

	return nil
}

// DialAndSend establishes a connection to the SMTP server with a
// default context.Background and sends the mail
func (c *Client) DialAndSend(ml ...*Msg) error {
	ctx := context.Background()
	if err := c.DialWithContext(ctx); err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	if err := c.Send(ml...); err != nil {
		return fmt.Errorf("send failed: %w", err)
	}
	if err := c.Close(); err != nil {
		return fmt.Errorf("failed to close connction: %s", err)
	}
	return nil
}

// checkConn makes sure that a required server connection is available and extends the
// connection deadline
func (c *Client) checkConn() error {
	if c.co == nil {
		return ErrNoActiveConnection
	}
	if err := c.sc.Noop(); err != nil {
		return ErrNoActiveConnection
	}
	if err := c.co.SetDeadline(time.Now().Add(c.cto)); err != nil {
		return ErrDeadlineExtendFailed
	}
	return nil
}

// tls tries to make sure that the STARTTLS requirements are satisfied
func (c *Client) tls() error {
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
			c.sa = auth.LoginAuth(c.user, c.pass, c.host)
		case SMTPAuthCramMD5:
			if !strings.Contains(sat, string(SMTPAuthCramMD5)) {
				return ErrCramMD5AuthNotSupported
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
