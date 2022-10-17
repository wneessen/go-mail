// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

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

	"github.com/wneessen/go-mail/auth"
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

// DSNMailReturnOption is a type to define which MAIL RET option is used when a DSN
// is requested
type DSNMailReturnOption string

// DSNRcptNotifyOption is a type to define which RCPT NOTIFY option is used when a DSN
// is requested
type DSNRcptNotifyOption string

const (
	// DSNMailReturnHeadersOnly requests that only the headers of the message be returned.
	// See: https://www.rfc-editor.org/rfc/rfc1891#section-5.3
	DSNMailReturnHeadersOnly DSNMailReturnOption = "HDRS"

	// DSNMailReturnFull requests that the entire message be returned in any "failed"
	// delivery status notification issued for this recipient
	// See: https://www.rfc-editor.org/rfc/rfc1891#section-5.3
	DSNMailReturnFull DSNMailReturnOption = "FULL"

	// DSNRcptNotifyNever requests that a DSN not be returned to the sender under
	// any conditions.
	// See: https://www.rfc-editor.org/rfc/rfc1891#section-5.1
	DSNRcptNotifyNever DSNRcptNotifyOption = "NEVER"

	// DSNRcptNotifySuccess requests that a DSN be issued on successful delivery
	// See: https://www.rfc-editor.org/rfc/rfc1891#section-5.1
	DSNRcptNotifySuccess DSNRcptNotifyOption = "SUCCESS"

	// DSNRcptNotifyFailure requests that a DSN be issued on delivery failure
	// See: https://www.rfc-editor.org/rfc/rfc1891#section-5.1
	DSNRcptNotifyFailure DSNRcptNotifyOption = "FAILURE"

	// DSNRcptNotifyDelay indicates the sender's willingness to receive
	// "delayed" DSNs. Delayed DSNs may be issued if delivery of a message has
	// been delayed for an unusual amount of time (as determined by the MTA at
	// which the message is delayed), but the final delivery status (whether
	// successful or failure) cannot be determined. The absence of the DELAY
	// keyword in a NOTIFY parameter requests that a "delayed" DSN NOT be
	// issued under any conditions.
	// See: https://www.rfc-editor.org/rfc/rfc1891#section-5.1
	DSNRcptNotifyDelay DSNRcptNotifyOption = "DELAY"
)

// Client is the SMTP client struct
type Client struct {
	// co is the net.Conn that the smtp.Client is based on
	co net.Conn

	// Timeout for the SMTP server connection
	cto time.Duration

	// dsn indicates that we want to use DSN for the Client
	dsn bool

	// dsnmrtype defines the DSNMailReturnOption in case DSN is enabled
	dsnmrtype DSNMailReturnOption

	// dsnrntype defines the DSNRcptNotifyOption in case DSN is enabled
	dsnrntype []string

	// enc indicates if a Client connection is encrypted or not
	enc bool

	// HELO/EHLO string for the greeting the target SMTP server
	helo string

	// Hostname of the target SMTP server cto connect cto
	host string

	// pass is the corresponding SMTP AUTH password
	pass string

	// Port of the SMTP server cto connect cto
	port int

	// sa is a pointer to smtp.Auth
	sa smtp.Auth

	// satype represents the authentication type for SMTP AUTH
	satype SMTPAuthType

	// sc is the smtp.Client that is set up when using the Dial*() methods
	sc *smtp.Client

	// Use SSL for the connection
	ssl bool

	// tlspolicy sets the client to use the provided TLSPolicy for the STARTTLS protocol
	tlspolicy TLSPolicy

	// tlsconfig represents the tls.Config setting for the STARTTLS connection
	tlsconfig *tls.Config

	// user is the SMTP AUTH username
	user string
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

	// ErrInvalidDSNMailReturnOption should be used when an invalid option is provided for the
	// DSNMailReturnOption in WithDSN
	ErrInvalidDSNMailReturnOption = errors.New("DSN mail return option can only be HDRS or FULL")

	// ErrInvalidDSNRcptNotifyOption should be used when an invalid option is provided for the
	// DSNRcptNotifyOption in WithDSN
	ErrInvalidDSNRcptNotifyOption = errors.New("DSN rcpt notify option can only be: NEVER, " +
		"SUCCESS, FAILURE or DELAY")

	// ErrInvalidDSNRcptNotifyCombination should be used when an invalid option is provided for the
	// DSNRcptNotifyOption in WithDSN
	ErrInvalidDSNRcptNotifyCombination = errors.New("DSN rcpt notify option NEVER cannot be " +
		"combined with any of SUCCESS, FAILURE or DELAY")
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

// WithDSN enables the Client to request DSNs (if the server supports it)
// as described in the RFC 1891 and set defaults for DSNMailReturnOption
// to DSNMailReturnFull and DSNRcptNotifyOption to DSNRcptNotifySuccess
// and DSNRcptNotifyFailure
func WithDSN() Option {
	return func(c *Client) error {
		c.dsn = true
		c.dsnmrtype = DSNMailReturnFull
		c.dsnrntype = []string{string(DSNRcptNotifyFailure), string(DSNRcptNotifySuccess)}
		return nil
	}
}

// WithDSNMailReturnType enables the Client to request DSNs (if the server supports it)
// as described in the RFC 1891 and set the MAIL FROM Return option type to the
// given DSNMailReturnOption
// See: https://www.rfc-editor.org/rfc/rfc1891
func WithDSNMailReturnType(mro DSNMailReturnOption) Option {
	return func(c *Client) error {
		switch mro {
		case DSNMailReturnHeadersOnly:
		case DSNMailReturnFull:
		default:
			return ErrInvalidDSNMailReturnOption
		}

		c.dsn = true
		c.dsnmrtype = mro
		return nil
	}
}

// WithDSNRcptNotifyType enables the Client to request DSNs as described in the RFC 1891
// and sets the RCPT TO notify options to the given list of DSNRcptNotifyOption
// See: https://www.rfc-editor.org/rfc/rfc1891
func WithDSNRcptNotifyType(rno ...DSNRcptNotifyOption) Option {
	return func(c *Client) error {
		var rnol []string
		var ns, nns bool
		if len(rno) > 0 {
			for _, crno := range rno {
				switch crno {
				case DSNRcptNotifyNever:
					ns = true
				case DSNRcptNotifySuccess:
					nns = true
				case DSNRcptNotifyFailure:
					nns = true
				case DSNRcptNotifyDelay:
					nns = true
				default:
					return ErrInvalidDSNRcptNotifyOption
				}
				rnol = append(rnol, string(crno))
			}
		}
		if ns && nns {
			return ErrInvalidDSNRcptNotifyCombination
		}

		c.dsn = true
		c.dsnrntype = rnol
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

// SetSSL tells the Client wether to use SSL or not
func (c *Client) SetSSL(s bool) {
	c.ssl = s
}

// SetTLSConfig overrides the current *tls.Config with the given *tls.Config value
func (c *Client) SetTLSConfig(co *tls.Config) error {
	if co == nil {
		return ErrInvalidTLSConfig
	}
	c.tlsconfig = co
	return nil
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

		if err := c.mail(f); err != nil {
			return fmt.Errorf("sending MAIL FROM command failed: %w", err)
		}
		for _, r := range rl {
			if err := c.rcpt(r); err != nil {
				return fmt.Errorf("sending RCPT TO command failed: %w", err)
			}
		}
		w, err := c.sc.Data()
		if err != nil {
			return fmt.Errorf("sending DATA command failed: %w", err)
		}
		_, err = m.WriteTo(w)
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
	return c.DialAndSendWithContext(ctx, ml...)
}

// DialAndSendWithContext establishes a connection to the SMTP server with a
// custom context and sends the mail
func (c *Client) DialAndSendWithContext(ctx context.Context, ml ...*Msg) error {
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
	if c.co == nil {
		return ErrNoActiveConnection
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

// mail is an extension to the Go std library mail method. It decideds wether to call the
// original mail method from the std library or in case DSN is enabled on the Client to
// call our own method instead
func (c *Client) mail(f string) error {
	ok, _ := c.sc.Extension("DSN")
	if ok && c.dsn {
		return c.dsnMail(f)
	}
	return c.sc.Mail(f)
}

// rcpt is an extension to the Go std library rcpt method. It decideds wether to call
// original rcpt method from the std library or in case DSN is enabled on the Client to
// call our own method instead
func (c *Client) rcpt(t string) error {
	ok, _ := c.sc.Extension("DSN")
	if ok && c.dsn {
		return c.dsnRcpt(t)
	}
	return c.sc.Rcpt(t)
}

// dsnRcpt issues a RCPT command to the server using the provided email address.
// A call to rcpt must be preceded by a call to mail and may be followed by
// a Data call or another rcpt call.
//
// This is a copy of the original Go std library net/smtp function with additions
// for the DSN extension
func (c *Client) dsnRcpt(t string) error {
	if err := validateLine(t); err != nil {
		return err
	}
	if len(c.dsnrntype) <= 0 {
		return c.sc.Rcpt(t)
	}

	rno := strings.Join(c.dsnrntype, ",")
	_, _, err := c.cmd(25, "RCPT TO:<%s> NOTIFY=%s", t, rno)
	return err
}

// dsnMail issues a MAIL command to the server using the provided email address.
// If the server supports the 8BITMIME extension, mail adds the BODY=8BITMIME
// parameter. If the server supports the SMTPUTF8 extension, mail adds the
// SMTPUTF8 parameter.
// This initiates a mail transaction and is followed by one or more rcpt calls.
//
// This is a copy of the original Go std library net/smtp function with additions
// for the DSN extension
func (c *Client) dsnMail(f string) error {
	if err := validateLine(f); err != nil {
		return err
	}
	cmdStr := "MAIL FROM:<%s>"
	if ok, _ := c.sc.Extension("8BITMIME"); ok {
		cmdStr += " BODY=8BITMIME"
	}
	if ok, _ := c.sc.Extension("SMTPUTF8"); ok {
		cmdStr += " SMTPUTF8"
	}
	cmdStr += fmt.Sprintf(" RET=%s", c.dsnmrtype)

	_, _, err := c.cmd(250, cmdStr, f)
	return err
}

// validateLine checks to see if a line has CR or LF as per RFC 5321
// This is a 1:1 copy of the method from the original Go std library net/smtp
func validateLine(line string) error {
	if strings.ContainsAny(line, "\n\r") {
		return errors.New("smtp: A line must not contain CR or LF")
	}
	return nil
}

// cmd is a convenience function that sends a command and returns the response
// This is a 1:1 copy of the method from the original Go std library net/smtp
func (c *Client) cmd(expectCode int, format string, args ...interface{}) (int, string, error) {
	id, err := c.sc.Text.Cmd(format, args...)
	if err != nil {
		return 0, "", err
	}
	c.sc.Text.StartResponse(id)
	defer c.sc.Text.EndResponse(id)
	code, msg, err := c.sc.Text.ReadResponse(expectCode)
	return code, msg, err
}
