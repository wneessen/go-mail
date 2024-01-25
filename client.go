// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/wneessen/go-mail/log"
	"github.com/wneessen/go-mail/smtp"
)

// Defaults
const (
	// DefaultPort is the default connection port to the SMTP server
	DefaultPort = 25

	// DefaultPortSSL is the default connection port for SSL/TLS to the SMTP server
	DefaultPortSSL = 465

	// DefaultPortTLS is the default connection port for STARTTLS to the SMTP server
	DefaultPortTLS = 587

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

// DialContextFunc is a type to define custom DialContext function.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

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

	// noNoop indicates the Noop is to be skipped
	noNoop bool

	// HELO/EHLO string for the greeting the target SMTP server
	helo string

	// Hostname of the target SMTP server to connect to
	host string

	// pass is the corresponding SMTP AUTH password
	pass string

	// Port of the SMTP server to connect to
	port         int
	fallbackPort int

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

	// dl enables the debug logging on the SMTP client
	dl bool

	// l is a logger that implements the log.Logger interface
	l log.Logger

	// dialContextFunc is a custom DialContext function to dial target SMTP server
	dialContextFunc DialContextFunc
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
//
// Deprecated: use WithSSLPort instead.
func WithSSL() Option {
	return func(c *Client) error {
		c.ssl = true
		return nil
	}
}

// WithSSLPort tells the client to use a SSL/TLS connection.
// It automatically sets the port to 465.
//
// When the SSL connection fails and fallback is set to true,
// the client will attempt to connect on port 25 using plaintext.
func WithSSLPort(fb bool) Option {
	return func(c *Client) error {
		c.SetSSLPort(true, fb)
		return nil
	}
}

// WithDebugLog tells the client to log incoming and outgoing messages of the SMTP client
// to StdErr
func WithDebugLog() Option {
	return func(c *Client) error {
		c.dl = true
		return nil
	}
}

// WithLogger overrides the default log.Logger that is used for debug logging
func WithLogger(l log.Logger) Option {
	return func(c *Client) error {
		c.l = l
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
//
// Deprecated: use WithTLSPortPolicy instead.
func WithTLSPolicy(p TLSPolicy) Option {
	return func(c *Client) error {
		c.tlspolicy = p
		return nil
	}
}

// WithTLSPortPolicy tells the client to use the provided TLSPolicy,
// The correct port is automatically set.
//
// Port 587 is used for TLSMandatory and TLSOpportunistic.
// If the connection fails with TLSOpportunistic,
// a plaintext connection is attempted on port 25 as a fallback.
// NoTLS will allways use port 25.
func WithTLSPortPolicy(p TLSPolicy) Option {
	return func(c *Client) error {
		c.SetTLSPortPolicy(p)
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

// WithoutNoop disables the Client Noop check during connections. This is primarily for servers which delay responses
// to SMTP commands that are not the AUTH command. For example Microsoft Exchange's Tarpit.
func WithoutNoop() Option {
	return func(c *Client) error {
		c.noNoop = true
		return nil
	}
}

// WithDialContextFunc overrides the default DialContext for connecting SMTP server
func WithDialContextFunc(f DialContextFunc) Option {
	return func(c *Client) error {
		c.dialContextFunc = f
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

// SetTLSPortPolicy overrides the current TLSPolicy with the given TLSPolicy
// value. The correct port is automatically set.
//
// Port 587 is used for TLSMandatory and TLSOpportunistic.
// If the connection fails with TLSOpportunistic, a plaintext connection is
// attempted on port 25 as a fallback.
// NoTLS will allways use port 25.
func (c *Client) SetTLSPortPolicy(p TLSPolicy) {
	c.port = DefaultPortTLS

	if p == TLSOpportunistic {
		c.fallbackPort = DefaultPort
	}
	if p == NoTLS {
		c.port = DefaultPort
	}

	c.tlspolicy = p
}

// SetSSL tells the Client wether to use SSL or not
func (c *Client) SetSSL(s bool) {
	c.ssl = s
}

// SetSSLPort tells the Client wether or not to use SSL and fallback.
// The correct port is automatically set.
//
// Port 465 is used when SSL set (true).
// Port 25 is used when SSL is unset (false).
// When the SSL connection fails and fallback is set to true,
// the client will attempt to connect on port 25 using plaintext.
func (c *Client) SetSSLPort(ssl bool, fb bool) {
	if ssl {
		c.port = DefaultPortSSL
	} else {
		c.port = DefaultPort
	}

	if fb {
		c.fallbackPort = DefaultPort
	} else {
		c.fallbackPort = 0
	}

	c.ssl = ssl
}

// SetDebugLog tells the Client whether debug logging is enabled or not
func (c *Client) SetDebugLog(v bool) {
	c.dl = v
	if c.sc != nil {
		c.sc.SetDebugLog(v)
	}
}

// SetLogger tells the Client which log.Logger to use
func (c *Client) SetLogger(l log.Logger) {
	c.l = l
	if c.sc != nil {
		c.sc.SetLogger(l)
	}
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

	if c.dialContextFunc == nil {
		nd := net.Dialer{}
		c.dialContextFunc = nd.DialContext

		if c.ssl {
			td := tls.Dialer{NetDialer: &nd, Config: c.tlsconfig}
			c.enc = true
			c.dialContextFunc = td.DialContext
		}
	}
	var err error
	c.co, err = c.dialContextFunc(ctx, "tcp", c.ServerAddr())
	if err != nil && c.fallbackPort != 0 {
		// TODO: should we somehow log or append the previous error?
		c.co, err = c.dialContextFunc(ctx, "tcp", c.serverFallbackAddr())
	}
	if err != nil {
		return err
	}

	sc, err := smtp.NewClient(c.co, c.host)
	if err != nil {
		return err
	}
	if sc == nil {
		return fmt.Errorf("SMTP client is nil")
	}
	c.sc = sc

	if c.l != nil {
		c.sc.SetLogger(c.l)
	}
	if c.dl {
		c.sc.SetDebugLog(true)
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
		return fmt.Errorf("failed to close connction: %w", err)
	}
	return nil
}

// checkConn makes sure that a required server connection is available and extends the
// connection deadline
func (c *Client) checkConn() error {
	if c.co == nil {
		return ErrNoActiveConnection
	}

	if !c.noNoop {
		if err := c.sc.Noop(); err != nil {
			return ErrNoActiveConnection
		}
	}

	if err := c.co.SetDeadline(time.Now().Add(c.cto)); err != nil {
		return ErrDeadlineExtendFailed
	}
	return nil
}

// serverFallbackAddr returns the currently set combination of hostname
// and fallback port.
func (c *Client) serverFallbackAddr() string {
	return fmt.Sprintf("%s:%d", c.host, c.fallbackPort)
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
			c.sa = smtp.LoginAuth(c.user, c.pass, c.host)
		case SMTPAuthCramMD5:
			if !strings.Contains(sat, string(SMTPAuthCramMD5)) {
				return ErrCramMD5AuthNotSupported
			}
			c.sa = smtp.CRAMMD5Auth(c.user, c.pass)
		case SMTPAuthXOAUTH2:
			if !strings.Contains(sat, string(SMTPAuthXOAUTH2)) {
				return ErrXOauth2AuthNotSupported
			}
			c.sa = smtp.XOAuth2Auth(c.user, c.pass)
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
