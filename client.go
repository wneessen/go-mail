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
	"sync"
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
	// connection is the net.Conn that the smtp.Client is based on
	connection net.Conn

	// Timeout for the SMTP server connection
	connTimeout time.Duration

	// dialContextFunc is a custom DialContext function to dial target SMTP server
	dialContextFunc DialContextFunc

	// dsn indicates that we want to use DSN for the Client
	dsn bool

	// dsnmrtype defines the DSNMailReturnOption in case DSN is enabled
	dsnmrtype DSNMailReturnOption

	// dsnrntype defines the DSNRcptNotifyOption in case DSN is enabled
	dsnrntype []string

	// fallbackPort is used as an alternative port number in case the primary port is unavailable or
	// fails to bind.
	fallbackPort int

	// HELO/EHLO string for the greeting the target SMTP server
	helo string

	// Hostname of the target SMTP server to connect to
	host string

	// isEncrypted indicates if a Client connection is encrypted or not
	isEncrypted bool

	// logger is a logger that implements the log.Logger interface
	logger log.Logger

	// mutex is used to synchronize access to shared resources, ensuring that only one goroutine can
	// modify them at a time.
	mutex sync.RWMutex

	// noNoop indicates the Noop is to be skipped
	noNoop bool

	// pass is the corresponding SMTP AUTH password
	pass string

	// port specifies the network port number on which the server listens for incoming connections.
	port int

	// smtpAuth is a pointer to smtp.Auth
	smtpAuth smtp.Auth

	// smtpAuthType represents the authentication type for SMTP AUTH
	smtpAuthType SMTPAuthType

	// smtpClient is the smtp.Client that is set up when using the Dial*() methods
	smtpClient *smtp.Client

	// tlspolicy sets the client to use the provided TLSPolicy for the STARTTLS protocol
	tlspolicy TLSPolicy

	// tlsconfig represents the tls.Config setting for the STARTTLS connection
	tlsconfig *tls.Config

	// useDebugLog enables the debug logging on the SMTP client
	useDebugLog bool

	// user is the SMTP AUTH username
	user string

	// Use SSL for the connection
	useSSL bool
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
func NewClient(host string, opts ...Option) (*Client, error) {
	c := &Client{
		connTimeout: DefaultTimeout,
		host:        host,
		port:        DefaultPort,
		tlsconfig:   &tls.Config{ServerName: host, MinVersion: DefaultTLSMinVersion},
		tlspolicy:   DefaultTLSPolicy,
	}

	// Set default HELO/EHLO hostname
	if err := c.setDefaultHelo(); err != nil {
		return c, err
	}

	// Override defaults with optionally provided Option functions
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(c); err != nil {
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
func WithPort(port int) Option {
	return func(c *Client) error {
		if port < 1 || port > 65535 {
			return ErrInvalidPort
		}
		c.port = port
		return nil
	}
}

// WithTimeout overrides the default connection timeout
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) error {
		if timeout <= 0 {
			return ErrInvalidTimeout
		}
		c.connTimeout = timeout
		return nil
	}
}

// WithSSL tells the client to use a SSL/TLS connection
func WithSSL() Option {
	return func(c *Client) error {
		c.useSSL = true
		return nil
	}
}

// WithSSLPort tells the Client wether or not to use SSL and fallback.
// The correct port is automatically set.
//
// Port 465 is used when SSL set (true).
// Port 25 is used when SSL is unset (false).
// When the SSL connection fails and fb is set to true,
// the client will attempt to connect on port 25 using plaintext.
//
// Note: If a different port has already been set otherwise, the port-choosing
// and fallback automatism will be skipped.
func WithSSLPort(fallback bool) Option {
	return func(c *Client) error {
		c.SetSSLPort(true, fallback)
		return nil
	}
}

// WithDebugLog tells the client to log incoming and outgoing messages of the SMTP client
// to StdErr
func WithDebugLog() Option {
	return func(c *Client) error {
		c.useDebugLog = true
		return nil
	}
}

// WithLogger overrides the default log.Logger that is used for debug logging
func WithLogger(logger log.Logger) Option {
	return func(c *Client) error {
		c.logger = logger
		return nil
	}
}

// WithHELO tells the client to use the provided string as HELO/EHLO greeting host
func WithHELO(helo string) Option {
	return func(c *Client) error {
		if helo == "" {
			return ErrInvalidHELO
		}
		c.helo = helo
		return nil
	}
}

// WithTLSPolicy tells the client to use the provided TLSPolicy
//
// Note: To follow best-practices for SMTP TLS connections, it is recommended
// to use WithTLSPortPolicy instead.
func WithTLSPolicy(policy TLSPolicy) Option {
	return func(c *Client) error {
		c.tlspolicy = policy
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
//
// Note: If a different port has already been set otherwise, the port-choosing
// and fallback automatism will be skipped.
func WithTLSPortPolicy(policy TLSPolicy) Option {
	return func(c *Client) error {
		c.SetTLSPortPolicy(policy)
		return nil
	}
}

// WithTLSConfig tells the client to use the provided *tls.Config
func WithTLSConfig(tlsconfig *tls.Config) Option {
	return func(c *Client) error {
		if tlsconfig == nil {
			return ErrInvalidTLSConfig
		}
		c.tlsconfig = tlsconfig
		return nil
	}
}

// WithSMTPAuth tells the client to use the provided SMTPAuthType for authentication
func WithSMTPAuth(authtype SMTPAuthType) Option {
	return func(c *Client) error {
		c.smtpAuthType = authtype
		return nil
	}
}

// WithSMTPAuthCustom tells the client to use the provided smtp.Auth for SMTP authentication
func WithSMTPAuthCustom(smtpAuth smtp.Auth) Option {
	return func(c *Client) error {
		c.smtpAuth = smtpAuth
		return nil
	}
}

// WithUsername tells the client to use the provided string as username for authentication
func WithUsername(username string) Option {
	return func(c *Client) error {
		c.user = username
		return nil
	}
}

// WithPassword tells the client to use the provided string as password/secret for authentication
func WithPassword(password string) Option {
	return func(c *Client) error {
		c.pass = password
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
func WithDSNMailReturnType(option DSNMailReturnOption) Option {
	return func(c *Client) error {
		switch option {
		case DSNMailReturnHeadersOnly:
		case DSNMailReturnFull:
		default:
			return ErrInvalidDSNMailReturnOption
		}

		c.dsn = true
		c.dsnmrtype = option
		return nil
	}
}

// WithDSNRcptNotifyType enables the Client to request DSNs as described in the RFC 1891
// and sets the RCPT TO notify options to the given list of DSNRcptNotifyOption
// See: https://www.rfc-editor.org/rfc/rfc1891
func WithDSNRcptNotifyType(opts ...DSNRcptNotifyOption) Option {
	return func(c *Client) error {
		var rcptOpts []string
		var ns, nns bool
		if len(opts) > 0 {
			for _, opt := range opts {
				switch opt {
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
				rcptOpts = append(rcptOpts, string(opt))
			}
		}
		if ns && nns {
			return ErrInvalidDSNRcptNotifyCombination
		}

		c.dsn = true
		c.dsnrntype = rcptOpts
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
func WithDialContextFunc(dialCtxFunc DialContextFunc) Option {
	return func(c *Client) error {
		c.dialContextFunc = dialCtxFunc
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
//
// Note: To follow best-practices for SMTP TLS connections, it is recommended
// to use SetTLSPortPolicy instead.
func (c *Client) SetTLSPolicy(policy TLSPolicy) {
	c.tlspolicy = policy
}

// SetTLSPortPolicy overrides the current TLSPolicy with the given TLSPolicy
// value. The correct port is automatically set.
//
// Port 587 is used for TLSMandatory and TLSOpportunistic.
// If the connection fails with TLSOpportunistic, a plaintext connection is
// attempted on port 25 as a fallback.
// NoTLS will allways use port 25.
//
// Note: If a different port has already been set otherwise, the port-choosing
// and fallback automatism will be skipped.
func (c *Client) SetTLSPortPolicy(policy TLSPolicy) {
	if c.port == DefaultPort {
		c.port = DefaultPortTLS

		if policy == TLSOpportunistic {
			c.fallbackPort = DefaultPort
		}
		if policy == NoTLS {
			c.port = DefaultPort
		}
	}

	c.tlspolicy = policy
}

// SetSSL tells the Client wether to use SSL or not
func (c *Client) SetSSL(ssl bool) {
	c.useSSL = ssl
}

// SetSSLPort tells the Client wether or not to use SSL and fallback.
// The correct port is automatically set.
//
// Port 465 is used when SSL set (true).
// Port 25 is used when SSL is unset (false).
// When the SSL connection fails and fb is set to true,
// the client will attempt to connect on port 25 using plaintext.
//
// Note: If a different port has already been set otherwise, the port-choosing
// and fallback automatism will be skipped.
func (c *Client) SetSSLPort(ssl bool, fallback bool) {
	if c.port == DefaultPort {
		if ssl {
			c.port = DefaultPortSSL
		}

		c.fallbackPort = 0
		if fallback {
			c.fallbackPort = DefaultPort
		}
	}

	c.useSSL = ssl
}

// SetDebugLog tells the Client whether debug logging is enabled or not
func (c *Client) SetDebugLog(val bool) {
	c.useDebugLog = val
	if c.smtpClient != nil {
		c.smtpClient.SetDebugLog(val)
	}
}

// SetLogger tells the Client which log.Logger to use
func (c *Client) SetLogger(logger log.Logger) {
	c.logger = logger
	if c.smtpClient != nil {
		c.smtpClient.SetLogger(logger)
	}
}

// SetTLSConfig overrides the current *tls.Config with the given *tls.Config value
func (c *Client) SetTLSConfig(tlsconfig *tls.Config) error {
	if tlsconfig == nil {
		return ErrInvalidTLSConfig
	}
	c.tlsconfig = tlsconfig
	return nil
}

// SetUsername overrides the current username string with the given value
func (c *Client) SetUsername(username string) {
	c.user = username
}

// SetPassword overrides the current password string with the given value
func (c *Client) SetPassword(password string) {
	c.pass = password
}

// SetSMTPAuth overrides the current SMTP AUTH type setting with the given value
func (c *Client) SetSMTPAuth(authtype SMTPAuthType) {
	c.smtpAuthType = authtype
}

// SetSMTPAuthCustom overrides the current SMTP AUTH setting with the given custom smtp.Auth
func (c *Client) SetSMTPAuthCustom(smtpAuth smtp.Auth) {
	c.smtpAuth = smtpAuth
}

// setDefaultHelo retrieves the current hostname and sets it as HELO/EHLO hostname
func (c *Client) setDefaultHelo() error {
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("failed to read local hostname: %w", err)
	}
	c.helo = hostname
	return nil
}

// DialWithContext establishes a connection to the SMTP server with a given context.Context
func (c *Client) DialWithContext(dialCtx context.Context) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	ctx, cancel := context.WithDeadline(dialCtx, time.Now().Add(c.connTimeout))
	defer cancel()

	if c.dialContextFunc == nil {
		netDialer := net.Dialer{}
		c.dialContextFunc = netDialer.DialContext

		if c.useSSL {
			tlsDialer := tls.Dialer{NetDialer: &netDialer, Config: c.tlsconfig}
			c.isEncrypted = true
			c.dialContextFunc = tlsDialer.DialContext
		}
	}
	connection, err := c.dialContextFunc(ctx, "tcp", c.ServerAddr())
	if err != nil && c.fallbackPort != 0 {
		// TODO: should we somehow log or append the previous error?
		connection, err = c.dialContextFunc(ctx, "tcp", c.serverFallbackAddr())
	}
	if err != nil {
		return err
	}

	client, err := smtp.NewClient(connection, c.host)
	if err != nil {
		return err
	}
	if client == nil {
		return fmt.Errorf("SMTP client is nil")
	}
	c.smtpClient = client

	if c.logger != nil {
		c.smtpClient.SetLogger(c.logger)
	}
	if c.useDebugLog {
		c.smtpClient.SetDebugLog(true)
	}
	if err = c.smtpClient.Hello(c.helo); err != nil {
		return err
	}

	if err = c.tls(); err != nil {
		return err
	}

	if err = c.auth(); err != nil {
		return err
	}

	return nil
}

// Close closes the Client connection
func (c *Client) Close() error {
	if err := c.checkConn(); err != nil {
		return err
	}
	if err := c.smtpClient.Quit(); err != nil {
		return fmt.Errorf("failed to close SMTP client: %w", err)
	}

	return nil
}

// Reset sends the RSET command to the SMTP client
func (c *Client) Reset() error {
	if err := c.checkConn(); err != nil {
		return err
	}
	if err := c.smtpClient.Reset(); err != nil {
		return fmt.Errorf("failed to send RSET to SMTP client: %w", err)
	}

	return nil
}

// DialAndSend establishes a connection to the SMTP server with a
// default context.Background and sends the mail
func (c *Client) DialAndSend(messages ...*Msg) error {
	ctx := context.Background()
	return c.DialAndSendWithContext(ctx, messages...)
}

// DialAndSendWithContext establishes a connection to the SMTP server with a
// custom context and sends the mail
func (c *Client) DialAndSendWithContext(ctx context.Context, messages ...*Msg) error {
	if err := c.DialWithContext(ctx); err != nil {
		return fmt.Errorf("dial failed: %w", err)
	}
	if err := c.Send(messages...); err != nil {
		return fmt.Errorf("send failed: %w", err)
	}
	if err := c.Close(); err != nil {
		return fmt.Errorf("failed to close connection: %w", err)
	}
	return nil
}

// checkConn makes sure that a required server connection is available and extends the
// connection deadline
func (c *Client) checkConn() error {
	if !c.smtpClient.HasConnection() {
		return ErrNoActiveConnection
	}

	if !c.noNoop {
		if err := c.smtpClient.Noop(); err != nil {
			return ErrNoActiveConnection
		}
	}

	if err := c.smtpClient.UpdateDeadline(c.connTimeout); err != nil {
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
	if !c.smtpClient.HasConnection() {
		return ErrNoActiveConnection
	}
	if !c.useSSL && c.tlspolicy != NoTLS {
		hasStartTLS := false
		extension, _ := c.smtpClient.Extension("STARTTLS")
		if c.tlspolicy == TLSMandatory {
			hasStartTLS = true
			if !extension {
				return fmt.Errorf("STARTTLS mode set to: %q, but target host does not support STARTTLS",
					c.tlspolicy)
			}
		}
		if c.tlspolicy == TLSOpportunistic {
			if extension {
				hasStartTLS = true
			}
		}
		if hasStartTLS {
			if err := c.smtpClient.StartTLS(c.tlsconfig); err != nil {
				return err
			}
		}
		_, c.isEncrypted = c.smtpClient.TLSConnectionState()
	}
	return nil
}

// auth will try to perform SMTP AUTH if requested
func (c *Client) auth() error {
	if err := c.checkConn(); err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}
	if c.smtpAuth == nil && c.smtpAuthType != "" {
		hasSMTPAuth, smtpAuthType := c.smtpClient.Extension("AUTH")
		if !hasSMTPAuth {
			return fmt.Errorf("server does not support SMTP AUTH")
		}

		switch c.smtpAuthType {
		case SMTPAuthPlain:
			if !strings.Contains(smtpAuthType, string(SMTPAuthPlain)) {
				return ErrPlainAuthNotSupported
			}
			c.smtpAuth = smtp.PlainAuth("", c.user, c.pass, c.host)
		case SMTPAuthLogin:
			if !strings.Contains(smtpAuthType, string(SMTPAuthLogin)) {
				return ErrLoginAuthNotSupported
			}
			c.smtpAuth = smtp.LoginAuth(c.user, c.pass, c.host)
		case SMTPAuthCramMD5:
			if !strings.Contains(smtpAuthType, string(SMTPAuthCramMD5)) {
				return ErrCramMD5AuthNotSupported
			}
			c.smtpAuth = smtp.CRAMMD5Auth(c.user, c.pass)
		case SMTPAuthXOAUTH2:
			if !strings.Contains(smtpAuthType, string(SMTPAuthXOAUTH2)) {
				return ErrXOauth2AuthNotSupported
			}
			c.smtpAuth = smtp.XOAuth2Auth(c.user, c.pass)
		default:
			return fmt.Errorf("unsupported SMTP AUTH type %q", c.smtpAuthType)
		}
	}

	if c.smtpAuth != nil {
		if err := c.smtpClient.Auth(c.smtpAuth); err != nil {
			return fmt.Errorf("SMTP AUTH failed: %w", err)
		}
	}
	return nil
}

// sendSingleMsg sends out a single message and returns an error if the transmission/delivery fails.
// It is invoked by the public Send methods
func (c *Client) sendSingleMsg(message *Msg) error {
	if message.encoding == NoEncoding {
		if ok, _ := c.smtpClient.Extension("8BITMIME"); !ok {
			return &SendError{Reason: ErrNoUnencoded, isTemp: false, affectedMsg: message}
		}
	}
	from, err := message.GetSender(false)
	if err != nil {
		return &SendError{
			Reason: ErrGetSender, errlist: []error{err}, isTemp: isTempError(err),
			affectedMsg: message,
		}
	}
	rcpts, err := message.GetRecipients()
	if err != nil {
		return &SendError{
			Reason: ErrGetRcpts, errlist: []error{err}, isTemp: isTempError(err),
			affectedMsg: message,
		}
	}

	if c.dsn {
		if c.dsnmrtype != "" {
			c.smtpClient.SetDSNMailReturnOption(string(c.dsnmrtype))
		}
	}
	if err = c.smtpClient.Mail(from); err != nil {
		retError := &SendError{
			Reason: ErrSMTPMailFrom, errlist: []error{err}, isTemp: isTempError(err),
			affectedMsg: message,
		}
		if resetSendErr := c.smtpClient.Reset(); resetSendErr != nil {
			retError.errlist = append(retError.errlist, resetSendErr)
		}
		return retError
	}
	hasError := false
	rcptSendErr := &SendError{affectedMsg: message}
	rcptSendErr.errlist = make([]error, 0)
	rcptSendErr.rcpt = make([]string, 0)
	rcptNotifyOpt := strings.Join(c.dsnrntype, ",")
	c.smtpClient.SetDSNRcptNotifyOption(rcptNotifyOpt)
	for _, rcpt := range rcpts {
		if err = c.smtpClient.Rcpt(rcpt); err != nil {
			rcptSendErr.Reason = ErrSMTPRcptTo
			rcptSendErr.errlist = append(rcptSendErr.errlist, err)
			rcptSendErr.rcpt = append(rcptSendErr.rcpt, rcpt)
			rcptSendErr.isTemp = isTempError(err)
			hasError = true
		}
	}
	if hasError {
		if resetSendErr := c.smtpClient.Reset(); resetSendErr != nil {
			rcptSendErr.errlist = append(rcptSendErr.errlist, resetSendErr)
		}
		return rcptSendErr
	}
	writer, err := c.smtpClient.Data()
	if err != nil {
		return &SendError{
			Reason: ErrSMTPData, errlist: []error{err}, isTemp: isTempError(err),
			affectedMsg: message,
		}
	}
	_, err = message.WriteTo(writer)
	if err != nil {
		return &SendError{
			Reason: ErrWriteContent, errlist: []error{err}, isTemp: isTempError(err),
			affectedMsg: message,
		}
	}
	message.isDelivered = true

	if err = writer.Close(); err != nil {
		return &SendError{
			Reason: ErrSMTPDataClose, errlist: []error{err}, isTemp: isTempError(err),
			affectedMsg: message,
		}
	}

	if err = c.Reset(); err != nil {
		return &SendError{
			Reason: ErrSMTPReset, errlist: []error{err}, isTemp: isTempError(err),
			affectedMsg: message,
		}
	}
	if err = c.checkConn(); err != nil {
		return &SendError{
			Reason: ErrConnCheck, errlist: []error{err}, isTemp: isTempError(err),
			affectedMsg: message,
		}
	}
	return nil
}
