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

const (
	// DefaultPort is the default connection port to the SMTP server.
	DefaultPort = 25

	// DefaultPortSSL is the default connection port for SSL/TLS to the SMTP server.
	DefaultPortSSL = 465

	// DefaultPortTLS is the default connection port for STARTTLS to the SMTP server.
	DefaultPortTLS = 587

	// DefaultTimeout is the default connection timeout.
	DefaultTimeout = time.Second * 15

	// DefaultTLSPolicy specifies the default TLS policy for connections.
	DefaultTLSPolicy = TLSMandatory

	// DefaultTLSMinVersion defines the minimum TLS version to be used for secure connections.
	// Nowadays TLS 1.2 is assumed be a sane default.
	DefaultTLSMinVersion = tls.VersionTLS12
)

const (

	// DSNMailReturnHeadersOnly requests that only the message headers of the mail message are returned in
	// a DSN (Delivery Status Notification).
	// https://datatracker.ietf.org/doc/html/rfc1891#section-5.3
	DSNMailReturnHeadersOnly DSNMailReturnOption = "HDRS"

	// DSNMailReturnFull requests that the entire mail message is returned in any failed  DSN
	// (Delivery Status Notification) issued for this recipient.
	// https://datatracker.ietf.org/doc/html/rfc1891/#section-5.3
	DSNMailReturnFull DSNMailReturnOption = "FULL"

	// DSNRcptNotifyNever indicates that no DSN (Delivery Status Notifications) should be sent for the
	// recipient under any condition.
	// https://datatracker.ietf.org/doc/html/rfc1891/#section-5.1
	DSNRcptNotifyNever DSNRcptNotifyOption = "NEVER"

	// DSNRcptNotifySuccess indicates that the sender requests a DSN (Delivery Status Notification) if the
	// message is successfully delivered.
	// https://datatracker.ietf.org/doc/html/rfc1891/#section-5.1
	DSNRcptNotifySuccess DSNRcptNotifyOption = "SUCCESS"

	// DSNRcptNotifyFailure requests that a DSN (Delivery Status Notification) is issued if delivery of
	// a message fails.
	// https://datatracker.ietf.org/doc/html/rfc1891/#section-5.1
	DSNRcptNotifyFailure DSNRcptNotifyOption = "FAILURE"

	// DSNRcptNotifyDelay indicates the sender's willingness to receive "delayed" DSNs.
	//
	// Delayed DSNs may be issued if delivery of a message has been delayed for an unusual amount of time
	// (as determined by the MTA at which the message is delayed), but the final delivery status (whether
	// successful or failure) cannot be determined. The absence of the DELAY keyword in a NOTIFY parameter
	// requests that a "delayed" DSN NOT be issued under any conditions.
	// https://datatracker.ietf.org/doc/html/rfc1891/#section-5.1
	DSNRcptNotifyDelay DSNRcptNotifyOption = "DELAY"
)

type (

	// DialContextFunc defines a function type for establishing a network connection using context, network
	// type, and address. It is used to specify custom DialContext function.
	//
	// By default we use net.Dial or tls.Dial respectively.
	DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

	// DSNMailReturnOption is a type wrapper for a string and specifies the type of return content requested
	// in a Delivery Status Notification (DSN).
	// https://datatracker.ietf.org/doc/html/rfc1891/
	DSNMailReturnOption string

	// DSNRcptNotifyOption is a type wrapper for a string and specifies the notification options for a
	// recipient in DSNs.
	// https://datatracker.ietf.org/doc/html/rfc1891/
	DSNRcptNotifyOption string

	// Option is a function type that modifies the configuration or behavior of a Client instance.
	Option func(*Client) error

	// Client is the go-mail client that is responsible for connecting and interacting with an SMTP server.
	Client struct {
		// connTimeout specifies timeout for the connection to the SMTP server.
		connTimeout time.Duration

		// dialContextFunc is the DialContextFunc that is used by the Client to connect to the SMTP server.
		dialContextFunc DialContextFunc

		// dsnRcptNotifyType represents the different types of notifications for DSN (Delivery Status Notifications)
		// receipts.
		dsnRcptNotifyType []string

		// dsnReturnType specifies the type of Delivery Status Notification (DSN) that should be requested for an
		// email.
		dsnReturnType DSNMailReturnOption

		// fallbackPort is used as an alternative port number in case the primary port is unavailable or
		// fails to bind.
		//
		// The fallbackPort is only used in combination with SetTLSPortPolicy and SetSSLPort correspondingly.
		fallbackPort int

		// helo is the hostname used in the HELO/EHLO greeting, that is sent to the target SMTP server.
		//
		// helo might be different as host. This can be useful in a shared-hosting scenario.
		helo string

		// host is the hostname of the SMTP server we are connecting to.
		host string

		// isEncrypted indicates wether the Client connection is encrypted or not.
		isEncrypted bool

		// logger is a logger that satisfies the log.Logger interface.
		logger log.Logger

		// mutex is used to synchronize access to shared resources, ensuring that only one goroutine can
		// modify them at a time.
		mutex sync.RWMutex

		// noNoop indicates that the Client should skip the "NOOP" command during the dial.
		//
		// This is useful for servers which delay potentially unwanted clients when they perform commands
		// other than AUTH.
		noNoop bool

		// pass represents a password or a secret token used for the SMTP authentication.
		pass string

		// port specifies the network port that is used to establish the connection with the SMTP server.
		port int

		// requestDSN indicates wether we want to request DSN (Delivery Status Notifications).
		requestDSN bool

		// smtpAuth is the authentication type that is used to authenticate the user with SMTP server. It
		// satisfies the smtp.Auth interface.
		//
		// Unless you plan to write you own custom authentication method, it is advised to not set this manually.
		// You should use one of go-mail's SMTPAuthType, instead.
		smtpAuth smtp.Auth

		// smtpAuthType specifies the authentication type to be used for SMTP authentication.
		smtpAuthType SMTPAuthType

		// smtpClient is an instance of smtp.Client used for handling the communication with the SMTP server.
		smtpClient *smtp.Client

		// tlspolicy defines the TLSPolicy configuration the Client uses for the STARTTLS protocol.
		// https://datatracker.ietf.org/doc/html/rfc3207#section-2
		tlspolicy TLSPolicy

		// tlsconfig is a pointer to tls.Config that specifies the TLS configuration for the STARTTLS communication.
		tlsconfig *tls.Config

		// useDebugLog indicates whether debug level logging is enabled for the Client.
		useDebugLog bool

		// user represents a username used for the SMTP authentication.
		user string

		// useSSL indicates whether to use SSL/TLS encryption for network communication.
		// https://datatracker.ietf.org/doc/html/rfc8314
		useSSL bool
	}
)

var (
	// ErrInvalidPort is returned when the specified port for the SMTP connection is not valid
	ErrInvalidPort = errors.New("invalid port number")

	// ErrInvalidTimeout is returned when the specified timeout is zero or negative.
	ErrInvalidTimeout = errors.New("timeout cannot be zero or negative")

	// ErrInvalidHELO is returned when the HELO/EHLO value is invalid due to being empty.
	ErrInvalidHELO = errors.New("invalid HELO/EHLO value - must not be empty")

	// ErrInvalidTLSConfig is returned when the provided TLS configuration is invalid or nil.
	ErrInvalidTLSConfig = errors.New("invalid TLS config")

	// ErrNoHostname is returned when the hostname for the client is not provided or empty.
	ErrNoHostname = errors.New("hostname for client cannot be empty")

	// ErrDeadlineExtendFailed is returned when an attempt to extend the connection deadline fails.
	ErrDeadlineExtendFailed = errors.New("connection deadline extension failed")

	// ErrNoActiveConnection indicates that there is no active connection to the SMTP server.
	ErrNoActiveConnection = errors.New("not connected to SMTP server")

	// ErrServerNoUnencoded indicates that the server does not support 8BITMIME for unencoded 8-bit messages.
	ErrServerNoUnencoded = errors.New("message is 8bit unencoded, but server does not support 8BITMIME")

	// ErrInvalidDSNMailReturnOption is returned when an invalid DSNMailReturnOption is provided as argument
	// to the WithDSN Option.
	ErrInvalidDSNMailReturnOption = errors.New("DSN mail return option can only be HDRS or FULL")

	// ErrInvalidDSNRcptNotifyOption is returned when an invalid DSNRcptNotifyOption is provided as argument
	// to the WithDSN Option.
	ErrInvalidDSNRcptNotifyOption = errors.New("DSN rcpt notify option can only be: NEVER, " +
		"SUCCESS, FAILURE or DELAY")

	// ErrInvalidDSNRcptNotifyCombination is returned when an invalid combination of DSNRcptNotifyOption is
	// provided as argument to the WithDSN Option.
	ErrInvalidDSNRcptNotifyCombination = errors.New("DSN rcpt notify option NEVER cannot be " +
		"combined with any of SUCCESS, FAILURE or DELAY")
)

// NewClient creates a new Client instance with the provided host and optional configuration Option functions.
// It initializes default values for connection timeout, port, TLS settings, and HELO/EHLO hostname.
// Option functions, if provided, override default values.
//
// Returns an error if critical defaults are unset.
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

// WithPort sets the port number for the Client and overrides the default port. It validates the port number to
// ensure it is between 1 and 65535. An error is returned if the provided port number is invalid.
func WithPort(port int) Option {
	return func(c *Client) error {
		if port < 1 || port > 65535 {
			return ErrInvalidPort
		}
		c.port = port
		return nil
	}
}

// WithTimeout sets the connection timeout for the Client to the provided duration and overrides the default
// timeout. An error is returned if the provided timeout is invalid.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Client) error {
		if timeout <= 0 {
			return ErrInvalidTimeout
		}
		c.connTimeout = timeout
		return nil
	}
}

// WithSSL enables implicit SSL/TLS for the Client.
func WithSSL() Option {
	return func(c *Client) error {
		c.useSSL = true
		return nil
	}
}

// WithSSLPort enables implicit SSL/TLS with an optional fallback for the Client. The correct port is
// automatically set.
//
// If this option is used with NewClient, the default port 25 will be overriden with port 465. If fallback
// is set to true and the SSL/TLS connection fails, the Client will attempt to connect on port 25 using
// using an unencrypted connection.
//
// Note: If a different port has already been set otherwise using WithPort, the selected port has higher
// precedence and is used to establish the SSL/TLS connection. In this case the authmatic fallback
// mechanism is skipped at all.
func WithSSLPort(fallback bool) Option {
	return func(c *Client) error {
		c.SetSSLPort(true, fallback)
		return nil
	}
}

// WithDebugLog enables debug logging for the Client. The debug logger will log incoming and outgoing
// communication between the Client and the server to os.StdErr.
//
// Note: The SMTP communication might include unencrypted authentication data, depending if you are
// using SMTP authentication and the type of authentication mechanism. This could pose a data
// protection problem. Use debug logging with care.
func WithDebugLog() Option {
	return func(c *Client) error {
		c.useDebugLog = true
		return nil
	}
}

// WithLogger defines a custom logger for the Client. The logger has to satisfy the log.Logger
// interface and is only used when debug logging is enabled on the Client.
//
// By default we use log.Stdlog.
func WithLogger(logger log.Logger) Option {
	return func(c *Client) error {
		c.logger = logger
		return nil
	}
}

// WithHELO sets the HELO/EHLO string used for the the Client.
//
// By default we use os.Hostname to identify the HELO/EHLO string.
func WithHELO(helo string) Option {
	return func(c *Client) error {
		if helo == "" {
			return ErrInvalidHELO
		}
		c.helo = helo
		return nil
	}
}

// WithTLSPolicy sets the TLSPolicy of the Client and overrides the DefaultTLSPolicy
//
// Note: To follow best-practices for SMTP TLS connections, it is recommended to use
// WithTLSPortPolicy instead.
func WithTLSPolicy(policy TLSPolicy) Option {
	return func(c *Client) error {
		c.tlspolicy = policy
		return nil
	}
}

// WithTLSPortPolicy enables explicit TLS via STARTTLS for the Client using the provided TLSPolicy. The
// correct port is automatically set.
//
// If TLSMandatory or TLSOpportunistic are provided as TLSPolicy, port 587 will be used for the connection.
// If the connection fails with TLSOpportunistic, the Client will attempt to connect on port 25 using
// using an unencrypted connection as a fallback. If NoTLS is provided, the Client will always use port 25.
//
// Note: If a different port has already been set otherwise using WithPort, the selected port has higher
// precedence and is used to establish the SSL/TLS connection. In this case the authmatic fallback
// mechanism is skipped at all.
func WithTLSPortPolicy(policy TLSPolicy) Option {
	return func(c *Client) error {
		c.SetTLSPortPolicy(policy)
		return nil
	}
}

// WithTLSConfig sets the tls.Config for the Client and overrides the default. An error is returned
// if the provided tls.Config is invalid.
func WithTLSConfig(tlsconfig *tls.Config) Option {
	return func(c *Client) error {
		if tlsconfig == nil {
			return ErrInvalidTLSConfig
		}
		c.tlsconfig = tlsconfig
		return nil
	}
}

// WithSMTPAuth configures the Client to use the specified SMTPAuthType for the SMTP authentication.
func WithSMTPAuth(authtype SMTPAuthType) Option {
	return func(c *Client) error {
		c.smtpAuthType = authtype
		return nil
	}
}

// WithSMTPAuthCustom sets a custom SMTP authentication mechanism for the client instance. The provided
// authentication mechanism has to satisfy the smtp.Auth interface.
func WithSMTPAuthCustom(smtpAuth smtp.Auth) Option {
	return func(c *Client) error {
		c.smtpAuth = smtpAuth
		return nil
	}
}

// WithUsername sets the username, the Client will use for the SMTP authentication.
func WithUsername(username string) Option {
	return func(c *Client) error {
		c.user = username
		return nil
	}
}

// WithPassword sets the password, the Client will use for the SMTP authentication.
func WithPassword(password string) Option {
	return func(c *Client) error {
		c.pass = password
		return nil
	}
}

// WithDSN enables DSN (Delivery Status Notifications) for the Client as described in the RFC 1891. DSN
// only work if the server supports them.
// https://datatracker.ietf.org/doc/html/rfc1891
//
// By default we set DSNMailReturnOption to DSNMailReturnFull and DSNRcptNotifyOption to DSNRcptNotifySuccess
// and DSNRcptNotifyFailure.
func WithDSN() Option {
	return func(c *Client) error {
		c.requestDSN = true
		c.dsnReturnType = DSNMailReturnFull
		c.dsnRcptNotifyType = []string{string(DSNRcptNotifyFailure), string(DSNRcptNotifySuccess)}
		return nil
	}
}

// WithDSNMailReturnType enables DSN (Delivery Status Notifications) for the Client as described in the
// RFC 1891. DSN only work if the server supports them.
// https://datatracker.ietf.org/doc/html/rfc1891
//
// It will set the DSNMailReturnOption to the provided value.
func WithDSNMailReturnType(option DSNMailReturnOption) Option {
	return func(c *Client) error {
		switch option {
		case DSNMailReturnHeadersOnly:
		case DSNMailReturnFull:
		default:
			return ErrInvalidDSNMailReturnOption
		}

		c.requestDSN = true
		c.dsnReturnType = option
		return nil
	}
}

// WithDSNRcptNotifyType enables DSN (Delivery Status Notifications) for the Client as described in the
// RFC 1891. DSN only work if the server supports them.
// https://datatracker.ietf.org/doc/html/rfc1891
//
// It will set the DSNRcptNotifyOption to the provided values.
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

		c.requestDSN = true
		c.dsnRcptNotifyType = rcptOpts
		return nil
	}
}

// WithoutNoop indicates that the Client should skip the "NOOP" command during the dial.
//
// This is useful for servers which delay potentially unwanted clients when they perform commands
// other than AUTH. For example Microsoft Exchange's Tarpit.
func WithoutNoop() Option {
	return func(c *Client) error {
		c.noNoop = true
		return nil
	}
}

// WithDialContextFunc sets the provided DialContextFunc as DialContext and overrides the default DialContext for
// connecting to the SMTP server
func WithDialContextFunc(dialCtxFunc DialContextFunc) Option {
	return func(c *Client) error {
		c.dialContextFunc = dialCtxFunc
		return nil
	}
}

// TLSPolicy returns the TLSPolicy that is currently set on the Client as string
func (c *Client) TLSPolicy() string {
	return c.tlspolicy.String()
}

// ServerAddr returns the server address that is currently set on the Client in the format "host:port".
func (c *Client) ServerAddr() string {
	return fmt.Sprintf("%s:%d", c.host, c.port)
}

// SetTLSPolicy sets or overrides the TLSPolicy that is currently set on the Client with the given
// TLSPolicy.
//
// Note: To follow best-practices for SMTP TLS connections, it is recommended to use SetTLSPortPolicy
// instead.
func (c *Client) SetTLSPolicy(policy TLSPolicy) {
	c.tlspolicy = policy
}

// SetTLSPortPolicy sets or overrides the TLSPolicy that is currently set on the Client with the given
// TLSPolicy. The correct port is automatically set.
//
// If TLSMandatory or TLSOpportunistic are provided as TLSPolicy, port 587 will be used for the connection.
// If the connection fails with TLSOpportunistic, the Client will attempt to connect on port 25 using
// using an unencrypted connection as a fallback. If NoTLS is provided, the Client will always use port 25.
//
// Note: If a different port has already been set otherwise using WithPort, the selected port has higher
// precedence and is used to establish the SSL/TLS connection. In this case the authmatic fallback
// mechanism is skipped at all.
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

// SetSSL sets or overrides wether the Client should use implicit SSL/TLS.
func (c *Client) SetSSL(ssl bool) {
	c.useSSL = ssl
}

// SetSSLPort sets or overrides wether the Client should use implicit SSL/TLS with optional fallback. The
// correct port is automatically set.
//
// If ssl is set to true, the default port 25 will be overriden with port 465. If fallback is set to true
// and the SSL/TLS connection fails, the Client will attempt to connect on port 25 using using an
// unencrypted connection.
//
// Note: If a different port has already been set otherwise using WithPort, the selected port has higher
// precedence and is used to establish the SSL/TLS connection. In this case the authmatic fallback
// mechanism is skipped at all.
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

// SetDebugLog sets or overrides wether the Client is using debug logging. The debug logger will log
// incoming and outgoing communication between the Client and the server to os.StdErr.
//
// Note: The SMTP communication might include unencrypted authentication data, depending if you are
// using SMTP authentication and the type of authentication mechanism. This could pose a data
// protection problem. Use debug logging with care.
func (c *Client) SetDebugLog(val bool) {
	c.useDebugLog = val
	if c.smtpClient != nil {
		c.smtpClient.SetDebugLog(val)
	}
}

// SetLogger sets of overrides the custom logger currently set for the Client. The logger has to satisfy
// the log.Logger interface and is only used when debug logging is enabled on the Client.
//
// By default we use log.Stdlog.
func (c *Client) SetLogger(logger log.Logger) {
	c.logger = logger
	if c.smtpClient != nil {
		c.smtpClient.SetLogger(logger)
	}
}

// SetTLSConfig sets or overrides the tls.Config that is currently set for the Client with the given value.
// An error is returned if the provided tls.Config is invalid.
func (c *Client) SetTLSConfig(tlsconfig *tls.Config) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

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
	c.smtpAuth = nil
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
		tlsConnState, err := c.smtpClient.GetTLSConnectionState()
		if err != nil {
			switch {
			case errors.Is(err, smtp.ErrNonTLSConnection):
				c.isEncrypted = false
				return nil
			default:
				return fmt.Errorf("failed to get TLS connection state: %w", err)
			}
		}
		c.isEncrypted = tlsConnState.HandshakeComplete
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
		case SMTPAuthSCRAMSHA1:
			if !strings.Contains(smtpAuthType, string(SMTPAuthSCRAMSHA1)) {
				return ErrSCRAMSHA1AuthNotSupported
			}
			c.smtpAuth = smtp.ScramSHA1Auth(c.user, c.pass)
		case SMTPAuthSCRAMSHA256:
			if !strings.Contains(smtpAuthType, string(SMTPAuthSCRAMSHA256)) {
				return ErrSCRAMSHA256AuthNotSupported
			}
			c.smtpAuth = smtp.ScramSHA256Auth(c.user, c.pass)
		case SMTPAuthSCRAMSHA1PLUS:
			if !strings.Contains(smtpAuthType, string(SMTPAuthSCRAMSHA1PLUS)) {
				return ErrSCRAMSHA1PLUSAuthNotSupported
			}
			tlsConnState, err := c.smtpClient.GetTLSConnectionState()
			if err != nil {
				return err
			}
			c.smtpAuth = smtp.ScramSHA1PlusAuth(c.user, c.pass, tlsConnState)
		case SMTPAuthSCRAMSHA256PLUS:
			if !strings.Contains(smtpAuthType, string(SMTPAuthSCRAMSHA256PLUS)) {
				return ErrSCRAMSHA256PLUSAuthNotSupported
			}
			tlsConnState, err := c.smtpClient.GetTLSConnectionState()
			if err != nil {
				return err
			}
			c.smtpAuth = smtp.ScramSHA256PlusAuth(c.user, c.pass, tlsConnState)
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
	c.mutex.Lock()
	defer c.mutex.Unlock()

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

	if c.requestDSN {
		if c.dsnReturnType != "" {
			c.smtpClient.SetDSNMailReturnOption(string(c.dsnReturnType))
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
	rcptNotifyOpt := strings.Join(c.dsnRcptNotifyType, ",")
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
