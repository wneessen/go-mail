// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wneessen/go-mail/log"
	"github.com/wneessen/go-mail/smtp"
)

const (
	// DefaultHost is used as default hostname for the Client
	DefaultHost = "localhost"
	// TestRcpt is a trash mail address to send test mails to
	TestRcpt = "couttifaddebro-1473@yopmail.com"
	// TestServerProto is the protocol used for the simple SMTP test server
	TestServerProto = "tcp"
	// TestServerAddr is the address the simple SMTP test server listens on
	TestServerAddr = "127.0.0.1"
	// TestServerPortBase is the base port for the simple SMTP test server
	TestServerPortBase = 12025
	// TestSenderValid is a test sender email address considered valid for sending test emails.
	TestSenderValid = "valid-from@domain.tld"
	// TestRcptValid is a test recipient email address considered valid for sending test emails.
	TestRcptValid = "valid-to@domain.tld"
)

// PortAdder is an atomic counter used to increment port numbers for the test SMTP server instances.
var PortAdder atomic.Int32

// localhostCert is a PEM-encoded TLS cert generated from src/crypto/tls:
//
//	go run generate_cert.go --rsa-bits 1024 --host 127.0.0.1,::1,example.com \
//		--ca --start-date "Jan 1 00:00:00 1970" --duration=1000000h
var localhostCert = []byte(`
-----BEGIN CERTIFICATE-----
MIICFDCCAX2gAwIBAgIRAK0xjnaPuNDSreeXb+z+0u4wDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAgFw03MDAxMDEwMDAwMDBaGA8yMDg0MDEyOTE2
MDAwMFowEjEQMA4GA1UEChMHQWNtZSBDbzCBnzANBgkqhkiG9w0BAQEFAAOBjQAw
gYkCgYEA0nFbQQuOWsjbGtejcpWz153OlziZM4bVjJ9jYruNw5n2Ry6uYQAffhqa
JOInCmmcVe2siJglsyH9aRh6vKiobBbIUXXUU1ABd56ebAzlt0LobLlx7pZEMy30
LqIi9E6zmL3YvdGzpYlkFRnRrqwEtWYbGBf3znO250S56CCWH2UCAwEAAaNoMGYw
DgYDVR0PAQH/BAQDAgKkMBMGA1UdJQQMMAoGCCsGAQUFBwMBMA8GA1UdEwEB/wQF
MAMBAf8wLgYDVR0RBCcwJYILZXhhbXBsZS5jb22HBH8AAAGHEAAAAAAAAAAAAAAA
AAAAAAEwDQYJKoZIhvcNAQELBQADgYEAbZtDS2dVuBYvb+MnolWnCNqvw1w5Gtgi
NmvQQPOMgM3m+oQSCPRTNGSg25e1Qbo7bgQDv8ZTnq8FgOJ/rbkyERw2JckkHpD4
n4qcK27WkEDBtQFlPihIM8hLIuzWoi/9wygiElTy/tVL3y7fGCvY2/k1KBthtZGF
tN8URjVmyEo=
-----END CERTIFICATE-----`)

// localhostKey is the private key for localhostCert.
var localhostKey = []byte(testingKey(`
-----BEGIN RSA TESTING KEY-----
MIICXgIBAAKBgQDScVtBC45ayNsa16NylbPXnc6XOJkzhtWMn2Niu43DmfZHLq5h
AB9+Gpok4icKaZxV7ayImCWzIf1pGHq8qKhsFshRddRTUAF3np5sDOW3QuhsuXHu
lkQzLfQuoiL0TrOYvdi90bOliWQVGdGurAS1ZhsYF/fOc7bnRLnoIJYfZQIDAQAB
AoGBAMst7OgpKyFV6c3JwyI/jWqxDySL3caU+RuTTBaodKAUx2ZEmNJIlx9eudLA
kucHvoxsM/eRxlxkhdFxdBcwU6J+zqooTnhu/FE3jhrT1lPrbhfGhyKnUrB0KKMM
VY3IQZyiehpxaeXAwoAou6TbWoTpl9t8ImAqAMY8hlULCUqlAkEA+9+Ry5FSYK/m
542LujIcCaIGoG1/Te6Sxr3hsPagKC2rH20rDLqXwEedSFOpSS0vpzlPAzy/6Rbb
PHTJUhNdwwJBANXkA+TkMdbJI5do9/mn//U0LfrCR9NkcoYohxfKz8JuhgRQxzF2
6jpo3q7CdTuuRixLWVfeJzcrAyNrVcBq87cCQFkTCtOMNC7fZnCTPUv+9q1tcJyB
vNjJu3yvoEZeIeuzouX9TJE21/33FaeDdsXbRhQEj23cqR38qFHsF1qAYNMCQQDP
QXLEiJoClkR2orAmqjPLVhR3t2oB3INcnEjLNSq8LHyQEfXyaFfu4U9l5+fRPL2i
jiC0k/9L5dHUsF0XZothAkEA23ddgRs+Id/HxtojqqUT27B8MT/IGNrYsp4DvS/c
qgkeluku4GjxRlDMBuXk94xOBEinUs+p/hwP1Alll80Tpg==
-----END RSA TESTING KEY-----`))

// logLine represents a log entry with time, level, message, and direction details.
type logLine struct {
	Time      time.Time `json:"time"`
	Level     string    `json:"level"`
	Message   string    `json:"msg"`
	Direction struct {
		From string `json:"from"`
		To   string `json:"to"`
	} `json:"direction"`
}

type logData struct {
	Lines []logLine `json:"lines"`
}

func TestNewClient(t *testing.T) {
	t.Run("create new Client", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if client.smtpAuthType != SMTPAuthNoAuth {
			t.Errorf("new Client failed. Expected smtpAuthType: %s, got: %s", SMTPAuthNoAuth,
				client.smtpAuthType)
		}
		if client.connTimeout != DefaultTimeout {
			t.Errorf("new Client failed. Expected connTimeout: %s, got: %s", DefaultTimeout.String(),
				client.connTimeout.String())
		}
		if client.host != DefaultHost {
			t.Errorf("new Client failed. Expected host: %s, got: %s", DefaultHost, client.host)
		}
		if client.port != DefaultPort {
			t.Errorf("new Client failed. Expected port: %d, got: %d", DefaultPort, client.port)
		}
		if client.tlsconfig == nil {
			t.Fatal("new Client failed. Expected tlsconfig but got nil")
		}
		if client.tlsconfig.MinVersion != DefaultTLSMinVersion {
			t.Errorf("new Client failed. Expected tlsconfig min TLS version: %d, got: %d",
				DefaultTLSMinVersion, client.tlsconfig.MinVersion)
		}
		if client.tlsconfig.ServerName != DefaultHost {
			t.Errorf("new Client failed. Expected tlsconfig server name: %s, got: %s",
				DefaultHost, client.tlsconfig.ServerName)
		}
		if client.tlspolicy != DefaultTLSPolicy {
			t.Errorf("new Client failed. Expected tlsconfig policy: %s, got: %s", DefaultTLSPolicy,
				client.tlspolicy)
		}

		hostname, err := os.Hostname()
		if err != nil {
			t.Fatalf("failed to get hostname: %s", err)
		}
		if client.helo != hostname {
			t.Errorf("new Client failed. Expected helo: %s, got: %s", hostname, client.helo)
		}
	})
	t.Run("NewClient with empty hostname should fail", func(t *testing.T) {
		_, err := NewClient("")
		if err == nil {
			t.Fatalf("NewClient with empty hostname should fail")
		}
		if !errors.Is(err, ErrNoHostname) {
			t.Errorf("NewClient with empty hostname should fail with error: %s, got: %s", ErrNoHostname, err)
		}
	})
	t.Run("NewClient with option", func(t *testing.T) {
		hostname := "mail.example.com"
		netDailer := net.Dialer{}
		tlsDailer := tls.Dialer{NetDialer: &netDailer, Config: &tls.Config{}}
		tests := []struct {
			name       string
			option     Option
			expectFunc func(c *Client) error
			shouldfail bool
			expectErr  *error
		}{
			{"nil option", nil, nil, false, nil},
			{
				"WithPort", WithPort(465),
				func(c *Client) error {
					if c.port != 465 {
						return fmt.Errorf("failed to set custom port. Want: %d, got: %d", 465, c.port)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithPort but too high port number", WithPort(100000), nil, true,
				&ErrInvalidPort,
			},
			{
				"WithTimeout", WithTimeout(time.Second * 100),
				func(c *Client) error {
					if c.connTimeout != time.Second*100 {
						return fmt.Errorf("failed to set custom timeout. Want: %d, got: %d", time.Second*100,
							c.connTimeout)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithTimeout but invalid timeout", WithTimeout(-10), nil, true,
				&ErrInvalidTimeout,
			},
			{
				"WithSSL", WithSSL(),
				func(c *Client) error {
					if !c.useSSL {
						return fmt.Errorf("failed to set useSSL. Want: %t, got: %t", true, c.useSSL)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithSSLPort with no fallback", WithSSLPort(false),
				func(c *Client) error {
					if !c.useSSL {
						return fmt.Errorf("failed to set useSSL. Want: %t, got: %t", true, c.useSSL)
					}
					if c.port != 465 {
						return fmt.Errorf("failed to set ssl port. Want: %d, got: %d", 465, c.port)
					}
					if c.fallbackPort != 0 {
						return fmt.Errorf("failed to set ssl fallbackport. Want: %d, got: %d", 0,
							c.fallbackPort)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithSSLPort with fallback", WithSSLPort(true),
				func(c *Client) error {
					if !c.useSSL {
						return fmt.Errorf("failed to set useSSL. Want: %t, got: %t", true, c.useSSL)
					}
					if c.port != 465 {
						return fmt.Errorf("failed to set ssl port. Want: %d, got: %d", 465, c.port)
					}
					if c.fallbackPort != 25 {
						return fmt.Errorf("failed to set ssl fallbackport. Want: %d, got: %d", 0,
							c.fallbackPort)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithDebugLog", WithDebugLog(),
				func(c *Client) error {
					if !c.useDebugLog {
						return fmt.Errorf("failed to set enable debug log. Want: %t, got: %t", true,
							c.useDebugLog)
					}
					if c.logAuthData {
						return fmt.Errorf("failed to set enable debug log. Want logAuthData: %t, got: %t", true,
							c.logAuthData)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithLogger log.Stdlog", WithLogger(log.New(os.Stderr, log.LevelDebug)),
				func(c *Client) error {
					if c.logger == nil {
						return errors.New("failed to set logger. Want logger bug got got nil")
					}
					loggerType := reflect.TypeOf(c.logger).String()
					if loggerType != "*log.Stdlog" {
						return fmt.Errorf("failed to set logger. Want logger type: %s, got: %s",
							"*log.Stdlog", loggerType)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithLogger log.JSONlog", WithLogger(log.NewJSON(os.Stderr, log.LevelDebug)),
				func(c *Client) error {
					if c.logger == nil {
						return errors.New("failed to set logger. Want logger bug got got nil")
					}
					loggerType := reflect.TypeOf(c.logger).String()
					if loggerType != "*log.JSONlog" {
						return fmt.Errorf("failed to set logger. Want logger type: %s, got: %s",
							"*log.JSONlog", loggerType)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithHELO", WithHELO(hostname),
				func(c *Client) error {
					if c.helo != hostname {
						return fmt.Errorf("failed to set custom HELO. Want: %s, got: %s", hostname, c.helo)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithHELO fail with empty hostname", WithHELO(""), nil,
				true, &ErrInvalidHELO,
			},
			{
				"WithTLSPolicy TLSMandatory", WithTLSPolicy(TLSMandatory),
				func(c *Client) error {
					if c.tlspolicy != TLSMandatory {
						return fmt.Errorf("failed to set custom TLS policy. Want: %s, got: %s", TLSMandatory,
							c.tlspolicy)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithTLSPolicy TLSOpportunistic", WithTLSPolicy(TLSOpportunistic),
				func(c *Client) error {
					if c.tlspolicy != TLSOpportunistic {
						return fmt.Errorf("failed to set custom TLS policy. Want: %s, got: %s", TLSOpportunistic,
							c.tlspolicy)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithTLSPolicy NoTLS", WithTLSPolicy(NoTLS),
				func(c *Client) error {
					if c.tlspolicy != NoTLS {
						return fmt.Errorf("failed to set custom TLS policy. Want: %s, got: %s", TLSOpportunistic,
							c.tlspolicy)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithTLSPortPolicy TLSMandatory", WithTLSPortPolicy(TLSMandatory),
				func(c *Client) error {
					if c.tlspolicy != TLSMandatory {
						return fmt.Errorf("failed to set custom TLS policy. Want: %s, got: %s", TLSMandatory,
							c.tlspolicy)
					}
					if c.port != 587 {
						return fmt.Errorf("failed to set custom TLS policy. Want port: %d, got: %d", 587,
							c.port)
					}
					if c.fallbackPort != 0 {
						return fmt.Errorf("failed to set custom TLS policy. Want fallback port: %d, got: %d",
							0, c.fallbackPort)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithTLSPortPolicy TLSOpportunistic", WithTLSPortPolicy(TLSOpportunistic),
				func(c *Client) error {
					if c.tlspolicy != TLSOpportunistic {
						return fmt.Errorf("failed to set custom TLS policy. Want: %s, got: %s", TLSOpportunistic,
							c.tlspolicy)
					}
					if c.port != 587 {
						return fmt.Errorf("failed to set custom TLS policy. Want port: %d, got: %d", 587,
							c.port)
					}
					if c.fallbackPort != 25 {
						return fmt.Errorf("failed to set custom TLS policy. Want fallback port: %d, got: %d",
							25, c.fallbackPort)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithTLSPortPolicy NoTLS", WithTLSPortPolicy(NoTLS),
				func(c *Client) error {
					if c.tlspolicy != NoTLS {
						return fmt.Errorf("failed to set custom TLS policy. Want: %s, got: %s", TLSOpportunistic,
							c.tlspolicy)
					}
					if c.port != 25 {
						return fmt.Errorf("failed to set custom TLS policy. Want port: %d, got: %d", 25,
							c.port)
					}
					if c.fallbackPort != 0 {
						return fmt.Errorf("failed to set custom TLS policy. Want fallback port: %d, got: %d",
							0, c.fallbackPort)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithTLSPortPolicy invalid", WithTLSPortPolicy(-1),
				func(c *Client) error {
					if c.tlspolicy.String() != "UnknownPolicy" {
						return fmt.Errorf("failed to set custom TLS policy. Want: %s, got: %s", "UnknownPolicy",
							c.tlspolicy)
					}
					if c.port != 587 {
						return fmt.Errorf("failed to set custom TLS policy. Want port: %d, got: %d", 587,
							c.port)
					}
					if c.fallbackPort != 0 {
						return fmt.Errorf("failed to set custom TLS policy. Want fallback port: %d, got: %d",
							25, c.fallbackPort)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithTLSConfig with empty tls.Config", WithTLSConfig(&tls.Config{}),
				func(c *Client) error {
					if c.tlsconfig == nil {
						return errors.New("failed to set custom TLS config. Wanted policy but got nil")
					}
					return nil
				},
				false, nil,
			},
			{
				"WithTLSConfig with custom tls.Config", WithTLSConfig(&tls.Config{ServerName: hostname}),
				func(c *Client) error {
					if c.tlsconfig == nil {
						return errors.New("failed to set custom TLS config. Wanted policy but got nil")
					}
					if c.tlsconfig.ServerName != hostname {
						return fmt.Errorf("failed to set custom TLS config. Want hostname: %s, got: %s",
							hostname, c.tlsconfig.ServerName)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithTLSConfig with nil", WithTLSConfig(nil), nil,
				true, &ErrInvalidTLSConfig,
			},
			{
				"WithSMTPAuthCustom with PLAIN auth",
				WithSMTPAuthCustom(smtp.PlainAuth("", "", "", "", false)),
				func(c *Client) error {
					if c.smtpAuthType != SMTPAuthCustom {
						return fmt.Errorf("failed to set custom SMTP auth method. Want smtp auth type: %s, "+
							"got: %s", SMTPAuthCustom, c.smtpAuthType)
					}
					if c.smtpAuth == nil {
						return errors.New("failed to set custom SMTP auth method. Wanted smtp auth method but" +
							" got nil")
					}
					smtpAuthType := reflect.TypeOf(c.smtpAuth).String()
					if smtpAuthType != "*smtp.plainAuth" {
						return fmt.Errorf("failed to set custom SMTP auth method. Want smtp auth method of type: %s, "+
							"got: %s", "*smtp.plainAuth", smtpAuthType)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithSMTPAuthCustom with LOGIN auth",
				WithSMTPAuthCustom(smtp.LoginAuth("", "", "", false)),
				func(c *Client) error {
					if c.smtpAuthType != SMTPAuthCustom {
						return fmt.Errorf("failed to set custom SMTP auth method. Want smtp auth type: %s, "+
							"got: %s", SMTPAuthCustom, c.smtpAuthType)
					}
					if c.smtpAuth == nil {
						return errors.New("failed to set custom SMTP auth method. Wanted smtp auth method but" +
							" got nil")
					}
					smtpAuthType := reflect.TypeOf(c.smtpAuth).String()
					if smtpAuthType != "*smtp.loginAuth" {
						return fmt.Errorf("failed to set custom SMTP auth method. Want smtp auth method of type: %s, "+
							"got: %s", "*smtp.loginAuth", smtpAuthType)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithSMTPAuthCustom with nil", WithSMTPAuthCustom(nil), nil,
				true, &ErrSMTPAuthMethodIsNil,
			},
			{
				"WithUsername", WithUsername("toni.tester"),
				func(c *Client) error {
					if c.user != "toni.tester" {
						return fmt.Errorf("failed to set username. Want username: %s, got: %s",
							"toni.tester", c.user)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithPassword", WithPassword("sU*p3rS3cr3t"),
				func(c *Client) error {
					if c.pass != "sU*p3rS3cr3t" {
						return fmt.Errorf("failed to set password. Want password: %s, got: %s",
							"sU*p3rS3cr3t", c.pass)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithDSN", WithDSN(),
				func(c *Client) error {
					if c.requestDSN != true {
						return fmt.Errorf("failed to enable DSN. Want requestDSN: %t, got: %t", true,
							c.requestDSN)
					}
					if c.dsnReturnType != DSNMailReturnFull {
						return fmt.Errorf("failed to enable DSN. Want dsnReturnType: %s, got: %s",
							DSNMailReturnFull, c.dsnReturnType)
					}
					if len(c.dsnRcptNotifyType) != 2 {
						return fmt.Errorf("failed to enable DSN. Want 2 default DSN Rcpt Notify types, got: %d",
							len(c.dsnRcptNotifyType))
					}
					if c.dsnRcptNotifyType[0] != string(DSNRcptNotifyFailure) {
						return fmt.Errorf("failed to enable DSN. Want DSN Rcpt Notify Failure type: %s, got: %s",
							string(DSNRcptNotifyFailure), c.dsnRcptNotifyType[0])
					}
					if c.dsnRcptNotifyType[1] != string(DSNRcptNotifySuccess) {
						return fmt.Errorf("failed to enable DSN. Want DSN Rcpt Notify Success type: %s, got: %s",
							string(DSNRcptNotifySuccess), c.dsnRcptNotifyType[1])
					}
					return nil
				},
				false, nil,
			},
			{
				"WithDSNMailReturnType DSNMailReturnHeadersOnly",
				WithDSNMailReturnType(DSNMailReturnHeadersOnly),
				func(c *Client) error {
					if c.requestDSN != true {
						return fmt.Errorf("failed to enable DSN. Want requestDSN: %t, got: %t", true,
							c.requestDSN)
					}
					if c.dsnReturnType != DSNMailReturnHeadersOnly {
						return fmt.Errorf("failed to enable DSN. Want dsnReturnType: %s, got: %s",
							DSNMailReturnHeadersOnly, c.dsnReturnType)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithDSNMailReturnType DSNMailReturnFull",
				WithDSNMailReturnType(DSNMailReturnFull),
				func(c *Client) error {
					if c.requestDSN != true {
						return fmt.Errorf("failed to enable DSN. Want requestDSN: %t, got: %t", true,
							c.requestDSN)
					}
					if c.dsnReturnType != DSNMailReturnFull {
						return fmt.Errorf("failed to enable DSN. Want dsnReturnType: %s, got: %s",
							DSNMailReturnFull, c.dsnReturnType)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithDSNMailReturnType invalid", WithDSNMailReturnType("invalid"), nil,
				true, &ErrInvalidDSNMailReturnOption,
			},
			{
				"WithDSNRcptNotifyType DSNRcptNotifyNever",
				WithDSNRcptNotifyType(DSNRcptNotifyNever),
				func(c *Client) error {
					if c.requestDSN != true {
						return fmt.Errorf("failed to enable DSN. Want requestDSN: %t, got: %t", true,
							c.requestDSN)
					}
					if len(c.dsnRcptNotifyType) != 1 {
						return fmt.Errorf("failed to enable DSN. Want 1 DSN Rcpt Notify type, got: %d",
							len(c.dsnRcptNotifyType))
					}
					if c.dsnRcptNotifyType[0] != string(DSNRcptNotifyNever) {
						return fmt.Errorf("failed to enable DSN. Want DSN Rcpt Notify Never type: %s, got: %s",
							string(DSNRcptNotifyNever), c.dsnRcptNotifyType[0])
					}
					return nil
				},
				false, nil,
			},
			{
				"WithDSNRcptNotifyType DSNRcptNotifySuccess, DSNRcptNotifyFailure",
				WithDSNRcptNotifyType(DSNRcptNotifySuccess, DSNRcptNotifyFailure),
				func(c *Client) error {
					if c.requestDSN != true {
						return fmt.Errorf("failed to enable DSN. Want requestDSN: %t, got: %t", true,
							c.requestDSN)
					}
					if len(c.dsnRcptNotifyType) != 2 {
						return fmt.Errorf("failed to enable DSN. Want 2 DSN Rcpt Notify type, got: %d",
							len(c.dsnRcptNotifyType))
					}
					if c.dsnRcptNotifyType[0] != string(DSNRcptNotifySuccess) {
						return fmt.Errorf("failed to enable DSN. Want DSN Rcpt Notify Success type: %s, got: %s",
							string(DSNRcptNotifySuccess), c.dsnRcptNotifyType[0])
					}
					if c.dsnRcptNotifyType[1] != string(DSNRcptNotifyFailure) {
						return fmt.Errorf("failed to enable DSN. Want DSN Rcpt Notify Failure type: %s, got: %s",
							string(DSNRcptNotifyFailure), c.dsnRcptNotifyType[1])
					}
					return nil
				},
				false, nil,
			},
			{
				"WithDSNRcptNotifyType DSNRcptNotifyDelay",
				WithDSNRcptNotifyType(DSNRcptNotifyDelay),
				func(c *Client) error {
					if c.requestDSN != true {
						return fmt.Errorf("failed to enable DSN. Want requestDSN: %t, got: %t", true,
							c.requestDSN)
					}
					if len(c.dsnRcptNotifyType) != 1 {
						return fmt.Errorf("failed to enable DSN. Want 1 DSN Rcpt Notify type, got: %d",
							len(c.dsnRcptNotifyType))
					}
					if c.dsnRcptNotifyType[0] != string(DSNRcptNotifyDelay) {
						return fmt.Errorf("failed to enable DSN. Want DSN Rcpt Notify Delay type: %s, got: %s",
							string(DSNRcptNotifyDelay), c.dsnRcptNotifyType[0])
					}
					return nil
				},
				false, nil,
			},
			{
				"WithDSNRcptNotifyType invalid", WithDSNRcptNotifyType("invalid"), nil,
				true, &ErrInvalidDSNRcptNotifyOption,
			},
			{
				"WithDSNRcptNotifyType mix valid and invalid",
				WithDSNRcptNotifyType(DSNRcptNotifyDelay, "invalid"), nil,
				true, &ErrInvalidDSNRcptNotifyOption,
			},
			{
				"WithDSNRcptNotifyType mix NEVER with SUCCESS",
				WithDSNRcptNotifyType(DSNRcptNotifyNever, DSNRcptNotifySuccess), nil,
				true, &ErrInvalidDSNRcptNotifyCombination,
			},
			{
				"WithDSNRcptNotifyType mix NEVER with FAIL",
				WithDSNRcptNotifyType(DSNRcptNotifyNever, DSNRcptNotifyFailure), nil,
				true, &ErrInvalidDSNRcptNotifyCombination,
			},
			{
				"WithDSNRcptNotifyType mix NEVER with DELAY",
				WithDSNRcptNotifyType(DSNRcptNotifyNever, DSNRcptNotifyDelay), nil,
				true, &ErrInvalidDSNRcptNotifyCombination,
			},
			{
				"WithoutNoop", WithoutNoop(),
				func(c *Client) error {
					if !c.noNoop {
						return fmt.Errorf("failed to disable Noop. Want noNoop: %t, got: %t", false, c.noNoop)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithDialContextFunc with net.Dailer", WithDialContextFunc(netDailer.DialContext),
				func(c *Client) error {
					if c.dialContextFunc == nil {
						return errors.New("failed to set dial context func, got: nil")
					}
					ctxType := reflect.TypeOf(c.dialContextFunc).String()
					if ctxType != "mail.DialContextFunc" {
						return fmt.Errorf("failed to set dial context func, want: %s, got: %s",
							"mail.DialContextFunc", ctxType)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithDialContextFunc with tls.Dailer", WithDialContextFunc(tlsDailer.DialContext),
				func(c *Client) error {
					if c.dialContextFunc == nil {
						return errors.New("failed to set dial context func, got: nil")
					}
					ctxType := reflect.TypeOf(c.dialContextFunc).String()
					if ctxType != "mail.DialContextFunc" {
						return fmt.Errorf("failed to set dial context func, want: %s, got: %s",
							"mail.DialContextFunc", ctxType)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithDialContextFunc with custom dialer",
				WithDialContextFunc(
					func(ctx context.Context, network, address string) (net.Conn, error) {
						return nil, nil
					},
				),
				func(c *Client) error {
					if c.dialContextFunc == nil {
						return errors.New("failed to set dial context func, got: nil")
					}
					ctxType := reflect.TypeOf(c.dialContextFunc).String()
					if ctxType != "mail.DialContextFunc" {
						return fmt.Errorf("failed to set dial context func, want: %s, got: %s",
							"mail.DialContextFunc", ctxType)
					}
					return nil
				},
				false, nil,
			},
			{
				"WithDialContextFunc with nil", WithDialContextFunc(nil), nil,
				true, &ErrDialContextFuncIsNil,
			},
			{
				"WithLogAuthData", WithLogAuthData(),
				func(c *Client) error {
					if !c.logAuthData {
						return fmt.Errorf("failed to enable auth data logging. Want logAuthData: %t, got: %t",
							true, c.logAuthData)
					}
					return nil
				},
				false, nil,
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				client, err := NewClient(DefaultHost, tt.option)
				if !tt.shouldfail && err != nil {
					t.Fatalf("failed to create new client: %s", err)
				}
				if tt.shouldfail && err == nil {
					t.Errorf("client creation was supposed to fail, but it didn't")
				}
				if tt.shouldfail && tt.expectErr != nil {
					if !errors.Is(err, *tt.expectErr) {
						t.Errorf("error for NewClient mismatch. Expected: %s, got: %s",
							*tt.expectErr, err)
					}
				}
				if tt.expectFunc != nil {
					if err = tt.expectFunc(client); err != nil {
						t.Errorf("NewClient with custom option failed: %s", err)
					}
				}
			})
		}
	})
	t.Run("NewClient WithSMTPAuth", func(t *testing.T) {
		tests := []struct {
			name     string
			option   Option
			expected SMTPAuthType
		}{
			{"CRAM-MD5", WithSMTPAuth(SMTPAuthCramMD5), SMTPAuthCramMD5},
			{"LOGIN", WithSMTPAuth(SMTPAuthLogin), SMTPAuthLogin},
			{"LOGIN-NOENC", WithSMTPAuth(SMTPAuthLoginNoEnc), SMTPAuthLoginNoEnc},
			{"NOAUTH", WithSMTPAuth(SMTPAuthNoAuth), SMTPAuthNoAuth},
			{"PLAIN", WithSMTPAuth(SMTPAuthPlain), SMTPAuthPlain},
			{"PLAIN-NOENC", WithSMTPAuth(SMTPAuthPlainNoEnc), SMTPAuthPlainNoEnc},
			{"SCRAM-SHA-1", WithSMTPAuth(SMTPAuthSCRAMSHA1), SMTPAuthSCRAMSHA1},
			{"SCRAM-SHA-1-PLUS", WithSMTPAuth(SMTPAuthSCRAMSHA1PLUS), SMTPAuthSCRAMSHA1PLUS},
			{"SCRAM-SHA-256", WithSMTPAuth(SMTPAuthSCRAMSHA256), SMTPAuthSCRAMSHA256},
			{"SCRAM-SHA-256-PLUS", WithSMTPAuth(SMTPAuthSCRAMSHA256PLUS), SMTPAuthSCRAMSHA256PLUS},
			{"XOAUTH2", WithSMTPAuth(SMTPAuthXOAUTH2), SMTPAuthXOAUTH2},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				client, err := NewClient(DefaultHost, tt.option)
				if err != nil {
					t.Fatalf("failed to create new client: %s", err)
				}
				if client.smtpAuthType != tt.expected {
					t.Errorf("failed to set custom SMTP auth type. Want: %s, got: %s",
						tt.expected, client.smtpAuthType)
				}
			})
		}
	})
}

func TestClient_TLSPolicy(t *testing.T) {
	t.Run("WithTLSPolicy fmt.Stringer interface", func(t *testing.T) {})
	tests := []struct {
		name  string
		value TLSPolicy
		want  string
	}{
		{"TLSMandatory", TLSMandatory, "TLSMandatory"},
		{"TLSOpportunistic", TLSOpportunistic, "TLSOpportunistic"},
		{"NoTLS", NoTLS, "NoTLS"},
		{"Invalid", -1, "UnknownPolicy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(DefaultHost, WithTLSPolicy(tt.value))
			if err != nil {
				t.Fatalf("failed to create new client: %s", err)
			}
			got := client.TLSPolicy()
			if !strings.EqualFold(got, tt.want) {
				t.Errorf("failed to get expected TLS policy string. Want: %s, got: %s", tt.want, got)
			}
		})
	}
}

func TestClient_ServerAddr(t *testing.T) {
	t.Run("ServerAddr of default client", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		got := client.ServerAddr()
		expected := fmt.Sprintf("%s:%d", DefaultHost, DefaultPort)
		if !strings.EqualFold(expected, got) {
			t.Errorf("failed to get expected server address. Want: %s, got: %s", expected, got)
		}
	})
	t.Run("ServerAddr of with custom port", func(t *testing.T) {
		client, err := NewClient(DefaultHost, WithPort(587))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		got := client.ServerAddr()
		expected := fmt.Sprintf("%s:%d", DefaultHost, 587)
		if !strings.EqualFold(expected, got) {
			t.Errorf("failed to get expected server address. Want: %s, got: %s", expected, got)
		}
	})
	t.Run("ServerAddr of with port policy TLSMandatory", func(t *testing.T) {
		client, err := NewClient(DefaultHost, WithTLSPortPolicy(TLSMandatory))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		got := client.ServerAddr()
		expected := fmt.Sprintf("%s:%d", DefaultHost, 587)
		if !strings.EqualFold(expected, got) {
			t.Errorf("failed to get expected server address. Want: %s, got: %s", expected, got)
		}
	})
	t.Run("ServerAddr of with port policy TLSOpportunistic", func(t *testing.T) {
		client, err := NewClient(DefaultHost, WithTLSPortPolicy(TLSOpportunistic))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		got := client.ServerAddr()
		expected := fmt.Sprintf("%s:%d", DefaultHost, 587)
		if !strings.EqualFold(expected, got) {
			t.Errorf("failed to get expected server address. Want: %s, got: %s", expected, got)
		}
	})
	t.Run("ServerAddr of with port policy NoTLS", func(t *testing.T) {
		client, err := NewClient(DefaultHost, WithTLSPortPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		got := client.ServerAddr()
		expected := fmt.Sprintf("%s:%d", DefaultHost, 25)
		if !strings.EqualFold(expected, got) {
			t.Errorf("failed to get expected server address. Want: %s, got: %s", expected, got)
		}
	})
	t.Run("ServerAddr of with SSL", func(t *testing.T) {
		client, err := NewClient(DefaultHost, WithSSLPort(false))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		got := client.ServerAddr()
		expected := fmt.Sprintf("%s:%d", DefaultHost, 465)
		if !strings.EqualFold(expected, got) {
			t.Errorf("failed to get expected server address. Want: %s, got: %s", expected, got)
		}
	})
}

func TestClient_SetTLSPolicy(t *testing.T) {
	t.Run("SetTLSPolicy TLSMandatory", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetTLSPolicy(TLSMandatory)
		if client.tlspolicy != TLSMandatory {
			t.Errorf("failed to set expected TLS policy. Want: %s, got: %s",
				TLSMandatory, client.tlspolicy)
		}
	})
	t.Run("SetTLSPolicy TLSOpportunistic", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetTLSPolicy(TLSOpportunistic)
		if client.tlspolicy != TLSOpportunistic {
			t.Errorf("failed to set expected TLS policy. Want: %s, got: %s",
				TLSOpportunistic, client.tlspolicy)
		}
	})
	t.Run("SetTLSPolicy NoTLS", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetTLSPolicy(NoTLS)
		if client.tlspolicy != NoTLS {
			t.Errorf("failed to set expected TLS policy. Want: %s, got: %s",
				NoTLS, client.tlspolicy)
		}
	})
	t.Run("SetTLSPolicy to override WithTLSPolicy", func(t *testing.T) {
		client, err := NewClient(DefaultHost, WithTLSPolicy(TLSOpportunistic))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetTLSPolicy(TLSMandatory)
		if client.tlspolicy != TLSMandatory {
			t.Errorf("failed to set expected TLS policy. Want: %s, got: %s",
				TLSMandatory, client.tlspolicy)
		}
	})
}

func TestClient_SetTLSPortPolicy(t *testing.T) {
	t.Run("SetTLSPortPolicy TLSMandatory", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetTLSPortPolicy(TLSMandatory)
		if client.tlspolicy != TLSMandatory {
			t.Errorf("failed to set expected TLS policy. Want policy: %s, got: %s",
				TLSMandatory, client.tlspolicy)
		}
		if client.port != 587 {
			t.Errorf("failed to set expected TLS policy. Want port: %d, got: %d", 587, client.port)
		}
		if client.fallbackPort != 0 {
			t.Errorf("failed to set expected TLS policy. Want fallback port: %d, got: %d", 0,
				client.fallbackPort)
		}
	})
	t.Run("SetTLSPortPolicy TLSOpportunistic", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetTLSPortPolicy(TLSOpportunistic)
		if client.tlspolicy != TLSOpportunistic {
			t.Errorf("failed to set expected TLS policy. Want policy: %s, got: %s",
				TLSOpportunistic, client.tlspolicy)
		}
		if client.port != 587 {
			t.Errorf("failed to set expected TLS policy. Want port: %d, got: %d", 587, client.port)
		}
		if client.fallbackPort != 25 {
			t.Errorf("failed to set expected TLS policy. Want fallback port: %d, got: %d", 25,
				client.fallbackPort)
		}
	})
	t.Run("SetTLSPortPolicy NoTLS", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetTLSPortPolicy(NoTLS)
		if client.tlspolicy != NoTLS {
			t.Errorf("failed to set expected TLS policy. Want policy: %s, got: %s",
				NoTLS, client.tlspolicy)
		}
		if client.port != 25 {
			t.Errorf("failed to set expected TLS policy. Want port: %d, got: %d", 25, client.port)
		}
		if client.fallbackPort != 0 {
			t.Errorf("failed to set expected TLS policy. Want fallback port: %d, got: %d", 0,
				client.fallbackPort)
		}
	})
	t.Run("SetTLSPortPolicy to override WithTLSPortPolicy", func(t *testing.T) {
		client, err := NewClient(DefaultHost, WithTLSPortPolicy(TLSOpportunistic), WithPort(25))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetTLSPortPolicy(TLSMandatory)
		if client.tlspolicy != TLSMandatory {
			t.Errorf("failed to set expected TLS policy. Want policy: %s, got: %s",
				TLSMandatory, client.tlspolicy)
		}
		if client.port != 587 {
			t.Errorf("failed to set expected TLS policy. Want port: %d, got: %d", 587, client.port)
		}
		if client.fallbackPort != 0 {
			t.Errorf("failed to set expected TLS policy. Want fallback port: %d, got: %d", 0,
				client.fallbackPort)
		}
	})
}

func TestClient_SetSSL(t *testing.T) {
	t.Run("SetSSL true", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetSSL(true)
		if !client.useSSL {
			t.Errorf("failed to set expected useSSL: %t", true)
		}
	})
	t.Run("SetSSL false", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetSSL(false)
		if client.useSSL {
			t.Errorf("failed to set expected useSSL: %t", false)
		}
	})
	t.Run("SetSSL to override WithSSL", func(t *testing.T) {
		client, err := NewClient(DefaultHost, WithSSL())
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetSSL(false)
		if client.useSSL {
			t.Errorf("failed to set expected useSSL: %t", false)
		}
	})
}

func TestClient_SetSSLPort(t *testing.T) {
	t.Run("SetSSLPort true no fallback", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetSSLPort(true, false)
		if !client.useSSL {
			t.Errorf("failed to set expected useSSL: %t", true)
		}
		if client.port != 465 {
			t.Errorf("failed to set expected port: %d, got: %d", 465, client.port)
		}
		if client.fallbackPort != 0 {
			t.Errorf("failed to set expected fallback: %d, got: %d", 0, client.fallbackPort)
		}
	})
	t.Run("SetSSLPort true with fallback", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetSSLPort(true, true)
		if !client.useSSL {
			t.Errorf("failed to set expected useSSL: %t", true)
		}
		if client.port != 465 {
			t.Errorf("failed to set expected port: %d, got: %d", 465, client.port)
		}
		if client.fallbackPort != 25 {
			t.Errorf("failed to set expected fallback: %d, got: %d", 25, client.fallbackPort)
		}
	})
	t.Run("SetSSLPort false no fallback", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetSSLPort(false, false)
		if client.useSSL {
			t.Errorf("failed to set expected useSSL: %t", false)
		}
		if client.port != 25 {
			t.Errorf("failed to set expected port: %d, got: %d", 25, client.port)
		}
		if client.fallbackPort != 0 {
			t.Errorf("failed to set expected fallback: %d, got: %d", 0, client.fallbackPort)
		}
	})
	t.Run("SetSSLPort false with fallback (makes no sense)", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetSSLPort(false, true)
		if client.useSSL {
			t.Errorf("failed to set expected useSSL: %t", false)
		}
		if client.port != 25 {
			t.Errorf("failed to set expected port: %d, got: %d", 25, client.port)
		}
		if client.fallbackPort != 25 {
			t.Errorf("failed to set expected fallback: %d, got: %d", 25, client.fallbackPort)
		}
	})
	t.Run("SetSSLPort to override WithSSL", func(t *testing.T) {
		client, err := NewClient(DefaultHost, WithSSL())
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetSSLPort(false, false)
		if client.useSSL {
			t.Errorf("failed to set expected useSSL: %t", false)
		}
		if client.port != 25 {
			t.Errorf("failed to set expected port: %d, got: %d", 25, client.port)
		}
		if client.fallbackPort != 0 {
			t.Errorf("failed to set expected fallback: %d, got: %d", 0, client.fallbackPort)
		}
	})
	t.Run("SetSSLPort with custom port", func(t *testing.T) {
		client, err := NewClient(DefaultHost, WithPort(123))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetSSLPort(false, false)
		if client.useSSL {
			t.Errorf("failed to set expected useSSL: %t", false)
		}
		if client.port != 123 {
			t.Errorf("failed to set expected port: %d, got: %d", 123, client.port)
		}
		if client.fallbackPort != 0 {
			t.Errorf("failed to set expected fallback: %d, got: %d", 0, client.fallbackPort)
		}
	})
}

func TestClient_SetDebugLog(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	PortAdder.Add(1)
	serverPort := int(TestServerPortBase + PortAdder.Load())
	featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, t, &serverProps{FeatureSet: featureSet, ListenPort: serverPort}); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 30)

	t.Run("SetDebugLog true", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetDebugLog(true)
		if !client.useDebugLog {
			t.Errorf("failed to set expected useDebugLog: %t", true)
		}
	})
	t.Run("SetDebugLog false", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetDebugLog(false)
		if client.useDebugLog {
			t.Errorf("failed to set expected useDebugLog: %t", false)
		}
	})
	t.Run("SetDebugLog true with active SMTP client", func(t *testing.T) {
		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		buffer := bytes.NewBuffer(nil)
		client.SetLogger(log.New(buffer, log.LevelDebug))
		client.SetDebugLog(true)

		if err = client.DialWithContext(ctxDial); err != nil {
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client to test server: %s", err)
			}
		})

		if !client.useDebugLog {
			t.Errorf("failed to set expected useDebugLog: %t", true)
		}
		if !strings.Contains(buffer.String(), "DEBUG: C --> S: EHLO") {
			t.Errorf("failed to enable debug log. Expected string: %s in log buffer but didn't find it. "+
				"Buffer: %s", "DEBUG: C --> S: EHLO", buffer.String())
		}
	})
	t.Run("SetDebugLog false to override WithDebugLog", func(t *testing.T) {
		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS), WithDebugLog())
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		buffer := bytes.NewBuffer(nil)
		client.SetLogger(log.New(buffer, log.LevelDebug))
		client.SetDebugLog(false)

		if err = client.DialWithContext(ctxDial); err != nil {
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client to test server: %s", err)
			}
		})

		if client.useDebugLog {
			t.Errorf("failed to set expected useDebugLog: %t", false)
		}
		if buffer.Len() > 0 {
			t.Errorf("failed to disable debug logger. Expected buffer to be empty but got: %d", buffer.Len())
		}
	})
	t.Run("SetDebugLog true active SMTP client after dial", func(t *testing.T) {
		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}

		if err = client.DialWithContext(ctxDial); err != nil {
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client to test server: %s", err)
			}
		})

		buffer := bytes.NewBuffer(nil)
		client.SetLogger(log.New(buffer, log.LevelDebug))
		client.SetDebugLog(true)
		if err = client.smtpClient.Noop(); err != nil {
			t.Errorf("failed to send NOOP command: %s", err)
		}

		if !client.useDebugLog {
			t.Errorf("failed to set expected useDebugLog: %t", true)
		}
		if !strings.Contains(buffer.String(), "DEBUG: C --> S: NOOP") {
			t.Errorf("failed to enable debug log. Expected string: %s in log buffer but didn't find it. "+
				"Buffer: %s", "DEBUG: C --> S: NOOP", buffer.String())
		}
	})
}

func TestClient_SetTLSConfig(t *testing.T) {
	t.Run("SetTLSConfig with &tls.Config", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.SetTLSConfig(&tls.Config{}); err != nil {
			t.Errorf("failed to set expected TLSConfig: %s", err)
		}
		if client.tlsconfig == nil {
			t.Fatalf("failed to set expected TLSConfig. TLSConfig is nil")
		}
	})
	t.Run("SetTLSConfig with InsecureSkipVerify", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.SetTLSConfig(&tls.Config{InsecureSkipVerify: true}); err != nil {
			t.Errorf("failed to set expected TLSConfig: %s", err)
		}
		if client.tlsconfig == nil {
			t.Fatalf("failed to set expected TLSConfig. TLSConfig is nil")
		}
		if !client.tlsconfig.InsecureSkipVerify {
			t.Errorf("failed to set expected TLSConfig. Expected InsecureSkipVerify: %t, got: %t", true,
				client.tlsconfig.InsecureSkipVerify)
		}
	})
	t.Run("SetTLSConfig with nil should fail", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		err = client.SetTLSConfig(nil)
		if err == nil {
			t.Errorf("SetTLSConfig with nil should fail")
		}
		if !errors.Is(err, ErrInvalidTLSConfig) {
			t.Errorf("SetTLSConfig was expected to fail with %s, got: %s", ErrInvalidTLSConfig, err)
		}
	})
}

func TestClient_SetUsername(t *testing.T) {
	t.Run("SetUsername", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetUsername("toni.tester")
		if client.user != "toni.tester" {
			t.Errorf("failed to set expected username, want: %s, got: %s", "toni.tester", client.user)
		}
	})
	t.Run("SetUsername to override WithUsername", func(t *testing.T) {
		client, err := NewClient(DefaultHost, WithUsername("toni.tester"))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetUsername("tina.tester")
		if client.user != "tina.tester" {
			t.Errorf("failed to set expected username, want: %s, got: %s", "tina.tester", client.user)
		}
	})
}

func TestClient_SetPassword(t *testing.T) {
	t.Run("SetPassword", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetPassword("sU*perS3crEt")
		if client.pass != "sU*perS3crEt" {
			t.Errorf("failed to set expected password, want: %s, got: %s", "sU*perS3crEt", client.pass)
		}
	})
	t.Run("SetPassword to override WithPassword", func(t *testing.T) {
		client, err := NewClient(DefaultHost, WithPassword("sU*perS3crEt"))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetPassword("Su%perS3crEt")
		if client.pass != "Su%perS3crEt" {
			t.Errorf("failed to set expected password, want: %s, got: %s", "Su%perS3crEt", client.pass)
		}
	})
}

func TestClient_SetSMTPAuth(t *testing.T) {
	t.Run("SetSMTPAuth", func(t *testing.T) {
		tests := []struct {
			name     string
			auth     SMTPAuthType
			expected SMTPAuthType
		}{
			{"CRAM-MD5", SMTPAuthCramMD5, SMTPAuthCramMD5},
			{"LOGIN", SMTPAuthLogin, SMTPAuthLogin},
			{"LOGIN-NOENC", SMTPAuthLoginNoEnc, SMTPAuthLoginNoEnc},
			{"NOAUTH", SMTPAuthNoAuth, SMTPAuthNoAuth},
			{"PLAIN", SMTPAuthPlain, SMTPAuthPlain},
			{"PLAIN-NOENC", SMTPAuthPlainNoEnc, SMTPAuthPlainNoEnc},
			{"SCRAM-SHA-1", SMTPAuthSCRAMSHA1, SMTPAuthSCRAMSHA1},
			{"SCRAM-SHA-1-PLUS", SMTPAuthSCRAMSHA1PLUS, SMTPAuthSCRAMSHA1PLUS},
			{"SCRAM-SHA-256", SMTPAuthSCRAMSHA256, SMTPAuthSCRAMSHA256},
			{"SCRAM-SHA-256-PLUS", SMTPAuthSCRAMSHA256PLUS, SMTPAuthSCRAMSHA256PLUS},
			{"XOAUTH2", SMTPAuthXOAUTH2, SMTPAuthXOAUTH2},
		}

		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				client.SetSMTPAuth(tt.auth)
				if client.smtpAuthType != tt.expected {
					t.Errorf("failed to set expected SMTPAuthType, want: %s, got: %s", tt.expected,
						client.smtpAuthType)
				}
			})
		}
	})
	t.Run("SetSMTPAuth to override WithSMTPAuth", func(t *testing.T) {
		tests := []struct {
			name     string
			auth     SMTPAuthType
			expected SMTPAuthType
		}{
			{"CRAM-MD5", SMTPAuthCramMD5, SMTPAuthCramMD5},
			{"LOGIN", SMTPAuthLogin, SMTPAuthLogin},
			{"LOGIN-NOENC", SMTPAuthLoginNoEnc, SMTPAuthLoginNoEnc},
			{"NOAUTH", SMTPAuthNoAuth, SMTPAuthNoAuth},
			{"PLAIN", SMTPAuthPlain, SMTPAuthPlain},
			{"PLAIN-NOENC", SMTPAuthPlainNoEnc, SMTPAuthPlainNoEnc},
			{"SCRAM-SHA-1", SMTPAuthSCRAMSHA1, SMTPAuthSCRAMSHA1},
			{"SCRAM-SHA-1-PLUS", SMTPAuthSCRAMSHA1PLUS, SMTPAuthSCRAMSHA1PLUS},
			{"SCRAM-SHA-256", SMTPAuthSCRAMSHA256, SMTPAuthSCRAMSHA256},
			{"SCRAM-SHA-256-PLUS", SMTPAuthSCRAMSHA256PLUS, SMTPAuthSCRAMSHA256PLUS},
			{"XOAUTH2", SMTPAuthXOAUTH2, SMTPAuthXOAUTH2},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				client, err := NewClient(DefaultHost, WithSMTPAuth(SMTPAuthLogin))
				if err != nil {
					t.Fatalf("failed to create new client: %s", err)
				}
				if client.smtpAuthType != SMTPAuthLogin {
					t.Fatalf("failed to create client with LOGIN auth, got: %s", client.smtpAuthType)
				}
				client.SetSMTPAuth(tt.auth)
				if client.smtpAuthType != tt.expected {
					t.Errorf("failed to set expected SMTPAuthType, want: %s, got: %s", tt.expected,
						client.smtpAuthType)
				}
			})
		}
	})
	t.Run("SetSMTPAuth override custom auth", func(t *testing.T) {
		client, err := NewClient(DefaultHost,
			WithSMTPAuthCustom(smtp.LoginAuth("", "", "", false)))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if client.smtpAuthType != SMTPAuthCustom {
			t.Fatalf("failed to create client with Custom auth, got: %s", client.smtpAuthType)
		}
		client.SetSMTPAuth(SMTPAuthSCRAMSHA256)
		if client.smtpAuthType != SMTPAuthSCRAMSHA256 {
			t.Errorf("failed to set expected SMTPAuthType, want: %s, got: %s", SMTPAuthSCRAMSHA256,
				client.smtpAuthType)
		}
		if client.smtpAuth != nil {
			t.Errorf("failed to set expected SMTPAuth, want: nil, got: %s", client.smtpAuth)
		}
	})
}

func TestClient_SetSMTPAuthCustom(t *testing.T) {
	t.Run("SetSMTPAuthCustom", func(t *testing.T) {
		tests := []struct {
			name     string
			authFunc smtp.Auth
			want     string
		}{
			{"CRAM-MD5", smtp.CRAMMD5Auth("", ""), "*smtp.cramMD5Auth"},
			{"LOGIN", smtp.LoginAuth("", "", "", false),
				"*smtp.loginAuth"},
			{"LOGIN-NOENC", smtp.LoginAuth("", "", "", true),
				"*smtp.loginAuth"},
			{"PLAIN", smtp.PlainAuth("", "", "", "", false),
				"*smtp.plainAuth"},
			{"PLAIN-NOENC", smtp.PlainAuth("", "", "", "", true),
				"*smtp.plainAuth"},
			{"SCRAM-SHA-1", smtp.ScramSHA1Auth("", ""), "*smtp.scramAuth"},
			{"SCRAM-SHA-1-PLUS", smtp.ScramSHA1PlusAuth("", "", nil),
				"*smtp.scramAuth"},
			{"SCRAM-SHA-256", smtp.ScramSHA256Auth("", ""), "*smtp.scramAuth"},
			{"SCRAM-SHA-256-PLUS", smtp.ScramSHA256PlusAuth("", "", nil),
				"*smtp.scramAuth"},
			{"XOAUTH2", smtp.XOAuth2Auth("", ""), "*smtp.xoauth2Auth"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				client, err := NewClient(DefaultHost)
				if err != nil {
					t.Fatalf("failed to create new client: %s", err)
				}
				client.SetSMTPAuthCustom(tt.authFunc)
				if client.smtpAuth == nil {
					t.Errorf("failed to set custom SMTP auth, expected auth method but got nil")
				}
				if client.smtpAuthType != SMTPAuthCustom {
					t.Errorf("failed to set custom SMTP auth, want auth type: %s, got: %s", SMTPAuthCustom,
						client.smtpAuthType)
				}
				authType := reflect.TypeOf(client.smtpAuth).String()
				if authType != tt.want {
					t.Errorf("failed to set custom SMTP auth, expected auth method type: %s, got: %s",
						tt.want, authType)
				}

			})
		}
	})
}

func TestClient_SetLogAuthData(t *testing.T) {
	t.Run("SetLogAuthData true", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetLogAuthData(true)
		if !client.logAuthData {
			t.Errorf("failed to set logAuthData, want: true, got: %t", client.logAuthData)
		}
	})
	t.Run("SetLogAuthData false", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetLogAuthData(false)
		if client.logAuthData {
			t.Errorf("failed to set logAuthData, want: false, got: %t", client.logAuthData)
		}
	})
	t.Run("SetLogAuthData override WithLogAuthData", func(t *testing.T) {
		client, err := NewClient(DefaultHost, WithLogAuthData())
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.SetLogAuthData(false)
		if client.logAuthData {
			t.Errorf("failed to set logAuthData, want: false, got: %t", client.logAuthData)
		}
	})
}

func TestClient_Close(t *testing.T) {
	t.Run("connect and close the Client", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			t.Fatalf("failed to connect to the test server: %s", err)
		}
		if !client.smtpClient.HasConnection() {
			t.Fatalf("client has no connection")
		}
		if err = client.Close(); err != nil {
			t.Errorf("failed to close the client: %s", err)
		}
	})
	t.Run("connect and double close the Client", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			t.Fatalf("failed to connect to the test server: %s", err)
		}
		if !client.smtpClient.HasConnection() {
			t.Fatalf("client has no connection")
		}
		if err = client.Close(); err != nil {
			t.Errorf("failed to close the client: %s", err)
		}
		if err = client.Close(); err != nil {
			t.Errorf("failed to close the client: %s", err)
		}
	})
	t.Run("test server will let close fail", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnQuit: true,
				FeatureSet: featureSet,
				ListenPort: serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			t.Fatalf("failed to connect to the test server: %s", err)
		}
		if !client.smtpClient.HasConnection() {
			t.Fatalf("client has no connection")
		}
		if err = client.Close(); err == nil {
			t.Errorf("close was supposed to fail, but didn't")
		}
	})
}

func TestClient_DialWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	PortAdder.Add(1)
	serverPort := int(TestServerPortBase + PortAdder.Load())
	featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, t, &serverProps{FeatureSet: featureSet, ListenPort: serverPort}); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 30)

	t.Run("connect and check connection", func(t *testing.T) {
		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			t.Fatalf("failed to connect to the test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close the client: %s", err)
			}
		})
		if !client.smtpClient.HasConnection() {
			t.Fatalf("client has no connection")
		}
	})
	t.Run("fail on base port use fallback", func(t *testing.T) {
		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.port = 12345
		client.fallbackPort = serverPort

		if err = client.DialWithContext(ctxDial); err != nil {
			t.Fatalf("failed to connect to the test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close the client: %s", err)
			}
		})
		if !client.smtpClient.HasConnection() {
			t.Fatalf("client has no connection")
		}
	})
	t.Run("fail on invalid host", func(t *testing.T) {
		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.host = "invalid.addr"

		if err = client.DialWithContext(ctxDial); err == nil {
			t.Errorf("client with invalid host should fail")
		}
		if client.smtpClient != nil {
			t.Errorf("client with invalid host should not have a smtp client")
		}
	})
	t.Run("fail on invalid HELO", func(t *testing.T) {
		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.helo = ""

		if err = client.DialWithContext(ctxDial); err == nil {
			t.Errorf("client with invalid HELO should fail")
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close the client: %s", err)
			}
		})
		if client.smtpClient == nil {
			t.Errorf("client with invalid HELO should still have a smtp client, got nil")
		}
		if !client.smtpClient.HasConnection() {
			t.Errorf("client with invalid HELO should still have a smtp client connection, got nil")
		}
	})
	t.Run("fail on base port and fallback", func(t *testing.T) {
		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		client.port = 12345
		client.fallbackPort = 12346

		if err = client.DialWithContext(ctxDial); err == nil {
			t.Fatalf("connection was supposed to fail, but didn't")
		}
		if client.smtpClient != nil {
			t.Fatalf("client has connection")
		}
	})
	t.Run("connect with full debug logging and auth logging", func(t *testing.T) {
		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		logBuffer := bytes.NewBuffer(nil)
		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS),
			WithDebugLog(), WithLogAuthData(), WithLogger(log.NewJSON(logBuffer, log.LevelDebug)),
			WithSMTPAuth(SMTPAuthPlain), WithUsername("test"), WithPassword("password"))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}

		if err = client.DialWithContext(ctxDial); err != nil {
			t.Fatalf("failed to connect to the test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Errorf("failed to close the client: %s", err)
			}
		})

		logs := parseJSONLog(t, logBuffer)
		if len(logs.Lines) == 0 {
			t.Errorf("failed to enable debug logging, but no logs were found")
		}
		authFound := false
		for _, logline := range logs.Lines {
			if strings.EqualFold(logline.Message, "AUTH PLAIN AHRlc3QAcGFzc3dvcmQ=") &&
				logline.Direction.From == "client" && logline.Direction.To == "server" {
				authFound = true
			}
		}
		if !authFound {
			t.Errorf("logAuthData not working, no authentication info found in logs")
		}
	})
	t.Run("connect should fail on HELO", func(t *testing.T) {
		ctxFail, cancelFail := context.WithCancel(context.Background())
		defer cancelFail()
		PortAdder.Add(1)
		failServerPort := int(TestServerPortBase + PortAdder.Load())
		failFeatureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctxFail, t, &serverProps{
				FailOnHelo: true,
				FeatureSet: failFeatureSet,
				ListenPort: failServerPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(failServerPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err == nil {
			t.Fatalf("connection was supposed to fail, but didn't")
		}
		if client.smtpClient == nil {
			t.Fatalf("client has no smtp client")
		}
		if !client.smtpClient.HasConnection() {
			t.Errorf("client has no connection")
		}
	})
	t.Run("connect with failing auth", func(t *testing.T) {
		ctxAuth, cancelAuth := context.WithCancel(context.Background())
		defer cancelAuth()
		PortAdder.Add(1)
		authServerPort := int(TestServerPortBase + PortAdder.Load())
		authFeatureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250-STARTTLS\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctxAuth, t, &serverProps{
				FailOnAuth: true,
				FeatureSet: authFeatureSet,
				ListenPort: authServerPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(authServerPort), WithTLSPolicy(NoTLS),
			WithSMTPAuth(SMTPAuthPlain), WithUsername("invalid"), WithPassword("invalid"))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err == nil {
			t.Fatalf("connection was supposed to fail, but didn't")
		}
	})
	t.Run("connect with STARTTLS", func(t *testing.T) {
		ctxTLS, cancelTLS := context.WithCancel(context.Background())
		defer cancelTLS()
		PortAdder.Add(1)
		tlsServerPort := int(TestServerPortBase + PortAdder.Load())
		tlsFeatureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250-STARTTLS\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctxTLS, t, &serverProps{
				FeatureSet: tlsFeatureSet,
				ListenPort: tlsServerPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		client, err := NewClient(DefaultHost, WithPort(tlsServerPort), WithTLSPolicy(TLSMandatory),
			WithTLSConfig(tlsConfig), WithSMTPAuth(SMTPAuthPlain), WithUsername("test"),
			WithPassword("password"))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			t.Fatalf("failed to connect to the test server: %s", err)
		}
	})
	t.Run("connect with STARTTLS Opportunisticly", func(t *testing.T) {
		ctxTLS, cancelTLS := context.WithCancel(context.Background())
		defer cancelTLS()
		PortAdder.Add(1)
		tlsServerPort := int(TestServerPortBase + PortAdder.Load())
		tlsFeatureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250-STARTTLS\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctxTLS, t, &serverProps{
				FeatureSet: tlsFeatureSet,
				ListenPort: tlsServerPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		client, err := NewClient(DefaultHost, WithPort(tlsServerPort), WithTLSPolicy(TLSOpportunistic),
			WithTLSConfig(tlsConfig), WithSMTPAuth(SMTPAuthPlain), WithUsername("test"),
			WithPassword("password"))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			t.Fatalf("failed to connect to the test server: %s", err)
		}
	})
	t.Run("connect with STARTTLS but fail", func(t *testing.T) {
		ctxTLS, cancelTLS := context.WithCancel(context.Background())
		defer cancelTLS()
		PortAdder.Add(1)
		tlsServerPort := int(TestServerPortBase + PortAdder.Load())
		tlsFeatureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250-STARTTLS\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctxTLS, t, &serverProps{
				FailOnSTARTTLS: true,
				FeatureSet:     tlsFeatureSet,
				ListenPort:     tlsServerPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		client, err := NewClient(DefaultHost, WithPort(tlsServerPort), WithTLSPolicy(TLSMandatory),
			WithTLSConfig(tlsConfig), WithSMTPAuth(SMTPAuthPlain), WithUsername("test"),
			WithPassword("password"))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err == nil {
			t.Fatalf("connection was supposed to fail, but didn't")
		}
	})
	t.Run("want STARTTLS, but server does not support it", func(t *testing.T) {
		ctxTLS, cancelTLS := context.WithCancel(context.Background())
		defer cancelTLS()
		PortAdder.Add(1)
		tlsServerPort := int(TestServerPortBase + PortAdder.Load())
		tlsFeatureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctxTLS, t, &serverProps{
				FeatureSet: tlsFeatureSet,
				ListenPort: tlsServerPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		client, err := NewClient(DefaultHost, WithPort(tlsServerPort), WithTLSPolicy(TLSMandatory),
			WithTLSConfig(tlsConfig), WithSMTPAuth(SMTPAuthPlain), WithUsername("test"),
			WithPassword("password"))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err == nil {
			t.Fatalf("connection was supposed to fail, but didn't")
		}
	})
	t.Run("connect with SSL", func(t *testing.T) {
		ctxSSL, cancelSSL := context.WithCancel(context.Background())
		defer cancelSSL()
		PortAdder.Add(1)
		sslServerPort := int(TestServerPortBase + PortAdder.Load())
		sslFeatureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctxSSL, t, &serverProps{
				SSLListener: true,
				FeatureSet:  sslFeatureSet,
				ListenPort:  sslServerPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)
		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		client, err := NewClient(DefaultHost, WithPort(sslServerPort), WithSSL(),
			WithTLSConfig(tlsConfig), WithSMTPAuth(SMTPAuthPlain), WithUsername("test"),
			WithPassword("password"))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			t.Fatalf("failed to connect to the test server: %s", err)
		}
		if err := client.Close(); err != nil {
			t.Fatalf("failed to close client: %s", err)
		}
	})
}

func TestClient_Reset(t *testing.T) {
	t.Run("reset client", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{FeatureSet: featureSet, ListenPort: serverPort}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithTLSPolicy(NoTLS), WithPort(serverPort))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			t.Fatalf("failed to connect to the test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Fatalf("failed to close client: %s", err)
			}
		})
		if err = client.Reset(); err != nil {
			t.Errorf("failed to reset client: %s", err)
		}
	})
	t.Run("reset should fail on disconnected client", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{FeatureSet: featureSet, ListenPort: serverPort}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithTLSPolicy(NoTLS), WithPort(serverPort))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			t.Fatalf("failed to connect to the test server: %s", err)
		}
		if err = client.Close(); err != nil {
			t.Fatalf("failed to close client: %s", err)
		}
		if err = client.Reset(); err == nil {
			t.Errorf("reset on disconnected client should fail")
		}
	})
	t.Run("reset with server failure", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnReset: true,
				FeatureSet:  featureSet,
				ListenPort:  serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithTLSPolicy(NoTLS), WithPort(serverPort))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			t.Fatalf("failed to connect to the test server: %s", err)
		}
		t.Cleanup(func() {
			if err = client.Close(); err != nil {
				t.Fatalf("failed to close client: %s", err)
			}
		})
		if err = client.Reset(); err == nil {
			t.Errorf("reset on disconnected client should fail")
		}
	})
}

func TestClient_DialAndSendWithContext(t *testing.T) {
	message := testMessage(t)
	t.Run("DialAndSend", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		client, err := NewClient(DefaultHost, WithTLSPolicy(NoTLS), WithPort(serverPort))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialAndSend(message); err != nil {
			t.Fatalf("failed to dial and send: %s", err)
		}
	})
	t.Run("DialAndSendWithContext", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithTLSPolicy(NoTLS), WithPort(serverPort))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialAndSendWithContext(ctxDial, message); err != nil {
			t.Fatalf("failed to dial and send: %s", err)
		}
	})
	t.Run("DialAndSendWithContext fail on dial", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnHelo: true,
				FeatureSet: featureSet,
				ListenPort: serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithTLSPolicy(NoTLS), WithPort(serverPort))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialAndSendWithContext(ctxDial, message); err == nil {
			t.Errorf("client was supposed to fail on dial")
		}
	})
	t.Run("DialAndSendWithContext fail on close", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnQuit: true,
				FeatureSet: featureSet,
				ListenPort: serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithTLSPolicy(NoTLS), WithPort(serverPort))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialAndSendWithContext(ctxDial, message); err == nil {
			t.Errorf("client was supposed to fail on dial")
		}
	})
	t.Run("DialAndSendWithContext fail on send", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnData: true,
				FeatureSet: featureSet,
				ListenPort: serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithTLSPolicy(NoTLS), WithPort(serverPort))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialAndSendWithContext(ctxDial, message); err == nil {
			t.Errorf("client was supposed to fail on dial")
		}
	})
}

func TestClient_auth(t *testing.T) {
	tests := []struct {
		name     string
		authType SMTPAuthType
	}{
		{"CRAM-MD5", SMTPAuthCramMD5},
		{"LOGIN", SMTPAuthLogin},
		{"LOGIN-NOENC", SMTPAuthLoginNoEnc},
		{"PLAIN", SMTPAuthPlain},
		{"PLAIN-NOENC", SMTPAuthPlainNoEnc},
		{"SCRAM-SHA-1", SMTPAuthSCRAMSHA1},
		{"SCRAM-SHA-1-PLUS", SMTPAuthSCRAMSHA1PLUS},
		{"SCRAM-SHA-256", SMTPAuthSCRAMSHA256},
		{"SCRAM-SHA-256-PLUS", SMTPAuthSCRAMSHA256PLUS},
		{"XOAUTH2", SMTPAuthXOAUTH2},
	}

	tlsConfig := tls.Config{InsecureSkipVerify: true}
	for _, tt := range tests {
		t.Run(tt.name+" should succeed", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			PortAdder.Add(1)
			serverPort := int(TestServerPortBase + PortAdder.Load())
			featureSet := "250-AUTH " + tt.name + "\r\n250-STARTTLS\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
			go func() {
				if err := simpleSMTPServer(ctx, t, &serverProps{
					FeatureSet: featureSet,
					ListenPort: serverPort,
				}); err != nil {
					t.Errorf("failed to start test server: %s", err)
					return
				}
			}()
			time.Sleep(time.Millisecond * 30)

			ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
			t.Cleanup(cancelDial)

			client, err := NewClient(DefaultHost, WithPort(serverPort),
				WithTLSPolicy(TLSMandatory), WithSMTPAuth(tt.authType), WithTLSConfig(&tlsConfig),
				WithUsername("test"), WithPassword("password"))
			if err != nil {
				t.Fatalf("failed to create new client: %s", err)
			}
			if err = client.DialWithContext(ctxDial); err != nil {
				t.Fatalf("failed to connect to test service: %s", err)
			}
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client connection: %s", err)
			}

		})
		t.Run(tt.name+" should fail", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			PortAdder.Add(1)
			serverPort := int(TestServerPortBase + PortAdder.Load())
			featureSet := "250-AUTH " + tt.name + "\r\n250-STARTTLS\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
			go func() {
				if err := simpleSMTPServer(ctx, t, &serverProps{
					FailOnAuth: true,
					FeatureSet: featureSet,
					ListenPort: serverPort,
				}); err != nil {
					t.Errorf("failed to start test server: %s", err)
					return
				}
			}()
			time.Sleep(time.Millisecond * 30)

			ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
			t.Cleanup(cancelDial)

			client, err := NewClient(DefaultHost, WithPort(serverPort),
				WithTLSPolicy(TLSMandatory), WithSMTPAuth(tt.authType), WithTLSConfig(&tlsConfig),
				WithUsername("test"), WithPassword("password"))
			if err != nil {
				t.Fatalf("failed to create new client: %s", err)
			}
			if err = client.DialWithContext(ctxDial); err == nil {
				t.Fatalf("client should have failed to connect")
			}
		})
		t.Run(tt.name+" should fail as unspported", func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			PortAdder.Add(1)
			serverPort := int(TestServerPortBase + PortAdder.Load())
			featureSet := "250-AUTH UNKNOWN\r\n250-8BITMIME\r\n250-STARTTLS\r\n250-DSN\r\n250 SMTPUTF8"
			go func() {
				if err := simpleSMTPServer(ctx, t, &serverProps{
					FeatureSet: featureSet,
					ListenPort: serverPort,
				}); err != nil {
					t.Errorf("failed to start test server: %s", err)
					return
				}
			}()
			time.Sleep(time.Millisecond * 30)

			ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
			t.Cleanup(cancelDial)

			client, err := NewClient(DefaultHost, WithPort(serverPort),
				WithTLSPolicy(TLSMandatory), WithSMTPAuth(tt.authType), WithTLSConfig(&tlsConfig),
				WithUsername("test"), WithPassword("password"))
			if err != nil {
				t.Fatalf("failed to create new client: %s", err)
			}
			if err = client.DialWithContext(ctxDial); err == nil {
				t.Fatalf("client should have failed to connect")
			}
		})
	}
	t.Run("auth is not supported at all", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-STARTTLS\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort),
			WithTLSPolicy(TLSMandatory), WithSMTPAuth(SMTPAuthPlain), WithTLSConfig(&tlsConfig),
			WithUsername("test"), WithPassword("password"))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err == nil {
			t.Fatalf("client should have failed to connect")
		}
	})
	t.Run("SCRAM-X-PLUS on non TLS connection should fail", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH SCRAM-SHA-256-PLUS\r\n250-8BITMIME\r\n250-STARTTLS\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithTLSPolicy(NoTLS), WithPort(serverPort),
			WithSMTPAuth(SMTPAuthSCRAMSHA256PLUS), WithTLSConfig(&tlsConfig),
			WithUsername("test"), WithPassword("password"))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err == nil {
			t.Fatalf("client should have failed to connect")
		}
	})
	t.Run("unknown auth type should fail", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-AUTH UNKNOWN\r\n250-8BITMIME\r\n250-STARTTLS\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort),
			WithTLSPolicy(TLSMandatory), WithSMTPAuth("UNKNOWN"), WithTLSConfig(&tlsConfig),
			WithUsername("test"), WithPassword("password"))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err == nil {
			t.Fatalf("client should have failed to connect")
		}
	})
}

func TestClient_Send(t *testing.T) {
	message := testMessage(t)
	t.Run("connect and send email", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err = client.DialWithContext(ctxDial); err != nil {
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.Send(message); err != nil {
			t.Errorf("failed to send email: %s", err)
		}
	})
	t.Run("send with no connection should fail", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err = client.Send(message); err == nil {
			t.Errorf("client should have failed to send email with no connection")
		}
		var sendErr *SendError
		if !errors.As(err, &sendErr) {
			t.Fatalf("expected SendError, got %T", err)
		}
		if sendErr.Reason != ErrConnCheck {
			t.Errorf("expected ErrConnCheck, got %s", sendErr.Reason)
		}
	})
	t.Run("concurrent sending on a single client connection", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err = client.DialWithContext(ctxDial); err != nil {
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})

		var messages []*Msg
		for i := 0; i < 50; i++ {
			curMessage := testMessage(t)
			curMessage.SetMessageIDWithValue("this.is.a.message.id")
			messages = append(messages, curMessage)
		}

		wg := sync.WaitGroup{}
		for id, curMessage := range messages {
			wg.Add(1)
			go func(curMsg *Msg, curID int) {
				defer wg.Done()
				if goroutineErr := client.Send(curMsg); err != nil {
					t.Errorf("failed to send message with ID %d: %s", curID, goroutineErr)
				}
			}(curMessage, id)
		}
		wg.Wait()
	})
}

func TestClient_sendSingleMsg(t *testing.T) {
	message := testMessage(t)
	t.Run("connect and send email", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err = client.DialWithContext(ctxDial); err != nil {
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.sendSingleMsg(message); err != nil {
			t.Errorf("failed to send message: %s", err)
		}
	})
}

// TestClient_onlinetests will perform some additional tests on a actual live mail server. These tests are only
// meant for the CI/CD pipeline and are usually skipped. They can be activated by setting PERFORM_ONLINE_TEST=true
// in the ENV. The normal test suite should provide all the tests needed to cover the full functionality.
func TestClient_onlinetests(t *testing.T) {
	if os.Getenv("PERFORM_ONLINE_TEST") != "true" {
		t.Skip(`"PERFORM_ONLINE_TEST" env variable is not set to "true". Skipping online tests.`)
	}
}

/*




// TestClient_checkConn tests the checkConn method with intentional breaking for the Client object
func TestClient_checkConn(t *testing.T) {
	c, err := getTestConnection(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}
	if err = c.checkConn(); err == nil {
		t.Errorf("connCheck() should fail but succeeded")
	}
}

// TestClient_DialAndSendWithDSN tests the DialAndSend() method of Client with DSN enabled
func TestClient_DialAndSendWithDSN(t *testing.T) {
	if os.Getenv("TEST_ALLOW_SEND") == "" {
		t.Skipf("TEST_ALLOW_SEND is not set. Skipping mail sending test")
	}
	m := NewMsg()
	_ = m.FromFormat("go-mail Test Mailer", os.Getenv("TEST_FROM"))
	_ = m.To(TestRcpt)
	m.Subject(fmt.Sprintf("This is a test mail from go-mail/v%s", VERSION))
	m.SetBulk()
	m.SetDate()
	m.SetMessageID()
	m.SetBodyString(TypeTextPlain, "This is a test mail from the go-mail library")

	c, err := getTestConnectionWithDSN(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}

	if err := c.DialAndSend(m); err != nil {
		t.Errorf("DialAndSend() failed: %s", err)
	}
}

// TestClient_DialSendCloseBroken tests the Dial(), Send() and Close() method of Client with broken settings
func TestClient_DialSendCloseBroken(t *testing.T) {
	if os.Getenv("TEST_ALLOW_SEND") == "" {
		t.Skipf("TEST_ALLOW_SEND is not set. Skipping mail sending test")
	}
	tests := []struct {
		name       string
		from       string
		to         string
		closestart bool
		closeearly bool
		sf         bool
	}{
		{"Invalid FROM", "foo@foo", TestRcpt, false, false, true},
		{"Invalid TO", os.Getenv("TEST_FROM"), "foo@foo", false, false, true},
		{"No FROM", "", TestRcpt, false, false, true},
		{"No TO", os.Getenv("TEST_FROM"), "", false, false, true},
		{"Close early", os.Getenv("TEST_FROM"), TestRcpt, false, true, true},
		{"Close start", os.Getenv("TEST_FROM"), TestRcpt, true, false, true},
		{"Close start/early", os.Getenv("TEST_FROM"), TestRcpt, true, true, true},
	}

	m := NewMsg(WithEncoding(NoEncoding))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.SetAddrHeaderIgnoreInvalid(HeaderFrom, tt.from)
			m.SetAddrHeaderIgnoreInvalid(HeaderTo, tt.to)

			c, err := getTestConnection(true)
			if err != nil {
				t.Skipf("failed to create test client: %s. Skipping tests", err)
			}

			ctx, cfn := context.WithTimeout(context.Background(), time.Second*10)
			defer cfn()
			if err := c.DialWithContext(ctx); err != nil && !tt.sf {
				t.Errorf("Dail() failed: %s", err)
				return
			}
			if tt.closestart {
				_ = c.smtpClient.Close()
			}
			if err = c.Send(m); err != nil && !tt.sf {
				t.Errorf("Send() failed: %s", err)
				return
			}
			if tt.closeearly {
				_ = c.smtpClient.Close()
			}
			if err = c.Close(); err != nil && !tt.sf {
				t.Errorf("Close() failed: %s", err)
				return
			}
		})
	}
}

// TestClient_DialSendCloseBrokenWithDSN tests the Dial(), Send() and Close() method of Client with
// broken settings and DSN enabled
func TestClient_DialSendCloseBrokenWithDSN(t *testing.T) {
	if os.Getenv("TEST_ALLOW_SEND") == "" {
		t.Skipf("TEST_ALLOW_SEND is not set. Skipping mail sending test")
	}
	tests := []struct {
		name       string
		from       string
		to         string
		closestart bool
		closeearly bool
		sf         bool
	}{
		{"Invalid FROM", "foo@foo", TestRcpt, false, false, true},
		{"Invalid TO", os.Getenv("TEST_FROM"), "foo@foo", false, false, true},
		{"No FROM", "", TestRcpt, false, false, true},
		{"No TO", os.Getenv("TEST_FROM"), "", false, false, true},
		{"Close early", os.Getenv("TEST_FROM"), TestRcpt, false, true, true},
		{"Close start", os.Getenv("TEST_FROM"), TestRcpt, true, false, true},
		{"Close start/early", os.Getenv("TEST_FROM"), TestRcpt, true, true, true},
	}

	m := NewMsg(WithEncoding(NoEncoding))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.SetAddrHeaderIgnoreInvalid(HeaderFrom, tt.from)
			m.SetAddrHeaderIgnoreInvalid(HeaderTo, tt.to)

			c, err := getTestConnectionWithDSN(true)
			if err != nil {
				t.Skipf("failed to create test client: %s. Skipping tests", err)
			}

			ctx, cfn := context.WithTimeout(context.Background(), time.Second*10)
			defer cfn()
			if err := c.DialWithContext(ctx); err != nil && !tt.sf {
				t.Errorf("Dail() failed: %s", err)
				return
			}
			if tt.closestart {
				_ = c.smtpClient.Close()
			}
			if err = c.Send(m); err != nil && !tt.sf {
				t.Errorf("Send() failed: %s", err)
				return
			}
			if tt.closeearly {
				_ = c.smtpClient.Close()
			}
			if err = c.Close(); err != nil && !tt.sf {
				t.Errorf("Close() failed: %s", err)
				return
			}
		})
	}
}

func TestClient_DialWithContext_switchAuth(t *testing.T) {
	if os.Getenv("TEST_ALLOW_SEND") == "" {
		t.Skipf("TEST_ALLOW_SEND is not set. Skipping mail sending test")
	}

	// We start with no auth explicitly set
	client, err := NewClient(
		os.Getenv("TEST_HOST"),
		WithTLSPortPolicy(TLSMandatory),
	)
	defer func() {
		_ = client.Close()
	}()
	if err != nil {
		t.Errorf("failed to create client: %s", err)
		return
	}
	if err = client.DialWithContext(context.Background()); err != nil {
		t.Errorf("failed to dial to sending server: %s", err)
	}
	if err = client.Close(); err != nil {
		t.Errorf("failed to close client connection: %s", err)
	}

	// We switch to LOGIN auth, which the server supports
	client.SetSMTPAuth(SMTPAuthLogin)
	client.SetUsername(os.Getenv("TEST_SMTPAUTH_USER"))
	client.SetPassword(os.Getenv("TEST_SMTPAUTH_PASS"))
	if err = client.DialWithContext(context.Background()); err != nil {
		t.Errorf("failed to dial to sending server: %s", err)
	}
	if err = client.Close(); err != nil {
		t.Errorf("failed to close client connection: %s", err)
	}

	// We switch to CRAM-MD5, which the server does not support - error expected
	client.SetSMTPAuth(SMTPAuthCramMD5)
	if err = client.DialWithContext(context.Background()); err == nil {
		t.Errorf("expected error when dialing with unsupported auth mechanism, got nil")
		return
	}
	if !errors.Is(err, ErrCramMD5AuthNotSupported) {
		t.Errorf("expected dial error: %s, but got: %s", ErrCramMD5AuthNotSupported, err)
	}

	// We switch to CUSTOM by providing PLAIN auth as function - the server supports this
	client.SetSMTPAuthCustom(smtp.PlainAuth("", os.Getenv("TEST_SMTPAUTH_USER"),
		os.Getenv("TEST_SMTPAUTH_PASS"), os.Getenv("TEST_HOST"), false))
	if client.smtpAuthType != SMTPAuthCustom {
		t.Errorf("expected auth type to be Custom, got: %s", client.smtpAuthType)
	}
	if err = client.DialWithContext(context.Background()); err != nil {
		t.Errorf("failed to dial to sending server: %s", err)
	}
	if err = client.Close(); err != nil {
		t.Errorf("failed to close client connection: %s", err)
	}

	// We switch back to explicit no authenticaiton
	client.SetSMTPAuth(SMTPAuthNoAuth)
	if err = client.DialWithContext(context.Background()); err != nil {
		t.Errorf("failed to dial to sending server: %s", err)
	}
	if err = client.Close(); err != nil {
		t.Errorf("failed to close client connection: %s", err)
	}

	// Finally we set an empty string as SMTPAuthType and expect and error. This way we can
	// verify that we do not accidentaly skip authentication with an empty string SMTPAuthType
	client.SetSMTPAuth("")
	if err = client.DialWithContext(context.Background()); err == nil {
		t.Errorf("expected error when dialing with empty auth mechanism, got nil")
	}
}

// TestClient_Send_MsgSendError tests the Client.Send method with a broken recipient and verifies
// that the SendError type works properly
func TestClient_Send_MsgSendError(t *testing.T) {
	if os.Getenv("TEST_ALLOW_SEND") == "" {
		t.Skipf("TEST_ALLOW_SEND is not set. Skipping mail sending test")
	}
	var msgs []*Msg
	rcpts := []string{"invalid@domain.tld", "invalid@address.invalid"}
	for _, rcpt := range rcpts {
		m := NewMsg()
		_ = m.FromFormat("go-mail Test Mailer", os.Getenv("TEST_FROM"))
		_ = m.To(rcpt)
		m.Subject(fmt.Sprintf("This is a test mail from go-mail/v%s", VERSION))
		m.SetBulk()
		m.SetDate()
		m.SetMessageID()
		m.SetBodyString(TypeTextPlain, "This is a test mail from the go-mail library")
		msgs = append(msgs, m)
	}

	c, err := getTestConnection(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}

	ctx, cfn := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cfn()
	if err := c.DialWithContext(ctx); err != nil {
		t.Errorf("failed to dial to sending server: %s", err)
	}
	if err := c.Send(msgs...); err == nil {
		t.Errorf("sending messages with broken recipients was supposed to fail but didn't")
	}
	if err := c.Close(); err != nil {
		t.Errorf("failed to close client connection: %s", err)
	}
	for _, m := range msgs {
		if !m.HasSendError() {
			t.Errorf("message was expected to have a send error, but didn't")
		}
		se := &SendError{Reason: ErrSMTPRcptTo}
		if !errors.Is(m.SendError(), se) {
			t.Errorf("error mismatch, expected: %s, got: %s", se, m.SendError())
		}
		if m.SendErrorIsTemp() {
			t.Errorf("message was not expected to be a temporary error, but reported as such")
		}
	}
}

// TestClient_DialAndSendWithContext_withSendError tests the Client.DialAndSendWithContext method
// with a broken recipient to make sure that the returned error satisfies the Msg.SendError type
func TestClient_DialAndSendWithContext_withSendError(t *testing.T) {
	if os.Getenv("TEST_ALLOW_SEND") == "" {
		t.Skipf("TEST_ALLOW_SEND is not set. Skipping mail sending test")
	}
	m := NewMsg()
	_ = m.FromFormat("go-mail Test Mailer", os.Getenv("TEST_FROM"))
	_ = m.To("invalid@domain.tld")
	m.Subject(fmt.Sprintf("This is a test mail from go-mail/v%s", VERSION))
	m.SetBulk()
	m.SetDate()
	m.SetMessageID()
	m.SetBodyString(TypeTextPlain, "This is a test mail from the go-mail library")

	c, err := getTestConnection(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}
	ctx, cfn := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cfn()
	err = c.DialAndSendWithContext(ctx, m)
	if err == nil {
		t.Errorf("expected DialAndSendWithContext with broken mail recipient to fail, but didn't")
		return
	}
	var se *SendError
	if !errors.As(err, &se) {
		t.Errorf("expected *SendError type as returned error, but didn't")
		return
	}
	if se.IsTemp() {
		t.Errorf("expected permanent error but IsTemp() returned true")
	}
	if m.IsDelivered() {
		t.Errorf("message is indicated to be delivered but shouldn't")
	}
}

func TestClient_SendErrorNoEncoding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	featureSet := "250-AUTH PLAIN\r\n250-DSN\r\n250 SMTPUTF8"
	serverPort := TestServerPortBase + 1
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, false, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 300)

	message := NewMsg()
	if err := message.From("valid-from@domain.tld"); err != nil {
		t.Errorf("failed to set FROM address: %s", err)
		return
	}
	if err := message.To("valid-to@domain.tld"); err != nil {
		t.Errorf("failed to set TO address: %s", err)
		return
	}
	message.Subject("Test subject")
	message.SetBodyString(TypeTextPlain, "Test body")
	message.SetMessageIDWithValue("this.is.a.message.id")
	message.SetEncoding(NoEncoding)

	client, err := NewClient(TestServerAddr, WithPort(serverPort),
		WithTLSPortPolicy(NoTLS), WithSMTPAuth(SMTPAuthPlain),
		WithUsername("toni@tester.com"),
		WithPassword("V3ryS3cr3t+"))
	if err != nil {
		t.Errorf("unable to create new client: %s", err)
	}
	if err = client.DialWithContext(context.Background()); err != nil {
		t.Errorf("failed to dial to test server: %s", err)
	}
	if err = client.Send(message); err == nil {
		t.Error("expected Send() to fail but didn't")
	}

	var sendErr *SendError
	if !errors.As(err, &sendErr) {
		t.Errorf("expected *SendError type as returned error, but got %T", sendErr)
	}
	if errors.As(err, &sendErr) {
		if sendErr.IsTemp() {
			t.Errorf("expected permanent error but IsTemp() returned true")
		}
		if sendErr.Reason != ErrNoUnencoded {
			t.Errorf("expected ErrNoUnencoded error, but got %s", sendErr.Reason)
		}
		if !strings.EqualFold(sendErr.MessageID(), "<this.is.a.message.id>") {
			t.Errorf("expected message ID: %q, but got %q", "<this.is.a.message.id>",
				sendErr.MessageID())
		}
		if sendErr.Msg() == nil {
			t.Errorf("expected message to be set, but got nil")
		}
	}

	if err = client.Close(); err != nil {
		t.Errorf("failed to close server connection: %s", err)
	}
}

func TestClient_SendErrorMailFrom(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 2
	featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, false, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 300)

	message := NewMsg()
	if err := message.From("invalid-from@domain.tld"); err != nil {
		t.Errorf("failed to set FROM address: %s", err)
		return
	}
	if err := message.To("valid-to@domain.tld"); err != nil {
		t.Errorf("failed to set TO address: %s", err)
		return
	}
	message.Subject("Test subject")
	message.SetBodyString(TypeTextPlain, "Test body")
	message.SetMessageIDWithValue("this.is.a.message.id")

	client, err := NewClient(TestServerAddr, WithPort(serverPort),
		WithTLSPortPolicy(NoTLS), WithSMTPAuth(SMTPAuthPlain),
		WithUsername("toni@tester.com"),
		WithPassword("V3ryS3cr3t+"))
	if err != nil {
		t.Errorf("unable to create new client: %s", err)
	}
	if err = client.DialWithContext(context.Background()); err != nil {
		t.Errorf("failed to dial to test server: %s", err)
	}
	if err = client.Send(message); err == nil {
		t.Error("expected Send() to fail but didn't")
	}

	var sendErr *SendError
	if !errors.As(err, &sendErr) {
		t.Errorf("expected *SendError type as returned error, but got %T", sendErr)
	}
	if errors.As(err, &sendErr) {
		if sendErr.IsTemp() {
			t.Errorf("expected permanent error but IsTemp() returned true")
		}
		if sendErr.Reason != ErrSMTPMailFrom {
			t.Errorf("expected ErrSMTPMailFrom error, but got %s", sendErr.Reason)
		}
		if !strings.EqualFold(sendErr.MessageID(), "<this.is.a.message.id>") {
			t.Errorf("expected message ID: %q, but got %q", "<this.is.a.message.id>",
				sendErr.MessageID())
		}
		if sendErr.Msg() == nil {
			t.Errorf("expected message to be set, but got nil")
		}
	}

	if err = client.Close(); err != nil {
		t.Errorf("failed to close server connection: %s", err)
	}
}


func TestClient_SendErrorToReset(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 4
	featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, true, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 300)

	message := NewMsg()
	if err := message.From("valid-from@domain.tld"); err != nil {
		t.Errorf("failed to set FROM address: %s", err)
		return
	}
	if err := message.To("invalid-to@domain.tld"); err != nil {
		t.Errorf("failed to set TO address: %s", err)
		return
	}
	message.Subject("Test subject")
	message.SetBodyString(TypeTextPlain, "Test body")
	message.SetMessageIDWithValue("this.is.a.message.id")

	client, err := NewClient(TestServerAddr, WithPort(serverPort),
		WithTLSPortPolicy(NoTLS), WithSMTPAuth(SMTPAuthPlain),
		WithUsername("toni@tester.com"),
		WithPassword("V3ryS3cr3t+"))
	if err != nil {
		t.Errorf("unable to create new client: %s", err)
	}
	if err = client.DialWithContext(context.Background()); err != nil {
		t.Errorf("failed to dial to test server: %s", err)
	}
	if err = client.Send(message); err == nil {
		t.Error("expected Send() to fail but didn't")
	}

	var sendErr *SendError
	if !errors.As(err, &sendErr) {
		t.Errorf("expected *SendError type as returned error, but got %T", sendErr)
	}
	if errors.As(err, &sendErr) {
		if sendErr.IsTemp() {
			t.Errorf("expected permanent error but IsTemp() returned true")
		}
		if sendErr.Reason != ErrSMTPRcptTo {
			t.Errorf("expected ErrSMTPRcptTo error, but got %s", sendErr.Reason)
		}
		if !strings.EqualFold(sendErr.MessageID(), "<this.is.a.message.id>") {
			t.Errorf("expected message ID: %q, but got %q", "<this.is.a.message.id>",
				sendErr.MessageID())
		}
		if len(sendErr.errlist) != 2 {
			t.Errorf("expected 2 errors, but got %d", len(sendErr.errlist))
			return
		}
		if !strings.EqualFold(sendErr.errlist[0].Error(), "500 5.1.2 Invalid to: <invalid-to@domain.tld>") {
			t.Errorf("expected error: %q, but got %q",
				"500 5.1.2 Invalid to: <invalid-to@domain.tld>", sendErr.errlist[0].Error())
		}
		if !strings.EqualFold(sendErr.errlist[1].Error(), "500 5.1.2 Error: reset failed") {
			t.Errorf("expected error: %q, but got %q",
				"500 5.1.2 Error: reset failed", sendErr.errlist[1].Error())
		}
	}

	if err = client.Close(); err != nil {
		t.Errorf("failed to close server connection: %s", err)
	}
}

func TestClient_SendErrorDataClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 5
	featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, false, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 300)

	message := NewMsg()
	if err := message.From("valid-from@domain.tld"); err != nil {
		t.Errorf("failed to set FROM address: %s", err)
		return
	}
	if err := message.To("valid-to@domain.tld"); err != nil {
		t.Errorf("failed to set TO address: %s", err)
		return
	}
	message.Subject("Test subject")
	message.SetBodyString(TypeTextPlain, "DATA close should fail")
	message.SetMessageIDWithValue("this.is.a.message.id")

	client, err := NewClient(TestServerAddr, WithPort(serverPort),
		WithTLSPortPolicy(NoTLS), WithSMTPAuth(SMTPAuthPlain),
		WithUsername("toni@tester.com"),
		WithPassword("V3ryS3cr3t+"))
	if err != nil {
		t.Errorf("unable to create new client: %s", err)
	}
	if err = client.DialWithContext(context.Background()); err != nil {
		t.Errorf("failed to dial to test server: %s", err)
	}
	if err = client.Send(message); err == nil {
		t.Error("expected Send() to fail but didn't")
	}

	var sendErr *SendError
	if !errors.As(err, &sendErr) {
		t.Errorf("expected *SendError type as returned error, but got %T", sendErr)
	}
	if errors.As(err, &sendErr) {
		if sendErr.IsTemp() {
			t.Errorf("expected permanent error but IsTemp() returned true")
		}
		if sendErr.Reason != ErrSMTPDataClose {
			t.Errorf("expected ErrSMTPDataClose error, but got %s", sendErr.Reason)
		}
		if !strings.EqualFold(sendErr.MessageID(), "<this.is.a.message.id>") {
			t.Errorf("expected message ID: %q, but got %q", "<this.is.a.message.id>",
				sendErr.MessageID())
		}
	}

	if err = client.Close(); err != nil {
		t.Errorf("failed to close server connection: %s", err)
	}
}

func TestClient_SendErrorDataWrite(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 6
	featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, false, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 300)

	message := NewMsg()
	if err := message.From("valid-from@domain.tld"); err != nil {
		t.Errorf("failed to set FROM address: %s", err)
		return
	}
	if err := message.To("valid-to@domain.tld"); err != nil {
		t.Errorf("failed to set TO address: %s", err)
		return
	}
	message.Subject("Test subject")
	message.SetBodyString(TypeTextPlain, "DATA write should fail")
	message.SetMessageIDWithValue("this.is.a.message.id")
	message.SetGenHeader("X-Test-Header", "DATA write should fail")

	client, err := NewClient(TestServerAddr, WithPort(serverPort),
		WithTLSPortPolicy(NoTLS), WithSMTPAuth(SMTPAuthPlain),
		WithUsername("toni@tester.com"),
		WithPassword("V3ryS3cr3t+"))
	if err != nil {
		t.Errorf("unable to create new client: %s", err)
	}
	if err = client.DialWithContext(context.Background()); err != nil {
		t.Errorf("failed to dial to test server: %s", err)
	}
	if err = client.Send(message); err == nil {
		t.Error("expected Send() to fail but didn't")
	}

	var sendErr *SendError
	if !errors.As(err, &sendErr) {
		t.Errorf("expected *SendError type as returned error, but got %T", sendErr)
	}
	if errors.As(err, &sendErr) {
		if sendErr.IsTemp() {
			t.Errorf("expected permanent error but IsTemp() returned true")
		}
		if sendErr.Reason != ErrSMTPDataClose {
			t.Errorf("expected ErrSMTPDataClose error, but got %s", sendErr.Reason)
		}
		if !strings.EqualFold(sendErr.MessageID(), "<this.is.a.message.id>") {
			t.Errorf("expected message ID: %q, but got %q", "<this.is.a.message.id>",
				sendErr.MessageID())
		}
	}
}

func TestClient_SendErrorReset(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 7
	featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, true, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 300)

	message := NewMsg()
	if err := message.From("valid-from@domain.tld"); err != nil {
		t.Errorf("failed to set FROM address: %s", err)
		return
	}
	if err := message.To("valid-to@domain.tld"); err != nil {
		t.Errorf("failed to set TO address: %s", err)
		return
	}
	message.Subject("Test subject")
	message.SetBodyString(TypeTextPlain, "Test body")
	message.SetMessageIDWithValue("this.is.a.message.id")

	client, err := NewClient(TestServerAddr, WithPort(serverPort),
		WithTLSPortPolicy(NoTLS), WithSMTPAuth(SMTPAuthPlain),
		WithUsername("toni@tester.com"),
		WithPassword("V3ryS3cr3t+"))
	if err != nil {
		t.Errorf("unable to create new client: %s", err)
	}
	if err = client.DialWithContext(context.Background()); err != nil {
		t.Errorf("failed to dial to test server: %s", err)
	}
	if err = client.Send(message); err == nil {
		t.Error("expected Send() to fail but didn't")
	}

	var sendErr *SendError
	if !errors.As(err, &sendErr) {
		t.Errorf("expected *SendError type as returned error, but got %T", sendErr)
	}
	if errors.As(err, &sendErr) {
		if sendErr.IsTemp() {
			t.Errorf("expected permanent error but IsTemp() returned true")
		}
		if sendErr.Reason != ErrSMTPReset {
			t.Errorf("expected ErrSMTPReset error, but got %s", sendErr.Reason)
		}
		if !strings.EqualFold(sendErr.MessageID(), "<this.is.a.message.id>") {
			t.Errorf("expected message ID: %q, but got %q", "<this.is.a.message.id>",
				sendErr.MessageID())
		}
	}

	if err = client.Close(); err != nil {
		t.Errorf("failed to close server connection: %s", err)
	}
}

func TestClient_DialSendConcurrent_online(t *testing.T) {
	if os.Getenv("TEST_ALLOW_SEND") == "" {
		t.Skipf("TEST_ALLOW_SEND is not set. Skipping mail sending test")
	}

	client, err := getTestConnection(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}

	var messages []*Msg
	for i := 0; i < 10; i++ {
		message := NewMsg()
		if err := message.FromFormat("go-mail Test Mailer", os.Getenv("TEST_FROM")); err != nil {
			t.Errorf("failed to set FROM address: %s", err)
			return
		}
		if err := message.To(TestRcpt); err != nil {
			t.Errorf("failed to set TO address: %s", err)
			return
		}
		message.Subject(fmt.Sprintf("Test subject for mail %d", i))
		message.SetBodyString(TypeTextPlain, fmt.Sprintf("This is the test body of the mail no. %d", i))
		message.SetMessageID()
		messages = append(messages, message)
	}

	if err = client.DialWithContext(context.Background()); err != nil {
		t.Errorf("failed to dial to test server: %s", err)
	}

	wg := sync.WaitGroup{}
	for id, message := range messages {
		wg.Add(1)
		go func(curMsg *Msg, curID int) {
			defer wg.Done()
			if goroutineErr := client.Send(curMsg); err != nil {
				t.Errorf("failed to send message with ID %d: %s", curID, goroutineErr)
			}
		}(message, id)
	}
	wg.Wait()

	if err = client.Close(); err != nil {
		t.Errorf("failed to close server connection: %s", err)
	}
}

func TestClient_DialSendConcurrent_local(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 20
	featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, false, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 500)

	client, err := NewClient(TestServerAddr, WithPort(serverPort),
		WithTLSPortPolicy(NoTLS), WithSMTPAuth(SMTPAuthPlain),
		WithUsername("toni@tester.com"),
		WithPassword("V3ryS3cr3t+"))
	if err != nil {
		t.Errorf("unable to create new client: %s", err)
	}

	var messages []*Msg
	for i := 0; i < 20; i++ {
		message := NewMsg()
		if err := message.From("valid-from@domain.tld"); err != nil {
			t.Errorf("failed to set FROM address: %s", err)
			return
		}
		if err := message.To("valid-to@domain.tld"); err != nil {
			t.Errorf("failed to set TO address: %s", err)
			return
		}
		message.Subject("Test subject")
		message.SetBodyString(TypeTextPlain, "Test body")
		message.SetMessageIDWithValue("this.is.a.message.id")
		messages = append(messages, message)
	}

	if err = client.DialWithContext(context.Background()); err != nil {
		t.Errorf("failed to dial to test server: %s", err)
	}

	wg := sync.WaitGroup{}
	for id, message := range messages {
		wg.Add(1)
		go func(curMsg *Msg, curID int) {
			defer wg.Done()
			if goroutineErr := client.Send(curMsg); err != nil {
				t.Errorf("failed to send message with ID %d: %s", curID, goroutineErr)
			}
		}(message, id)
	}
	wg.Wait()

	if err = client.Close(); err != nil {
		t.Logf("failed to close server connection: %s", err)
	}
}

func TestClient_AuthSCRAMSHAX(t *testing.T) {
	if os.Getenv("TEST_ONLINE_SCRAM") == "" {
		t.Skipf("TEST_ONLINE_SCRAM is not set. Skipping online SCRAM tests")
	}
	hostname := os.Getenv("TEST_HOST_SCRAM")
	username := os.Getenv("TEST_USER_SCRAM")
	password := os.Getenv("TEST_PASS_SCRAM")

	tests := []struct {
		name     string
		authtype SMTPAuthType
	}{
		{"SCRAM-SHA-1", SMTPAuthSCRAMSHA1},
		{"SCRAM-SHA-256", SMTPAuthSCRAMSHA256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(hostname,
				WithTLSPortPolicy(TLSMandatory),
				WithSMTPAuth(tt.authtype),
				WithUsername(username), WithPassword(password))
			if err != nil {
				t.Errorf("unable to create new client: %s", err)
				return
			}
			if err = client.DialWithContext(context.Background()); err != nil {
				t.Errorf("failed to dial to test server: %s", err)
			}
			if err = client.Close(); err != nil {
				t.Errorf("failed to close server connection: %s", err)
			}
		})
	}
}

func TestClient_AuthLoginSuccess(t *testing.T) {
	tests := []struct {
		name       string
		featureSet string
	}{
		{"default", "250-AUTH LOGIN\r\n250-X-DEFAULT-LOGIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"},
		{"mox server", "250-AUTH LOGIN\r\n250-X-MOX-LOGIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"},
		{"null byte", "250-AUTH LOGIN\r\n250-X-NULLBYTE-LOGIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"},
		{"bogus responses", "250-AUTH LOGIN\r\n250-X-BOGUS-LOGIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"},
		{"empty responses", "250-AUTH LOGIN\r\n250-X-EMPTY-LOGIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"},
	}

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			serverPort := TestServerPortBase + 40 + i
			go func() {
				if err := simpleSMTPServer(ctx, tt.featureSet, true, serverPort); err != nil {
					t.Errorf("failed to start test server: %s", err)
					return
				}
			}()
			time.Sleep(time.Millisecond * 300)

			client, err := NewClient(TestServerAddr,
				WithPort(serverPort),
				WithTLSPortPolicy(NoTLS),
				WithSMTPAuth(SMTPAuthLogin),
				WithUsername("toni@tester.com"),
				WithPassword("V3ryS3cr3t+"))
			if err != nil {
				t.Errorf("unable to create new client: %s", err)
				return
			}
			if err = client.DialWithContext(context.Background()); err != nil {
				t.Errorf("failed to dial to test server: %s", err)
			}
			if err = client.Close(); err != nil {
				t.Errorf("failed to close server connection: %s", err)
			}
		})
	}
}

func TestClient_AuthLoginFail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 50
	featureSet := "250-AUTH LOGIN\r\n250-X-DEFAULT-LOGIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, true, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 300)

	client, err := NewClient(TestServerAddr,
		WithPort(serverPort),
		WithTLSPortPolicy(NoTLS),
		WithSMTPAuth(SMTPAuthLogin),
		WithUsername("toni@tester.com"),
		WithPassword("InvalidPassword"))
	if err != nil {
		t.Errorf("unable to create new client: %s", err)
		return
	}
	if err = client.DialWithContext(context.Background()); err == nil {
		t.Error("expected to fail to dial to test server, but it succeeded")
	}
}

func TestClient_AuthLoginFail_noTLS(t *testing.T) {
	if os.Getenv("TEST_SKIP_ONLINE") != "" {
		t.Skipf("env variable TEST_SKIP_ONLINE is set. Skipping online tests")
	}
	th := os.Getenv("TEST_HOST")
	if th == "" {
		t.Skipf("no host set. Skipping online tests")
	}
	tp := 587
	if tps := os.Getenv("TEST_PORT"); tps != "" {
		tpi, err := strconv.Atoi(tps)
		if err == nil {
			tp = tpi
		}
	}
	client, err := NewClient(th, WithPort(tp), WithSMTPAuth(SMTPAuthLogin), WithTLSPolicy(NoTLS))
	if err != nil {
		t.Errorf("failed to create new client: %s", err)
	}
	u := os.Getenv("TEST_SMTPAUTH_USER")
	if u != "" {
		client.SetUsername(u)
	}
	p := os.Getenv("TEST_SMTPAUTH_PASS")
	if p != "" {
		client.SetPassword(p)
	}
	// We don't want to log authentication data in tests
	client.SetDebugLog(false)

	if err = client.DialWithContext(context.Background()); err == nil {
		t.Error("expected to fail to dial to test server, but it succeeded")
	}
	if !errors.Is(err, smtp.ErrUnencrypted) {
		t.Errorf("expected error to be %s, but got %s", smtp.ErrUnencrypted, err)
	}
}

func TestClient_AuthSCRAMSHAX_fail(t *testing.T) {
	if os.Getenv("TEST_ONLINE_SCRAM") == "" {
		t.Skipf("TEST_ONLINE_SCRAM is not set. Skipping online SCRAM tests")
	}
	hostname := os.Getenv("TEST_HOST_SCRAM")

	tests := []struct {
		name     string
		authtype SMTPAuthType
	}{
		{"SCRAM-SHA-1", SMTPAuthSCRAMSHA1},
		{"SCRAM-SHA-1-PLUS", SMTPAuthSCRAMSHA1PLUS},
		{"SCRAM-SHA-256", SMTPAuthSCRAMSHA256},
		{"SCRAM-SHA-256-PLUS", SMTPAuthSCRAMSHA256PLUS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(hostname,
				WithTLSPortPolicy(TLSMandatory),
				WithSMTPAuth(tt.authtype),
				WithUsername("invalid"), WithPassword("invalid"))
			if err != nil {
				t.Errorf("unable to create new client: %s", err)
				return
			}
			if err = client.DialWithContext(context.Background()); err == nil {
				t.Errorf("expected error but got nil")
			}
		})
	}
}

func TestClient_AuthSCRAMSHAX_unsupported(t *testing.T) {
	if os.Getenv("TEST_ALLOW_SEND") == "" {
		t.Skipf("TEST_ALLOW_SEND is not set. Skipping mail sending test")
	}

	client, err := getTestConnection(true)
	if err != nil {
		t.Skipf("failed to create test client: %s. Skipping tests", err)
	}

	tests := []struct {
		name     string
		authtype SMTPAuthType
		expErr   error
	}{
		{"SCRAM-SHA-1", SMTPAuthSCRAMSHA1, ErrSCRAMSHA1AuthNotSupported},
		{"SCRAM-SHA-1-PLUS", SMTPAuthSCRAMSHA1PLUS, ErrSCRAMSHA1PLUSAuthNotSupported},
		{"SCRAM-SHA-256", SMTPAuthSCRAMSHA256, ErrSCRAMSHA256AuthNotSupported},
		{"SCRAM-SHA-256-PLUS", SMTPAuthSCRAMSHA256PLUS, ErrSCRAMSHA256PLUSAuthNotSupported},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client.SetSMTPAuth(tt.authtype)
			client.SetTLSPolicy(TLSMandatory)
			if err = client.DialWithContext(context.Background()); err == nil {
				t.Errorf("expected error but got nil")
			}
			if !errors.Is(err, tt.expErr) {
				t.Errorf("expected error %s, but got %s", tt.expErr, err)
			}
		})
	}
}

func TestClient_AuthSCRAMSHAXPLUS_tlsexporter(t *testing.T) {
	if os.Getenv("TEST_ONLINE_SCRAM") == "" {
		t.Skipf("TEST_ONLINE_SCRAM is not set. Skipping online SCRAM tests")
	}
	hostname := os.Getenv("TEST_HOST_SCRAM")
	username := os.Getenv("TEST_USER_SCRAM")
	password := os.Getenv("TEST_PASS_SCRAM")

	tests := []struct {
		name     string
		authtype SMTPAuthType
	}{
		{"SCRAM-SHA-1-PLUS", SMTPAuthSCRAMSHA1PLUS},
		{"SCRAM-SHA-256-PLUS", SMTPAuthSCRAMSHA256PLUS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(hostname,
				WithTLSPortPolicy(TLSMandatory),
				WithSMTPAuth(tt.authtype),
				WithUsername(username), WithPassword(password))
			if err != nil {
				t.Errorf("unable to create new client: %s", err)
				return
			}
			if err = client.DialWithContext(context.Background()); err != nil {
				t.Errorf("failed to dial to test server: %s", err)
			}
			if err = client.Close(); err != nil {
				t.Errorf("failed to close server connection: %s", err)
			}
		})
	}
}

func TestClient_AuthSCRAMSHAXPLUS_tlsunique(t *testing.T) {
	if os.Getenv("TEST_ONLINE_SCRAM") == "" {
		t.Skipf("TEST_ONLINE_SCRAM is not set. Skipping online SCRAM tests")
	}
	hostname := os.Getenv("TEST_HOST_SCRAM")
	username := os.Getenv("TEST_USER_SCRAM")
	password := os.Getenv("TEST_PASS_SCRAM")
	tlsConfig := &tls.Config{}
	tlsConfig.MaxVersion = tls.VersionTLS12
	tlsConfig.ServerName = hostname

	tests := []struct {
		name     string
		authtype SMTPAuthType
	}{
		{"SCRAM-SHA-1-PLUS", SMTPAuthSCRAMSHA1PLUS},
		{"SCRAM-SHA-256-PLUS", SMTPAuthSCRAMSHA256PLUS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(hostname,
				WithTLSPortPolicy(TLSMandatory),
				WithTLSConfig(tlsConfig),
				WithSMTPAuth(tt.authtype),
				WithUsername(username), WithPassword(password))
			if err != nil {
				t.Errorf("unable to create new client: %s", err)
				return
			}
			if err = client.DialWithContext(context.Background()); err != nil {
				t.Errorf("failed to dial to test server: %s", err)
			}
			if err = client.Close(); err != nil {
				t.Errorf("failed to close server connection: %s", err)
			}
		})
	}
}

// getTestConnection takes environment variables to establish a connection to a real
// SMTP server to test all functionality that requires a connection
func getTestConnection(auth bool) (*Client, error) {
	if os.Getenv("TEST_SKIP_ONLINE") != "" {
		return nil, fmt.Errorf("env variable TEST_SKIP_ONLINE is set. Skipping online tests")
	}
	th := os.Getenv("TEST_HOST")
	if th == "" {
		return nil, fmt.Errorf("no TEST_HOST set")
	}
	tp := 25
	if tps := os.Getenv("TEST_PORT"); tps != "" {
		tpi, err := strconv.Atoi(tps)
		if err == nil {
			tp = tpi
		}
	}
	sv := false
	if sve := os.Getenv("TEST_TLS_SKIP_VERIFY"); sve != "" {
		sv = true
	}
	c, err := NewClient(th, WithPort(tp))
	if err != nil {
		return c, err
	}
	c.tlsconfig.InsecureSkipVerify = sv
	if auth {
		st := os.Getenv("TEST_SMTPAUTH_TYPE")
		if st != "" {
			c.SetSMTPAuth(SMTPAuthType(st))
		}
		u := os.Getenv("TEST_SMTPAUTH_USER")
		if u != "" {
			c.SetUsername(u)
		}
		p := os.Getenv("TEST_SMTPAUTH_PASS")
		if p != "" {
			c.SetPassword(p)
		}
		// We don't want to log authentication data in tests
		c.SetDebugLog(false)
	}
	if err = c.DialWithContext(context.Background()); err != nil {
		return c, fmt.Errorf("connection to test server failed: %w", err)
	}
	if err = c.Close(); err != nil {
		return c, fmt.Errorf("disconnect from test server failed: %w", err)
	}
	return c, nil
}

// getTestConnectionNoTestPort takes environment variables (except the port) to establish a
// connection to a real SMTP server to test all functionality that requires a connection
func getTestConnectionNoTestPort(auth bool) (*Client, error) {
	if os.Getenv("TEST_SKIP_ONLINE") != "" {
		return nil, fmt.Errorf("env variable TEST_SKIP_ONLINE is set. Skipping online tests")
	}
	th := os.Getenv("TEST_HOST")
	if th == "" {
		return nil, fmt.Errorf("no TEST_HOST set")
	}
	sv := false
	if sve := os.Getenv("TEST_TLS_SKIP_VERIFY"); sve != "" {
		sv = true
	}
	c, err := NewClient(th)
	if err != nil {
		return c, err
	}
	c.tlsconfig.InsecureSkipVerify = sv
	if auth {
		st := os.Getenv("TEST_SMTPAUTH_TYPE")
		if st != "" {
			c.SetSMTPAuth(SMTPAuthType(st))
		}
		u := os.Getenv("TEST_SMTPAUTH_USER")
		if u != "" {
			c.SetUsername(u)
		}
		p := os.Getenv("TEST_SMTPAUTH_PASS")
		if p != "" {
			c.SetPassword(p)
		}
		// We don't want to log authentication data in tests
		c.SetDebugLog(false)
	}
	if err := c.DialWithContext(context.Background()); err != nil {
		return c, fmt.Errorf("connection to test server failed: %w", err)
	}
	if err := c.Close(); err != nil {
		return c, fmt.Errorf("disconnect from test server failed: %w", err)
	}
	return c, nil
}

// getTestClient takes environment variables to establish a client without connecting
// to the SMTP server
func getTestClient(auth bool) (*Client, error) {
	if os.Getenv("TEST_SKIP_ONLINE") != "" {
		return nil, fmt.Errorf("env variable TEST_SKIP_ONLINE is set. Skipping online tests")
	}
	th := os.Getenv("TEST_HOST")
	if th == "" {
		return nil, fmt.Errorf("no TEST_HOST set")
	}
	tp := 25
	if tps := os.Getenv("TEST_PORT"); tps != "" {
		tpi, err := strconv.Atoi(tps)
		if err == nil {
			tp = tpi
		}
	}
	sv := false
	if sve := os.Getenv("TEST_TLS_SKIP_VERIFY"); sve != "" {
		sv = true
	}
	c, err := NewClient(th, WithPort(tp))
	if err != nil {
		return c, err
	}
	c.tlsconfig.InsecureSkipVerify = sv
	if auth {
		st := os.Getenv("TEST_SMTPAUTH_TYPE")
		if st != "" {
			c.SetSMTPAuth(SMTPAuthType(st))
		}
		u := os.Getenv("TEST_SMTPAUTH_USER")
		if u != "" {
			c.SetUsername(u)
		}
		p := os.Getenv("TEST_SMTPAUTH_PASS")
		if p != "" {
			c.SetPassword(p)
		}
		// We don't want to log authentication data in tests
		c.SetDebugLog(false)
	}
	return c, nil
}

// getTestConnectionWithDSN takes environment variables to establish a connection to a real
// SMTP server to test all functionality that requires a connection. It also enables DSN
func getTestConnectionWithDSN(auth bool) (*Client, error) {
	if os.Getenv("TEST_SKIP_ONLINE") != "" {
		return nil, fmt.Errorf("env variable TEST_SKIP_ONLINE is set. Skipping online tests")
	}
	th := os.Getenv("TEST_HOST")
	if th == "" {
		return nil, fmt.Errorf("no TEST_HOST set")
	}
	tp := 25
	if tps := os.Getenv("TEST_PORT"); tps != "" {
		tpi, err := strconv.Atoi(tps)
		if err == nil {
			tp = tpi
		}
	}
	c, err := NewClient(th, WithDSN(), WithPort(tp))
	if err != nil {
		return c, err
	}
	if auth {
		st := os.Getenv("TEST_SMTPAUTH_TYPE")
		if st != "" {
			c.SetSMTPAuth(SMTPAuthType(st))
		}
		u := os.Getenv("TEST_SMTPAUTH_USER")
		if u != "" {
			c.SetUsername(u)
		}
		p := os.Getenv("TEST_SMTPAUTH_PASS")
		if p != "" {
			c.SetPassword(p)
		}
	}
	if err := c.DialWithContext(context.Background()); err != nil {
		return c, fmt.Errorf("connection to test server failed: %w", err)
	}
	if err := c.Close(); err != nil {
		return c, fmt.Errorf("disconnect from test server failed: %w", err)
	}
	return c, nil
}

func TestXOAuth2OK(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 30
	featureSet := "250-AUTH XOAUTH2\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, false, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 500)

	c, err := NewClient("127.0.0.1",
		WithPort(serverPort),
		WithTLSPortPolicy(TLSOpportunistic),
		WithSMTPAuth(SMTPAuthXOAUTH2),
		WithUsername("user"),
		WithPassword("token"))
	if err != nil {
		t.Fatalf("unable to create new client: %v", err)
	}
	if err = c.DialWithContext(context.Background()); err != nil {
		t.Fatalf("unexpected dial error: %v", err)
	}
	if err = c.Close(); err != nil {
		t.Fatalf("disconnect from test server failed: %v", err)
	}
}

func TestXOAuth2Unsupported(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 31
	featureSet := "250-AUTH LOGIN PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, false, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 500)

	c, err := NewClient("127.0.0.1",
		WithPort(serverPort),
		WithTLSPolicy(TLSOpportunistic),
		WithSMTPAuth(SMTPAuthXOAUTH2),
		WithUsername("user"),
		WithPassword("token"))
	if err != nil {
		t.Fatalf("unable to create new client: %v", err)
	}
	if err = c.DialWithContext(context.Background()); err == nil {
		t.Fatal("expected dial error got nil")
	} else {
		if !errors.Is(err, ErrXOauth2AuthNotSupported) {
			t.Fatalf("expected %v; got %v", ErrXOauth2AuthNotSupported, err)
		}
	}
	if err = c.Close(); err != nil {
		t.Fatalf("disconnect from test server failed: %v", err)
	}
}

func TestXOAuth2OK_faker(t *testing.T) {
	server := []string{
		"220 Fake server ready ESMTP",
		"250-fake.server",
		"250-AUTH LOGIN XOAUTH2",
		"250 8BITMIME",
		"250 OK",
		"235 2.7.0 Accepted",
		"221 OK",
	}
	var wrote strings.Builder
	var fake faker
	fake.ReadWriter = struct {
		io.Reader
		io.Writer
	}{
		strings.NewReader(strings.Join(server, "\r\n")),
		&wrote,
	}
	c, err := NewClient("fake.host",
		WithDialContextFunc(getFakeDialFunc(fake)),
		WithTLSPortPolicy(TLSOpportunistic),
		WithSMTPAuth(SMTPAuthXOAUTH2),
		WithUsername("user"),
		WithPassword("token"))
	if err != nil {
		t.Fatalf("unable to create new client: %v", err)
	}
	if err = c.DialWithContext(context.Background()); err != nil {
		t.Fatalf("unexpected dial error: %v", err)
	}
	if err = c.Close(); err != nil {
		t.Fatalf("disconnect from test server failed: %v", err)
	}
	if !strings.Contains(wrote.String(), "AUTH XOAUTH2 dXNlcj11c2VyAWF1dGg9QmVhcmVyIHRva2VuAQE=\r\n") {
		t.Fatalf("got %q; want AUTH XOAUTH2 dXNlcj11c2VyAWF1dGg9QmVhcmVyIHRva2VuAQE=\r\n", wrote.String())
	}
}

func TestXOAuth2Unsupported_faker(t *testing.T) {
	server := []string{
		"220 Fake server ready ESMTP",
		"250-fake.server",
		"250-AUTH LOGIN PLAIN",
		"250 8BITMIME",
		"250 OK",
		"221 OK",
	}
	var wrote strings.Builder
	var fake faker
	fake.ReadWriter = struct {
		io.Reader
		io.Writer
	}{
		strings.NewReader(strings.Join(server, "\r\n")),
		&wrote,
	}
	c, err := NewClient("fake.host",
		WithDialContextFunc(getFakeDialFunc(fake)),
		WithTLSPortPolicy(TLSOpportunistic),
		WithSMTPAuth(SMTPAuthXOAUTH2))
	if err != nil {
		t.Fatalf("unable to create new client: %v", err)
	}
	if err = c.DialWithContext(context.Background()); err == nil {
		t.Fatal("expected dial error got nil")
	} else {
		if !errors.Is(err, ErrXOauth2AuthNotSupported) {
			t.Fatalf("expected %v; got %v", ErrXOauth2AuthNotSupported, err)
		}
	}
	if err = c.Close(); err != nil {
		t.Fatalf("disconnect from test server failed: %v", err)
	}
	client := strings.Split(wrote.String(), "\r\n")
	if len(client) != 4 {
		t.Fatalf("unexpected number of client requests got %d; want 5", len(client))
	}
	if !strings.HasPrefix(client[0], "EHLO") {
		t.Fatalf("expected EHLO, got %q", client[0])
	}
	if client[1] != "NOOP" {
		t.Fatalf("expected NOOP, got %q", client[1])
	}
	if client[2] != "QUIT" {
		t.Fatalf("expected QUIT, got %q", client[3])
	}
}

func getFakeDialFunc(conn net.Conn) DialContextFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return conn, nil
	}
}

type faker struct {
	io.ReadWriter
}

func (f faker) Close() error                     { return nil }
func (f faker) LocalAddr() net.Addr              { return nil }
func (f faker) RemoteAddr() net.Addr             { return nil }
func (f faker) SetDeadline(time.Time) error      { return nil }
func (f faker) SetReadDeadline(time.Time) error  { return nil }
func (f faker) SetWriteDeadline(time.Time) error { return nil }
*/

// parseJSONLog parses a JSON encoded log from the provided buffer and returns a slice of logLine structs.
// In case of a decode error, it reports the error to the testing framework.
func parseJSONLog(t *testing.T, buf *bytes.Buffer) logData {
	t.Helper()

	builder := strings.Builder{}
	builder.WriteString(`{"lines":[`)
	lines := strings.Split(buf.String(), "\n")
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		builder.WriteString(line)
		if i < len(lines)-2 {
			builder.WriteString(`,`)
		}
	}
	builder.WriteString("]}")

	var logdata logData
	readBuffer := bytes.NewBuffer(nil)
	readBuffer.WriteString(builder.String())
	if err := json.NewDecoder(readBuffer).Decode(&logdata); err != nil {
		t.Errorf("failed to decode json log: %s", err)
	}
	return logdata
}

// testMessage configures and returns a new email message for testing, initializing it with valid sender and recipient.
func testMessage(t *testing.T) *Msg {
	t.Helper()
	message := NewMsg()
	if err := message.From(TestSenderValid); err != nil {
		t.Errorf("failed to set sender address: %s", err)
	}
	if err := message.To(TestRcptValid); err != nil {
		t.Errorf("failed to set recipient address: %s", err)
	}
	message.Subject("Testmail")
	message.SetBodyString(TypeTextPlain, "Testmail")
	return message
}

// testingKey replaces the substring "TESTING KEY" with "PRIVATE KEY" in the given string s.
func testingKey(s string) string { return strings.ReplaceAll(s, "TESTING KEY", "PRIVATE KEY") }

// serverProps represents the configuration properties for the SMTP server.
type serverProps struct {
	FailOnAuth     bool
	FailOnData     bool
	FailOnHelo     bool
	FailOnQuit     bool
	FailOnReset    bool
	FailOnSTARTTLS bool
	FeatureSet     string
	ListenPort     int
	SSLListener    bool
	IsTLS          bool
}

// simpleSMTPServer starts a simple TCP server that resonds to SMTP commands.
// The provided featureSet represents in what the server responds to EHLO command
// failReset controls if a RSET succeeds
func simpleSMTPServer(ctx context.Context, t *testing.T, props *serverProps) error {
	t.Helper()
	if props == nil {
		return fmt.Errorf("no server properties provided")
	}

	var listener net.Listener
	var err error
	if props.SSLListener {
		keypair, err := tls.X509KeyPair(localhostCert, localhostKey)
		if err != nil {
			return fmt.Errorf("failed to read TLS keypair: %s", err)
		}
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{keypair}}
		listener, err = tls.Listen(TestServerProto, fmt.Sprintf("%s:%d", TestServerAddr, props.ListenPort),
			tlsConfig)
	} else {
		listener, err = net.Listen(TestServerProto, fmt.Sprintf("%s:%d", TestServerAddr, props.ListenPort))
	}
	if err != nil {
		return fmt.Errorf("unable to listen on %s://%s: %w (SSL: %t)", TestServerProto, TestServerAddr, err,
			props.SSLListener)
	}

	defer func() {
		if err := listener.Close(); err != nil {
			t.Logf("failed to close listener: %s", err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			connection, err := listener.Accept()
			var opErr *net.OpError
			if err != nil {
				if errors.As(err, &opErr) && opErr.Temporary() {
					continue
				}
				return fmt.Errorf("unable to accept connection: %w", err)
			}
			handleTestServerConnection(connection, t, props)
		}
	}
}

func handleTestServerConnection(connection net.Conn, t *testing.T, props *serverProps) {
	t.Helper()
	if !props.IsTLS {
		t.Cleanup(func() {
			if err := connection.Close(); err != nil {
				t.Logf("failed to close connection: %s", err)
			}
		})
	}

	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)

	writeLine := func(data string) {
		_, err := writer.WriteString(data + "\r\n")
		if err != nil {
			t.Logf("failed to write line: %s", err)
		}
		_ = writer.Flush()
	}
	writeOK := func() {
		writeLine("250 2.0.0 OK")
	}

	if !props.IsTLS {
		writeLine("220 go-mail test server ready ESMTP")
	}

	for {
		data, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		time.Sleep(time.Millisecond)

		var datastring string
		data = strings.TrimSpace(data)
		switch {
		case strings.HasPrefix(data, "EHLO"), strings.HasPrefix(data, "HELO"):
			if len(strings.Split(data, " ")) != 2 {
				writeLine("501 Syntax: EHLO hostname")
				break
			}
			if props.FailOnHelo {
				writeLine("500 5.5.2 Error: fail on HELO")
				break
			}
			writeLine("250-localhost.localdomain\r\n" + props.FeatureSet)
			break
		case strings.HasPrefix(data, "MAIL FROM:"):
			from := strings.TrimPrefix(data, "MAIL FROM:")
			from = strings.ReplaceAll(from, "BODY=8BITMIME", "")
			from = strings.ReplaceAll(from, "SMTPUTF8", "")
			from = strings.TrimSpace(from)
			if !strings.EqualFold(from, "<valid-from@domain.tld>") {
				writeLine(fmt.Sprintf("503 5.1.2 Invalid from: %s", from))
				break
			}
			writeOK()
		case strings.HasPrefix(data, "RCPT TO:"):
			to := strings.TrimPrefix(data, "RCPT TO:")
			to = strings.TrimSpace(to)
			if !strings.EqualFold(to, "<valid-to@domain.tld>") {
				writeLine(fmt.Sprintf("500 5.1.2 Invalid to: %s", to))
				break
			}
			writeOK()
		case strings.HasPrefix(data, "AUTH"):
			if props.FailOnAuth {
				writeLine("535 5.7.8 Error: authentication failed")
				break
			}
			writeLine("235 2.7.0 Authentication successful")
		case strings.EqualFold(data, "DATA"):
			writeLine("354 End data with <CR><LF>.<CR><LF>")
			for {
				ddata, derr := reader.ReadString('\n')
				if derr != nil {
					t.Logf("failed to read data from connection: %s", derr)
					break
				}
				ddata = strings.TrimSpace(ddata)
				if ddata == "." {
					if props.FailOnData {
						writeLine("500 5.0.0 Error during DATA transmission")
						break
					}
					writeLine("250 2.0.0 Ok: queued as 1234567890")
					break
				}
				datastring += ddata + "\n"
			}
		case strings.EqualFold(data, "noop"),
			strings.EqualFold(data, "vrfy"):
			writeOK()
		case strings.EqualFold(data, "rset"):
			if props.FailOnReset {
				writeLine("500 5.1.2 Error: reset failed")
				break
			}
			writeOK()
		case strings.EqualFold(data, "quit"):
			if props.FailOnQuit {
				writeLine("500 5.1.2 Error: quit failed")
				break
			}
			writeLine("221 2.0.0 Bye")
			return
		case strings.EqualFold(data, "starttls"):
			if props.FailOnSTARTTLS {
				writeLine("500 5.1.2 Error: starttls failed")
				break
			}
			keypair, err := tls.X509KeyPair(localhostCert, localhostKey)
			if err != nil {
				writeLine("500 5.1.2 Error: starttls failed - " + err.Error())
				break
			}
			writeLine("220 Ready to start TLS")
			tlsConfig := &tls.Config{Certificates: []tls.Certificate{keypair}}
			connection = tls.Server(connection, tlsConfig)
			props.IsTLS = true
			handleTestServerConnection(connection, t, props)
		default:
			writeLine("500 5.5.2 Error: bad syntax")
		}
	}
}
