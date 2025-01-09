// SPDX-FileCopyrightText: The go-mail Authors
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
	"io"
	"net"
	"net/mail"
	"os"
	"reflect"
	"strconv"
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
	DefaultHost = "127.0.0.1"
	// TestServerProto is the protocol used for the simple SMTP test server
	TestServerProto = "tcp"
	// TestServerAddr is the address the simple SMTP test server listens on
	TestServerAddr = "127.0.0.1"
	// TestSenderValid is a test sender email address considered valid for sending test emails.
	TestSenderValid = "valid-from@domain.tld"
	// TestRcptValid is a test recipient email address considered valid for sending test emails.
	TestRcptValid = "valid-to@domain.tld"
)

// TestServerPortBase is the base port for the simple SMTP test server
var TestServerPortBase int32 = 30025

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

func init() {
	testPort := os.Getenv("TEST_BASEPORT")
	if testPort == "" {
		return
	}
	if port, err := strconv.Atoi(testPort); err == nil {
		if port <= 65000 && port > 1023 {
			TestServerPortBase = int32(port)
		}
	}
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
	t.Run("NewClient on Unix Domain Socket", func(t *testing.T) {
		client, err := NewClient("unix:///tmp/mail.sock")
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if !client.useUnixSocket {
			t.Error("Expected useUnixSocket flag to be set to true")
		}
		if !strings.EqualFold(client.host, "/tmp/mail.sock") {
			t.Errorf("expected host to be set to unix socket path, expected: %s, got: %s", "/tmp/mail.sock",
				client.host)
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
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
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
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
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
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
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
			{
				"LOGIN", smtp.LoginAuth("", "", "", false),
				"*smtp.loginAuth",
			},
			{
				"LOGIN-NOENC", smtp.LoginAuth("", "", "", true),
				"*smtp.loginAuth",
			},
			{
				"PLAIN", smtp.PlainAuth("", "", "", "", false),
				"*smtp.plainAuth",
			},
			{
				"PLAIN-NOENC", smtp.PlainAuth("", "", "", "", true),
				"*smtp.plainAuth",
			},
			{"SCRAM-SHA-1", smtp.ScramSHA1Auth("", ""), "*smtp.scramAuth"},
			{
				"SCRAM-SHA-1-PLUS", smtp.ScramSHA1PlusAuth("", "", nil),
				"*smtp.scramAuth",
			},
			{"SCRAM-SHA-256", smtp.ScramSHA256Auth("", ""), "*smtp.scramAuth"},
			{
				"SCRAM-SHA-256-PLUS", smtp.ScramSHA256PlusAuth("", "", nil),
				"*smtp.scramAuth",
			},
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
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
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
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
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
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to the test server: %s", err)
		}
		if !client.smtpClient.HasConnection() {
			t.Fatalf("client has no connection")
		}
		if err = client.Close(); err == nil {
			t.Errorf("close was supposed to fail, but didn't")
		}
	})
	t.Run("close on a nil smtpclient should return nil", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.Close(); err != nil {
			t.Errorf("failed to close the client: %s", err)
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
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
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
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
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
		if client.smtpClient != nil {
			t.Error("client with invalid HELO should not have a smtp client")
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
	t.Run("connect should fail on HELO", func(t *testing.T) {
		ctxFail, cancelFail := context.WithCancel(ctx)
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
		if client.smtpClient != nil {
			t.Fatalf("client is not supposed to have a smtp client")
		}
	})
	t.Run("connect with failing auth", func(t *testing.T) {
		ctxAuth, cancelAuth := context.WithCancel(ctx)
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
		ctxTLS, cancelTLS := context.WithCancel(ctx)
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
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to the test server: %s", err)
		}
	})
	t.Run("connect with STARTTLS Opportunisticly", func(t *testing.T) {
		ctxTLS, cancelTLS := context.WithCancel(ctx)
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
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to the test server: %s", err)
		}
	})
	t.Run("connect with STARTTLS but fail", func(t *testing.T) {
		ctxTLS, cancelTLS := context.WithCancel(ctx)
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
		ctxTLS, cancelTLS := context.WithCancel(ctx)
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
		ctxSSL, cancelSSL := context.WithCancel(ctx)
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
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
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
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
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
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
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
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
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
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
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
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
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
				FailOnDataClose: true,
				FeatureSet:      featureSet,
				ListenPort:      serverPort,
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
	// https://github.com/wneessen/go-mail/issues/380
	t.Run("concurrent sending via DialAndSendWithContext", func(t *testing.T) {
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

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}

		wg := sync.WaitGroup{}
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				msg := testMessage(t)
				msg.SetMessageIDWithValue("this.is.a.message.id")

				ctxDial, cancelDial := context.WithTimeout(ctx, time.Minute)
				defer cancelDial()
				if goroutineErr := client.DialAndSendWithContext(ctxDial, msg); goroutineErr != nil {
					t.Errorf("failed to dial and send message: %s", goroutineErr)
				}
			}()
		}
		wg.Wait()
	})
	// https://github.com/wneessen/go-mail/issues/385
	t.Run("concurrent sending via DialAndSendWithContext on receiver func", func(t *testing.T) {
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

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		sender := testSender{client}

		ctxDial := context.Background()
		wg := sync.WaitGroup{}
		for i := 0; i < 5; i++ {
			wg.Add(1)
			msg := testMessage(t)
			go func() {
				defer wg.Done()
				if goroutineErr := sender.Send(ctxDial, msg); goroutineErr != nil {
					t.Errorf("failed to send message: %s", goroutineErr)
				}
			}()
		}
		wg.Wait()
	})
}

func TestClient_auth(t *testing.T) {
	tests := []struct {
		name     string
		authType SMTPAuthType
	}{
		{"LOGIN via AUTODISCOVER", SMTPAuthAutoDiscover},
		{"PLAIN via AUTODISCOVER", SMTPAuthAutoDiscover},
		{"SCRAM-SHA-1 via AUTODISCOVER", SMTPAuthAutoDiscover},
		{"SCRAM-SHA-256 via AUTODISCOVER", SMTPAuthAutoDiscover},
		{"XOAUTH2 via AUTODISCOVER", SMTPAuthAutoDiscover},
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
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					t.Skip("failed to connect to the test server due to timeout")
				}
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

func TestClient_authTypeAutoDiscover(t *testing.T) {
	tests := []struct {
		supported  string
		tls        bool
		expect     SMTPAuthType
		shouldFail bool
	}{
		{"LOGIN SCRAM-SHA-256 SCRAM-SHA-1 SCRAM-SHA-256-PLUS SCRAM-SHA-1-PLUS", true, SMTPAuthSCRAMSHA256PLUS, false},
		{"LOGIN SCRAM-SHA-256 SCRAM-SHA-1 SCRAM-SHA-256-PLUS SCRAM-SHA-1-PLUS", false, SMTPAuthSCRAMSHA256, false},
		{"LOGIN PLAIN SCRAM-SHA-1 SCRAM-SHA-1-PLUS", true, SMTPAuthSCRAMSHA1PLUS, false},
		{"LOGIN PLAIN SCRAM-SHA-1 SCRAM-SHA-1-PLUS", false, SMTPAuthSCRAMSHA1, false},
		{"LOGIN XOAUTH2 SCRAM-SHA-1-PLUS", false, SMTPAuthXOAUTH2, false},
		{"PLAIN LOGIN CRAM-MD5", false, SMTPAuthCramMD5, false},
		{"CRAM-MD5", false, SMTPAuthCramMD5, false},
		{"PLAIN", true, SMTPAuthPlain, false},
		{"LOGIN PLAIN", true, SMTPAuthPlain, false},
		{"LOGIN PLAIN", false, "no secure mechanism", true},
		{"", false, "supported list empty", true},
	}
	for _, tt := range tests {
		t.Run("AutoDiscover selects the strongest auth type: "+string(tt.expect), func(t *testing.T) {
			client := &Client{smtpAuthType: SMTPAuthAutoDiscover}
			authType, err := client.authTypeAutoDiscover(tt.supported, tt.tls)
			if err != nil && !tt.shouldFail {
				t.Fatalf("failed to auto discover auth type: %s", err)
			}
			if tt.shouldFail && err == nil {
				t.Fatal("expected auto discover to fail")
			}
			if !tt.shouldFail && authType != tt.expect {
				t.Errorf("expected strongest auth type: %s, got: %s", tt.expect, authType)
			}
		})
	}
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
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
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
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.Send(message); err == nil {
			t.Errorf("client should have failed to send email with no connection")
		}
		var sendErr *SendError
		if !errors.As(err, &sendErr) {
			t.Fatalf("expected SendError, got %s", err)
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
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					t.Skip("failed to close the test server connection due to timeout")
				}
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

func TestClient_DialToSMTPClientWithContext(t *testing.T) {
	t.Run("establish a new client connection", func(t *testing.T) {
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
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		smtpClient, err := client.DialToSMTPClientWithContext(ctxDial)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.CloseWithSMTPClient(smtpClient); err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					t.Skip("failed to close the test server connection due to timeout")
				}
				t.Errorf("failed to close client: %s", err)
			}
		})
		if smtpClient == nil {
			t.Fatal("expected SMTP client, got nil")
		}
		if !smtpClient.HasConnection() {
			t.Fatal("expected connection on smtp client")
		}
		if ok, _ := smtpClient.Extension("DSN"); !ok {
			t.Error("expected DSN extension but it was not found")
		}
	})
	t.Run("dial to SMTP server fails on first client writeFile", func(t *testing.T) {
		var fake faker
		fake.ReadWriter = struct {
			io.Reader
			io.Writer
		}{
			failReadWriteSeekCloser{},
			failReadWriteSeekCloser{},
		}

		ctxDial, cancelDial := context.WithTimeout(context.Background(), time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithDialContextFunc(getFakeDialFunc(fake)))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		_, err = client.DialToSMTPClientWithContext(ctxDial)
		if err == nil {
			t.Fatal("expected connection to fake to fail")
		}
	})
	t.Run("dial to Unix domain socket", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		props := &serverProps{
			FeatureSet: featureSet,
			ListenPort: serverPort,
			UnixSocket: true,
		}
		go func() {
			if err := simpleSMTPServer(ctx, t, props); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)
		t.Cleanup(func() {
			if err := os.RemoveAll(props.UnixSocketPath); err != nil {
				t.Errorf("failed to remove unix socket: %s", err)
			}
		})

		client, err := NewClient("unix://"+props.UnixSocketPath+"/server.sock", WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		smtpClient, err := client.DialToSMTPClientWithContext(ctxDial)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.CloseWithSMTPClient(smtpClient); err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					t.Skip("failed to close the test server connection due to timeout")
				}
				t.Errorf("failed to close client: %s", err)
			}
		})
		if smtpClient == nil {
			t.Fatal("expected SMTP client, got nil")
		}
		if !smtpClient.HasConnection() {
			t.Fatal("expected connection on smtp client")
		}
		if ok, _ := smtpClient.Extension("DSN"); !ok {
			t.Error("expected DSN extension but it was not found")
		}
	})
}

func TestClient_sendSingleMsg(t *testing.T) {
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

		message := testMessage(t)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.sendSingleMsg(client.smtpClient, message); err != nil {
			t.Errorf("failed to send message: %s", err)
		}
	})
	t.Run("server does not support 8BITMIME", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-DSN\r\n250 SMTPUTF8"
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

		message := testMessage(t)
		message.SetEncoding(NoEncoding)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.sendSingleMsg(client.smtpClient, message); err == nil {
			t.Errorf("client should have failed to send message")
		}
	})
	t.Run("fail on invalid sender address", func(t *testing.T) {
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

		message := testMessage(t)
		message.addrHeader["From"] = []*mail.Address{
			{Name: "invalid", Address: "invalid"},
		}

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.sendSingleMsg(client.smtpClient, message); err == nil {
			t.Errorf("client should have failed to send message")
		}
		var sendErr *SendError
		if !errors.As(err, &sendErr) {
			t.Errorf("expected SendError, got %s", err)
		}
		if sendErr.Reason != ErrSMTPMailFrom {
			t.Errorf("expected ErrSMTPMailFrom, got %s", sendErr.Reason)
		}
	})
	t.Run("fail with no sender address", func(t *testing.T) {
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

		message := testMessage(t)
		message.addrHeader["From"] = nil

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.sendSingleMsg(client.smtpClient, message); err == nil {
			t.Errorf("client should have failed to send message")
		}
		var sendErr *SendError
		if !errors.As(err, &sendErr) {
			t.Errorf("expected SendError, got %s", err)
		}
		if sendErr.Reason != ErrGetSender {
			t.Errorf("expected ErrGetSender, got %s", sendErr.Reason)
		}
	})
	t.Run("fail with no recipient addresses", func(t *testing.T) {
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

		message := testMessage(t)
		message.addrHeader["To"] = nil

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.sendSingleMsg(client.smtpClient, message); err == nil {
			t.Errorf("client should have failed to send message")
		}
		var sendErr *SendError
		if !errors.As(err, &sendErr) {
			t.Errorf("expected SendError, got %s", err)
		}
		if sendErr.Reason != ErrGetRcpts {
			t.Errorf("expected ErrGetRcpts, got %s", sendErr.Reason)
		}
	})
	t.Run("connect and send email with DSN", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FeatureSet: featureSet,
				ListenPort: serverPort,
				SupportDSN: true,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		message := testMessage(t)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS), WithDSN())
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.sendSingleMsg(client.smtpClient, message); err != nil {
			t.Errorf("failed to send message: %s", err)
		}
	})
	t.Run("connect and send email but fail on reset", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
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

		message := testMessage(t)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.sendSingleMsg(client.smtpClient, message); err == nil {
			t.Errorf("client should have failed to send message")
		}
		var sendErr *SendError
		if !errors.As(err, &sendErr) {
			t.Errorf("expected SendError, got %s", err)
		}
		if sendErr.Reason != ErrSMTPReset {
			t.Errorf("expected ErrSMTPReset, got %s", sendErr.Reason)
		}
	})
	t.Run("connect and send email but with mix of valid and invalid rcpts", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
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

		message := testMessage(t)
		message.addrHeader["To"] = append(message.addrHeader["To"], &mail.Address{Name: "invalid", Address: "invalid"})

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.sendSingleMsg(client.smtpClient, message); err == nil {
			t.Errorf("client should have failed to send message")
		}
		var sendErr *SendError
		if !errors.As(err, &sendErr) {
			t.Errorf("expected SendError, got %s", err)
		}
		if sendErr.Reason != ErrSMTPRcptTo {
			t.Errorf("expected ErrSMTPRcptTo, got %s", sendErr.Reason)
		}
	})
	t.Run("connect and send email but fail on mail to and reset", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnMailFrom: true,
				FailOnReset:    true,
				FeatureSet:     featureSet,
				ListenPort:     serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		message := testMessage(t)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.sendSingleMsg(client.smtpClient, message); err == nil {
			t.Errorf("client should have failed to send message")
		}
		var sendErr *SendError
		if !errors.As(err, &sendErr) {
			t.Errorf("expected SendError, got %s", err)
		}
		if sendErr.Reason != ErrSMTPMailFrom {
			t.Errorf("expected ErrSMTPMailFrom, got %s", sendErr.Reason)
		}
	})
	t.Run("connect and send email but fail on data init", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnDataInit: true,
				FeatureSet:     featureSet,
				ListenPort:     serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		message := testMessage(t)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.sendSingleMsg(client.smtpClient, message); err == nil {
			t.Errorf("client should have failed to send message")
		}
		var sendErr *SendError
		if !errors.As(err, &sendErr) {
			t.Errorf("expected SendError, got %s", err)
		}
		if sendErr.Reason != ErrSMTPData {
			t.Errorf("expected ErrSMTPData, got %s", sendErr.Reason)
		}
	})
	t.Run("connect and send email but fail on data close", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnDataClose: true,
				FeatureSet:      featureSet,
				ListenPort:      serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		message := testMessage(t)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.sendSingleMsg(client.smtpClient, message); err == nil {
			t.Errorf("client should have failed to send message")
		}
		var sendErr *SendError
		if !errors.As(err, &sendErr) {
			t.Errorf("expected SendError, got %s", err)
		}
		if sendErr.Reason != ErrSMTPDataClose {
			t.Errorf("expected ErrSMTPDataClose, got %s", sendErr.Reason)
		}
	})
	t.Run("error code and enhanced status code support", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnMailFrom: true,
				FeatureSet:     featureSet,
				ListenPort:     serverPort,
			}); err != nil {
				t.Errorf("failed to start test server: %s", err)
				return
			}
		}()
		time.Sleep(time.Millisecond * 30)

		message := testMessage(t)

		ctxDial, cancelDial := context.WithTimeout(ctx, time.Millisecond*500)
		t.Cleanup(cancelDial)

		client, err := NewClient(DefaultHost, WithPort(serverPort), WithTLSPolicy(NoTLS))
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.sendSingleMsg(client.smtpClient, message); err == nil {
			t.Error("expected mail delivery to fail")
		}
		var sendErr *SendError
		if !errors.As(err, &sendErr) {
			t.Fatalf("expected SendError, got %s", err)
		}
		if sendErr.errcode != 500 {
			t.Errorf("expected error code 500, got %d", sendErr.errcode)
		}
		if !strings.EqualFold(sendErr.enhancedStatusCode, "5.5.2") {
			t.Errorf("expected enhanced status code 5.5.2, got %s", sendErr.enhancedStatusCode)
		}
	})
}

func TestClient_checkConn(t *testing.T) {
	t.Run("connection is alive", func(t *testing.T) {
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
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.DialWithContext(ctxDial); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.checkConn(client.smtpClient); err != nil {
			t.Errorf("failed to check connection: %s", err)
		}
	})
	t.Run("connection should fail on noop", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		PortAdder.Add(1)
		serverPort := int(TestServerPortBase + PortAdder.Load())
		featureSet := "250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
		go func() {
			if err := simpleSMTPServer(ctx, t, &serverProps{
				FailOnNoop: true,
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
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("failed to connect to test server: %s", err)
		}
		t.Cleanup(func() {
			if err := client.Close(); err != nil {
				t.Errorf("failed to close client: %s", err)
			}
		})
		if err = client.checkConn(client.smtpClient); err == nil {
			t.Errorf("client should have failed on connection check")
		}
		if !errors.Is(err, ErrNoActiveConnection) {
			t.Errorf("expected ErrNoActiveConnection, got %s", err)
		}
	})
	t.Run("connection should fail on no connection", func(t *testing.T) {
		client, err := NewClient(DefaultHost)
		if err != nil {
			t.Fatalf("failed to create new client: %s", err)
		}
		if err = client.checkConn(client.smtpClient); err == nil {
			t.Errorf("client should have failed on connection check")
		}
		if !errors.Is(err, ErrNoActiveConnection) {
			t.Errorf("expected ErrNoActiveConnection, got %s", err)
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
	t.Run("Authentication", func(t *testing.T) {
		hostname := os.Getenv("TEST_HOST")
		username := os.Getenv("TEST_USER")
		password := os.Getenv("TEST_PASS")
		tests := []struct {
			name     string
			authtype SMTPAuthType
		}{
			{"LOGIN", SMTPAuthLogin},
			{"PLAIN", SMTPAuthPlain},
			{"CRAM-MD5", SMTPAuthCramMD5},
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
					WithUsername(username), WithPassword(password))
				if err != nil {
					t.Fatalf("unable to create new client: %s", err)
				}

				ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
				t.Cleanup(cancel)

				if err = client.DialWithContext(ctx); err != nil {
					var netErr net.Error
					if errors.As(err, &netErr) && netErr.Timeout() {
						t.Skip("failed to connect to the test server due to timeout")
					}
					t.Fatalf("failed to dial to test server: %s", err)
				}
				if err = client.smtpClient.Noop(); err != nil {
					t.Errorf("failed to send noop: %s", err)
				}
				if err = client.Close(); err != nil {
					t.Errorf("failed to close client connection: %s", err)
				}
			})
		}
	})
	t.Run("SCRAM-SHA-PLUS TLSExporter method (TLS 1.3)", func(t *testing.T) {
		hostname := os.Getenv("TEST_HOST")
		username := os.Getenv("TEST_USER")
		password := os.Getenv("TEST_PASS")
		tests := []struct {
			name     string
			authtype SMTPAuthType
		}{
			{"SCRAM-SHA-1-PLUS", SMTPAuthSCRAMSHA1PLUS},
			{"SCRAM-SHA-256-PLUS", SMTPAuthSCRAMSHA256PLUS},
		}

		tlsConfig := &tls.Config{
			MaxVersion: tls.VersionTLS13,
			MinVersion: tls.VersionTLS13,
			ServerName: hostname,
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				client, err := NewClient(hostname,
					WithTLSPortPolicy(TLSMandatory), WithTLSConfig(tlsConfig),
					WithSMTPAuth(tt.authtype),
					WithUsername(username), WithPassword(password))
				if err != nil {
					t.Fatalf("unable to create new client: %s", err)
				}

				ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
				t.Cleanup(cancel)

				if err = client.DialWithContext(ctx); err != nil {
					var netErr net.Error
					if errors.As(err, &netErr) && netErr.Timeout() {
						t.Skip("failed to connect to the test server due to timeout")
					}
					t.Fatalf("failed to dial to test server: %s", err)
				}
				if err = client.smtpClient.Noop(); err != nil {
					t.Errorf("failed to send noop: %s", err)
				}
				if err = client.Close(); err != nil {
					t.Errorf("failed to close client connection: %s", err)
				}
			})
		}
	})
	t.Run("SCRAM-SHA-PLUS TLSUnique method (TLS 1.2)", func(t *testing.T) {
		hostname := os.Getenv("TEST_HOST")
		username := os.Getenv("TEST_USER")
		password := os.Getenv("TEST_PASS")
		tests := []struct {
			name     string
			authtype SMTPAuthType
		}{
			{"SCRAM-SHA-1-PLUS", SMTPAuthSCRAMSHA1PLUS},
			{"SCRAM-SHA-256-PLUS", SMTPAuthSCRAMSHA256PLUS},
		}

		tlsConfig := &tls.Config{
			MaxVersion: tls.VersionTLS12,
			MinVersion: tls.VersionTLS12,
			ServerName: hostname,
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				client, err := NewClient(hostname,
					WithTLSPortPolicy(TLSMandatory), WithTLSConfig(tlsConfig),
					WithSMTPAuth(tt.authtype),
					WithUsername(username), WithPassword(password))
				if err != nil {
					t.Fatalf("unable to create new client: %s", err)
				}

				ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
				t.Cleanup(cancel)

				if err = client.DialWithContext(ctx); err != nil {
					var netErr net.Error
					if errors.As(err, &netErr) && netErr.Timeout() {
						t.Skip("failed to connect to the test server due to timeout")
					}
					t.Fatalf("failed to dial to test server: %s", err)
				}
				if err = client.smtpClient.Noop(); err != nil {
					t.Errorf("failed to send noop: %s", err)
				}
				if err = client.Close(); err != nil {
					t.Errorf("failed to close client connection: %s", err)
				}
			})
		}
	})
}

func TestClient_XOAuth2OnFaker(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		server := []string{
			"220 Fake server ready ESMTP",
			"250-fake.server",
			"250-AUTH LOGIN XOAUTH2",
			"250 8BITMIME",
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
			WithTLSPortPolicy(NoTLS),
			WithSMTPAuth(SMTPAuthXOAUTH2),
			WithUsername("user"),
			WithPassword("token"))
		if err != nil {
			t.Fatalf("unable to create new client: %v", err)
		}
		if err = c.DialWithContext(context.Background()); err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Skip("failed to connect to the test server due to timeout")
			}
			t.Fatalf("unexpected dial error: %v", err)
		}
		if err = c.Close(); err != nil {
			t.Fatalf("disconnect from test server failed: %v", err)
		}
		if !strings.Contains(wrote.String(), "AUTH XOAUTH2 dXNlcj11c2VyAWF1dGg9QmVhcmVyIHRva2VuAQE=\r\n") {
			t.Fatalf("got %q; want AUTH XOAUTH2 dXNlcj11c2VyAWF1dGg9QmVhcmVyIHRva2VuAQE=\r\n", wrote.String())
		}
	})
	t.Run("Unsupported", func(t *testing.T) {
		server := []string{
			"220 Fake server ready ESMTP",
			"250-fake.server",
			"250-AUTH LOGIN PLAIN",
			"250 8BITMIME",
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
		}
		if !errors.Is(err, ErrXOauth2AuthNotSupported) {
			t.Fatalf("expected %v; got %v", ErrXOauth2AuthNotSupported, err)
		}
		if err = c.Close(); err != nil {
			t.Fatalf("disconnect from test server failed: %v", err)
		}
		client := strings.Split(wrote.String(), "\r\n")
		if len(client) != 2 {
			t.Fatalf("unexpected number of client requests got %d; want 2", len(client))
		}
		if !strings.HasPrefix(client[0], "EHLO") {
			t.Fatalf("expected EHLO, got %q", client[0])
		}
	})
}

// getFakeDialFunc returns a DialContextFunc that always returns the given net.Conn without establishing a
// real network connection.
func getFakeDialFunc(conn net.Conn) DialContextFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return conn, nil
	}
}

// faker is an internal structure that embeds io.ReadWriter to simulate network read/write operations.
type faker struct {
	io.ReadWriter
}

func (f faker) Close() error                     { return nil }
func (f faker) LocalAddr() net.Addr              { return nil }
func (f faker) RemoteAddr() net.Addr             { return nil }
func (f faker) SetDeadline(time.Time) error      { return nil }
func (f faker) SetReadDeadline(time.Time) error  { return nil }
func (f faker) SetWriteDeadline(time.Time) error { return nil }

type testSender struct {
	client *Client
}

func (t *testSender) Send(ctx context.Context, m *Msg) error {
	if err := t.client.DialAndSendWithContext(ctx, m); err != nil {
		return fmt.Errorf("failed to dial and send mail: %w", err)
	}
	return nil
}

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
func testMessage(t *testing.T, opts ...MsgOption) *Msg {
	t.Helper()
	message := NewMsg(opts...)
	if message == nil {
		t.Fatal("failed to create new message")
	}
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
	BufferMutex     sync.RWMutex
	EchoBuffer      io.Writer
	FailOnAuth      bool
	FailOnDataInit  bool
	FailOnDataClose bool
	FailOnHelo      bool
	FailOnMailFrom  bool
	FailOnNoop      bool
	FailOnQuit      bool
	FailOnReset     bool
	FailOnSTARTTLS  bool
	FailTemp        bool
	FeatureSet      string
	ListenPort      int
	SSLListener     bool
	IsTLS           bool
	SupportDSN      bool
	UnixSocket      bool
	UnixSocketPath  string
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
	switch {
	case props.UnixSocket:
		path, perr := os.MkdirTemp("", "go-mail-server-*")
		if perr != nil {
			return fmt.Errorf("failed to create temp directory: %w", perr)
		}
		listener, err = net.Listen("unix", path+"/server.sock")
		props.UnixSocketPath = path
	case props.SSLListener:
		keypair, kerr := tls.X509KeyPair(localhostCert, localhostKey)
		if kerr != nil {
			return fmt.Errorf("failed to read TLS keypair: %w", kerr)
		}
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{keypair}}
		listener, err = tls.Listen(TestServerProto, fmt.Sprintf("%s:%d", TestServerAddr, props.ListenPort),
			tlsConfig)
	default:
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
		if props.EchoBuffer != nil {
			props.BufferMutex.Lock()
			if _, berr := props.EchoBuffer.Write([]byte(data + "\r\n")); berr != nil {
				t.Errorf("failed write to echo buffer: %s", berr)
			}
			props.BufferMutex.Unlock()
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
		if props.EchoBuffer != nil {
			props.BufferMutex.Lock()
			if _, berr := props.EchoBuffer.Write([]byte(data)); berr != nil {
				t.Errorf("failed write to echo buffer: %s", berr)
			}
			props.BufferMutex.Unlock()
		}

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
		case strings.HasPrefix(data, "MAIL FROM:"):
			if props.FailOnMailFrom {
				writeLine("500 5.5.2 Error: fail on MAIL FROM")
				break
			}
			from := strings.TrimPrefix(data, "MAIL FROM:")
			from = strings.ReplaceAll(from, "BODY=8BITMIME", "")
			from = strings.ReplaceAll(from, "SMTPUTF8", "")
			if props.SupportDSN {
				from = strings.ReplaceAll(from, "RET=FULL", "")
			}
			from = strings.TrimSpace(from)
			if !strings.EqualFold(from, "<valid-from@domain.tld>") {
				writeLine(fmt.Sprintf("503 5.1.2 Invalid from: %s", from))
				break
			}
			writeOK()
		case strings.HasPrefix(data, "RCPT TO:"):
			to := strings.TrimPrefix(data, "RCPT TO:")
			if props.SupportDSN {
				to = strings.ReplaceAll(to, "NOTIFY=FAILURE,SUCCESS", "")
			}
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
			if props.FailOnDataInit {
				writeLine("503 5.5.1 Error: fail on DATA init")
				break
			}
			writeLine("354 End data with <CR><LF>.<CR><LF>")
			for {
				ddata, derr := reader.ReadString('\n')
				if derr != nil {
					t.Logf("failed to read data from connection: %s", derr)
					break
				}
				if props.EchoBuffer != nil {
					props.BufferMutex.Lock()
					if _, berr := props.EchoBuffer.Write([]byte(ddata)); berr != nil {
						t.Errorf("failed write to echo buffer: %s", berr)
					}
					props.BufferMutex.Unlock()
				}
				ddata = strings.TrimSpace(ddata)
				if ddata == "." {
					if props.FailOnDataClose {
						writeLine("500 5.0.0 Error during DATA transmission")
						break
					}
					if props.FailTemp {
						writeLine("451 4.3.0 Error: fail on DATA close")
						break
					}
					writeLine("250 2.0.0 Ok: queued as 1234567890")
					break
				}
				datastring += ddata + "\n"
			}
		case strings.EqualFold(data, "noop"):
			if props.FailOnNoop {
				writeLine("500 5.0.0 Error: fail on NOOP")
				break
			}
			writeOK()
		case strings.EqualFold(data, "vrfy"):
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
