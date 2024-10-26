// SPDX-FileCopyrightText: 2024 The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build go1.21
// +build go1.21

package mail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wneessen/go-mail/log"
)

func TestNewClientNewVersionsOnly(t *testing.T) {
	tests := []struct {
		name       string
		option     Option
		expectFunc func(c *Client) error
		shouldfail bool
		expectErr  *error
	}{
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
}

func TestClient_DialWithContextNewVersionsOnly(t *testing.T) {
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
}
