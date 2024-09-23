// SPDX-FileCopyrightText: 2022-2024 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestNewConnPool(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 10
	featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, true, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 300)

	pool, err := newConnPool(serverPort)
	if err != nil {
		t.Errorf("failed to create connection pool: %s", err)
	}
	if pool == nil {
		t.Errorf("connection pool is nil")
		return
	}
	if pool.Size() != 5 {
		t.Errorf("expected 5 connections, got %d", pool.Size())
	}
	for i := 0; i < 5; i++ {
		go func() {
			conn, err := pool.Get()
			if err != nil {
				t.Errorf("failed to get connection: %s", err)
			}
			if _, err := conn.Write([]byte("EHLO test.localhost.localdomain\r\nQUIT\r\n")); err != nil {
				t.Errorf("failed to write quit command to first connection: %s", err)
			}
		}()
	}
}

func newConnPool(port int) (Pool, error) {
	netDialer := net.Dialer{}
	return NewConnPool(context.Background(), 5, 30, netDialer.DialContext, "tcp",
		fmt.Sprintf("127.0.0.1:%d", port))
}
