// SPDX-FileCopyrightText: 2022-2024 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"context"
	"fmt"
	"net"
	"sync"
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
	defer pool.Close()
	if pool == nil {
		t.Errorf("connection pool is nil")
		return
	}
	if pool.Size() != 5 {
		t.Errorf("expected 5 connections, got %d", pool.Size())
	}
	conn, err := pool.Get()
	if err != nil {
		t.Errorf("failed to get connection: %s", err)
	}
	if _, err := conn.Write([]byte("EHLO test.localhost.localdomain\r\nQUIT\r\n")); err != nil {
		t.Errorf("failed to write quit command to first connection: %s", err)
	}
}

func TestConnPool_Get_Type(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 11
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
	defer pool.Close()

	conn, err := pool.Get()
	if err != nil {
		t.Errorf("failed to get new connection from pool: %s", err)
		return
	}

	_, ok := conn.(*PoolConn)
	if !ok {
		t.Error("received connection from pool is not of type PoolConn")
		return
	}
	if _, err := conn.Write([]byte("EHLO test.localhost.localdomain\r\nQUIT\r\n")); err != nil {
		t.Errorf("failed to write quit command to first connection: %s", err)
	}
}

func TestConnPool_Get(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 12
	featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, true, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 300)

	p, _ := newConnPool(serverPort)
	defer p.Close()

	conn, err := p.Get()
	if err != nil {
		t.Errorf("failed to get new connection from pool: %s", err)
		return
	}
	if _, err = conn.Write([]byte("EHLO test.localhost.localdomain\r\nQUIT\r\n")); err != nil {
		t.Errorf("failed to write quit command to first connection: %s", err)
	}

	if p.Size() != 4 {
		t.Errorf("getting new connection from pool failed. Expected pool size: 4, got %d", p.Size())
	}

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			wgconn, err := p.Get()
			if err != nil {
				t.Errorf("failed to get new connection from pool: %s", err)
			}
			if _, err = wgconn.Write([]byte("EHLO test.localhost.localdomain\r\nQUIT\r\n")); err != nil {
				t.Errorf("failed to write quit command to first connection: %s", err)
			}
		}()
	}
	wg.Wait()

	if p.Size() != 0 {
		t.Errorf("Get error. Expecting 0, got %d", p.Size())
	}

	conn, err = p.Get()
	if err != nil {
		t.Errorf("failed to get new connection from pool: %s", err)
	}
	if _, err = conn.Write([]byte("EHLO test.localhost.localdomain\r\nQUIT\r\n")); err != nil {
		t.Errorf("failed to write quit command to first connection: %s", err)
	}
	p.Close()
}

func TestPoolConn_Close(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 13
	featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, true, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 300)

	netDialer := net.Dialer{}
	p, err := NewConnPool(context.Background(), 0, 30, netDialer.DialContext, "tcp",
		fmt.Sprintf("127.0.0.1:%d", serverPort))
	if err != nil {
		t.Errorf("failed to create connection pool: %s", err)
	}
	defer p.Close()

	conns := make([]net.Conn, 30)
	for i := 0; i < 30; i++ {
		conn, _ := p.Get()
		if _, err = conn.Write([]byte("EHLO test.localhost.localdomain\r\nQUIT\r\n")); err != nil {
			t.Errorf("failed to write quit command to first connection: %s", err)
		}
		conns[i] = conn
	}
	for _, conn := range conns {
		if err = conn.Close(); err != nil {
			t.Errorf("failed to close connection: %s", err)
		}
	}

	if p.Size() != 30 {
		t.Errorf("failed to return all connections to pool. Expected pool size: 30, got %d", p.Size())
	}

	conn, err := p.Get()
	if err != nil {
		t.Errorf("failed to get new connection from pool: %s", err)
	}
	if _, err = conn.Write([]byte("EHLO test.localhost.localdomain\r\nQUIT\r\n")); err != nil {
		t.Errorf("failed to write quit command to first connection: %s", err)
	}
	p.Close()

	if err = conn.Close(); err != nil {
		t.Errorf("failed to close connection: %s", err)
	}
	if p.Size() != 0 {
		t.Errorf("closed pool shouldn't allow to put connections.")
	}
}

func TestPoolConn_MarkUnusable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 14
	featureSet := "250-AUTH PLAIN\r\n250-8BITMIME\r\n250-DSN\r\n250 SMTPUTF8"
	go func() {
		if err := simpleSMTPServer(ctx, featureSet, true, serverPort); err != nil {
			t.Errorf("failed to start test server: %s", err)
			return
		}
	}()
	time.Sleep(time.Millisecond * 300)

	pool, _ := newConnPool(serverPort)
	defer pool.Close()

	conn, err := pool.Get()
	if err != nil {
		t.Errorf("failed to get new connection from pool: %s", err)
	}
	if err = conn.Close(); err != nil {
		t.Errorf("failed to close connection: %s", err)
	}

	poolSize := pool.Size()
	conn, err = pool.Get()
	if err != nil {
		t.Errorf("failed to get new connection from pool: %s", err)
	}
	if err = conn.Close(); err != nil {
		t.Errorf("failed to close connection: %s", err)
	}
	if pool.Size() != poolSize {
		t.Errorf("pool size is expected to be equal to initial size")
	}

	conn, err = pool.Get()
	if err != nil {
		t.Errorf("failed to get new connection from pool: %s", err)
	}
	if pc, ok := conn.(*PoolConn); !ok {
		t.Errorf("this should never happen")
	} else {
		pc.MarkUnusable()
	}
	if err = conn.Close(); err != nil {
		t.Errorf("failed to close connection: %s", err)
	}
	if pool.Size() != poolSize-1 {
		t.Errorf("pool size is expected to be: %d but got: %d", poolSize-1, pool.Size())
	}
}

func TestConnPool_Close(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 15
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
	pool.Close()

	castPool := pool.(*connPool)

	if castPool.conns != nil {
		t.Error("closing pool failed: conns channel should be nil")
	}
	if castPool.dialCtxFunc != nil {
		t.Error("closing pool failed: dialCtxFunc should be nil")
	}
	if castPool.dialContext != nil {
		t.Error("closing pool failed: dialContext should be nil")
	}
	if castPool.dialAddress != "" {
		t.Error("closing pool failed: dialAddress should be empty")
	}
	if castPool.dialNetwork != "" {
		t.Error("closing pool failed: dialNetwork should be empty")
	}

	conn, err := pool.Get()
	if err == nil {
		t.Errorf("closing pool failed: getting new connection should return an error")
	}
	if conn != nil {
		t.Errorf("closing pool failed: getting new connection should return a nil-connection")
	}
	if pool.Size() != 0 {
		t.Errorf("closing pool failed: pool size should be 0, but got: %d", pool.Size())
	}
}

func TestConnPool_Concurrency(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	serverPort := TestServerPortBase + 16
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
	defer pool.Close()
	pipe := make(chan net.Conn)

	getWg := sync.WaitGroup{}
	closeWg := sync.WaitGroup{}
	for i := 0; i < 30; i++ {
		getWg.Add(1)
		closeWg.Add(1)
		go func() {
			conn, err := pool.Get()
			if err != nil {
				t.Errorf("failed to get new connection from pool: %s", err)
			}
			pipe <- conn
			getWg.Done()
		}()

		go func() {
			conn := <-pipe
			if conn == nil {
				return
			}
			if err = conn.Close(); err != nil {
				t.Errorf("failed to close connection: %s", err)
			}
			closeWg.Done()
		}()
		getWg.Wait()
		closeWg.Wait()
	}
}

func newConnPool(port int) (Pool, error) {
	netDialer := net.Dialer{}
	return NewConnPool(context.Background(), 5, 30, netDialer.DialContext, "tcp",
		fmt.Sprintf("127.0.0.1:%d", port))
}
