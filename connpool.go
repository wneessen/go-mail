// SPDX-FileCopyrightText: 2022-2024 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"errors"
	"net"
	"sync"
)

// Parts of the connection pool code is forked from https://github.com/fatih/pool/
// Thanks to Fatih Arslan and the project contributors for providing this great
// concurrency template.

var (
	ErrPoolInvalidCap = errors.New("invalid connection pool capacity settings")
)

// Pool interface describes a connection pool implementation. A Pool is
// thread-/go-routine safe.
type Pool interface {
	// Get returns a new connection from the pool. Closing the connections returns
	// it back into the Pool. Closing a connection when the Pool is destroyed or
	// full will be counted as an error.
	Get() (net.Conn, error)

	// Close closes the pool and all its connections. After Close() the pool is
	// no longer usable.
	Close()

	// Len returns the current number of connections of the pool.
	Len() int
}

// connPool implements the Pool interface
type connPool struct {
	// mutex is used to synchronize access to the connection pool to ensure thread-safe operations
	mutex sync.RWMutex
	// conns is a channel used to manage and distribute net.Conn objects within the connection pool
	conns chan net.Conn
	// dialCtx represents the actual net.Conn returned by the DialContextFunc
	dialCtx DialContextFunc
}

// NewConnPool returns a new pool based on buffered channels with an initial
// capacity and maximum capacity. The DialContextFunc is used when the initial
// capacity is greater than zero to fill the pool. A zero initialCap doesn't
// fill the Pool until a new Get() is called. During a Get(), if there is no
// new connection available in the pool, a new connection will be created via
// the corresponding DialContextFunc() method.
func NewConnPool(initialCap, maxCap int, dialCtxFunc DialContextFunc) (Pool, error) {
	if initialCap < 0 || maxCap <= 0 || initialCap > maxCap {
		return nil, ErrPoolInvalidCap
	}

	pool := &connPool{
		conns:   make(chan net.Conn, maxCap),
		dialCtx: dialCtxFunc,
	}

	// create initial connections, if something goes wrong,
	// just close the pool error out.
	for i := 0; i < initialCap; i++ {
		/*
			conn, err := dialCtxFunc()
			if err != nil {
				pool.Close()
				return nil, fmt.Errorf("factory is not able to fill the pool: %s", err)
			}
			c.conns <- conn

		*/
	}

	return pool, nil
}

func (c *connPool) Get() (net.Conn, error) {
	return nil, nil
}
func (c *connPool) Close() {
	return
}

func (c *connPool) Len() int {
	return 0
}
