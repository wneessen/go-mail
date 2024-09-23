// SPDX-FileCopyrightText: 2022-2024 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
)

// Parts of the connection pool code is forked from https://github.com/fatih/pool/
// Thanks to Fatih Arslan and the project contributors for providing this great
// concurrency template.

var (
	// ErrPoolInvalidCap is returned when the connection pool's capacity settings are
	// invalid (e.g., initial capacity is negative).
	ErrPoolInvalidCap = errors.New("invalid connection pool capacity settings")
	// ErrClosed is returned when an operation is attempted on a closed connection pool.
	ErrClosed = errors.New("connection pool is closed")
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
	// mutex is used to synchronize access to the connection pool to ensure thread-safe operations.
	mutex sync.RWMutex
	// conns is a channel used to manage and distribute net.Conn objects within the connection pool.
	conns chan net.Conn

	// dialCtxFunc represents the actual net.Conn returned by the DialContextFunc.
	dialCtxFunc DialContextFunc
	// dialContext is the context used for dialing new network connections within the connection pool.
	dialContext context.Context
	// dialNetwork specifies the network type (e.g., "tcp", "udp") used to establish connections in
	// the connection pool.
	dialNetwork string
	// dialAddress specifies the address used to establish network connections within the connection pool.
	dialAddress string
}

// PoolConn is a wrapper around net.Conn to modify the the behavior of net.Conn's Close() method.
type PoolConn struct {
	net.Conn
	mutex    sync.RWMutex
	pool     *connPool
	unusable bool
}

// NewConnPool returns a new pool based on buffered channels with an initial
// capacity and maximum capacity. The DialContextFunc is used when the initial
// capacity is greater than zero to fill the pool. A zero initialCap doesn't
// fill the Pool until a new Get() is called. During a Get(), if there is no
// new connection available in the pool, a new connection will be created via
// the corresponding DialContextFunc() method.
func NewConnPool(ctx context.Context, initialCap, maxCap int, dialCtxFunc DialContextFunc,
	network, address string) (Pool, error) {
	if initialCap < 0 || maxCap <= 0 || initialCap > maxCap {
		return nil, ErrPoolInvalidCap
	}

	pool := &connPool{
		conns:       make(chan net.Conn, maxCap),
		dialCtxFunc: dialCtxFunc,
		dialContext: ctx,
		dialAddress: address,
		dialNetwork: network,
	}

	// Initial connections for the pool. Pool will be closed on connection error
	for i := 0; i < initialCap; i++ {
		conn, err := dialCtxFunc(ctx, network, address)
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("dialContextFunc is not able to fill the connection pool: %s", err)
		}
		pool.conns <- conn

	}

	return pool, nil
}

// Get satisfies the Get() method of the Pool inteface. If there is no new
// connection available in the Pool, a new connection will be created via the
// DialContextFunc() method.
func (p *connPool) Get() (net.Conn, error) {
	ctx, conns, dialCtxFunc := p.getConnsAndDialContext()
	if conns == nil {
		return nil, ErrClosed
	}

	// wrap the connections into the custom net.Conn implementation that puts
	// connections back to the pool
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case conn := <-conns:
		if conn == nil {
			return nil, ErrClosed
		}
		return p.wrapConn(conn), nil
	default:
		conn, err := dialCtxFunc(ctx, p.dialNetwork, p.dialAddress)
		if err != nil {
			return nil, err
		}
		return p.wrapConn(conn), nil
	}
}

// Close terminates all connections in the pool and frees associated resources. Once closed,
// the pool is no longer usable.
func (p *connPool) Close() {
	p.mutex.Lock()
	conns := p.conns
	p.conns = nil
	p.dialCtxFunc = nil
	p.dialContext = nil
	p.dialAddress = ""
	p.dialNetwork = ""
	p.mutex.Unlock()

	if conns == nil {
		return
	}

	close(conns)
	for conn := range conns {
		_ = conn.Close()
	}
}

// Len returns the current number of connections in the connection pool.
func (p *connPool) Len() int {
	_, conns, _ := p.getConnsAndDialContext()
	return len(conns)
}

// getConnsAndDialContext returns the connection channel and the DialContext function for the
// connection pool.
func (p *connPool) getConnsAndDialContext() (context.Context, chan net.Conn, DialContextFunc) {
	p.mutex.RLock()
	conns := p.conns
	dialCtxFunc := p.dialCtxFunc
	ctx := p.dialContext
	p.mutex.RUnlock()
	return ctx, conns, dialCtxFunc
}

// wrapConn wraps a given net.Conn with a PoolConn, modifying the net.Conn's Close() method.
func (p *connPool) wrapConn(conn net.Conn) net.Conn {
	poolconn := &PoolConn{pool: p}
	poolconn.Conn = conn
	return poolconn
}
