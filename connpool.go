// SPDX-FileCopyrightText: 2022-2024 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import "net"

// Parts of the connection pool code is forked from https://github.com/fatih/pool/
// Thanks to Fatih Arslan and the project contributors for providing this great
// concurrency template.

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
