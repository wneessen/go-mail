// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build go1.20
// +build go1.20

package mail

import (
	"errors"
)

// Send attempts to send one or more Msg using the Client connection to the SMTP server.
// If the Client has no active connection to the server, Send will fail with an error. For each of the
// provided Msg it will associate a SendError to the Msg in case there of a transmission or delivery
// error.
func (c *Client) Send(messages ...*Msg) (returnErr error) {
	if err := c.checkConn(); err != nil {
		returnErr = &SendError{Reason: ErrConnCheck, errlist: []error{err}, isTemp: isTempError(err)}
		return
	}

	var errs []error
	defer func() {
		returnErr = errors.Join(errs...)
	}()

	for id, message := range messages {
		if sendErr := c.sendSingleMsg(message); sendErr != nil {
			messages[id].sendError = sendErr
			errs = append(errs, sendErr)
		}
	}

	return
}
