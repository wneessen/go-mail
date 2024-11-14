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
// If the Client has no active connection to the server, Send will fail with an error. For each
// of the provided Msg, it will associate a SendError with the Msg in case of a transmission
// or delivery error.
//
// This method first checks for an active connection to the SMTP server. If the connection is
// not valid, it returns an error wrapped in a SendError. It then iterates over the provided
// messages, attempting to send each one. If an error occurs during sending, the method records
// the error and associates it with the corresponding Msg.
//
// Parameters:
//   - messages: A variadic list of pointers to Msg objects to be sent.
//
// Returns:
//   - An error that aggregates any SendErrors encountered during the sending process; otherwise, returns nil.
func (c *Client) Send(messages ...*Msg) (returnErr error) {
	escSupport := false
	if c.smtpClient != nil {
		escSupport, _ = c.smtpClient.Extension("ENHANCEDSTATUSCODES")
	}
	if err := c.checkConn(); err != nil {
		returnErr = &SendError{Reason: ErrConnCheck, errlist: []error{err}, isTemp: isTempError(err),
			errcode: errorCode(err), enhancedStatusCode: enhancedStatusCode(err, escSupport)}
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
