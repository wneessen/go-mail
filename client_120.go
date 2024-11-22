// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build go1.20
// +build go1.20

package mail

import (
	"errors"

	"github.com/wneessen/go-mail/smtp"
)

// SendWithSMTPClient attempts to send one or more Msg using a provided smtp.Client with an
// established connection to the SMTP server. If the smtp.Client has no active connection to
// the server, SendWithSMTPClient will fail with an error. For each of the provided Msg, it
// will associate a SendError with the Msg in case of a transmission or delivery error.
//
// This method first checks for an active connection to the SMTP server. If the connection is
// not valid, it returns a SendError. It then iterates over the provided messages, attempting
// to send each one. If an error occurs during sending, the method records the error and
// associates it with the corresponding Msg. If multiple errors are encountered, it aggregates
// them into a single SendError to be returned.
//
// Parameters:
//   - client: A pointer to the smtp.Client that holds the connection to the SMTP server
//   - messages: A variadic list of pointers to Msg objects to be sent.
//
// Returns:
//   - An error that represents the sending result, which may include multiple SendErrors if
//     any occurred; otherwise, returns nil.
func (c *Client) SendWithSMTPClient(client *smtp.Client, messages ...*Msg) (returnErr error) {
	escSupport := false
	if client != nil {
		escSupport, _ = client.Extension("ENHANCEDSTATUSCODES")
	}
	if err := c.checkConn(client); err != nil {
		returnErr = &SendError{
			Reason: ErrConnCheck, errlist: []error{err}, isTemp: isTempError(err),
			errcode: errorCode(err), enhancedStatusCode: enhancedStatusCode(err, escSupport),
		}
		return
	}

	var errs []error
	defer func() {
		returnErr = errors.Join(errs...)
	}()

	for id, message := range messages {
		if sendErr := c.sendSingleMsg(client, message); sendErr != nil {
			messages[id].sendError = sendErr
			errs = append(errs, sendErr)
		}
	}

	return
}
