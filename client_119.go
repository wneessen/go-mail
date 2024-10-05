// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build !go1.20
// +build !go1.20

package mail

import "errors"

// Send attempts to send one or more Msg using the Client connection to the SMTP server.
// If the Client has no active connection to the server, Send will fail with an error. For each of the
// provided Msg it will associate a SendError to the Msg in case there of a transmission or delivery
// error.
func (c *Client) Send(messages ...*Msg) error {
	if err := c.checkConn(); err != nil {
		return &SendError{Reason: ErrConnCheck, errlist: []error{err}, isTemp: isTempError(err)}
	}
	var errs []*SendError
	for id, message := range messages {
		if sendErr := c.sendSingleMsg(message); sendErr != nil {
			messages[id].sendError = sendErr

			var msgSendErr *SendError
			if errors.As(sendErr, &msgSendErr) {
				errs = append(errs, msgSendErr)
			}
		}
	}

	if len(errs) > 0 {
		if len(errs) > 1 {
			returnErr := &SendError{Reason: ErrAmbiguous}
			for i := range errs {
				returnErr.errlist = append(returnErr.errlist, errs[i].errlist...)
				returnErr.rcpt = append(returnErr.rcpt, errs[i].rcpt...)
			}

			// We assume that the isTemp flag from the last error we received should be the
			// indicator for the returned isTemp flag as well
			returnErr.isTemp = errs[len(errs)-1].isTemp

			return returnErr
		}
		return errs[0]
	}
	return nil
}
