// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build go1.20
// +build go1.20

package mail

import (
	"errors"
)

// Send sends out the mail message
func (c *Client) Send(messages ...*Msg) (returnErr error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

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
