// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build go1.20
// +build go1.20

package mail

import (
	"errors"
	"strings"
)

// Send sends out the mail message
func (c *Client) Send(messages ...*Msg) (returnErr error) {
	if err := c.checkConn(); err != nil {
		returnErr = &SendError{Reason: ErrConnCheck, errlist: []error{err}, isTemp: isTempError(err)}
		return
	}
	for _, message := range messages {
		message.sendError = nil
		if message.encoding == NoEncoding {
			if ok, _ := c.smtpClient.Extension("8BITMIME"); !ok {
				message.sendError = &SendError{Reason: ErrNoUnencoded, isTemp: false}
				returnErr = errors.Join(returnErr, message.sendError)
				continue
			}
		}
		from, err := message.GetSender(false)
		if err != nil {
			message.sendError = &SendError{Reason: ErrGetSender, errlist: []error{err}, isTemp: isTempError(err)}
			returnErr = errors.Join(returnErr, message.sendError)
			continue
		}
		rcpts, err := message.GetRecipients()
		if err != nil {
			message.sendError = &SendError{Reason: ErrGetRcpts, errlist: []error{err}, isTemp: isTempError(err)}
			returnErr = errors.Join(returnErr, message.sendError)
			continue
		}

		if c.dsn {
			if c.dsnmrtype != "" {
				c.smtpClient.SetDSNMailReturnOption(string(c.dsnmrtype))
			}
		}
		if err = c.smtpClient.Mail(from); err != nil {
			message.sendError = &SendError{Reason: ErrSMTPMailFrom, errlist: []error{err}, isTemp: isTempError(err)}
			returnErr = errors.Join(returnErr, message.sendError)
			if resetSendErr := c.smtpClient.Reset(); resetSendErr != nil {
				returnErr = errors.Join(returnErr, resetSendErr)
			}
			continue
		}
		failed := false
		rcptSendErr := &SendError{}
		rcptSendErr.errlist = make([]error, 0)
		rcptSendErr.rcpt = make([]string, 0)
		rcptNotifyOpt := strings.Join(c.dsnrntype, ",")
		c.smtpClient.SetDSNRcptNotifyOption(rcptNotifyOpt)
		for _, rcpt := range rcpts {
			if err = c.smtpClient.Rcpt(rcpt); err != nil {
				rcptSendErr.Reason = ErrSMTPRcptTo
				rcptSendErr.errlist = append(rcptSendErr.errlist, err)
				rcptSendErr.rcpt = append(rcptSendErr.rcpt, rcpt)
				rcptSendErr.isTemp = isTempError(err)
				failed = true
			}
		}
		if failed {
			if resetSendErr := c.smtpClient.Reset(); resetSendErr != nil {
				returnErr = errors.Join(returnErr, resetSendErr)
			}
			message.sendError = rcptSendErr
			returnErr = errors.Join(returnErr, message.sendError)
			continue
		}
		writer, err := c.smtpClient.Data()
		if err != nil {
			message.sendError = &SendError{Reason: ErrSMTPData, errlist: []error{err}, isTemp: isTempError(err)}
			returnErr = errors.Join(returnErr, message.sendError)
			continue
		}
		_, err = message.WriteTo(writer)
		if err != nil {
			message.sendError = &SendError{Reason: ErrWriteContent, errlist: []error{err}, isTemp: isTempError(err)}
			returnErr = errors.Join(returnErr, message.sendError)
			continue
		}
		message.isDelivered = true

		if err = writer.Close(); err != nil {
			message.sendError = &SendError{Reason: ErrSMTPDataClose, errlist: []error{err}, isTemp: isTempError(err)}
			returnErr = errors.Join(returnErr, message.sendError)
			continue
		}

		if err = c.Reset(); err != nil {
			message.sendError = &SendError{Reason: ErrSMTPReset, errlist: []error{err}, isTemp: isTempError(err)}
			returnErr = errors.Join(returnErr, message.sendError)
			continue
		}
		if err = c.checkConn(); err != nil {
			message.sendError = &SendError{Reason: ErrConnCheck, errlist: []error{err}, isTemp: isTempError(err)}
			returnErr = errors.Join(returnErr, message.sendError)
		}
	}

	return
}
