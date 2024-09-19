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

// sendSingleMsg sends out a single message and returns an error if the transmission/delivery fails.
// It is invoked by the public Send methods
func (c *Client) sendSingleMsg(message *Msg) error {
	if message.encoding == NoEncoding {
		if ok, _ := c.smtpClient.Extension("8BITMIME"); !ok {
			return &SendError{Reason: ErrNoUnencoded, isTemp: false}
		}
	}
	from, err := message.GetSender(false)
	if err != nil {
		return &SendError{Reason: ErrGetSender, errlist: []error{err}, isTemp: isTempError(err),
			affectedMsg: message}
	}
	rcpts, err := message.GetRecipients()
	if err != nil {
		return &SendError{Reason: ErrGetRcpts, errlist: []error{err}, isTemp: isTempError(err),
			affectedMsg: message}
	}

	if c.dsn {
		if c.dsnmrtype != "" {
			c.smtpClient.SetDSNMailReturnOption(string(c.dsnmrtype))
		}
	}
	if err = c.smtpClient.Mail(from); err != nil {
		retError := &SendError{Reason: ErrSMTPMailFrom, errlist: []error{err}, isTemp: isTempError(err)}
		if resetSendErr := c.smtpClient.Reset(); resetSendErr != nil {
			retError.errlist = append(retError.errlist, resetSendErr)
		}
		return retError
	}
	hasError := false
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
			hasError = true
		}
	}
	if hasError {
		if resetSendErr := c.smtpClient.Reset(); resetSendErr != nil {
			rcptSendErr.errlist = append(rcptSendErr.errlist, resetSendErr)
		}
		return rcptSendErr
	}
	writer, err := c.smtpClient.Data()
	if err != nil {
		return &SendError{Reason: ErrSMTPData, errlist: []error{err}, isTemp: isTempError(err)}
	}
	_, err = message.WriteTo(writer)
	if err != nil {
		return &SendError{Reason: ErrWriteContent, errlist: []error{err}, isTemp: isTempError(err)}
	}
	message.isDelivered = true

	if err = writer.Close(); err != nil {
		return &SendError{Reason: ErrSMTPDataClose, errlist: []error{err}, isTemp: isTempError(err)}
	}

	if err = c.Reset(); err != nil {
		return &SendError{Reason: ErrSMTPReset, errlist: []error{err}, isTemp: isTempError(err)}
	}
	if err = c.checkConn(); err != nil {
		return &SendError{Reason: ErrConnCheck, errlist: []error{err}, isTemp: isTempError(err)}
	}
	return nil
}
