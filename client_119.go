// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build !go1.20
// +build !go1.20

package mail

import "strings"

// Send sends out the mail message
func (c *Client) Send(messages ...*Msg) error {
	if cerr := c.checkConn(); cerr != nil {
		return &SendError{Reason: ErrConnCheck, errlist: []error{cerr}, isTemp: isTempError(cerr)}
	}
	var errs []*SendError
	for _, message := range messages {
		message.sendError = nil
		if message.encoding == NoEncoding {
			if ok, _ := c.smtpClient.Extension("8BITMIME"); !ok {
				sendErr := &SendError{Reason: ErrNoUnencoded, isTemp: false}
				message.sendError = sendErr
				errs = append(errs, sendErr)
				continue
			}
		}
		from, err := message.GetSender(false)
		if err != nil {
			sendErr := &SendError{Reason: ErrGetSender, errlist: []error{err}, isTemp: isTempError(err)}
			message.sendError = sendErr
			errs = append(errs, sendErr)
			continue
		}
		rcpts, err := message.GetRecipients()
		if err != nil {
			sendErr := &SendError{Reason: ErrGetRcpts, errlist: []error{err}, isTemp: isTempError(err)}
			message.sendError = sendErr
			errs = append(errs, sendErr)
			continue
		}

		if c.dsn {
			if c.dsnmrtype != "" {
				c.smtpClient.SetDSNMailReturnOption(string(c.dsnmrtype))
			}
		}
		if err = c.smtpClient.Mail(from); err != nil {
			sendErr := &SendError{Reason: ErrSMTPMailFrom, errlist: []error{err}, isTemp: isTempError(err)}
			if resetSendErr := c.smtpClient.Reset(); resetSendErr != nil {
				sendErr.errlist = append(sendErr.errlist, resetSendErr)
			}
			message.sendError = sendErr
			errs = append(errs, sendErr)
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
				rcptSendErr.errlist = append(rcptSendErr.errlist, err)
			}
			message.sendError = rcptSendErr
			errs = append(errs, rcptSendErr)
			continue
		}
		writer, err := c.smtpClient.Data()
		if err != nil {
			sendErr := &SendError{Reason: ErrSMTPData, errlist: []error{err}, isTemp: isTempError(err)}
			message.sendError = sendErr
			errs = append(errs, sendErr)
			continue
		}
		_, err = message.WriteTo(writer)
		if err != nil {
			sendErr := &SendError{Reason: ErrWriteContent, errlist: []error{err}, isTemp: isTempError(err)}
			message.sendError = sendErr
			errs = append(errs, sendErr)
			continue
		}
		message.isDelivered = true

		if err = writer.Close(); err != nil {
			sendErr := &SendError{Reason: ErrSMTPDataClose, errlist: []error{err}, isTemp: isTempError(err)}
			message.sendError = sendErr
			errs = append(errs, sendErr)
			continue
		}

		if err = c.Reset(); err != nil {
			sendErr := &SendError{Reason: ErrSMTPReset, errlist: []error{err}, isTemp: isTempError(err)}
			message.sendError = sendErr
			errs = append(errs, sendErr)
			continue
		}
		if err = c.checkConn(); err != nil {
			sendErr := &SendError{Reason: ErrConnCheck, errlist: []error{err}, isTemp: isTempError(err)}
			message.sendError = sendErr
			errs = append(errs, sendErr)
			continue
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
