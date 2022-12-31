// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

//go:build go1.20
// +build go1.20

package mail

import (
	"errors"
	"fmt"
)

// Send sends out the mail message
func (c *Client) Send(ml ...*Msg) (rerr error) {
	if err := c.checkConn(); err != nil {
		rerr = fmt.Errorf("failed to send mail: %w", err)
		return
	}
	for _, m := range ml {
		if m.encoding == NoEncoding {
			if ok, _ := c.sc.Extension("8BITMIME"); !ok {
				rerr = errors.Join(rerr, ErrServerNoUnencoded)
				m.sendError = SendError{Err: ErrServerNoUnencoded}
				continue
			}
		}
		f, err := m.GetSender(false)
		if err != nil {
			rerr = errors.Join(rerr, err)
			m.sendError = SendError{Err: ErrGetSender, details: []error{err}}
			continue
		}
		rl, err := m.GetRecipients()
		if err != nil {
			rerr = errors.Join(rerr, err)
			m.sendError = SendError{Err: ErrGetRcpts, details: []error{err}}
			continue
		}

		if err := c.mail(f); err != nil {
			rerr = errors.Join(rerr, fmt.Errorf("sending MAIL FROM command failed: %w", err))
			m.sendError = SendError{Err: ErrSMTPMailFrom, details: []error{err}}
			if reserr := c.sc.Reset(); reserr != nil {
				rerr = errors.Join(rerr, reserr)
			}
			continue
		}
		failed := false
		rse := SendError{}
		rse.details = make([]error, 0)
		rse.rcpt = make([]string, 0)
		for _, r := range rl {
			if err := c.rcpt(r); err != nil {
				rerr = errors.Join(rerr, fmt.Errorf("sending RCPT TO command failed: %w", err))
				rse.Err = ErrSMTPRcptTo
				rse.details = append(rse.details, err)
				rse.rcpt = append(rse.rcpt, r)
				failed = true
			}
		}
		if failed {
			if reserr := c.sc.Reset(); reserr != nil {
				rerr = errors.Join(rerr, reserr)
			}
			m.sendError = rse
			continue
		}
		w, err := c.sc.Data()
		if err != nil {
			rerr = errors.Join(rerr, fmt.Errorf("sending DATA command failed: %w", err))
			m.sendError = SendError{Err: ErrSMTPData, details: []error{err}}
			continue
		}
		_, err = m.WriteTo(w)
		if err != nil {
			rerr = errors.Join(rerr, fmt.Errorf("sending mail content failed: %w", err))
			m.sendError = SendError{Err: ErrWriteContent, details: []error{err}}
			continue
		}

		if err := w.Close(); err != nil {
			rerr = errors.Join(rerr, fmt.Errorf("failed to close DATA writer: %w", err))
			m.sendError = SendError{Err: ErrSMTPDataClose, details: []error{err}}
			continue
		}

		if err := c.Reset(); err != nil {
			rerr = errors.Join(rerr, fmt.Errorf("sending RSET command failed: %w", err))
			m.sendError = SendError{Err: ErrSMTPReset, details: []error{err}}
			continue
		}
		if err := c.checkConn(); err != nil {
			rerr = errors.Join(rerr, fmt.Errorf("failed to check server connection: %w", err))
			m.sendError = SendError{Err: ErrConnCheck, details: []error{err}}
		}
	}

	return
}
