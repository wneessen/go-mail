// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

//go:build !go1.20
// +build !go1.20

package mail

import (
	"fmt"
)

// Send sends out the mail message
func (c *Client) Send(ml ...*Msg) error {
	var errs []error
	if err := c.checkConn(); err != nil {
		return fmt.Errorf("failed to send mail: %w", err)
	}
	for _, m := range ml {
		if m.encoding == NoEncoding {
			if ok, _ := c.sc.Extension("8BITMIME"); !ok {
				errs = append(errs, ErrServerNoUnencoded)
				continue
			}
		}
		f, err := m.GetSender(false)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rl, err := m.GetRecipients()
		if err != nil {
			errs = append(errs, err)
			continue
		}

		if err := c.mail(f); err != nil {
			errs = append(errs, fmt.Errorf("sending MAIL FROM command failed: %w", err))
			if reserr := c.sc.Reset(); reserr != nil {
				errs = append(errs, reserr)
			}
			continue
		}
		failed := false
		for _, r := range rl {
			if err := c.rcpt(r); err != nil {
				errs = append(errs, fmt.Errorf("sending RCPT TO command failed: %w", err))
				failed = true
			}
		}
		if failed {
			if reserr := c.sc.Reset(); reserr != nil {
				errs = append(errs, reserr)
			}
			continue
		}
		w, err := c.sc.Data()
		if err != nil {
			errs = append(errs, fmt.Errorf("sending DATA command failed: %w", err))
			continue
		}
		_, err = m.WriteTo(w)
		if err != nil {
			errs = append(errs, fmt.Errorf("sending mail content failed: %w", err))
			continue
		}

		if err := w.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close DATA writer: %w", err))
			continue
		}

		if err := c.Reset(); err != nil {
			errs = append(errs, fmt.Errorf("sending RSET command failed: %w", err))
			continue
		}
		if err := c.checkConn(); err != nil {
			errs = append(errs, fmt.Errorf("failed to check server connection: %w", err))
			continue
		}
	}

	if len(errs) > 0 {
		errtxt := ""
		for i := range errs {
			errtxt += fmt.Sprintf("%s", errs[i])
			if i < len(errs) {
				errtxt += "\n"
			}
		}
		return fmt.Errorf("%s", errtxt)
	}
	return nil
}
