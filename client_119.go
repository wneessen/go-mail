// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build !go1.20
// +build !go1.20

package mail

import "strings"

// Send sends out the mail message
func (c *Client) Send(ml ...*Msg) error {
	if cerr := c.checkConn(); cerr != nil {
		return &SendError{Reason: ErrConnCheck, errlist: []error{cerr}, isTemp: isTempError(cerr)}
	}
	var errs []*SendError
	for _, m := range ml {
		m.sendError = nil
		if m.encoding == NoEncoding {
			if ok, _ := c.sc.Extension("8BITMIME"); !ok {
				se := &SendError{Reason: ErrNoUnencoded, isTemp: false}
				m.sendError = se
				errs = append(errs, se)
				continue
			}
		}
		f, err := m.GetSender(false)
		if err != nil {
			se := &SendError{Reason: ErrGetSender, errlist: []error{err}, isTemp: isTempError(err)}
			m.sendError = se
			errs = append(errs, se)
			continue
		}
		rl, err := m.GetRecipients()
		if err != nil {
			se := &SendError{Reason: ErrGetRcpts, errlist: []error{err}, isTemp: isTempError(err)}
			m.sendError = se
			errs = append(errs, se)
			continue
		}

		if c.dsn {
			if c.dsnmrtype != "" {
				c.sc.SetDSNMailReturnOption(string(c.dsnmrtype))
			}
		}
		if err := c.sc.Mail(f); err != nil {
			se := &SendError{Reason: ErrSMTPMailFrom, errlist: []error{err}, isTemp: isTempError(err)}
			if reserr := c.sc.Reset(); reserr != nil {
				se.errlist = append(se.errlist, reserr)
			}
			m.sendError = se
			errs = append(errs, se)
			continue
		}
		failed := false
		rse := &SendError{}
		rse.errlist = make([]error, 0)
		rse.rcpt = make([]string, 0)
		rno := strings.Join(c.dsnrntype, ",")
		c.sc.SetDSNRcptNotifyOption(rno)
		for _, r := range rl {
			if err := c.sc.Rcpt(r); err != nil {
				rse.Reason = ErrSMTPRcptTo
				rse.errlist = append(rse.errlist, err)
				rse.rcpt = append(rse.rcpt, r)
				rse.isTemp = isTempError(err)
				failed = true
			}
		}
		if failed {
			if reserr := c.sc.Reset(); reserr != nil {
				rse.errlist = append(rse.errlist, err)
			}
			m.sendError = rse
			errs = append(errs, rse)
			continue
		}
		w, err := c.sc.Data()
		if err != nil {
			se := &SendError{Reason: ErrSMTPData, errlist: []error{err}, isTemp: isTempError(err)}
			m.sendError = se
			errs = append(errs, se)
			continue
		}
		_, err = m.WriteTo(w)
		if err != nil {
			se := &SendError{Reason: ErrWriteContent, errlist: []error{err}, isTemp: isTempError(err)}
			m.sendError = se
			errs = append(errs, se)
			continue
		}

		if err := w.Close(); err != nil {
			se := &SendError{Reason: ErrSMTPDataClose, errlist: []error{err}, isTemp: isTempError(err)}
			m.sendError = se
			errs = append(errs, se)
			continue
		}

		if err := c.Reset(); err != nil {
			se := &SendError{Reason: ErrSMTPReset, errlist: []error{err}, isTemp: isTempError(err)}
			m.sendError = se
			errs = append(errs, se)
			continue
		}
		if err := c.checkConn(); err != nil {
			se := &SendError{Reason: ErrConnCheck, errlist: []error{err}, isTemp: isTempError(err)}
			m.sendError = se
			errs = append(errs, se)
			continue
		}
	}

	if len(errs) > 0 {
		if len(errs) > 1 {
			re := &SendError{Reason: ErrAmbiguous}
			for i := range errs {
				re.errlist = append(re.errlist, errs[i].errlist...)
				re.rcpt = append(re.rcpt, errs[i].rcpt...)
			}

			// We assume that the isTemp flag from the last error we received should be the
			// indicator for the returned isTemp flag as well
			re.isTemp = errs[len(errs)-1].isTemp

			return re
		}
		return errs[0]
	}
	return nil
}
