// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

package mail

import (
	"errors"
	"strings"
)

// List of SendError reasons
const (
	// ErrGetSender is returned if the Msg.GetSender method fails during a Client.Send
	ErrGetSender SendErrReason = iota

	// ErrGetRcpts is returned if the Msg.GetRecipients method fails during a Client.Send
	ErrGetRcpts

	// ErrSMTPMailFrom is returned if the Msg delivery failed when sending the MAIL FROM command
	// to the sending SMTP server
	ErrSMTPMailFrom

	// ErrSMTPRcptTo is returned if the Msg delivery failed when sending the RCPT TO command
	// to the sending SMTP server
	ErrSMTPRcptTo

	// ErrSMTPData is returned if the Msg delivery failed when sending the DATA command
	// to the sending SMTP server
	ErrSMTPData

	// ErrSMTPDataClose is returned if the Msg delivery failed when trying to close the
	// Client data writer
	ErrSMTPDataClose

	// ErrSMTPReset is returned if the Msg delivery failed when sending the RSET command
	// to the sending SMTP server
	ErrSMTPReset

	// ErrWriteContent is returned if the Msg delivery failed when sending Msg content
	// to the Client writer
	ErrWriteContent

	// ErrConnCheck is returned if the Msg delivery failed when checking if the SMTP
	// server connection is still working
	ErrConnCheck

	// ErrNoUnencoded is returned if the Msg delivery failed when the Msg is configured for
	// unencoded delivery but the server does not support this
	ErrNoUnencoded

	// ErrAmbiguous is a generalized delivery error for the SendError type that is
	// returned if the exact reason for the delivery failure is ambiguous
	ErrAmbiguous
)

// SendError is an error wrapper for delivery errors of the Msg
type SendError struct {
	Reason  SendErrReason
	isTemp  bool
	errlist []error
	rcpt    []string
}

// SendErrReason represents a comparable reason on why the delivery failed
type SendErrReason int

// Error implements the error interface for the SendError type
func (e *SendError) Error() string {
	if e.Reason > 10 {
		return "unknown reason"
	}

	var em strings.Builder
	em.WriteString(e.Reason.String())
	if len(e.errlist) > 0 {
		em.WriteRune(':')
		for i := range e.errlist {
			em.WriteRune(' ')
			em.WriteString(e.errlist[i].Error())
			if i != len(e.errlist)-1 {
				em.WriteString(", ")
			}
		}
	}
	if len(e.rcpt) > 0 {
		em.WriteString(", affected recipient(s): ")
		for i := range e.rcpt {
			em.WriteString(e.rcpt[i])
			if i != len(e.rcpt)-1 {
				em.WriteString(", ")
			}
		}
	}
	return em.String()
}

// Is implements the errors.Is functionality and compares the SendErrReason
func (e *SendError) Is(et error) bool {
	var t *SendError
	if errors.As(et, &t) {
		return e.Reason == t.Reason && e.isTemp == t.isTemp
	}
	return false
}

// IsTemp returns true if the delivery error is of temporary nature and can be retried
func (e *SendError) IsTemp() bool {
	return e.isTemp
}

// String implements the Stringer interface for the SendErrReason
func (r SendErrReason) String() string {
	switch r {
	case ErrGetSender:
		return "getting sender address"
	case ErrGetRcpts:
		return "getting recipient addresses"
	case ErrSMTPMailFrom:
		return "sending SMTP MAIL FROM command"
	case ErrSMTPRcptTo:
		return "sending SMTP RCPT TO command"
	case ErrSMTPData:
		return "sending SMTP DATA command"
	case ErrSMTPDataClose:
		return "closing SMTP DATA writer"
	case ErrSMTPReset:
		return "sending SMTP RESET command"
	case ErrWriteContent:
		return "sending message content"
	case ErrConnCheck:
		return "checking SMTP connection"
	case ErrNoUnencoded:
		return ErrServerNoUnencoded.Error()
	case ErrAmbiguous:
		return "ambiguous reason, check Msg.SendError for message specific reasons"
	}
	return "unknown reason"
}

// isTempError checks the given SMTP error and returns true if the given error is of temporary nature
// and should be retried
func isTempError(e error) bool {
	return e.Error()[0] == '4'
}
