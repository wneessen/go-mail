package mail

import (
	"errors"
	"fmt"
	"strings"
)

// List of SendError errors
var (
	// ErrGetSender is returned if the Msg.GetSender method fails during a Client.Send
	ErrGetSender = errors.New("getting sender address")

	// ErrGetRcpts is returned if the Msg.GetRecipients method fails during a Client.Send
	ErrGetRcpts = errors.New("getting recipient addresses")

	// ErrSMTPMailFrom is returned if the Msg delivery failed when sending the MAIL FROM command
	// to the sending SMTP server
	ErrSMTPMailFrom = errors.New("sending SMTP MAIL FROM command")

	// ErrSMTPRcptTo is returned if the Msg delivery failed when sending the RCPT TO command
	// to the sending SMTP server
	ErrSMTPRcptTo = errors.New("sending SMTP RCPT TO command")

	// ErrSMTPData is returned if the Msg delivery failed when sending the DATA command
	// to the sending SMTP server
	ErrSMTPData = errors.New("sending SMTP DATA command")

	// ErrSMTPDataClose is returned if the Msg delivery failed when trying to close the
	// Client data writer
	ErrSMTPDataClose = errors.New("closing SMTP DATA writer")

	// ErrSMTPReset is returned if the Msg delivery failed when sending the RSET command
	// to the sending SMTP server
	ErrSMTPReset = errors.New("sending SMTP RESET command")

	// ErrWriteContent is returned if the Msg delivery failed when sending Msg content
	// to the Client writer
	ErrWriteContent = errors.New("sending message content")

	// ErrConnCheck is returned if the Msg delivery failed when checking if the SMTP
	// server connection is still working
	ErrConnCheck = errors.New("checking SMTP connection")
)

// SendError is an error wrapper for delivery errors of the Msg
type SendError struct {
	Err     error
	details []error
	rcpt    []string
}

// Error implements the error interface for the SendError type
func (e SendError) Error() string {
	var em strings.Builder
	_, _ = fmt.Fprintf(&em, "client_send: %s", e.Err)
	if len(e.details) > 0 {
		for i := range e.details {
			em.WriteString(fmt.Sprintf(", error_details: %s", e.details[i]))
		}
	}
	if len(e.rcpt) > 0 {
		for i := range e.rcpt {
			em.WriteString(fmt.Sprintf(", rcpt: %s", e.rcpt[i]))
		}
	}
	return em.String()
}
