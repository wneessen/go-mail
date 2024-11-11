// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"errors"
	"strings"
	"testing"
)

// TestSendError_Error tests the SendError and SendErrReason error handling methods
func TestSendError_Error(t *testing.T) {
	t.Run("TestSendError_Error with various reasons", func(t *testing.T) {
		tests := []struct {
			name   string
			reason SendErrReason
			isTemp bool
		}{
			{"ErrGetSender/temp", ErrGetSender, true},
			{"ErrGetSender/perm", ErrGetSender, false},
			{"ErrGetRcpts/temp", ErrGetRcpts, true},
			{"ErrGetRcpts/perm", ErrGetRcpts, false},
			{"ErrSMTPMailFrom/temp", ErrSMTPMailFrom, true},
			{"ErrSMTPMailFrom/perm", ErrSMTPMailFrom, false},
			{"ErrSMTPRcptTo/temp", ErrSMTPRcptTo, true},
			{"ErrSMTPRcptTo/perm", ErrSMTPRcptTo, false},
			{"ErrSMTPData/temp", ErrSMTPData, true},
			{"ErrSMTPData/perm", ErrSMTPData, false},
			{"ErrSMTPDataClose/temp", ErrSMTPDataClose, true},
			{"ErrSMTPDataClose/perm", ErrSMTPDataClose, false},
			{"ErrSMTPReset/temp", ErrSMTPReset, true},
			{"ErrSMTPReset/perm", ErrSMTPReset, false},
			{"ErrWriteContent/temp", ErrWriteContent, true},
			{"ErrWriteContent/perm", ErrWriteContent, false},
			{"ErrConnCheck/temp", ErrConnCheck, true},
			{"ErrConnCheck/perm", ErrConnCheck, false},
			{"ErrNoUnencoded/temp", ErrNoUnencoded, true},
			{"ErrNoUnencoded/perm", ErrNoUnencoded, false},
			{"ErrAmbiguous/temp", ErrAmbiguous, true},
			{"ErrAmbiguous/perm", ErrAmbiguous, false},
			{"Unknown/temp", 9999, true},
			{"Unknown/perm", 9999, false},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				err := returnSendError(tt.reason, tt.isTemp)
				if err == nil {
					t.Fatalf("error expected, got nil")
				}
				want := &SendError{Reason: tt.reason, isTemp: tt.isTemp}
				if !errors.Is(err, want) {
					t.Errorf("error mismatch, expected: %s (temp: %t), got: %s (temp: %t)",
						tt.reason, tt.isTemp, want.Error(), want.isTemp)
				}
				if !strings.Contains(err.Error(), tt.reason.String()) {
					t.Errorf("error string mismatch, expected: %s, got: %s",
						tt.reason.String(), err.Error())
				}
			})
		}
	})
	t.Run("TestSendError_Error with multiple errors", func(t *testing.T) {
		message := testMessage(t)
		err := &SendError{
			affectedMsg: message,
			errlist:     []error{ErrNoRcptAddresses, ErrNoFromAddress},
			rcpt:        []string{"<toni.tester@domain.tld>", "<tina.tester@domain.tld>"},
			Reason:      ErrAmbiguous,
		}
		if !strings.Contains(err.Error(), "ambiguous reason, check Msg.SendError for message specific reasons") {
			t.Errorf("error string mismatch, expected: ambiguous reason, check Msg.SendError for message "+
				"specific reasons, got: %s", err.Error())
		}
		if !strings.Contains(err.Error(), "no recipient addresses set, no FROM address set") {
			t.Errorf("error string mismatch, expected: no recipient addresses set, no FROM address set, got: %s",
				err.Error())
		}
		if !strings.Contains(err.Error(), "affected recipient(s): <toni.tester@domain.tld>, "+
			"<tina.tester@domain.tld>") {
			t.Errorf("error string mismatch, expected: affected recipient(s): <toni.tester@domain.tld>, "+
				"<tina.tester@domain.tld>, got: %s", err.Error())
		}
	})
}

func TestSendError_Is(t *testing.T) {
	t.Run("TestSendError_Is errors match", func(t *testing.T) {
		err1 := returnSendError(ErrAmbiguous, false)
		err2 := returnSendError(ErrAmbiguous, false)
		if !errors.Is(err1, err2) {
			t.Error("error mismatch, expected ErrAmbiguous to be equal to ErrAmbiguous")
		}
	})
	t.Run("TestSendError_Is errors mismatch", func(t *testing.T) {
		err1 := returnSendError(ErrAmbiguous, false)
		err2 := returnSendError(ErrSMTPMailFrom, false)
		if errors.Is(err1, err2) {
			t.Error("error mismatch, ErrAmbiguous should not be equal to ErrSMTPMailFrom")
		}
	})
	t.Run("TestSendError_Is on nil", func(t *testing.T) {
		var err *SendError
		if err.Is(ErrNoFromAddress) {
			t.Error("expected false on nil-senderror")
		}
	})
}

func TestSendError_IsTemp(t *testing.T) {
	t.Run("TestSendError_IsTemp is true", func(t *testing.T) {
		err := returnSendError(ErrAmbiguous, true)
		if err == nil {
			t.Fatalf("error expected, got nil")
		}
		var sendErr *SendError
		if !errors.As(err, &sendErr) {
			t.Fatal("error expected to be of type *SendError")
		}
		if !sendErr.IsTemp() {
			t.Errorf("expected temporary error, got: temperr: %t", sendErr.IsTemp())
		}
	})
	t.Run("TestSendError_IsTemp is false", func(t *testing.T) {
		err := returnSendError(ErrAmbiguous, false)
		if err == nil {
			t.Fatalf("error expected, got nil")
		}
		var sendErr *SendError
		if !errors.As(err, &sendErr) {
			t.Fatal("error expected to be of type *SendError")
		}
		if sendErr.IsTemp() {
			t.Errorf("expected permanent error, got: temperr: %t", sendErr.IsTemp())
		}
	})
	t.Run("TestSendError_IsTemp is nil", func(t *testing.T) {
		var se *SendError
		if se.IsTemp() {
			t.Error("expected false on nil-senderror")
		}
	})
}

func TestSendError_MessageID(t *testing.T) {
	t.Run("TestSendError_MessageID message ID is set", func(t *testing.T) {
		var sendErr *SendError
		err := returnSendError(ErrAmbiguous, false)
		if !errors.As(err, &sendErr) {
			t.Fatal("error mismatch, expected error to be of type *SendError")
		}
		if sendErr.MessageID() == "" {
			t.Error("sendError expected message-id, but got empty string")
		}
		if !strings.EqualFold(sendErr.MessageID(), "<this.is.a.message.id>") {
			t.Errorf("sendError message-id expected: %s, but got: %s", "<this.is.a.message.id>",
				sendErr.MessageID())
		}
	})
	t.Run("TestSendError_MessageID message ID is not set", func(t *testing.T) {
		var sendErr *SendError
		message := testMessage(t)
		err := &SendError{
			affectedMsg: message,
			errlist:     []error{ErrNoRcptAddresses},
			rcpt:        []string{"<toni.tester@domain.tld>", "<tina.tester@domain.tld>"},
			Reason:      ErrAmbiguous,
		}
		if !errors.As(err, &sendErr) {
			t.Fatal("error mismatch, expected error to be of type *SendError")
		}
		if sendErr.MessageID() != "" {
			t.Errorf("sendError expected empty message-id, got: %s", sendErr.MessageID())
		}
	})
	t.Run("TestSendError_MessageID on nil error should return empty", func(t *testing.T) {
		var sendErr *SendError
		if sendErr.MessageID() != "" {
			t.Error("expected empty message-id on nil-senderror")
		}
	})
}

func TestSendError_Msg(t *testing.T) {
	t.Run("TestSendError_Msg message is set", func(t *testing.T) {
		var sendErr *SendError
		err := returnSendError(ErrAmbiguous, false)
		if !errors.As(err, &sendErr) {
			t.Fatal("error mismatch, expected error to be of type *SendError")
		}
		msg := sendErr.Msg()
		if msg == nil {
			t.Fatalf("sendError expected msg pointer, but got nil")
		}
		from := msg.GetFromString()
		if len(from) == 0 {
			t.Fatal("sendError expected msg from, but got empty string")
		}
		if !strings.EqualFold(from[0], "<toni.tester@domain.tld>") {
			t.Errorf("sendError message from expected: %s, but got: %s", "<toni.tester@domain.tld>",
				from[0])
		}
	})
	t.Run("TestSendError_Msg message is not set", func(t *testing.T) {
		var sendErr *SendError
		err := &SendError{
			errlist: []error{ErrNoRcptAddresses},
			rcpt:    []string{"<toni.tester@domain.tld>", "<tina.tester@domain.tld>"},
			Reason:  ErrAmbiguous,
		}
		if !errors.As(err, &sendErr) {
			t.Fatal("error mismatch, expected error to be of type *SendError")
		}
		if sendErr.Msg() != nil {
			t.Errorf("sendError expected nil msg pointer, got: %v", sendErr.Msg())
		}
	})
}

// returnSendError is a helper method to retunr a SendError with a specific reason
func returnSendError(r SendErrReason, t bool) error {
	message := NewMsg()
	_ = message.From("toni.tester@domain.tld")
	_ = message.To("tina.tester@domain.tld")
	message.Subject("This is the subject")
	message.SetBodyString(TypeTextPlain, "This is the message body")
	message.SetMessageIDWithValue("this.is.a.message.id")
	return &SendError{Reason: r, isTemp: t, affectedMsg: message}
}
