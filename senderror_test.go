// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestSendError_Error tests the SendError and SendErrReason error handling methods
func TestSendError_Error(t *testing.T) {
	tl := []struct {
		n  string
		r  SendErrReason
		te bool
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

	for _, tt := range tl {
		t.Run(tt.n, func(t *testing.T) {
			if err := returnSendError(tt.r, tt.te); err != nil {
				exp := &SendError{Reason: tt.r, isTemp: tt.te}
				if !errors.Is(err, exp) {
					t.Errorf("error mismatch, expected: %s (temp: %t), got: %s (temp: %t)", tt.r, tt.te,
						exp.Error(), exp.isTemp)
				}
				if !strings.Contains(fmt.Sprintf("%s", err), tt.r.String()) {
					t.Errorf("error string mismatch, expected: %s, got: %s",
						tt.r.String(), fmt.Sprintf("%s", err))
				}
			}
		})
	}
}

func TestSendError_IsTemp(t *testing.T) {
	var se *SendError
	err1 := returnSendError(ErrAmbiguous, true)
	if !errors.As(err1, &se) {
		t.Errorf("error mismatch, expected error to be of type *SendError")
		return
	}
	if errors.As(err1, &se) && !se.IsTemp() {
		t.Errorf("error mismatch, expected temporary error")
		return
	}
	err2 := returnSendError(ErrAmbiguous, false)
	if !errors.As(err2, &se) {
		t.Errorf("error mismatch, expected error to be of type *SendError")
		return
	}
	if errors.As(err2, &se) && se.IsTemp() {
		t.Errorf("error mismatch, expected non-temporary error")
		return
	}
}

func TestSendError_IsTempNil(t *testing.T) {
	var se *SendError
	if se.IsTemp() {
		t.Error("expected false on nil-senderror")
	}
}

func TestSendError_MessageID(t *testing.T) {
	var se *SendError
	err := returnSendError(ErrAmbiguous, false)
	if !errors.As(err, &se) {
		t.Errorf("error mismatch, expected error to be of type *SendError")
		return
	}
	if errors.As(err, &se) {
		if se.MessageID() == "" {
			t.Errorf("sendError expected message-id, but got empty string")
		}
		if !strings.EqualFold(se.MessageID(), "<this.is.a.message.id>") {
			t.Errorf("sendError message-id expected: %s, but got: %s", "<this.is.a.message.id>",
				se.MessageID())
		}
	}
}

func TestSendError_MessageIDNil(t *testing.T) {
	var se *SendError
	if se.MessageID() != "" {
		t.Error("expected empty string on nil-senderror")
	}
}

func TestSendError_Msg(t *testing.T) {
	var se *SendError
	err := returnSendError(ErrAmbiguous, false)
	if !errors.As(err, &se) {
		t.Errorf("error mismatch, expected error to be of type *SendError")
		return
	}
	if errors.As(err, &se) {
		if se.Msg() == nil {
			t.Errorf("sendError expected msg pointer, but got nil")
		}
		from := se.Msg().GetFromString()
		if len(from) == 0 {
			t.Errorf("sendError expected msg from, but got empty string")
			return
		}
		if !strings.EqualFold(from[0], "<toni.tester@domain.tld>") {
			t.Errorf("sendError message from expected: %s, but got: %s", "<toni.tester@domain.tld>",
				from[0])
		}
	}
}

func TestSendError_MsgNil(t *testing.T) {
	var se *SendError
	if se.Msg() != nil {
		t.Error("expected nil on nil-senderror")
	}
}

func TestSendError_IsFail(t *testing.T) {
	err1 := returnSendError(ErrAmbiguous, false)
	err2 := returnSendError(ErrSMTPMailFrom, false)
	if errors.Is(err1, err2) {
		t.Errorf("error mismatch, ErrAmbiguous should not be equal to ErrSMTPMailFrom")
	}
}

func TestSendError_ErrorMulti(t *testing.T) {
	expected := `ambiguous reason, check Msg.SendError for message specific reasons, ` +
		`affected recipient(s): <email1@domain.tld>, <email2@domain.tld>`
	err := &SendError{
		Reason: ErrAmbiguous, isTemp: false, affectedMsg: nil,
		rcpt: []string{"<email1@domain.tld>", "<email2@domain.tld>"},
	}
	if err.Error() != expected {
		t.Errorf("error mismatch, expected: %s, got: %s", expected, err.Error())
	}
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
