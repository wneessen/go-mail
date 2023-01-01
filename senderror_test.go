// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

package mail

import (
	"errors"
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
			}
		})
	}
}

// returnSendError is a helper method to retunr a SendError with a specific reason
func returnSendError(r SendErrReason, t bool) error {
	return &SendError{Reason: r, isTemp: t}
}
