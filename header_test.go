// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"testing"
)

var (
	genHeaderTests = []struct {
		name   string
		header Header
		want   string
	}{
		{"Header: Content-Description", HeaderContentDescription, "Content-Description"},
		{"Header: Content-Disposition", HeaderContentDisposition, "Content-Disposition"},
		{"Header: Content-ID", HeaderContentID, "Content-ID"},
		{"Header: Content-Language", HeaderContentLang, "Content-Language"},
		{"Header: Content-Location", HeaderContentLocation, "Content-Location"},
		{"Header: Content-Transfer-Encoding", HeaderContentTransferEnc, "Content-Transfer-Encoding"},
		{"Header: Content-Type", HeaderContentType, "Content-Type"},
		{"Header: Date", HeaderDate, "Date"},
		{
			"Header: Disposition-Notification-To", HeaderDispositionNotificationTo,
			"Disposition-Notification-To",
		},
		{"Header: Importance", HeaderImportance, "Importance"},
		{"Header: In-Reply-To", HeaderInReplyTo, "In-Reply-To"},
		{"Header: List-Unsubscribe", HeaderListUnsubscribe, "List-Unsubscribe"},
		{"Header: List-Unsubscribe-Post", HeaderListUnsubscribePost, "List-Unsubscribe-Post"},
		{"Header: Message-ID", HeaderMessageID, "Message-ID"},
		{"Header: MIME-Version", HeaderMIMEVersion, "MIME-Version"},
		{"Header: Organization", HeaderOrganization, "Organization"},
		{"Header: Precedence", HeaderPrecedence, "Precedence"},
		{"Header: Priority", HeaderPriority, "Priority"},
		{"Header: References", HeaderReferences, "References"},
		{"Header: Reply-To", HeaderReplyTo, "Reply-To"},
		{"Header: Subject", HeaderSubject, "Subject"},
		{"Header: User-Agent", HeaderUserAgent, "User-Agent"},
		{"Header: X-Auto-Response-Suppress", HeaderXAutoResponseSuppress, "X-Auto-Response-Suppress"},
		{"Header: X-Mailer", HeaderXMailer, "X-Mailer"},
		{"Header: X-MSMail-Priority", HeaderXMSMailPriority, "X-MSMail-Priority"},
		{"Header: X-Priority", HeaderXPriority, "X-Priority"},
	}
	addrHeaderTests = []struct {
		name string
		ah   AddrHeader
		want string
	}{
		{"Address header: From", HeaderFrom, "From"},
		{"Address header: To", HeaderTo, "To"},
		{"Address header: Cc", HeaderCc, "Cc"},
		{"Address header: Bcc", HeaderBcc, "Bcc"},
	}
)

func TestImportance_Stringer(t *testing.T) {
	tests := []struct {
		name    string
		imp     Importance
		wantnum string
		xprio   string
		want    string
	}{
		{"Importance: Non-Urgent", ImportanceNonUrgent, "0", "5", "non-urgent"},
		{"Importance: Low", ImportanceLow, "0", "5", "low"},
		{"Importance: Normal", ImportanceNormal, "", "", ""},
		{"Importance: High", ImportanceHigh, "1", "1", "high"},
		{"Importance: Urgent", ImportanceUrgent, "1", "1", "urgent"},
		{"Importance: Unknown", 9, "", "", ""},
	}
	t.Run("String", func(t *testing.T) {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if tt.imp.String() != tt.want {
					t.Errorf("wrong string for Importance returned. Expected: %s, got: %s", tt.want, tt.imp.String())
				}
			})
		}
	})
	t.Run("NumString", func(t *testing.T) {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if tt.imp.NumString() != tt.wantnum {
					t.Errorf("wrong number string for Importance returned. Expected: %s, got: %s", tt.wantnum,
						tt.imp.NumString())
				}
			})
		}
	})
	t.Run("XPrioString", func(t *testing.T) {
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if tt.imp.XPrioString() != tt.xprio {
					t.Errorf("wrong x-prio string for Importance returned. Expected: %s, got: %s", tt.xprio,
						tt.imp.XPrioString())
				}
			})
		}
	})
}

func TestAddrHeader_Stringer(t *testing.T) {
	for _, tt := range addrHeaderTests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.ah.String() != tt.want {
				t.Errorf("wrong string for AddrHeader returned. Expected: %s, got: %s",
					tt.want, tt.ah.String())
			}
		})
	}
}

func TestHeader_Stringer(t *testing.T) {
	for _, tt := range genHeaderTests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.header.String() != tt.want {
				t.Errorf("wrong string for Header returned. Expected: %s, got: %s",
					tt.want, tt.header.String())
			}
		})
	}
}
