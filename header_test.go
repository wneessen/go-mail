package mail

import (
	"testing"
)

// TestImportance_StringFuncs tests the different string method of the Importance object
func TestImportance_StringFuncs(t *testing.T) {
	tests := []struct {
		name   string
		imp    Importance
		wantns string
		xprio  string
		want   string
	}{
		{"Importance: Non-Urgent", ImportanceNonUrgent, "0", "5", "non-urgent"},
		{"Importance: Low", ImportanceLow, "0", "5", "low"},
		{"Importance: Normal", ImportanceNormal, "", "", ""},
		{"Importance: High", ImportanceHigh, "1", "1", "high"},
		{"Importance: Urgent", ImportanceUrgent, "1", "1", "urgent"},
		{"Importance: Unknown", 9, "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.imp.NumString() != tt.wantns {
				t.Errorf("wrong number string for Importance returned. Expected: %s, got: %s",
					tt.wantns, tt.imp.NumString())
			}
			if tt.imp.XPrioString() != tt.xprio {
				t.Errorf("wrong x-prio string for Importance returned. Expected: %s, got: %s",
					tt.xprio, tt.imp.XPrioString())
			}
			if tt.imp.String() != tt.want {
				t.Errorf("wrong string for Importance returned. Expected: %s, got: %s",
					tt.want, tt.imp.String())
			}
		})
	}
}

// TestAddrHeader_String tests the string method of the AddrHeader object
func TestAddrHeader_String(t *testing.T) {
	tests := []struct {
		name string
		ah   AddrHeader
		want string
	}{
		{"Address header: From", HeaderFrom, "From"},
		{"Address header: To", HeaderTo, "To"},
		{"Address header: Cc", HeaderCc, "Cc"},
		{"Address header: Bcc", HeaderBcc, "Bcc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.ah.String() != tt.want {
				t.Errorf("wrong string for AddrHeader returned. Expected: %s, got: %s",
					tt.want, tt.ah.String())
			}
		})
	}
}

// TestHeader_String tests the string method of the Header object
func TestHeader_String(t *testing.T) {
	tests := []struct {
		name string
		h    Header
		want string
	}{
		{"Header: Content-Disposition", HeaderContentDisposition, "Content-Disposition"},
		{"Header: Content-ID", HeaderContentID, "Content-ID"},
		{"Header: Content-Language", HeaderContentLang, "Content-Language"},
		{"Header: Content-Location", HeaderContentLocation, "Content-Location"},
		{"Header: Content-Transfer-Encoding", HeaderContentTransferEnc, "Content-Transfer-Encoding"},
		{"Header: Content-Type", HeaderContentType, "Content-Type"},
		{"Header: Date", HeaderDate, "Date"},
		{"Header: Importance", HeaderImportance, "Importance"},
		{"Header: In-Reply-To", HeaderInReplyTo, "In-Reply-To"},
		{"Header: List-Unsubscribe", HeaderListUnsubscribe, "List-Unsubscribe"},
		{"Header: List-Unsubscribe-Post", HeaderListUnsubscribePost, "List-Unsubscribe-Post"},
		{"Header: Message-ID", HeaderMessageID, "Message-ID"},
		{"Header: MIME-Version", HeaderMIMEVersion, "MIME-Version"},
		{"Header: Organization", HeaderOrganization, "Organization"},
		{"Header: Precedence", HeaderPrecedence, "Precedence"},
		{"Header: Priority", HeaderPriority, "Priority"},
		{"Header: Reply-To", HeaderReplyTo, "Reply-To"},
		{"Header: Subject", HeaderSubject, "Subject"},
		{"Header: User-Agent", HeaderUserAgent, "User-Agent"},
		{"Header: X-Mailer", HeaderXMailer, "X-Mailer"},
		{"Header: X-MSMail-Priority", HeaderXMSMailPriority, "X-MSMail-Priority"},
		{"Header: X-Priority", HeaderXPriority, "X-Priority"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.h.String() != tt.want {
				t.Errorf("wrong string for Header returned. Expected: %s, got: %s",
					tt.want, tt.h.String())
			}
		})
	}
}
