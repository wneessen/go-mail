// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

// Header represents a generic mail header field name
type Header string

// AddrHeader represents a address related mail Header field name
type AddrHeader string

// Importance represents a Importance/Priority value string
type Importance int

// List of common generic header field names
const (
	// HeaderContentDescription is the "Content-Description" header
	HeaderContentDescription Header = "Content-Description"

	// HeaderContentDisposition is the "Content-Disposition" header
	HeaderContentDisposition Header = "Content-Disposition"

	// HeaderContentID is the "Content-ID" header
	HeaderContentID Header = "Content-ID"

	// HeaderContentLang is the "Content-Language" header
	HeaderContentLang Header = "Content-Language"

	// HeaderContentLocation is the "Content-Location" header (RFC 2110)
	HeaderContentLocation Header = "Content-Location"

	// HeaderContentTransferEnc is the "Content-Transfer-Encoding" header
	HeaderContentTransferEnc Header = "Content-Transfer-Encoding"

	// HeaderContentType is the "Content-Type" header
	HeaderContentType Header = "Content-Type"

	// HeaderDate represents the "Date" field
	// See: https://www.rfc-editor.org/rfc/rfc822#section-5.1
	HeaderDate Header = "Date"

	// HeaderDispositionNotificationTo is the MDN header as described in RFC8098
	// See: https://www.rfc-editor.org/rfc/rfc8098.html#section-2.1
	HeaderDispositionNotificationTo Header = "Disposition-Notification-To"

	// HeaderImportance represents the "Importance" field
	HeaderImportance Header = "Importance"

	// HeaderInReplyTo represents the "In-Reply-To" field
	HeaderInReplyTo Header = "In-Reply-To"

	// HeaderListUnsubscribe is the "List-Unsubscribe" header field
	HeaderListUnsubscribe Header = "List-Unsubscribe"

	// HeaderListUnsubscribePost is the "List-Unsubscribe-Post" header field
	HeaderListUnsubscribePost Header = "List-Unsubscribe-Post"

	// HeaderMessageID represents the "Message-ID" field for message identification
	// See: https://www.rfc-editor.org/rfc/rfc1036#section-2.1.5
	HeaderMessageID Header = "Message-ID"

	// HeaderMIMEVersion represents the "MIME-Version" field as per RFC 2045
	// See: https://datatracker.ietf.org/doc/html/rfc2045#section-4
	HeaderMIMEVersion Header = "MIME-Version"

	// HeaderOrganization is the "Organization" header field
	HeaderOrganization Header = "Organization"

	// HeaderPrecedence is the "Precedence" header field
	HeaderPrecedence Header = "Precedence"

	// HeaderPriority represents the "Priority" field
	HeaderPriority Header = "Priority"

	// HeaderReferences is the "References" header field
	HeaderReferences Header = "References"

	// HeaderReplyTo is the "Reply-To" header field
	HeaderReplyTo Header = "Reply-To"

	// HeaderSubject is the "Subject" header field
	HeaderSubject Header = "Subject"

	// HeaderUserAgent is the "User-Agent" header field
	HeaderUserAgent Header = "User-Agent"

	// HeaderXMailer is the "X-Mailer" header field
	HeaderXMailer Header = "X-Mailer"

	// HeaderXMSMailPriority is the "X-MSMail-Priority" header field
	HeaderXMSMailPriority Header = "X-MSMail-Priority"

	// HeaderXPriority is the "X-Priority" header field
	HeaderXPriority Header = "X-Priority"
)

// List of common address header field names
const (
	// HeaderBcc is the "Blind Carbon Copy" header field
	HeaderBcc AddrHeader = "Bcc"

	// HeaderCc is the "Carbon Copy" header field
	HeaderCc AddrHeader = "Cc"

	// HeaderEnvelopeFrom is the envelope FROM header field
	// It's not included in the mail body but only used by the Client for the envelope
	HeaderEnvelopeFrom AddrHeader = "EnvelopeFrom"

	// HeaderFrom is the "From" header field
	HeaderFrom AddrHeader = "From"

	// HeaderTo is the "Receipient" header field
	HeaderTo AddrHeader = "To"
)

// List of Importance values
const (
	ImportanceLow Importance = iota
	ImportanceNormal
	ImportanceHigh
	ImportanceNonUrgent
	ImportanceUrgent
)

// NumString returns the importance number string based on the Importance
func (i Importance) NumString() string {
	switch i {
	case ImportanceNonUrgent:
		return "0"
	case ImportanceLow:
		return "0"
	case ImportanceHigh:
		return "1"
	case ImportanceUrgent:
		return "1"
	default:
		return ""
	}
}

// XPrioString returns the X-Priority number string based on the Importance
func (i Importance) XPrioString() string {
	switch i {
	case ImportanceNonUrgent:
		return "5"
	case ImportanceLow:
		return "5"
	case ImportanceHigh:
		return "1"
	case ImportanceUrgent:
		return "1"
	default:
		return ""
	}
}

// String returns the importance string based on the Importance
func (i Importance) String() string {
	switch i {
	case ImportanceNonUrgent:
		return "non-urgent"
	case ImportanceLow:
		return "low"
	case ImportanceHigh:
		return "high"
	case ImportanceUrgent:
		return "urgent"
	default:
		return ""
	}
}

// String returns the header string based on the given Header
func (h Header) String() string {
	return string(h)
}

// String returns the address header string based on the given AddrHeader
func (a AddrHeader) String() string {
	return string(a)
}
