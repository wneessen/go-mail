package mail

// Header represents a generic mail header field name
type Header string

// AddrHeader represents a address related mail Header field name
type AddrHeader string

// List of common generic header field names
const (
	// HeaderContentLang is the "Content-Language" header
	HeaderContentLang Header = "Content-Language"

	// HeaderContentType is the "Content-Type" header
	HeaderContentType Header = "Content-Type"

	// HeaderDate represents the "Date" field
	// See: https://www.rfc-editor.org/rfc/rfc822#section-5.1
	HeaderDate Header = "Date"

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

	// HeaderPrecedence is the "Precedence" header field
	HeaderPrecedence Header = "Precedence"

	// HeaderReplyTo is the "Reply-To" header field
	HeaderReplyTo Header = "Reply-To"

	// HeaderSubject is the "Subject" header field
	HeaderSubject Header = "Subject"
)

// List of common generic header field names
const (
	// HeaderBcc is the "Blind Carbon Copy" header field
	HeaderBcc AddrHeader = "Bcc"

	// HeaderCc is the "Carbon Copy" header field
	HeaderCc AddrHeader = "Cc"

	// HeaderFrom is the "From" header field
	HeaderFrom AddrHeader = "From"

	// HeaderTo is the "Receipient" header field
	HeaderTo AddrHeader = "To"
)
