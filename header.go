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

	// HeaderMessageID represents the "Message-ID" field for message identification
	// See: https://www.rfc-editor.org/rfc/rfc1036#section-2.1.5
	HeaderMessageID Header = "Message-ID"

	// HeaderMIMEVersion represents the "MIME-Version" field as per RFC 2045
	// See: https://datatracker.ietf.org/doc/html/rfc2045#section-4
	HeaderMIMEVersion Header = "MIME-Version"

	// HeaderPrecedence is the "Precedence" genHeader field
	HeaderPrecedence Header = "Precedence"

	// HeaderSubject is the "Subject" genHeader field
	HeaderSubject Header = "Subject"
)

// List of common generic header field names
const (
	// HeaderBcc is the "Blind Carbon Copy" genHeader field
	HeaderBcc AddrHeader = "Bcc"

	// HeaderCc is the "Carbon Copy" genHeader field
	HeaderCc AddrHeader = "Cc"

	// HeaderFrom is the "From" genHeader field
	HeaderFrom AddrHeader = "From"

	// HeaderTo is the "Receipient" genHeader field
	HeaderTo AddrHeader = "To"
)
