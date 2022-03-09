package mail

// Header represents a mail header field name
type Header string

// List of common header field names
const (
	// HeaderFrom is the "From" header field
	HeaderFrom Header = "From"

	// HeaderTo is the "Receipient" header field
	HeaderTo Header = "To"

	// HeaderCc is the "Carbon Copy" header field
	HeaderCc Header = "Cc"

	// HeaderPrecedence is the "Precedence" header field
	HeaderPrecedence Header = "Precedence"

	// HeaderDate represents the "Date" field
	// See: https://www.rfc-editor.org/rfc/rfc822#section-5.1
	HeaderDate Header = "Date"

	// HeaderMessageID represents the "Message-ID" field for message identification
	// See: https://www.rfc-editor.org/rfc/rfc1036#section-2.1.5
	HeaderMessageID Header = "Message-ID"
)
