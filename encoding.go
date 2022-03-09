package mail

// Encoding represents a MIME encoding scheme like quoted-printable or base64.
type Encoding string

const (
	// EncodingB64 represents the Base64 encoding as specified in RFC 2045.
	EncodingB64 Encoding = "base64"

	// EncodingQP represents the "quoted-printable" encoding as specified in RFC 2045.
	EncodingQP Encoding = "quoted-printable"

	// NoEncoding avoids any character encoding (except of the mail headers)
	NoEncoding Encoding = "8bit"
)
