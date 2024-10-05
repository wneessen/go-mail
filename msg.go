// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	ht "html/template"
	"io"
	"mime"
	"net/mail"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	tt "text/template"
	"time"
)

var (
	// ErrNoFromAddress indicates that the FROM address is not set, which is required.
	ErrNoFromAddress = errors.New("no FROM address set")

	// ErrNoRcptAddresses indicates that no recipient addresses have been set.
	ErrNoRcptAddresses = errors.New("no recipient addresses set")
)

const (
	// errTplExecuteFailed indicates that the execution of a template has failed, including the underlying error.
	errTplExecuteFailed = "failed to execute template: %w"

	// errTplPointerNil indicates that a template pointer is nil, which prevents further template execution or
	// processing.
	errTplPointerNil = "template pointer is nil"

	// errParseMailAddr indicates that parsing of a mail address has failed, including the problematic address
	// and error.
	errParseMailAddr = "failed to parse mail address %q: %w"
)

const (
	// NoPGP indicates that a message should not be treated as PGP encrypted or signed and is the default value
	// for a message
	NoPGP PGPType = iota
	// PGPEncrypt indicates that a message should be treated as PGP encrypted. This works closely together with
	// the corresponding go-mail-middleware.
	PGPEncrypt
	// PGPSignature indicates that a message should be treated as PGP signed. This works closely together with
	// the corresponding go-mail-middleware.
	PGPSignature
)

// MiddlewareType is a type wrapper for a string. It describes the type of the Middleware and needs to be
// returned by the Middleware.Type method to satisfy the Middleware interface.
type MiddlewareType string

// Middleware represents the interface for modifying or handling email messages. A Middleware allows the user to
// alter a Msg before it is finally processed. Multiple Middleware can be applied to a Msg.
//
// Type returns a unique MiddlewareType. It describes the type of Middleware and makes sure that
// a Middleware is only applied once.
// Handle performs all the processing to the Msg. It always needs to return a Msg back.
type Middleware interface {
	Handle(*Msg) *Msg
	Type() MiddlewareType
}

// PGPType is a type wrapper for an int, representing a type of PGP encryption or signature.
type PGPType int

// Msg represents an email message with various headers, attachments, and encoding settings.
//
// The Msg is the central part of go-mail. It provided a lot of methods that you would expect in a mail
// user agent (MUA). Msg satisfies the io.WriterTo and io.Reader interfaces.
type Msg struct {
	// addrHeader holds a mapping between AddrHeader keys and their corresponding slices of mail.Address pointers.
	addrHeader map[AddrHeader][]*mail.Address

	// attachments holds a list of File pointers that represent files either as attachments or embeds files in
	// a Msg.
	attachments []*File

	// boundary represents the delimiter for separating parts in a multipart message.
	boundary string

	// charset represents the Charset of the Msg.
	//
	// By default we set CharsetUTF8 for a Msg unless overridden by a corresponding MsgOption.
	charset Charset

	// embeds contains a slice of File pointers representing the embedded files in a Msg.
	embeds []*File

	// encoder is a mime.WordEncoder used to encode strings (such as email headers) using a specified
	// Encoding.
	encoder mime.WordEncoder

	// encoding specifies the type of Encoding used for email messages and/or parts.
	encoding Encoding

	// genHeader is a map where the keys are email headers (of type Header) and the values are slices of strings
	// representing header values.
	genHeader map[Header][]string

	// isDelivered indicates wether the Msg has been delivered.
	isDelivered bool

	// middlewares is a slice of Middleware used for modifying or handling messages before they are processed.
	//
	// middlewares are processed in FIFO order.
	middlewares []Middleware

	// mimever represents the MIME version used in a Msg.
	mimever MIMEVersion

	// parts is a slice that holds pointers to Part structures, which represent different parts of a Msg.
	parts []*Part

	// preformHeader maps Header types to their already preformatted string values.
	//
	// Preformatted Header values will not be affected by automatic line breaks.
	preformHeader map[Header]string

	// pgptype indicates that a message has a PGPType assigned and therefore will generate
	// different Content-Type settings in the msgWriter.
	pgptype PGPType

	// sendError represents an error encountered during the process of sending a Msg during the
	// Client.Send operation.
	//
	// sendError will hold an error of type SendError.
	sendError error

	// noDefaultUserAgent indicates whether the default User-Agent will be omitted for the Msg when it is
	// being sent.
	//
	// This can be useful in scenarios where headers are conditionally passed based on receipt - i. e. SMTP proxies.
	noDefaultUserAgent bool
}

// SendmailPath is the default system path to the sendmail binary - at least on standard Unix-like OS.
const SendmailPath = "/usr/sbin/sendmail"

// MsgOption is a function type that modifies a Msg instance during its creation or initialization.
type MsgOption func(*Msg)

// NewMsg creates a new email message with optional MsgOption functions that customize various aspects
// of the message.
//
// This function initializes a new Msg instance with default values for address headers, character set,
// encoding, general headers, and MIME version. It then applies any provided MsgOption functions to
// customize the message according to the user's needs. If an option is nil, it will be ignored.
// After applying the options, the function sets the appropriate MIME WordEncoder for the message.
//
// Parameters:
//   - opts: A variadic list of MsgOption functions that can be used to customize the Msg instance.
//
// Returns:
//   - A pointer to the newly created Msg instance.
//
// References:
//   - https://datatracker.ietf.org/doc/html/rfc5321
func NewMsg(opts ...MsgOption) *Msg {
	msg := &Msg{
		addrHeader:    make(map[AddrHeader][]*mail.Address),
		charset:       CharsetUTF8,
		encoding:      EncodingQP,
		genHeader:     make(map[Header][]string),
		preformHeader: make(map[Header]string),
		mimever:       MIME10,
	}

	// Override defaults with optionally provided MsgOption functions.
	for _, option := range opts {
		if option == nil {
			continue
		}
		option(msg)
	}

	// Set the matcing mime.WordEncoder for the Msg
	msg.setEncoder()

	return msg
}

// WithCharset sets the Charset type for a Msg during its creation or initialization.
//
// This MsgOption function allows you to specify the character set to be used in the email message.
// The charset defines how the text in the message is encoded and interpreted by the email client.
// This option should be called when creating a new Msg instance to ensure that the desired charset
// is set correctly.
//
// Parameters:
//   - charset: The Charset value that specifies the desired character set for the Msg.
//
// Returns:
//   - A MsgOption function that can be used to customize the Msg instance.
//
// References:
//   - https://datatracker.ietf.org/doc/html/rfc2047#section-5
func WithCharset(charset Charset) MsgOption {
	return func(m *Msg) {
		m.charset = charset
	}
}

// WithEncoding sets the Encoding type for a Msg during its creation or initialization.
//
// This MsgOption function allows you to specify the encoding type to be used in the email message.
// The encoding defines how the message content is encoded, which affects how it is transmitted
// and decoded by email clients. This option should be called when creating a new Msg instance to
// ensure that the desired encoding is set correctly.
//
// Parameters:
//   - encoding: The Encoding value that specifies the desired encoding type for the Msg.
//
// Returns:
//   - A MsgOption function that can be used to customize the Msg instance.
//
// References:
//   - https://datatracker.ietf.org/doc/html/rfc2047#section-6
func WithEncoding(encoding Encoding) MsgOption {
	return func(m *Msg) {
		m.encoding = encoding
	}
}

// WithMIMEVersion sets the MIMEVersion type for a Msg during its creation or initialization.
//
// Note that in the context of email, MIME Version 1.0 is the only officially standardized and
// supported version. While MIME has been updated and extended over time via various RFCs, these
// updates and extensions do not introduce new MIME versions; they refine or add features within
// the framework of MIME 1.0. Therefore, there should be no reason to ever use this MsgOption.
//
// Parameters:
//   - version: The MIMEVersion value that specifies the desired MIME version for the Msg.
//
// Returns:
//   - A MsgOption function that can be used to customize the Msg instance.
//
// References:
//   - https://datatracker.ietf.org/doc/html/rfc1521
//   - https://datatracker.ietf.org/doc/html/rfc2045
//   - https://datatracker.ietf.org/doc/html/rfc2049
func WithMIMEVersion(version MIMEVersion) MsgOption {
	return func(m *Msg) {
		m.mimever = version
	}
}

// WithBoundary sets the boundary of a Msg to the provided string value during its creation or
// initialization.
//
// Note that by default, random MIME boundaries are created. This option should only be used if
// a specific boundary is required for the email message. Using a predefined boundary can be
// helpful when constructing multipart messages with specific formatting or content separation.
//
// Parameters:
//   - boundary: The string value that specifies the desired boundary for the Msg.
//
// Returns:
//   - A MsgOption function that can be used to customize the Msg instance.
func WithBoundary(boundary string) MsgOption {
	return func(m *Msg) {
		m.boundary = boundary
	}
}

// WithMiddleware adds the given Middleware to the end of the list of the Client middlewares slice.
// Middleware are processed in FIFO order.
//
// This MsgOption function allows you to specify custom middleware that will be applied during the
// message handling process. Middleware can be used to modify the message, perform logging, or
// implement additional functionality as the message flows through the system. Each middleware
// is executed in the order it was added.
//
// Parameters:
//   - middleware: The Middleware to be added to the list for processing.
//
// Returns:
//   - A MsgOption function that can be used to customize the Msg instance.
func WithMiddleware(middleware Middleware) MsgOption {
	return func(m *Msg) {
		m.middlewares = append(m.middlewares, middleware)
	}
}

// WithPGPType sets the PGP type for the Msg during its creation or initialization, determining
// the encryption or signature method.
//
// This MsgOption function allows you to specify the PGP (Pretty Good Privacy) type to be used
// for securing the message. The chosen PGP type influences how the message is encrypted or
// signed, ensuring confidentiality and integrity of the content. This option should be called
// when creating a new Msg instance to set the desired PGP type appropriately.
//
// Parameters:
//   - pgptype: The PGPType value that specifies the desired PGP type for the Msg.
//
// Returns:
//   - A MsgOption function that can be used to customize the Msg instance.
//
// References:
//   - https://datatracker.ietf.org/doc/html/rfc4880
func WithPGPType(pgptype PGPType) MsgOption {
	return func(m *Msg) {
		m.pgptype = pgptype
	}
}

// WithNoDefaultUserAgent disables the inclusion of a default User-Agent header in the Msg during
// its creation or initialization.
//
// This MsgOption function allows you to customize the Msg instance by omitting the default
// User-Agent header, which is typically included to provide information about the software
// sending the email. This option can be useful when you want to have more control over the
// headers included in the message, such as when sending from a custom application or for
// privacy reasons.
//
// Returns:
//   - A MsgOption function that can be used to customize the Msg instance.
func WithNoDefaultUserAgent() MsgOption {
	return func(m *Msg) {
		m.noDefaultUserAgent = true
	}
}

// SetCharset sets or overrides the currently set encoding charset of the Msg.
//
// This method allows you to specify a character set for the email message. The charset is
// important for ensuring that the content of the message is correctly interpreted by
// mail clients. Common charset values include UTF-8, ISO-8859-1, and others. If a charset
// is not explicitly set, CharsetUTF8 is used as default.
//
// Parameters:
//   - charset: The Charset value to set for the Msg, determining the encoding used for the message content.
func (m *Msg) SetCharset(charset Charset) {
	m.charset = charset
}

// SetEncoding sets or overrides the currently set Encoding of the Msg.
//
// This method allows you to specify the encoding type for the email message. The encoding
// determines how the message content is represented and can affect the size and compatibility
// of the email. Common encoding types include Base64 and Quoted-Printable. Setting a new
// encoding may also adjust how the message content is processed and transmitted.
//
// Parameters:
//   - encoding: The Encoding value to set for the Msg, determining the method used to encode the
//     message content.
func (m *Msg) SetEncoding(encoding Encoding) {
	m.encoding = encoding
	m.setEncoder()
}

// SetBoundary sets or overrides the currently set boundary of the Msg.
//
// This method allows you to specify a custom boundary string for the MIME message. The
// boundary is used to separate different parts of the message, especially when dealing
// with multipart messages. By default, the Msg generates random MIME boundaries. This
// function should only be used if you have a specific boundary requirement for the
// message. Ensure that the boundary value does not conflict with any content within the
// message to avoid parsing errors.
//
// Parameters:
//   - boundary: The string value representing the boundary to set for the Msg, used in
//     multipart messages to delimit different sections.
func (m *Msg) SetBoundary(boundary string) {
	m.boundary = boundary
}

// SetMIMEVersion sets or overrides the currently set MIME version of the Msg.
//
// In the context of email, MIME Version 1.0 is the only officially standardized and
// supported version. Although MIME has been updated and extended over time through
// various RFCs, these updates do not introduce new MIME versions; they refine or add
// features within the framework of MIME 1.0. Therefore, there is generally no need to
// use this function to set a different MIME version.
//
// Parameters:
//   - version: The MIMEVersion value to set for the Msg, which determines the MIME
//     version used in the email message.
//
// References:
//   - https://datatracker.ietf.org/doc/html/rfc1521
//   - https://datatracker.ietf.org/doc/html/rfc2045
//   - https://datatracker.ietf.org/doc/html/rfc2049
func (m *Msg) SetMIMEVersion(version MIMEVersion) {
	m.mimever = version
}

// SetPGPType sets or overrides the currently set PGP type for the Msg, determining the
// encryption or signature method.
//
// This method allows you to specify the PGP type that will be used when encrypting or
// signing the message. Different PGP types correspond to various encryption and signing
// algorithms, and selecting the appropriate type is essential for ensuring the security
// and integrity of the message content.
//
// Parameters:
//   - pgptype: The PGPType value to set for the Msg, which determines the encryption
//     or signature method used for the email message.
func (m *Msg) SetPGPType(pgptype PGPType) {
	m.pgptype = pgptype
}

// Encoding returns the currently set Encoding of the Msg as a string.
//
// This method retrieves the encoding type that is currently applied to the message. The
// encoding type determines how the message content is encoded for transmission. Common
// encoding types include quoted-printable and base64, and the returned string will reflect
// the specific encoding method in use.
//
// Returns:
//   - A string representation of the current Encoding of the Msg.
func (m *Msg) Encoding() string {
	return m.encoding.String()
}

// Charset returns the currently set Charset of the Msg as a string.
//
// This method retrieves the character set that is currently applied to the message. The
// charset defines the encoding for the text content of the message, ensuring that
// characters are displayed correctly across different email clients and platforms. The
// returned string will reflect the specific charset in use, such as UTF-8 or ISO-8859-1.
//
// Returns:
//   - A string representation of the current Charset of the Msg.
func (m *Msg) Charset() string {
	return m.charset.String()
}

// SetHeader sets a generic header field of the Msg.
//
// Deprecated: This method only exists for compatibility reasons. Please use SetGenHeader
// instead. For adding address headers like "To:" or "From", use SetAddrHeader instead.
//
// This method allows you to set a header field for the message, providing the header name
// and its corresponding values. However, it is recommended to utilize the newer methods
// for better clarity and functionality. Using SetGenHeader or SetAddrHeader is preferred
// for more specific header types, ensuring proper handling of the message headers.
//
// Parameters:
//   - header: The header field to set in the Msg.
//   - values: One or more string values to associate with the header field.
//
// References:
//   - https://datatracker.ietf.org/doc/html/rfc5322#section-3
//   - https://datatracker.ietf.org/doc/html/rfc2047
func (m *Msg) SetHeader(header Header, values ...string) {
	m.SetGenHeader(header, values...)
}

// SetGenHeader sets a generic header field of the Msg to the provided list of values.
//
// This method is intended for setting generic headers in the email message. It takes a
// header name and a variadic list of string values, encoding them as necessary before
// storing them in the message's internal header map.
//
// Note: For adding email address-related headers (like "To:", "From", "Cc", etc.),
// use SetAddrHeader instead to ensure proper formatting and validation.
//
// Parameters:
//   - header: The header field to set in the Msg.
//   - values: One or more string values to associate with the header field.
//
// This method ensures that all values are appropriately encoded for email transmission,
// adhering to the necessary standards.
//
// References:
//   - https://datatracker.ietf.org/doc/html/rfc5322#section-3
//   - https://datatracker.ietf.org/doc/html/rfc2047
func (m *Msg) SetGenHeader(header Header, values ...string) {
	if m.genHeader == nil {
		m.genHeader = make(map[Header][]string)
	}
	for i, val := range values {
		values[i] = m.encodeString(val)
	}
	m.genHeader[header] = values
}

// SetHeaderPreformatted sets a generic header field of the Msg, which content is already preformatted.
//
// Deprecated: This method only exists for compatibility reasons. Please use
// SetGenHeaderPreformatted instead for setting preformatted generic header fields.
//
// Parameters:
//   - header: The header field to set in the Msg.
//   - value: The preformatted string value to associate with the header field.
//
// References:
//   - https://datatracker.ietf.org/doc/html/rfc5322#section-3
//   - https://datatracker.ietf.org/doc/html/rfc2047
func (m *Msg) SetHeaderPreformatted(header Header, value string) {
	m.SetGenHeaderPreformatted(header, value)
}

// SetGenHeaderPreformatted sets a generic header field of the Msg which content is already preformatted.
//
// This method does not take a slice of values but only a single value. The reason for this is that we do not
// perform any content alteration on these kinds of headers and expect the user to have already taken care of
// any kind of formatting required for the header.
//
// Note: This method should be used only as a last resort. Since the user is responsible for the formatting of
// the message header, we cannot guarantee any compliance with RFC 2822. It is advised to use SetGenHeader
// instead for general header fields.
//
// Parameters:
//   - header: The header field to set in the Msg.
//   - value: The preformatted string value to associate with the header field.
//
// References:
//   - https://datatracker.ietf.org/doc/html/rfc2822
func (m *Msg) SetGenHeaderPreformatted(header Header, value string) {
	if m.preformHeader == nil {
		m.preformHeader = make(map[Header]string)
	}
	m.preformHeader[header] = value
}

// SetAddrHeader sets the specified AddrHeader for the Msg to the given values.
//
// Addresses are parsed according to RFC 5322. If parsing any of the provided values fails,
// an error is returned. If you cannot guarantee that all provided values are valid, you can
// use SetAddrHeaderIgnoreInvalid instead, which will silently skip any parsing errors.
//
// This method allows you to set address-related headers for the message, ensuring that the
// provided addresses are properly formatted and parsed. Using this method helps maintain the
// integrity of the email addresses within the message.
//
// Parameters:
//   - header: The AddrHeader to set in the Msg (e.g., "From", "To", "Cc", "Bcc").
//   - values: One or more string values representing the email addresses to associate with
//     the specified header.
//
// References:
//   - https://datatracker.ietf.org/doc/html/rfc5322#section-3.4
func (m *Msg) SetAddrHeader(header AddrHeader, values ...string) error {
	if m.addrHeader == nil {
		m.addrHeader = make(map[AddrHeader][]*mail.Address)
	}
	var addresses []*mail.Address
	for _, addrVal := range values {
		address, err := mail.ParseAddress(addrVal)
		if err != nil {
			return fmt.Errorf(errParseMailAddr, addrVal, err)
		}
		addresses = append(addresses, address)
	}
	switch header {
	case HeaderFrom:
		if len(addresses) > 0 {
			m.addrHeader[header] = []*mail.Address{addresses[0]}
		}
	default:
		m.addrHeader[header] = addresses
	}
	return nil
}

// SetAddrHeaderIgnoreInvalid sets the specified AddrHeader for the Msg to the given values.
//
// Addresses are parsed according to RFC 5322. If parsing of any of the provided values fails,
// the error is ignored and the address is omitted from the address list.
//
// This method allows for setting address headers while ignoring invalid addresses. It is useful
// in scenarios where you want to ensure that only valid addresses are included without halting
// execution due to parsing errors.
//
// Parameters:
//   - header: The AddrHeader field to set in the Msg.
//   - values: One or more string values representing email addresses.
//
// References:
//   - https://datatracker.ietf.org/doc/html/rfc5322#section-3.4
func (m *Msg) SetAddrHeaderIgnoreInvalid(header AddrHeader, values ...string) {
	var addresses []*mail.Address
	for _, addrVal := range values {
		address, err := mail.ParseAddress(m.encodeString(addrVal))
		if err != nil {
			continue
		}
		addresses = append(addresses, address)
	}
	m.addrHeader[header] = addresses
}

// EnvelopeFrom sets the envelope from address for the Msg.
//
// The HeaderEnvelopeFrom address is generally not included in the mail body but only used by the
// Client for communication with the SMTP server. If the Msg has no "FROM" address set in the
// mail body, the msgWriter will try to use the envelope from address if it has been set for the Msg.
// The provided address is validated according to RFC 5322 and will return an error if the validation fails.
//
// Parameters:
//   - from: The envelope from address to set in the Msg.
//
// References:
//   - https://datatracker.ietf.org/doc/html/rfc5322#section-3.4
func (m *Msg) EnvelopeFrom(from string) error {
	return m.SetAddrHeader(HeaderEnvelopeFrom, from)
}

// EnvelopeFromFormat sets the provided name and mail address as HeaderEnvelopeFrom for the Msg.
//
// The HeaderEnvelopeFrom address is generally not included in the mail body but only used by the
// Client for communication with the SMTP server. If the Msg has no "FROM" address set in the mail
// body, the msgWriter will try to use the envelope from address if it has been set for the Msg.
// The provided name and address are validated according to RFC 5322 and will return an error if
// the validation fails.
//
// Parameters:
//   - name: The name to associate with the envelope from address.
//   - addr: The mail address to set as the envelope from address.
//
// References:
//   - https://datatracker.ietf.org/doc/html/rfc5322#section-3.4
func (m *Msg) EnvelopeFromFormat(name, addr string) error {
	return m.SetAddrHeader(HeaderEnvelopeFrom, fmt.Sprintf(`"%s" <%s>`, name, addr))
}

// From sets the "FROM" address in the mail body for the Msg.
//
// The "FROM" address is included in the mail body and indicates the sender of the message to
// the recipient. This address is visible in the email client and is typically displayed to the
// recipient. If the "FROM" address is not set, the msgWriter may attempt to use the envelope
// from address (if available) for sending. The provided address is validated according to RFC
// 5322 and will return an error if the validation fails.
//
// Parameters:
//   - from: The "FROM" address to set in the mail body.
//
// References:
//   - https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.2
func (m *Msg) From(from string) error {
	return m.SetAddrHeader(HeaderFrom, from)
}

// FromFormat sets the provided name and mail address as the "FROM" address in the mail body for the Msg.
//
// The "FROM" address is included in the mail body and indicates the sender of the message to the recipient,
// and is visible in the email client. If the "FROM" address is not explicitly set, the msgWriter may use
// the envelope from address (if provided) when sending the message. The provided name and address are
// validated according to RFC 5322 and will return an error if the validation fails.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.2
func (m *Msg) FromFormat(name, addr string) error {
	return m.SetAddrHeader(HeaderFrom, fmt.Sprintf(`"%s" <%s>`, name, addr))
}

// To sets one or more "TO" addresses in the mail body for the Msg.
//
// The "TO" address specifies the primary recipient(s) of the message and is included in the mail body.
// This address is visible to the recipient and any other recipients of the message. Multiple "TO" addresses
// can be set by passing them as variadic arguments to this method. Each provided address is validated
// according to RFC 5322, and an error will be returned if ANY validation fails.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.3
func (m *Msg) To(rcpts ...string) error {
	return m.SetAddrHeader(HeaderTo, rcpts...)
}

// AddTo adds a single "TO" address to the existing list of recipients in the mail body for the Msg.
//
// This method allows you to add a single recipient to the "TO" field without replacing any previously set
// "TO" addresses. The "TO" address specifies the primary recipient(s) of the message and is visible in the mail
// client. The provided address is validated according to RFC 5322, and an error will be returned if the
// validation fails.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.3
func (m *Msg) AddTo(rcpt string) error {
	return m.addAddr(HeaderTo, rcpt)
}

// AddToFormat adds a single "TO" address with the provided name and email to the existing list of recipients
// in the mail body for the Msg.
//
// This method allows you to add a recipient's name and email address to the "TO" field without replacing any
// previously set "TO" addresses. The "TO" address specifies the primary recipient(s) of the message and is
// visible in the mail client. The provided name and address are validated according to RFC 5322, and an error
// will be returned if the validation fails.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.3
func (m *Msg) AddToFormat(name, addr string) error {
	return m.addAddr(HeaderTo, fmt.Sprintf(`"%s" <%s>`, name, addr))
}

// ToIgnoreInvalid sets one or more "TO" addresses in the mail body for the Msg, ignoring any invalid addresses.
//
// This method allows you to add multiple "TO" recipients to the message body. Unlike the standard `To` method,
// any invalid addresses are ignored, and no error is returned for those addresses. Valid addresses will still be
// included in the "TO" field, which is visible in the recipient's mail client. Use this method with caution if
// address validation is critical. Invalid addresses are determined according to RFC 5322.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.3
func (m *Msg) ToIgnoreInvalid(rcpts ...string) {
	m.SetAddrHeaderIgnoreInvalid(HeaderTo, rcpts...)
}

// ToFromString takes a string of comma-separated email addresses, validates each, and sets them as the
// "TO" addresses for the Msg.
//
// This method allows you to pass a single string containing multiple email addresses separated by commas.
// Each address is validated according to RFC 5322 and set as a recipient in the "TO" field. If any validation
// fails, an error will be returned. The addresses are visible in the mail body and displayed to recipients in
// the mail client. Any "TO" address applied previously will be overwritten.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.3
func (m *Msg) ToFromString(rcpts string) error {
	return m.To(strings.Split(rcpts, ",")...)
}

// Cc sets one or more "CC" (carbon copy) addresses in the mail body for the Msg.
//
// The "CC" address specifies secondary recipient(s) of the message, and is included in the mail body.
// These addresses are visible to all recipients, including those listed in the "TO" and other "CC" fields.
// Multiple "CC" addresses can be set by passing them as variadic arguments to this method. Each provided
// address is validated according to RFC 5322, and an error will be returned if ANY validation fails.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.3
func (m *Msg) Cc(rcpts ...string) error {
	return m.SetAddrHeader(HeaderCc, rcpts...)
}

// AddCc adds a single "CC" (carbon copy) address to the existing list of "CC" recipients in the mail body
// for the Msg.
//
// This method allows you to add a single recipient to the "CC" field without replacing any previously set "CC"
// addresses. The "CC" address specifies secondary recipient(s) and is visible to all recipients, including those
// in the "TO" field. The provided address is validated according to RFC 5322, and an error will be returned if
// the validation fails.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.3
func (m *Msg) AddCc(rcpt string) error {
	return m.addAddr(HeaderCc, rcpt)
}

// AddCcFormat adds a single "CC" (carbon copy) address with the provided name and email to the existing list
// of "CC" recipients in the mail body for the Msg.
//
// This method allows you to add a recipient's name and email address to the "CC" field without replacing any
// previously set "CC" addresses. The "CC" address specifies secondary recipient(s) and is visible to all
// recipients, including those in the "TO" field. The provided name and address are validated according to
// RFC 5322, and an error will be returned if the validation fails.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.3
func (m *Msg) AddCcFormat(name, addr string) error {
	return m.addAddr(HeaderCc, fmt.Sprintf(`"%s" <%s>`, name, addr))
}

// CcIgnoreInvalid sets one or more "CC" (carbon copy) addresses in the mail body for the Msg, ignoring any
// invalid addresses.
//
// This method allows you to add multiple "CC" recipients to the message body. Unlike the standard `Cc` method,
// any invalid addresses are ignored, and no error is returned for those addresses. Valid addresses will still
// be included in the "CC" field, which is visible to all recipients in the mail client. Use this method with
// caution if address validation is critical, as invalid addresses are determined according to RFC 5322.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.3
func (m *Msg) CcIgnoreInvalid(rcpts ...string) {
	m.SetAddrHeaderIgnoreInvalid(HeaderCc, rcpts...)
}

// CcFromString takes a string of comma-separated email addresses, validates each, and sets them as the "CC"
// addresses for the Msg.
//
// This method allows you to pass a single string containing multiple email addresses separated by commas.
// Each address is validated according to RFC 5322 and set as a recipient in the "CC" field. If any validation
// fails, an error will be returned. The addresses are visible in the mail body and displayed to recipients
// in the mail client.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.3
func (m *Msg) CcFromString(rcpts string) error {
	return m.Cc(strings.Split(rcpts, ",")...)
}

// Bcc sets one or more "BCC" (blind carbon copy) addresses in the mail body for the Msg.
//
// The "BCC" address specifies recipient(s) of the message who will receive a copy without other recipients
// being aware of it. These addresses are not visible in the mail body or to any other recipients, ensuring
// the privacy of BCC'd recipients. Multiple "BCC" addresses can be set by passing them as variadic arguments
// to this method. Each provided address is validated according to RFC 5322, and an error will be returned
// if ANY validation fails.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.3
func (m *Msg) Bcc(rcpts ...string) error {
	return m.SetAddrHeader(HeaderBcc, rcpts...)
}

// AddBcc adds a single "BCC" (blind carbon copy) address to the existing list of "BCC" recipients in the mail
// body for the Msg.
//
// This method allows you to add a single recipient to the "BCC" field without replacing any previously set
// "BCC" addresses. The "BCC" address specifies recipient(s) of the message who will receive a copy without other
// recipients being aware of it. The provided address is validated according to RFC 5322, and an error will be
// returned if the validation fails.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.3
func (m *Msg) AddBcc(rcpt string) error {
	return m.addAddr(HeaderBcc, rcpt)
}

// AddBccFormat adds a single "BCC" (blind carbon copy) address with the provided name and email to the existing
// list of "BCC" recipients in the mail body for the Msg.
//
// This method allows you to add a recipient's name and email address to the "BCC" field without replacing
// any previously set "BCC" addresses. The "BCC" address specifies recipient(s) of the message who will receive
// a copy without other recipients being aware of it. The provided name and address are validated according to
// RFC 5322, and an error will be returned if the validation fails.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.3
func (m *Msg) AddBccFormat(name, addr string) error {
	return m.addAddr(HeaderBcc, fmt.Sprintf(`"%s" <%s>`, name, addr))
}

// BccIgnoreInvalid sets one or more "BCC" (blind carbon copy) addresses in the mail body for the Msg,
// ignoring any invalid addresses.
//
// This method allows you to add multiple "BCC" recipients to the message body. Unlike the standard `Bcc`
// method, any invalid addresses are ignored, and no error is returned for those addresses. Valid addresses
// will still be included in the "BCC" field, which ensures the privacy of the BCC'd recipients. Use this method
// with caution if address validation is critical, as invalid addresses are determined according to RFC 5322.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.3
func (m *Msg) BccIgnoreInvalid(rcpts ...string) {
	m.SetAddrHeaderIgnoreInvalid(HeaderBcc, rcpts...)
}

// BccFromString takes a string of comma-separated email addresses, validates each, and sets them as the "BCC"
// addresses for the Msg.
//
// This method allows you to pass a single string containing multiple email addresses separated by commas.
// Each address is validated according to RFC 5322 and set as a recipient in the "BCC" field. If any validation
// fails, an error will be returned. The addresses are not visible in the mail body and ensure the privacy of
// BCC'd recipients.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.3
func (m *Msg) BccFromString(rcpts string) error {
	return m.Bcc(strings.Split(rcpts, ",")...)
}

// ReplyTo sets the "Reply-To" address for the Msg, specifying where replies should be sent.
//
// This method takes a single email address as input and attempts to parse it. If the address is valid, it sets
// the "Reply-To" header in the message. The "Reply-To" address can be different from the "From" address,
// allowing the sender to specify an alternate address for responses. If the provided address cannot be parsed,
// an error will be returned, indicating the parsing failure.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.2
func (m *Msg) ReplyTo(addr string) error {
	replyTo, err := mail.ParseAddress(addr)
	if err != nil {
		return fmt.Errorf("failed to parse reply-to address: %w", err)
	}
	m.SetGenHeader(HeaderReplyTo, replyTo.String())
	return nil
}

// ReplyToFormat sets the "Reply-To" address for the Msg using the provided name and email address, specifying
// where replies should be sent.
//
// This method formats the name and email address into a single "Reply-To" header. If the formatted address is valid,
// it sets the "Reply-To" header in the message. This allows the sender to specify a display name along with the
// reply address, providing clarity for recipients. If the constructed address cannot be parsed, an error will
// be returned, indicating the parsing failure.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.2
func (m *Msg) ReplyToFormat(name, addr string) error {
	return m.ReplyTo(fmt.Sprintf(`"%s" <%s>`, name, addr))
}

// Subject sets the "Subject" header for the Msg, specifying the topic of the message.
//
// This method takes a single string as input and sets it as the "Subject" of the email. The subject line provides
// a brief summary of the content of the message, allowing recipients to quickly understand its purpose.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.5
func (m *Msg) Subject(subj string) {
	m.SetGenHeader(HeaderSubject, subj)
}

// SetMessageID generates and sets a unique "Message-ID" header for the Msg.
//
// This method creates a "Message-ID" string using the current process ID, random numbers, and the hostname
// of the machine. The generated ID helps uniquely identify the message in email systems, facilitating tracking
// and preventing duplication. If the hostname cannot be retrieved, it defaults to "localhost.localdomain".
//
// The generated Message-ID follows the format
// "<processID.randomNumberPrimary.randomNumberSecondary.randomString@hostname>".
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4
func (m *Msg) SetMessageID() {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "localhost.localdomain"
	}
	randNumPrimary := randNum(100000000)
	randNumSecondary := randNum(10000)
	randString, _ := randomStringSecure(17)
	procID := os.Getpid() * randNumSecondary
	messageID := fmt.Sprintf("%d.%d%d.%s@%s", procID, randNumPrimary, randNumSecondary,
		randString, hostname)
	m.SetMessageIDWithValue(messageID)
}

// GetMessageID retrieves the "Message-ID" header from the Msg.
//
// This method checks if a "Message-ID" has been set in the message's generated headers. If a valid "Message-ID"
// exists in the Msg, it returns the first occurrence of the header. If the "Message-ID" has not been set or
// is empty, it returns an empty string. This allows other components to access the unique identifier for the
// message, which is useful for tracking and referencing in email systems.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4
func (m *Msg) GetMessageID() string {
	if msgidheader, ok := m.genHeader[HeaderMessageID]; ok {
		if len(msgidheader) > 0 {
			return msgidheader[0]
		}
	}
	return ""
}

// SetMessageIDWithValue sets the "Message-ID" header for the Msg using the provided messageID string.
//
// This method formats the input messageID by enclosing it in angle brackets ("<>") and sets it as the "Message-ID"
// header in the message. The "Message-ID" is a unique identifier for the email, helping email clients and servers
// to track and reference the message. There are no validations performed on the input messageID, so it should
// be in a suitable format for use as a Message-ID.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.4
func (m *Msg) SetMessageIDWithValue(messageID string) {
	m.SetGenHeader(HeaderMessageID, fmt.Sprintf("<%s>", messageID))
}

// SetBulk sets the "Precedence: bulk" and "X-Auto-Response-Suppress: All" headers for the Msg,
// which are recommended for automated emails such as out-of-office replies.
//
// The "Precedence: bulk" header indicates that the message is a bulk email, and the "X-Auto-Response-Suppress: All"
// header instructs mail servers and clients to suppress automatic responses to this message.
// This is particularly useful for reducing unnecessary replies to automated notifications or replies.
// For further details, refer to RFC 2076, Section 3.9, and Microsoft's documentation on
// handling automated emails.
//
// https://www.rfc-editor.org/rfc/rfc2076#section-3.9
//
// https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxcmail/ced68690-498a-4567-9d14-5c01f974d8b1#Appendix_A_Target_51
func (m *Msg) SetBulk() {
	m.SetGenHeader(HeaderPrecedence, "bulk")
	m.SetGenHeader(HeaderXAutoResponseSuppress, "All")
}

// SetDate sets the "Date" header for the Msg to the current time in a valid RFC 1123 format.
//
// This method retrieves the current time and formats it according to RFC 1123, ensuring that the "Date"
// header is compliant with email standards. The "Date" header indicates when the message was created,
// providing recipients with context for the timing of the email.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.3
func (m *Msg) SetDate() {
	now := time.Now().Format(time.RFC1123Z)
	m.SetGenHeader(HeaderDate, now)
}

// SetDateWithValue sets the "Date" header for the Msg using the provided time value in a valid RFC 1123 format.
//
// This method takes a `time.Time` value as input and formats it according to RFC 1123, ensuring that the "Date"
// header is compliant with email standards. The "Date" header indicates when the message was created,
// providing recipients with context for the timing of the email. This allows for setting a custom date
// rather than using the current time.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.3
func (m *Msg) SetDateWithValue(timeVal time.Time) {
	m.SetGenHeader(HeaderDate, timeVal.Format(time.RFC1123Z))
}

// SetImportance sets the "Importance" and "Priority" headers for the Msg to the specified Importance level.
//
// This method adjusts the email's importance based on the provided Importance value. If the importance level
// is set to `ImportanceNormal`, no headers are modified. Otherwise, it sets the "Importance", "Priority",
// "X-Priority", and "X-MSMail-Priority" headers accordingly, providing email clients with information on
// how to prioritize the message. This allows the sender to indicate the significance of the email to recipients.
//
// https://datatracker.ietf.org/doc/html/rfc2156
func (m *Msg) SetImportance(importance Importance) {
	if importance == ImportanceNormal {
		return
	}
	m.SetGenHeader(HeaderImportance, importance.String())
	m.SetGenHeader(HeaderPriority, importance.NumString())
	m.SetGenHeader(HeaderXPriority, importance.XPrioString())
	m.SetGenHeader(HeaderXMSMailPriority, importance.NumString())
}

// SetOrganization sets the "Organization" header for the Msg to the specified organization string.
//
// This method allows you to specify the organization associated with the email sender. The "Organization"
// header provides recipients with information about the organization that is sending the message.
// This can help establish context and credibility for the email communication.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.4
func (m *Msg) SetOrganization(org string) {
	m.SetGenHeader(HeaderOrganization, org)
}

// SetUserAgent sets the "User-Agent" and "X-Mailer" headers for the Msg to the specified user agent string.
//
// This method allows you to specify the user agent or mailer software used to send the email.
// The "User-Agent" and "X-Mailer" headers provide recipients with information about the email client
// or application that generated the message. This can be useful for identifying the source of the email,
// particularly for troubleshooting or filtering purposes.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.7
func (m *Msg) SetUserAgent(userAgent string) {
	m.SetGenHeader(HeaderUserAgent, userAgent)
	m.SetGenHeader(HeaderXMailer, userAgent)
}

// IsDelivered indicates whether the Msg has been delivered.
//
// This method checks the internal state of the message to determine if it has been successfully
// delivered. It returns true if the message is marked as delivered and false otherwise.
// This can be useful for tracking the status of the email communication.
func (m *Msg) IsDelivered() bool {
	return m.isDelivered
}

// RequestMDNTo adds the "Disposition-Notification-To" header to the Msg to request a Message Disposition
// Notification (MDN) from the receiving end, as specified in RFC 8098.
//
// This method allows you to provide a list of recipient addresses to receive the MDN.
// Each address is validated according to RFC 5322 standards. If ANY address is invalid, an error
// will be returned indicating the parsing failure. If the "Disposition-Notification-To" header
// is already set, it will be updated with the new list of addresses.
//
// https://datatracker.ietf.org/doc/html/rfc8098
func (m *Msg) RequestMDNTo(rcpts ...string) error {
	var addresses []string
	for _, addrVal := range rcpts {
		address, err := mail.ParseAddress(addrVal)
		if err != nil {
			return fmt.Errorf(errParseMailAddr, addrVal, err)
		}
		addresses = append(addresses, address.String())
	}
	if _, ok := m.genHeader[HeaderDispositionNotificationTo]; ok {
		m.genHeader[HeaderDispositionNotificationTo] = addresses
	}
	return nil
}

// RequestMDNToFormat adds the "Disposition-Notification-To" header to the Msg to request a Message Disposition
// Notification (MDN) from the receiving end, as specified in RFC 8098.
//
// This method allows you to provide a recipient address along with a name, formatting it appropriately.
// Address validation is performed according to RFC 5322 standards. If the provided address is invalid,
// an error will be returned. This method internally calls RequestMDNTo to handle the actual setting of the header.
//
// https://datatracker.ietf.org/doc/html/rfc8098
func (m *Msg) RequestMDNToFormat(name, addr string) error {
	return m.RequestMDNTo(fmt.Sprintf(`%s <%s>`, name, addr))
}

// RequestMDNAddTo adds an additional recipient to the "Disposition-Notification-To" header for the Msg.
//
// This method allows you to append a new recipient address to the existing list of recipients for the
// MDN. The provided address is validated according to RFC 5322 standards. If the address is invalid,
// an error will be returned indicating the parsing failure. If the "Disposition-Notification-To"
// header is already set, the new recipient will be added to the existing list.
//
// https://datatracker.ietf.org/doc/html/rfc8098
func (m *Msg) RequestMDNAddTo(rcpt string) error {
	address, err := mail.ParseAddress(rcpt)
	if err != nil {
		return fmt.Errorf(errParseMailAddr, rcpt, err)
	}
	var addresses []string
	addresses = append(addresses, m.genHeader[HeaderDispositionNotificationTo]...)
	addresses = append(addresses, address.String())
	if _, ok := m.genHeader[HeaderDispositionNotificationTo]; ok {
		m.genHeader[HeaderDispositionNotificationTo] = addresses
	}
	return nil
}

// RequestMDNAddToFormat adds an additional formatted recipient to the "Disposition-Notification-To"
// header for the Msg.
//
// This method allows you to specify a recipient address along with a name, formatting it appropriately
// before adding it to the existing list of recipients for the MDN. The formatted address is validated
// according to RFC 5322 standards. If the provided address is invalid, an error will be returned.
// This method internally calls RequestMDNAddTo to handle the actual addition of the recipient.
//
// https://datatracker.ietf.org/doc/html/rfc8098
func (m *Msg) RequestMDNAddToFormat(name, addr string) error {
	return m.RequestMDNAddTo(fmt.Sprintf(`"%s" <%s>`, name, addr))
}

// GetSender returns the currently set envelope "FROM" address for the Msg. If no envelope
// "FROM" address is set, it will use the first "FROM" address from the mail body. If the
// useFullAddr parameter is true, it will return the full address string, including the name
// if it is set.
//
// If neither the envelope "FROM" nor the body "FROM" addresses are available, it will return
// an error indicating that no "FROM" address is present.
//
// Parameters:
//   - useFullAddr: A boolean indicating whether to return the full address string (including
//     the name) or just the email address.
//
// Returns:
//   - The sender's address as a string and an error if applicable.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.2
func (m *Msg) GetSender(useFullAddr bool) (string, error) {
	from, ok := m.addrHeader[HeaderEnvelopeFrom]
	if !ok || len(from) == 0 {
		from, ok = m.addrHeader[HeaderFrom]
		if !ok || len(from) == 0 {
			return "", ErrNoFromAddress
		}
	}
	if useFullAddr {
		return from[0].String(), nil
	}
	return from[0].Address, nil
}

// GetRecipients returns a list of the currently set "TO", "CC", and "BCC" addresses for the Msg.
//
// This method aggregates recipients from the "TO", "CC", and "BCC" headers and returns them as a
// slice of strings. If no recipients are found in these headers, it will return an error indicating
// that no recipient addresses are present.
//
// Returns:
//   - A slice of strings containing the recipients' addresses and an error if applicable.
//   - If there are no recipient addresses set, it will return an error indicating no recipient
//     addresses are available.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6.3
func (m *Msg) GetRecipients() ([]string, error) {
	var rcpts []string
	for _, addressType := range []AddrHeader{HeaderTo, HeaderCc, HeaderBcc} {
		addresses, ok := m.addrHeader[addressType]
		if !ok || len(addresses) == 0 {
			continue
		}
		for _, r := range addresses {
			rcpts = append(rcpts, r.Address)
		}
	}
	if len(rcpts) <= 0 {
		return rcpts, ErrNoRcptAddresses
	}
	return rcpts, nil
}

// GetAddrHeader returns the content of the requested address header for the Msg.
//
// This method retrieves the addresses associated with the specified address header. It returns a
// slice of pointers to mail.Address structures representing the addresses found in the header.
// If the requested header does not exist or contains no addresses, it will return nil.
//
// Parameters:
//   - header: The AddrHeader enum value indicating which address header to retrieve (e.g., "TO",
//     "CC", "BCC", etc.).
//
// Returns:
//   - A slice of pointers to mail.Address structures containing the addresses from the specified
//     header.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6
func (m *Msg) GetAddrHeader(header AddrHeader) []*mail.Address {
	return m.addrHeader[header]
}

// GetAddrHeaderString returns the address strings of the requested address header for the Msg.
//
// This method retrieves the addresses associated with the specified address header and returns them
// as a slice of strings. Each address is formatted as a string, which includes both the name (if
// available) and the email address. If the requested header does not exist or contains no addresses,
// it will return an empty slice.
//
// Parameters:
//   - header: The AddrHeader enum value indicating which address header to retrieve (e.g., "TO",
//     "CC", "BCC", etc.).
//
// Returns:
//   - A slice of strings containing the formatted addresses from the specified header.
//
// https://datatracker.ietf.org/doc/html/rfc5322#section-3.6
func (m *Msg) GetAddrHeaderString(header AddrHeader) []string {
	var addresses []string
	for _, mh := range m.addrHeader[header] {
		addresses = append(addresses, mh.String())
	}
	return addresses
}

// GetFrom returns the content of the From address header of the Msg
func (m *Msg) GetFrom() []*mail.Address {
	return m.GetAddrHeader(HeaderFrom)
}

// GetFromString returns the content of the From address header of the Msg as string slice
func (m *Msg) GetFromString() []string {
	return m.GetAddrHeaderString(HeaderFrom)
}

// GetTo returns the content of the To address header of the Msg
func (m *Msg) GetTo() []*mail.Address {
	return m.GetAddrHeader(HeaderTo)
}

// GetToString returns the content of the To address header of the Msg as string slice
func (m *Msg) GetToString() []string {
	return m.GetAddrHeaderString(HeaderTo)
}

// GetCc returns the content of the Cc address header of the Msg
func (m *Msg) GetCc() []*mail.Address {
	return m.GetAddrHeader(HeaderCc)
}

// GetCcString returns the content of the Cc address header of the Msg as string slice
func (m *Msg) GetCcString() []string {
	return m.GetAddrHeaderString(HeaderCc)
}

// GetBcc returns the content of the Bcc address header of the Msg
func (m *Msg) GetBcc() []*mail.Address {
	return m.GetAddrHeader(HeaderBcc)
}

// GetBccString returns the content of the Bcc address header of the Msg as string slice
func (m *Msg) GetBccString() []string {
	return m.GetAddrHeaderString(HeaderBcc)
}

// GetGenHeader returns the content of the requested generic header of the Msg
func (m *Msg) GetGenHeader(header Header) []string {
	return m.genHeader[header]
}

// GetParts returns the message parts of the Msg
func (m *Msg) GetParts() []*Part {
	return m.parts
}

// GetAttachments returns the attachments of the Msg
func (m *Msg) GetAttachments() []*File {
	return m.attachments
}

// GetBoundary returns the boundary of the Msg
func (m *Msg) GetBoundary() string {
	return m.boundary
}

// SetAttachments sets the attachments of the message.
func (m *Msg) SetAttachments(files []*File) {
	m.attachments = files
}

// SetAttachements sets the attachments of the message.
//
// Deprecated: use SetAttachments instead.
func (m *Msg) SetAttachements(files []*File) {
	m.SetAttachments(files)
}

// UnsetAllAttachments unset the attachments of the message.
func (m *Msg) UnsetAllAttachments() {
	m.attachments = nil
}

// GetEmbeds returns the embeds of the Msg
func (m *Msg) GetEmbeds() []*File {
	return m.embeds
}

// SetEmbeds sets the embeds of the message.
func (m *Msg) SetEmbeds(files []*File) {
	m.embeds = files
}

// UnsetAllEmbeds unset the embeds of the message.
func (m *Msg) UnsetAllEmbeds() {
	m.embeds = nil
}

// UnsetAllParts unset the embeds and attachments of the message.
func (m *Msg) UnsetAllParts() {
	m.UnsetAllAttachments()
	m.UnsetAllEmbeds()
}

// SetBodyString sets the body of the message.
func (m *Msg) SetBodyString(contentType ContentType, content string, opts ...PartOption) {
	buffer := bytes.NewBufferString(content)
	writeFunc := writeFuncFromBuffer(buffer)
	m.SetBodyWriter(contentType, writeFunc, opts...)
}

// SetBodyWriter sets the body of the message.
func (m *Msg) SetBodyWriter(
	contentType ContentType, writeFunc func(io.Writer) (int64, error),
	opts ...PartOption,
) {
	p := m.newPart(contentType, opts...)
	p.writeFunc = writeFunc
	m.parts = []*Part{p}
}

// SetBodyHTMLTemplate sets the body of the message from a given html/template.Template pointer
// The content type will be set to text/html automatically
func (m *Msg) SetBodyHTMLTemplate(tpl *ht.Template, data interface{}, opts ...PartOption) error {
	if tpl == nil {
		return errors.New(errTplPointerNil)
	}
	buffer := bytes.Buffer{}
	if err := tpl.Execute(&buffer, data); err != nil {
		return fmt.Errorf(errTplExecuteFailed, err)
	}
	writeFunc := writeFuncFromBuffer(&buffer)
	m.SetBodyWriter(TypeTextHTML, writeFunc, opts...)
	return nil
}

// SetBodyTextTemplate sets the body of the message from a given text/template.Template pointer
// The content type will be set to text/plain automatically
func (m *Msg) SetBodyTextTemplate(tpl *tt.Template, data interface{}, opts ...PartOption) error {
	if tpl == nil {
		return errors.New(errTplPointerNil)
	}
	buf := bytes.Buffer{}
	if err := tpl.Execute(&buf, data); err != nil {
		return fmt.Errorf(errTplExecuteFailed, err)
	}
	writeFunc := writeFuncFromBuffer(&buf)
	m.SetBodyWriter(TypeTextPlain, writeFunc, opts...)
	return nil
}

// AddAlternativeString sets the alternative body of the message.
func (m *Msg) AddAlternativeString(contentType ContentType, content string, opts ...PartOption) {
	buffer := bytes.NewBufferString(content)
	writeFunc := writeFuncFromBuffer(buffer)
	m.AddAlternativeWriter(contentType, writeFunc, opts...)
}

// AddAlternativeWriter sets the body of the message.
func (m *Msg) AddAlternativeWriter(
	contentType ContentType, writeFunc func(io.Writer) (int64, error),
	opts ...PartOption,
) {
	part := m.newPart(contentType, opts...)
	part.writeFunc = writeFunc
	m.parts = append(m.parts, part)
}

// AddAlternativeHTMLTemplate sets the alternative body of the message to a html/template.Template output
// The content type will be set to text/html automatically
func (m *Msg) AddAlternativeHTMLTemplate(tpl *ht.Template, data interface{}, opts ...PartOption) error {
	if tpl == nil {
		return errors.New(errTplPointerNil)
	}
	buffer := bytes.Buffer{}
	if err := tpl.Execute(&buffer, data); err != nil {
		return fmt.Errorf(errTplExecuteFailed, err)
	}
	writeFunc := writeFuncFromBuffer(&buffer)
	m.AddAlternativeWriter(TypeTextHTML, writeFunc, opts...)
	return nil
}

// AddAlternativeTextTemplate sets the alternative body of the message to a text/template.Template output
// The content type will be set to text/plain automatically
func (m *Msg) AddAlternativeTextTemplate(tpl *tt.Template, data interface{}, opts ...PartOption) error {
	if tpl == nil {
		return errors.New(errTplPointerNil)
	}
	buffer := bytes.Buffer{}
	if err := tpl.Execute(&buffer, data); err != nil {
		return fmt.Errorf(errTplExecuteFailed, err)
	}
	writeFunc := writeFuncFromBuffer(&buffer)
	m.AddAlternativeWriter(TypeTextPlain, writeFunc, opts...)
	return nil
}

// AttachFile adds an attachment File to the Msg
func (m *Msg) AttachFile(name string, opts ...FileOption) {
	file := fileFromFS(name)
	if file == nil {
		return
	}
	m.attachments = m.appendFile(m.attachments, file, opts...)
}

// AttachReader adds an attachment File via io.Reader to the Msg
//
// CAVEAT: For AttachReader to work it has to read all data of the io.Reader
// into memory first, so it can seek through it. Using larger amounts of
// data on the io.Reader should be avoided. For such, it is recommended to
// either use AttachFile or AttachReadSeeker instead
func (m *Msg) AttachReader(name string, reader io.Reader, opts ...FileOption) error {
	file, err := fileFromReader(name, reader)
	if err != nil {
		return err
	}
	m.attachments = m.appendFile(m.attachments, file, opts...)
	return nil
}

// AttachReadSeeker adds an attachment File via io.ReadSeeker to the Msg
func (m *Msg) AttachReadSeeker(name string, reader io.ReadSeeker, opts ...FileOption) {
	file := fileFromReadSeeker(name, reader)
	m.attachments = m.appendFile(m.attachments, file, opts...)
}

// AttachHTMLTemplate adds the output of a html/template.Template pointer as File attachment to the Msg
func (m *Msg) AttachHTMLTemplate(
	name string, tpl *ht.Template, data interface{}, opts ...FileOption,
) error {
	file, err := fileFromHTMLTemplate(name, tpl, data)
	if err != nil {
		return fmt.Errorf("failed to attach template: %w", err)
	}
	m.attachments = m.appendFile(m.attachments, file, opts...)
	return nil
}

// AttachTextTemplate adds the output of a text/template.Template pointer as File attachment to the Msg
func (m *Msg) AttachTextTemplate(
	name string, tpl *tt.Template, data interface{}, opts ...FileOption,
) error {
	file, err := fileFromTextTemplate(name, tpl, data)
	if err != nil {
		return fmt.Errorf("failed to attach template: %w", err)
	}
	m.attachments = m.appendFile(m.attachments, file, opts...)
	return nil
}

// AttachFromEmbedFS adds an attachment File from an embed.FS to the Msg
func (m *Msg) AttachFromEmbedFS(name string, fs *embed.FS, opts ...FileOption) error {
	if fs == nil {
		return fmt.Errorf("embed.FS must not be nil")
	}
	file, err := fileFromEmbedFS(name, fs)
	if err != nil {
		return err
	}
	m.attachments = m.appendFile(m.attachments, file, opts...)
	return nil
}

// EmbedFile adds an embedded File to the Msg
func (m *Msg) EmbedFile(name string, opts ...FileOption) {
	file := fileFromFS(name)
	if file == nil {
		return
	}
	m.embeds = m.appendFile(m.embeds, file, opts...)
}

// EmbedReader adds an embedded File from an io.Reader to the Msg
//
// CAVEAT: For EmbedReader to work it has to read all data of the io.Reader
// into memory first, so it can seek through it. Using larger amounts of
// data on the io.Reader should be avoided. For such, it is recommended to
// either use EmbedFile or EmbedReadSeeker instead
func (m *Msg) EmbedReader(name string, reader io.Reader, opts ...FileOption) error {
	file, err := fileFromReader(name, reader)
	if err != nil {
		return err
	}
	m.embeds = m.appendFile(m.embeds, file, opts...)
	return nil
}

// EmbedReadSeeker adds an embedded File from an io.ReadSeeker to the Msg
func (m *Msg) EmbedReadSeeker(name string, reader io.ReadSeeker, opts ...FileOption) {
	file := fileFromReadSeeker(name, reader)
	m.embeds = m.appendFile(m.embeds, file, opts...)
}

// EmbedHTMLTemplate adds the output of a html/template.Template pointer as embedded File to the Msg
func (m *Msg) EmbedHTMLTemplate(
	name string, tpl *ht.Template, data interface{}, opts ...FileOption,
) error {
	file, err := fileFromHTMLTemplate(name, tpl, data)
	if err != nil {
		return fmt.Errorf("failed to embed template: %w", err)
	}
	m.embeds = m.appendFile(m.embeds, file, opts...)
	return nil
}

// EmbedTextTemplate adds the output of a text/template.Template pointer as embedded File to the Msg
func (m *Msg) EmbedTextTemplate(
	name string, tpl *tt.Template, data interface{}, opts ...FileOption,
) error {
	file, err := fileFromTextTemplate(name, tpl, data)
	if err != nil {
		return fmt.Errorf("failed to embed template: %w", err)
	}
	m.embeds = m.appendFile(m.embeds, file, opts...)
	return nil
}

// EmbedFromEmbedFS adds an embedded File from an embed.FS to the Msg
func (m *Msg) EmbedFromEmbedFS(name string, fs *embed.FS, opts ...FileOption) error {
	if fs == nil {
		return fmt.Errorf("embed.FS must not be nil")
	}
	file, err := fileFromEmbedFS(name, fs)
	if err != nil {
		return err
	}
	m.embeds = m.appendFile(m.embeds, file, opts...)
	return nil
}

// Reset resets all headers, body parts and attachments/embeds of the Msg
// It leaves already set encodings, charsets, boundaries, etc. as is
func (m *Msg) Reset() {
	m.addrHeader = make(map[AddrHeader][]*mail.Address)
	m.attachments = nil
	m.embeds = nil
	m.genHeader = make(map[Header][]string)
	m.parts = nil
}

// ApplyMiddlewares apply the list of middlewares to a Msg
func (m *Msg) applyMiddlewares(msg *Msg) *Msg {
	for _, middleware := range m.middlewares {
		msg = middleware.Handle(msg)
	}
	return msg
}

// WriteTo writes the formated Msg into a give io.Writer and satisfies the io.WriteTo interface
func (m *Msg) WriteTo(writer io.Writer) (int64, error) {
	mw := &msgWriter{writer: writer, charset: m.charset, encoder: m.encoder}
	mw.writeMsg(m.applyMiddlewares(m))
	return mw.bytesWritten, mw.err
}

// WriteToSkipMiddleware writes the formated Msg into a give io.Writer and satisfies
// the io.WriteTo interface but will skip the given Middleware
func (m *Msg) WriteToSkipMiddleware(writer io.Writer, middleWareType MiddlewareType) (int64, error) {
	var origMiddlewares, middlewares []Middleware
	origMiddlewares = m.middlewares
	for i := range m.middlewares {
		if m.middlewares[i].Type() == middleWareType {
			continue
		}
		middlewares = append(middlewares, m.middlewares[i])
	}
	m.middlewares = middlewares
	mw := &msgWriter{writer: writer, charset: m.charset, encoder: m.encoder}
	mw.writeMsg(m.applyMiddlewares(m))
	m.middlewares = origMiddlewares
	return mw.bytesWritten, mw.err
}

// Write is an alias method to WriteTo due to compatibility reasons
func (m *Msg) Write(writer io.Writer) (int64, error) {
	return m.WriteTo(writer)
}

// appendFile adds a File to the Msg (as attachment or embed)
func (m *Msg) appendFile(files []*File, file *File, opts ...FileOption) []*File {
	// Override defaults with optionally provided FileOption functions
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(file)
	}

	if files == nil {
		return []*File{file}
	}

	return append(files, file)
}

// WriteToFile stores the Msg as file on disk. It will try to create the given filename
// Already existing files will be overwritten
func (m *Msg) WriteToFile(name string) error {
	file, err := os.Create(name)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer func() { _ = file.Close() }()
	_, err = m.WriteTo(file)
	if err != nil {
		return fmt.Errorf("failed to write to output file: %w", err)
	}
	return file.Close()
}

// WriteToSendmail returns WriteToSendmailWithCommand with a default sendmail path
func (m *Msg) WriteToSendmail() error {
	return m.WriteToSendmailWithCommand(SendmailPath)
}

// WriteToSendmailWithCommand returns WriteToSendmailWithContext with a default timeout
// of 5 seconds and a given sendmail path
func (m *Msg) WriteToSendmailWithCommand(sendmailPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	return m.WriteToSendmailWithContext(ctx, sendmailPath)
}

// WriteToSendmailWithContext opens an pipe to the local sendmail binary and tries to send the
// mail though that. It takes a context.Context, the path to the sendmail binary and additional
// arguments for the sendmail binary as parameters
func (m *Msg) WriteToSendmailWithContext(ctx context.Context, sendmailPath string, args ...string) error {
	cmdCtx := exec.CommandContext(ctx, sendmailPath)
	cmdCtx.Args = append(cmdCtx.Args, "-oi", "-t")
	cmdCtx.Args = append(cmdCtx.Args, args...)

	stdErr, err := cmdCtx.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to set STDERR pipe: %w", err)
	}

	stdIn, err := cmdCtx.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to set STDIN pipe: %w", err)
	}
	if stdErr == nil || stdIn == nil {
		return fmt.Errorf("received nil for STDERR or STDIN pipe")
	}

	// Start the execution and write to STDIN
	if err = cmdCtx.Start(); err != nil {
		return fmt.Errorf("could not start sendmail execution: %w", err)
	}
	_, err = m.WriteTo(stdIn)
	if err != nil {
		if !errors.Is(err, syscall.EPIPE) {
			return fmt.Errorf("failed to write mail to buffer: %w", err)
		}
	}

	// Close STDIN and wait for completion or cancellation of the sendmail executable
	if err = stdIn.Close(); err != nil {
		return fmt.Errorf("failed to close STDIN pipe: %w", err)
	}

	// Read the stderr pipe for possible errors
	sendmailErr, err := io.ReadAll(stdErr)
	if err != nil {
		return fmt.Errorf("failed to read STDERR pipe: %w", err)
	}
	if len(sendmailErr) > 0 {
		return fmt.Errorf("sendmail command failed: %s", string(sendmailErr))
	}

	if err = cmdCtx.Wait(); err != nil {
		return fmt.Errorf("sendmail command execution failed: %w", err)
	}

	return nil
}

// NewReader returns a Reader type that satisfies the io.Reader interface.
//
// IMPORTANT: when creating a new Reader, the current state of the Msg is taken, as
// basis for the Reader. If you perform changes on Msg after creating the Reader, these
// changes will not be reflected in the Reader. You will have to use Msg.UpdateReader
// first to update the Reader's buffer with the current Msg content
func (m *Msg) NewReader() *Reader {
	reader := &Reader{}
	buffer := bytes.Buffer{}
	_, err := m.Write(&buffer)
	if err != nil {
		reader.err = fmt.Errorf("failed to write Msg to Reader buffer: %w", err)
	}
	reader.buffer = buffer.Bytes()
	return reader
}

// UpdateReader will update a Reader with the content of the given Msg and reset the
// Reader position to the start
func (m *Msg) UpdateReader(reader *Reader) {
	buffer := bytes.Buffer{}
	_, err := m.Write(&buffer)
	reader.Reset()
	reader.buffer = buffer.Bytes()
	reader.err = err
}

// HasSendError returns true if the Msg experienced an error during the message delivery and the
// sendError field of the Msg is not nil
func (m *Msg) HasSendError() bool {
	return m.sendError != nil
}

// SendErrorIsTemp returns true if the Msg experienced an error during the message delivery and the
// corresponding error was of temporary nature and should be retried later
func (m *Msg) SendErrorIsTemp() bool {
	var err *SendError
	if errors.As(m.sendError, &err) && err != nil {
		return err.isTemp
	}
	return false
}

// SendError returns the sendError field of the Msg
func (m *Msg) SendError() error {
	return m.sendError
}

// addAddr adds an additional address to the given addrHeader of the Msg
func (m *Msg) addAddr(header AddrHeader, addr string) error {
	var addresses []string
	for _, address := range m.addrHeader[header] {
		addresses = append(addresses, address.String())
	}
	addresses = append(addresses, addr)
	return m.SetAddrHeader(header, addresses...)
}

// encodeString encodes a string based on the configured message encoder and the corresponding
// charset for the Msg
func (m *Msg) encodeString(str string) string {
	return m.encoder.Encode(string(m.charset), str)
}

// hasAlt returns true if the Msg has more than one part
func (m *Msg) hasAlt() bool {
	count := 0
	for _, part := range m.parts {
		if !part.isDeleted {
			count++
		}
	}
	return count > 1 && m.pgptype == 0
}

// hasMixed returns true if the Msg has mixed parts
func (m *Msg) hasMixed() bool {
	return m.pgptype == 0 && ((len(m.parts) > 0 && len(m.attachments) > 0) || len(m.attachments) > 1)
}

// hasRelated returns true if the Msg has related parts
func (m *Msg) hasRelated() bool {
	return m.pgptype == 0 && ((len(m.parts) > 0 && len(m.embeds) > 0) || len(m.embeds) > 1)
}

// hasPGPType returns true if the Msg should be treated as PGP encoded message
func (m *Msg) hasPGPType() bool {
	return m.pgptype > 0
}

// newPart returns a new Part for the Msg
func (m *Msg) newPart(contentType ContentType, opts ...PartOption) *Part {
	p := &Part{
		contentType: contentType,
		charset:     m.charset,
		encoding:    m.encoding,
	}

	// Override defaults with optionally provided MsgOption functions
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(p)
	}

	return p
}

// setEncoder creates a new mime.WordEncoder based on the encoding setting of the message
func (m *Msg) setEncoder() {
	m.encoder = getEncoder(m.encoding)
}

// checkUserAgent checks if a useragent/x-mailer is set and if not will set a default
// version string
func (m *Msg) checkUserAgent() {
	if m.noDefaultUserAgent {
		return
	}
	_, uaok := m.genHeader[HeaderUserAgent]
	_, xmok := m.genHeader[HeaderXMailer]
	if !uaok && !xmok {
		m.SetUserAgent(fmt.Sprintf("go-mail v%s // https://github.com/wneessen/go-mail",
			VERSION))
	}
}

// addDefaultHeader sets some default headers, if they haven't been set before
func (m *Msg) addDefaultHeader() {
	if _, ok := m.genHeader[HeaderDate]; !ok {
		m.SetDate()
	}
	if _, ok := m.genHeader[HeaderMessageID]; !ok {
		m.SetMessageID()
	}
	m.SetGenHeader(HeaderMIMEVersion, string(m.mimever))
}

// fileFromEmbedFS returns a File pointer from a given file in the provided embed.FS
func fileFromEmbedFS(name string, fs *embed.FS) (*File, error) {
	_, err := fs.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open file from embed.FS: %w", err)
	}
	return &File{
		Name:   filepath.Base(name),
		Header: make(map[string][]string),
		Writer: func(writer io.Writer) (int64, error) {
			file, err := fs.Open(name)
			if err != nil {
				return 0, err
			}
			numBytes, err := io.Copy(writer, file)
			if err != nil {
				_ = file.Close()
				return numBytes, fmt.Errorf("failed to copy file to io.Writer: %w", err)
			}
			return numBytes, file.Close()
		},
	}, nil
}

// fileFromFS returns a File pointer from a given file in the system's file system
func fileFromFS(name string) *File {
	_, err := os.Stat(name)
	if err != nil {
		return nil
	}

	return &File{
		Name:   filepath.Base(name),
		Header: make(map[string][]string),
		Writer: func(writer io.Writer) (int64, error) {
			file, err := os.Open(name)
			if err != nil {
				return 0, err
			}
			numBytes, err := io.Copy(writer, file)
			if err != nil {
				_ = file.Close()
				return numBytes, fmt.Errorf("failed to copy file to io.Writer: %w", err)
			}
			return numBytes, file.Close()
		},
	}
}

// fileFromReader returns a File pointer from a given io.Reader
func fileFromReader(name string, reader io.Reader) (*File, error) {
	d, err := io.ReadAll(reader)
	if err != nil {
		return &File{}, err
	}
	byteReader := bytes.NewReader(d)
	return &File{
		Name:   name,
		Header: make(map[string][]string),
		Writer: func(writer io.Writer) (int64, error) {
			readBytes, copyErr := io.Copy(writer, byteReader)
			if copyErr != nil {
				return readBytes, copyErr
			}
			_, copyErr = byteReader.Seek(0, io.SeekStart)
			return readBytes, copyErr
		},
	}, nil
}

// fileFromReadSeeker returns a File pointer from a given io.ReadSeeker
func fileFromReadSeeker(name string, reader io.ReadSeeker) *File {
	return &File{
		Name:   name,
		Header: make(map[string][]string),
		Writer: func(writer io.Writer) (int64, error) {
			readBytes, err := io.Copy(writer, reader)
			if err != nil {
				return readBytes, err
			}
			_, err = reader.Seek(0, io.SeekStart)
			return readBytes, err
		},
	}
}

// fileFromHTMLTemplate returns a File pointer form a given html/template.Template
func fileFromHTMLTemplate(name string, tpl *ht.Template, data interface{}) (*File, error) {
	if tpl == nil {
		return nil, errors.New(errTplPointerNil)
	}
	buffer := bytes.Buffer{}
	if err := tpl.Execute(&buffer, data); err != nil {
		return nil, fmt.Errorf(errTplExecuteFailed, err)
	}
	return fileFromReader(name, &buffer)
}

// fileFromTextTemplate returns a File pointer form a given text/template.Template
func fileFromTextTemplate(name string, tpl *tt.Template, data interface{}) (*File, error) {
	if tpl == nil {
		return nil, errors.New(errTplPointerNil)
	}
	buffer := bytes.Buffer{}
	if err := tpl.Execute(&buffer, data); err != nil {
		return nil, fmt.Errorf(errTplExecuteFailed, err)
	}
	return fileFromReader(name, &buffer)
}

// getEncoder creates a new mime.WordEncoder based on the encoding setting of the message
func getEncoder(enc Encoding) mime.WordEncoder {
	switch enc {
	case EncodingQP:
		return mime.QEncoding
	case EncodingB64:
		return mime.BEncoding
	default:
		return mime.QEncoding
	}
}

// writeFuncFromBuffer is a common method to convert a byte buffer into a writeFunc as
// often required by this library
func writeFuncFromBuffer(buffer *bytes.Buffer) func(io.Writer) (int64, error) {
	writeFunc := func(w io.Writer) (int64, error) {
		numBytes, err := w.Write(buffer.Bytes())
		return int64(numBytes), err
	}
	return writeFunc
}
