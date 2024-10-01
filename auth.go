// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import "errors"

// SMTPAuthType represents a string to any SMTP AUTH type
type SMTPAuthType string

// Supported SMTP AUTH types
const (
	// SMTPAuthCramMD5 is the "CRAM-MD5" SASL authentication mechanism as described in RFC 4954
	SMTPAuthCramMD5 SMTPAuthType = "CRAM-MD5"

	// SMTPAuthLogin is the "LOGIN" SASL authentication mechanism
	SMTPAuthLogin SMTPAuthType = "LOGIN"

	// SMTPAuthNoAuth is equivalent to performing no authentication at all. It is a convenience
	// option and should not be used. Instead, for mail servers that do no support/require
	// authentication, the Client should not be used with the WithSMTPAuth option
	SMTPAuthNoAuth SMTPAuthType = ""

	// SMTPAuthPlain is the "PLAIN" authentication mechanism as described in RFC 4616
	SMTPAuthPlain SMTPAuthType = "PLAIN"

	// SMTPAuthXOAUTH2 is the "XOAUTH2" SASL authentication mechanism.
	// https://developers.google.com/gmail/imap/xoauth2-protocol
	SMTPAuthXOAUTH2 SMTPAuthType = "XOAUTH2"

	SMTPAuthSCRAMSHA1       SMTPAuthType = "SCRAM-SHA-1"
	SMTPAuthSCRAMSHA1PLUS   SMTPAuthType = "SCRAM-SHA-1-PLUS"
	SMTPAuthSCRAMSHA256     SMTPAuthType = "SCRAM-SHA-256"
	SMTPAuthSCRAMSHA256PLUS SMTPAuthType = "SCRAM-SHA-256-PLUS"
)

// SMTP Auth related static errors
var (
	// ErrPlainAuthNotSupported should be used if the target server does not support the "PLAIN" schema
	ErrPlainAuthNotSupported = errors.New("server does not support SMTP AUTH type: PLAIN")

	// ErrLoginAuthNotSupported should be used if the target server does not support the "LOGIN" schema
	ErrLoginAuthNotSupported = errors.New("server does not support SMTP AUTH type: LOGIN")

	// ErrCramMD5AuthNotSupported should be used if the target server does not support the "CRAM-MD5" schema
	ErrCramMD5AuthNotSupported = errors.New("server does not support SMTP AUTH type: CRAM-MD5")

	// ErrXOauth2AuthNotSupported should be used if the target server does not support the "XOAUTH2" schema
	ErrXOauth2AuthNotSupported = errors.New("server does not support SMTP AUTH type: XOAUTH2")

	// ErrSCRAMSHA1AuthNotSupported should be used if the target server does not support the "XOAUTH2" schema
	ErrSCRAMSHA1AuthNotSupported = errors.New("server does not support SMTP AUTH type: SCRAM-SHA-1")

	// ErrSCRAMSHA1PLUSAuthNotSupported should be used if the target server does not support the "XOAUTH2" schema
	ErrSCRAMSHA1PLUSAuthNotSupported = errors.New("server does not support SMTP AUTH type: SCRAM-SHA-1-PLUS")

	// ErrSCRAMSHA256AuthNotSupported should be used if the target server does not support the "XOAUTH2" schema
	ErrSCRAMSHA256AuthNotSupported = errors.New("server does not support SMTP AUTH type: SCRAM-SHA-256")

	// ErrSCRAMSHA256PLUSAuthNotSupported should be used if the target server does not support the "XOAUTH2" schema
	ErrSCRAMSHA256PLUSAuthNotSupported = errors.New("server does not support SMTP AUTH type: SCRAM-SHA-256-PLUS")
)
