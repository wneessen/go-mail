// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import "errors"

// SMTPAuthType represents a string to any SMTP AUTH type
type SMTPAuthType string

// Supported SMTP AUTH types
const (
	// SMTPAuthLogin is the "LOGIN" SASL authentication mechanism
	SMTPAuthLogin SMTPAuthType = "LOGIN"

	// SMTPAuthPlain is the "PLAIN" authentication mechanism as described in RFC 4616
	SMTPAuthPlain SMTPAuthType = "PLAIN"

	// SMTPAuthCramMD5 is the "CRAM-MD5" SASL authentication mechanism as described in RFC 4954
	SMTPAuthCramMD5 SMTPAuthType = "CRAM-MD5"
)

// SMTP Auth related static errors
var (
	// ErrPlainAuthNotSupported should be used if the target server does not support the "PLAIN" schema
	ErrPlainAuthNotSupported = errors.New("server does not support SMTP AUTH type: PLAIN")

	// ErrLoginAuthNotSupported should be used if the target server does not support the "LOGIN" schema
	ErrLoginAuthNotSupported = errors.New("server does not support SMTP AUTH type: LOGIN")

	// ErrCramMD5AuthNotSupported should be used if the target server does not support the "CRAM-MD5" schema
	ErrCramMD5AuthNotSupported = errors.New("server does not support SMTP AUTH type: CRAM-MD5")
)
