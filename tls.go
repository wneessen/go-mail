// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

// TLSPolicy type describes a int alias for the different TLS policies we allow
type TLSPolicy int

const (
	// TLSMandatory requires that the connection to the server is
	// encrypting using STARTTLS. If the server does not support STARTTLS
	// the connection will be terminated with an error
	TLSMandatory TLSPolicy = iota

	// TLSOpportunistic tries to establish an encrypted connection via the
	// STARTTLS protocol. If the server does not support this, it will fall
	// back to non-encrypted plaintext transmission
	TLSOpportunistic

	// NoTLS forces the transaction to be not encrypted
	NoTLS
)

// String is a standard method to convert a TLSPolicy into a printable format
func (p TLSPolicy) String() string {
	switch p {
	case TLSMandatory:
		return "TLSMandatory"
	case TLSOpportunistic:
		return "TLSOpportunistic"
	case NoTLS:
		return "NoTLS"
	default:
		return "UnknownPolicy"
	}
}
