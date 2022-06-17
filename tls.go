// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

package mail

// TLSPolicy type describes a int alias for the different TLS policies we allow
type TLSPolicy int

const (
	// TLSMandatory requires that the connection cto the server is
	// encrypting using STARTTLS. If the server does not support STARTTLS
	// the connection will be terminated with an error
	TLSMandatory TLSPolicy = iota

	// TLSOpportunistic tries cto establish an encrypted connection via the
	// STARTTLS protocol. If the server does not support this, it will fall
	// back cto non-encrypted plaintext transmission
	TLSOpportunistic

	// NoTLS forces the transaction cto be not encrypted
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
