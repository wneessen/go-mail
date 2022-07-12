// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

package dkim

import (
	"crypto"
	"fmt"
)

type SignerConfig struct {
	// Signing Domain Identifier (SDID)
	// See: https://datatracker.ietf.org/doc/html/rfc6376#section-2.5
	//
	// A single domain name that is the mandatory payload output of DKIM
	// and that refers to the identity claiming some responsibility for
	// the message by signing it.
	//
	// Domain MUST not be empty
	Domain string

	// Domain selectors
	// See: https://datatracker.ietf.org/doc/html/rfc6376#section-3.1
	//
	// To support multiple concurrent public keys per signing domain, the
	// key namespace is subdivided using "selectors".  For example,
	// selectors might indicate the names of office locations (e.g.,
	// "sanfrancisco", "coolumbeach", and "reykjavik"), the signing date
	// (e.g., "january2005", "february2005", etc.), or even an individual
	// user.
	//
	// Selector MUST not be empty
	Selector string

	// Agent or User Identifier (AUID)
	// See: https://datatracker.ietf.org/doc/html/rfc6376#section-2.6
	//
	// A single identifier that refers to the agent or user on behalf of
	// whom the Signing Domain Identifier (SDID) has taken responsibility.
	// The AUID comprises a domain name and an optional <local-part>.  The
	// domain name is the same as that used for the SDID or is a subdomain
	// of it.  For DKIM processing, the domain name portion of the AUID has
	// only basic domain name semantics; any possible owner-specific
	// semantics are outside the scope of DKIM.
	//
	// AUID is optional
	AUID string

	// DKIM Hash Algorithms
	// See: https://datatracker.ietf.org/doc/html/rfc6376#section-7.7
	//
	// DKIM supports SHA1 and SHA256. Please note that SHA1 is not
	// recommended anymore, since the SHA1 hashing algorithm has been
	// proven to be broken
	//
	// If no HashAlgo is provided, it will default to SHA256
	HashAlgo crypto.Hash
}

// SignerOption returns a function that can be used for grouping SignerConfig options
type SignerOption func(config *SignerConfig) error

// NewConfig returns a new SignerConfig struct. It requires a domain name d and a
// domain selector d. All other values can be prefilled using the With*() SignerOption
// methods
func NewConfig(d string, s string, o ...SignerOption) (*SignerConfig, error) {
	sc := &SignerConfig{
		Domain:   d,
		Selector: s,
		HashAlgo: crypto.SHA256,
	}

	// Override defaults with optionally provided Option functions
	for _, co := range o {
		if co == nil {
			continue
		}
		if err := co(sc); err != nil {
			return sc, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	return sc, nil
}

// WithAUID provides the optional AUID value for the SignerConfig
func WithAUID(a string) SignerOption {
	return func(sc *SignerConfig) error {
		sc.AUID = a
		return nil
	}
}

// WithHashAlgo provides the Hashing algorithm to the SignerConfig
func WithHashAlgo(ha crypto.Hash) SignerOption {
	return func(sc *SignerConfig) error {
		switch ha.String() {
		case "SHA-256":
		case "SHA-1":
		default:
			return fmt.Errorf("unsupported hashing algorithm: %s", ha.String())
		}
		sc.HashAlgo = ha
		return nil
	}
}

// SetAUID sets/overrides the AUID of the SignerConfig
func (sc *SignerConfig) SetAUID(a string) {
	sc.AUID = a
}

// SetHashAlgo sets/override the hashing algorithm of the SignerConfig
func (sc *SignerConfig) SetHashAlgo(ha crypto.Hash) error {
	switch ha.String() {
	case "SHA-256":
	case "SHA-1":
	default:
		return fmt.Errorf("unsupported hashing algorithm: %s", ha.String())
	}
	sc.HashAlgo = ha
	return nil
}

// SetSelector overrides the Selector of the SignerConfig
func (sc *SignerConfig) SetSelector(s string) error {
	if s == "" {
		return fmt.Errorf("DKIM selector must not be empty")
	}
	sc.Selector = s
	return nil
}

// Signer is a struct that represents the main object for signing mails using DKIM
type Signer struct {
	c *SignerConfig
}

// NewSigner returns a new Signer instance
func NewSigner(sc *SignerConfig) (*Signer, error) {
	s := &Signer{c: sc}

	// Check some prerequisites
	if sc.Domain == "" {
		return s, fmt.Errorf("signing domain must not be empty")
	}
	if sc.Selector == "" {
		return s, fmt.Errorf("domain selector must not be empty")
	}

	return s, nil
}
