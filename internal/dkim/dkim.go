// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

// Package dkim implements DKIM signing and verification according to RFC 6376. It provides
// support for both simple and relaxed canonicalization algorithms as well as support for
// RSA and ED25519 signature algorithms.
//
// This package only supports RSA-SHA256 and ED25519-SHA256 signature algorithms. RSA-SHA1
// is not supported since it's deprecated and prohibited by RFC 8301.
//
// See: https://datatracker.ietf.org/doc/html/rfc6376
// and: https://datatracker.ietf.org/doc/html/rfc8301#section-3.1
package dkim

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Canonicalization defines the DKIM canonicalization algorithm
type Canonicalization string

const (
	// CanonicalizationSimple is the simple canonicalization algorithm
	CanonicalizationSimple Canonicalization = "simple"

	// CanonicalizationRelaxed is the relaxed canonicalization algorithm
	CanonicalizationRelaxed Canonicalization = "relaxed"
)

// SignatureAlgo defines the DKIM signature algorithm
type SignatureAlgo string

const (
	// SignatureAlgoRSA is the RSA SHA-256 signature algorithm
	SignatureAlgoRSA SignatureAlgo = "rsa-sha256"

	// SignatureAlgoED25519 is the ED25519 SHA-256 signature algorithm
	SignatureAlgoED25519 SignatureAlgo = "ed25519-sha256"
)

var (
	// ErrDKIMNoDomain is returned when no DKIM domain is set
	ErrDKIMNoDomain = errors.New("a DKIM domain must be set")

	// ErrDKIMNoSelector is returned when no DKIM selector is set
	ErrDKIMNoSelector = errors.New("a DKIM selector must be set")

	// ErrDKIMNoSigner is returned when no DKIM crypto signer is provided
	ErrDKIMNoSigner = errors.New("a DKIM crypto signer must be provided")

	// ErrDKIMMissingFrom is returned when the FROM header is missing
	ErrDKIMMissingFrom = errors.New("FROM is a required DKIM header")
)

var (
	// defaultHeader is the default set of headers to sign
	defaultHeader = []string{"From", "To", "Subject", "Date", "Message-ID",
		"Content-Type", "MIME-Version"}
)

// DKIM holds all DKIM signing parameters.
type DKIM struct {
	Domain    string
	Selector  string
	Signer    crypto.Signer
	Algorithm SignatureAlgo

	// We default to CanonicalizationRelaxed for both header and body
	HeaderCanon Canonicalization
	BodyCanon   Canonicalization

	SignedHeaders []string
	Oversign      []string
	Expiration    time.Duration
	AUID          string
	BodyLength    int64

	// Now is injectable for deterministic tests, we default to time.Now
	Now func() time.Time
}

// Validate validates the DKIM configuration for required settings
func (d *DKIM) ValidateConfig() error {
	switch {
	case d.Domain == "":
		return ErrDKIMNoDomain
	case d.Selector == "":
		return ErrDKIMNoSelector
	case d.Signer == nil:
		return ErrDKIMNoSigner
	}
	for _, h := range d.effectiveHeaders() {
		if strings.EqualFold(h, "from") {
			return nil
		}
	}
	return ErrDKIMMissingFrom
}

// effectiveHeaders returns the list of headers to sign, defaulting to the standard set
// if none are configured
func (d *DKIM) effectiveHeaders() []string {
	if len(d.SignedHeaders) == 0 {
		return defaultHeader
	}
	return d.SignedHeaders
}

// headerListForTag returns the list of headers to sign for a given tag, including any
// oversign headers
func (d *DKIM) headerListForTag() []string {
	base := d.effectiveHeaders()
	if len(d.Oversign) == 0 {
		return base
	}
	return append(append([]string{}, base...), d.Oversign...)
}

// now returns the current time, using the injected Now function if set, or
// time.Now otherwise as default
func (d *DKIM) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// Sign returns the DKIM-Signature header line for the given raw headers and body
func (d *DKIM) Sign(rawHeaders, body []byte) (string, error) {
	if err := d.ValidateConfig(); err != nil {
		return "", err
	}

	algo := d.Algorithm
	if algo == "" {
		if _, ok := d.Signer.Public().(ed25519.PublicKey); ok {
			algo = SignatureAlgoED25519
		} else {
			algo = SignatureAlgoRSA
		}
	}
	hc, bc := d.HeaderCanon, d.BodyCanon
	if hc == "" {
		hc = CanonicalizationRelaxed
	}
	if bc == "" {
		bc = CanonicalizationRelaxed
	}

	// Create the body hash (bh=)
	cb := canonicalizeBody(body, bc)
	if d.BodyLength > 0 && int64(len(cb)) > d.BodyLength {
		cb = cb[:d.BodyLength]
	}
	bh := sha256.Sum256(cb)

	// Assemble the header tags as signature placeholder (empty b=)
	tags := []string{
		"v=1", "a=" + string(algo),
		"c=" + string(hc) + "/" + string(bc),
		"d=" + d.Domain, "s=" + d.Selector,
		fmt.Sprintf("t=%d", d.now().Unix()),
		"h=" + strings.Join(d.headerListForTag(), ":"),
		"bh=" + base64.StdEncoding.EncodeToString(bh[:]),
	}
	if d.Expiration > 0 {
		tags = append(tags, fmt.Sprintf("x=%d", d.now().Add(d.Expiration).Unix()))
	}
	if d.AUID != "" {
		tags = append(tags, "i="+d.AUID)
	}
	if d.BodyLength > 0 {
		tags = append(tags, fmt.Sprintf("l=%d", d.BodyLength))
	}
	tags = append(tags, "b=")
	value := strings.Join(tags, "; ")

	// Parse headers and assemble the input to signature (with empty b=)
	store := parseHeaders(rawHeaders)
	in := bytes.NewBuffer(nil)
	for _, header := range d.headerListForTag() {
		if line, ok := store.pop(header); ok {
			in.Write(canonicalizeHeader(line, hc))
			in.WriteString("\r\n")
		}
	}

	// Fold the tags ONCE with an empty b=. These exact bytes are reused for the
	// wire, so the fold points can never diverge between what we sign and what
	// we emit.
	foldedTags := foldHeader(value) // value ends in "b="

	switch hc {
	case CanonicalizationSimple:
		in.WriteString("DKIM-Signature: ")
		in.WriteString(value) // unfolded, b= empty — matches the emitted line
	case CanonicalizationRelaxed:
		in.Write(canonicalizeHeader("DKIM-Signature:"+value, hc))
	}

	// Both algorithms sign the SHA-256 digest of the canonicalized headers
	// Ed25519-SHA256 is PureEdDSA over that hash
	//
	// See: https://datatracker.ietf.org/doc/html/rfc6376#section-3.7
	// and https://datatracker.ietf.org/doc/html/rfc8463#section-3
	digest := sha256.Sum256(in.Bytes())
	var signature []byte
	var err error
	switch key := d.Signer.(type) {
	case ed25519.PrivateKey:
		signature = ed25519.Sign(key, digest[:]) // PureEdDSA over the digest
	default:
		signature, err = key.Sign(rand.Reader, digest[:], crypto.SHA256)
	}
	if err != nil {
		return "", err
	}

	sigB64 := base64.StdEncoding.EncodeToString(signature)
	if hc == CanonicalizationSimple {
		// Emit a single unfolded line: no byte-significant fold points for an
		// MTA to rewrap. Must match the hash input, which also used the
		// unfolded value.
		return "DKIM-Signature: " + value + sigB64 + "\r\n", nil
	}
	// relaxed: folding is unfolded away by verifiers, so wrap for readability.
	return "DKIM-Signature: " + appendFoldedBase64(foldedTags, sigB64) + "\r\n", nil
}
