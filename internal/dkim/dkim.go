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

// Signer represents a DKIM signer that holds all signing parameters
type Signer struct {
	// Domain represents the DKIM Signing Domain Identifier (SDID). It is
	// d single domain name that is the mandatory payload output of DKIM
	// and that refers to the identity claiming some responsibility for
	// the message by signing it.
	//
	// Domain MUST not be empty
	//
	// See: https://datatracker.ietf.org/doc/html/rfc6376#section-2.5
	Domain string

	// Selector represents the DKIM domain selectors
	//
	// To support multiple concurrent public keys per signing domain, the
	// key namespace is subdivided using "selectors". For example,
	// selectors might indicate the names of office locations (e.g.,
	// "sanfrancisco", "coolumbeach", and "reykjavik"), the signing date
	// (e.g., "january2005", "february2005", etc.), or even an individual
	// user.
	//
	// Selector MUST not be empty
	//
	// See: https://datatracker.ietf.org/doc/html/rfc6376#section-3.1
	Selector string

	// Signer is the crypto.Signer used to sign the message.
	Signer crypto.Signer

	// auid represents the DKIM Agent or User Identifier (auid)
	// See: https://datatracker.ietf.org/doc/html/rfc6376#section-2.6
	//
	// A single identifier that refers to the agent or user on behalf of
	// whom the Signing Domain Identifier (SDID) has taken responsibility.
	// The auid comprises a domain name and an optional <local-part>.  The
	// domain name is the same as that used for the SDID or is a subdomain
	// of it.  For DKIM processing, the domain name portion of the auid has
	// only basic domain name semantics; any possible owner-specific
	// semantics are outside the scope of DKIM.
	//
	// auid is optional and can be empty
	auid string

	// bodyCanonicalization defines the type of Canonicalization used for the
	// mail.Msg body.
	//
	// We default to CanonicalizationRelaxed for the body.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc6376#section-3.4
	bodyCanonicalization Canonicalization

	// expiration is an optional expiration time of the signature.
	//
	// Signatures MAY be considered invalid if the verification time at
	// the verifier is past the expiration date. The verification
	// time should be the time that the message was first received at
	// the administrative domain of the verifier if that time is
	// reliably available; otherwise, the current time should be
	// used.
	//
	// See: https://www.rfc-editor.org/rfc/rfc6376.html#section-3.5
	expiration time.Duration

	// headerCanonicalization defines the type of Canonicalization used for the
	// mail.Msg header.
	//
	// We default to CanonicalizationRelaxed for the header.
	//
	// See: https://datatracker.ietf.org/doc/html/rfc6376#section-3.4
	headerCanonicalization Canonicalization

	algorithm       SignatureAlgo
	bodyLength      int64
	signedHeaders   []string
	oversignHeaders []string

	// NowFunc represents a function that is used to determine the signature's
	// time field (t=). It can be overridden for deterministic tests.
	NowFunc func() time.Time
}

func NewSigner(domain, selector string, signer crypto.Signer) *Signer {
	dkimSigner := &Signer{
		Domain:   domain,
		Selector: selector,
		Signer:   signer,
	}
	return dkimSigner
}

func (s *Signer) BodyCanonicalization(mode Canonicalization) {
	s.bodyCanonicalization = mode
}

func (s *Signer) HeaderCanonicalization(mode Canonicalization) {
	s.headerCanonicalization = mode
}

func (s *Signer) ExpireIn(expiration time.Duration) {
	s.expiration = expiration
}

func (s *Signer) SignHeaders(headers ...string) {
	if len(headers) == 0 {
		return
	}
	s.signedHeaders = headers
}

func (s *Signer) AUID(auid string) {
	s.auid = auid
}

// Validate validates the DKIM configuration for required settings
func (s *Signer) ValidateConfig() error {
	switch {
	case s.Domain == "":
		return ErrDKIMNoDomain
	case s.Selector == "":
		return ErrDKIMNoSelector
	case s.Signer == nil:
		return ErrDKIMNoSigner
	}
	for _, h := range s.effectiveHeaders() {
		if strings.EqualFold(h, "from") {
			return nil
		}
	}
	return ErrDKIMMissingFrom
}

// effectiveHeaders returns the list of headers to sign, defaulting to the standard set
// if none are configured
func (s *Signer) effectiveHeaders() []string {
	if len(s.signedHeaders) == 0 {
		return defaultHeader
	}
	return s.signedHeaders
}

// headerListForTag returns the list of headers to sign for a given tag, including any
// oversign headers
func (s *Signer) headerListForTag() []string {
	base := s.effectiveHeaders()
	if len(s.oversignHeaders) == 0 {
		return base
	}
	return append(append([]string{}, base...), s.oversignHeaders...)
}

// now returns the current time, using the injected Now function if set, or
// time.Now otherwise as default
func (s *Signer) now() time.Time {
	if s.NowFunc != nil {
		return s.NowFunc()
	}
	return time.Now()
}

// Sign returns the DKIM-Signature header line for the given raw headers and body
func (s *Signer) Sign(rawHeaders, body []byte) (string, error) {
	if err := s.ValidateConfig(); err != nil {
		return "", err
	}

	algo := s.algorithm
	if algo == "" {
		if _, ok := s.Signer.Public().(ed25519.PublicKey); ok {
			algo = SignatureAlgoED25519
		} else {
			algo = SignatureAlgoRSA
		}
	}
	hc, bc := s.headerCanonicalization, s.bodyCanonicalization
	if hc == "" {
		hc = CanonicalizationRelaxed
	}
	if bc == "" {
		bc = CanonicalizationRelaxed
	}

	// Create the body hash (bh=)
	cb := canonicalizeBody(body, bc)
	if s.bodyLength > 0 && int64(len(cb)) > s.bodyLength {
		cb = cb[:s.bodyLength]
	}
	bh := sha256.Sum256(cb)

	// Assemble the header tags as signature placeholder (empty b=)
	tags := []string{
		"v=1", "a=" + string(algo),
		"c=" + string(hc) + "/" + string(bc),
		"d=" + s.Domain, "s=" + s.Selector,
		fmt.Sprintf("t=%d", s.now().Unix()),
		"h=" + strings.Join(s.headerListForTag(), ":"),
		"bh=" + base64.StdEncoding.EncodeToString(bh[:]),
	}
	if s.expiration > 0 {
		tags = append(tags, fmt.Sprintf("x=%d", s.now().Add(s.expiration).Unix()))
	}
	if s.auid != "" {
		tags = append(tags, "i="+s.auid)
	}
	if s.bodyLength > 0 {
		tags = append(tags, fmt.Sprintf("l=%d", s.bodyLength))
	}
	tags = append(tags, "b=")
	value := strings.Join(tags, "; ")

	// Parse headers and assemble the input to signature (with empty b=)
	store := parseHeaders(rawHeaders)
	in := bytes.NewBuffer(nil)
	for _, header := range s.headerListForTag() {
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
	switch key := s.Signer.(type) {
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
