// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

// Package dkim implements
// TODO: document this properly
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
	ErrDKIMNoDomain    = errors.New("a DKIM domain must be set")
	ErrDKIMNoSelector  = errors.New("a DKIM selector must be set")
	ErrDKIMNoSigner    = errors.New("a DKIM crypto signer must be provided")
	ErrDKIMMissingFrom = errors.New("FROM is a required DKIM header")
)

var (
	// defaultHeader is the default set of headers to sign
	defaultHeader = []string{"From", "To", "Subject", "Date", "Message-ID",
		"Content-Type", "MIME-Version"}
)

// Config holds all DKIM signing parameters.
type Config struct {
	Domain    string
	Selector  string
	Signer    crypto.Signer
	Algorithm SignatureAlgo

	// We default to CanonicalizationRelaxed for both header and body canonicalization
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
func (c *Config) Validate() error {
	switch {
	case c.Domain == "":
		return ErrDKIMNoDomain
	case c.Selector == "":
		return ErrDKIMNoSelector
	case c.Signer == nil:
		return ErrDKIMNoSigner
	}
	for _, h := range c.effectiveHeaders() {
		if strings.EqualFold(h, "from") {
			return nil
		}
	}
	return ErrDKIMMissingFrom
}

// effectiveHeaders returns the list of headers to sign, defaulting to the standard set
// if none are configured
func (c *Config) effectiveHeaders() []string {
	if len(c.SignedHeaders) == 0 {
		return defaultHeader
	}
	return c.SignedHeaders
}

// headerListForTag returns the list of headers to sign for a given tag, including any
// oversign headers
func (c *Config) headerListForTag() []string {
	base := c.effectiveHeaders()
	if len(c.Oversign) == 0 {
		return base
	}
	return append(append([]string{}, base...), c.Oversign...)
}

// now returns the current time, using the injected Now function if set, or
// time.Now otherwise as default
func (c *Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Sign returns the DKIM-Signature header line for the given raw headers and body
func Sign(config Config, rawHeaders, body []byte) (string, error) {
	if err := config.Validate(); err != nil {
		return "", err
	}

	algo := config.Algorithm
	if algo == "" {
		if _, ok := config.Signer.Public().(ed25519.PublicKey); ok {
			algo = SignatureAlgoED25519
		} else {
			algo = SignatureAlgoRSA
		}
	}
	hc, bc := config.HeaderCanon, config.BodyCanon
	if hc == "" {
		hc = CanonicalizationRelaxed
	}
	if bc == "" {
		bc = CanonicalizationRelaxed
	}

	// Create the body hash (bh=)
	cb := canonicalizeBody(body, bc)
	if config.BodyLength > 0 && int64(len(cb)) > config.BodyLength {
		cb = cb[:config.BodyLength]
	}
	bh := sha256.Sum256(cb)

	// Assemble the header tags as signature placeholder (empty b=)
	tags := []string{
		"v=1", "a=" + string(algo),
		"c=" + string(hc) + "/" + string(bc),
		"d=" + config.Domain, "s=" + config.Selector,
		fmt.Sprintf("t=%d", config.now().Unix()),
		"h=" + strings.Join(config.headerListForTag(), ":"),
		"bh=" + base64.StdEncoding.EncodeToString(bh[:]),
	}
	if config.Expiration > 0 {
		tags = append(tags, fmt.Sprintf("x=%d", config.now().Add(config.Expiration).Unix()))
	}
	if config.AUID != "" {
		tags = append(tags, "i="+config.AUID)
	}
	if config.BodyLength > 0 {
		tags = append(tags, fmt.Sprintf("l=%d", config.BodyLength))
	}
	tags = append(tags, "b=")
	value := strings.Join(tags, "; ")

	// Parse headers and assemble the input to signature (with empty b=)
	store := parseHeaders(rawHeaders)
	var in bytes.Buffer
	for _, h := range config.headerListForTag() {
		if line, ok := store.pop(h); ok {
			in.Write(canonicalizeHeader(line, hc))
			in.WriteString("\r\n")
		}
	}
	in.Write(canonicalizeHeader("DKIM-Signature:"+value, hc))

	// Sign the message (Ed25519 signs the message, while RSA signs the SHA-256 digest)
	var sig []byte
	var err error
	if key, ok := config.Signer.(ed25519.PrivateKey); ok {
		sig = ed25519.Sign(key, in.Bytes())
	} else {
		d := sha256.Sum256(in.Bytes())
		sig, err = config.Signer.Sign(rand.Reader, d[:], crypto.SHA256)
	}
	if err != nil {
		return "", err
	}

	return "DKIM-Signature: " + foldHeader(value+base64.StdEncoding.EncodeToString(sig)) +
		"\r\n", nil
}
