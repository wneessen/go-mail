// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/wneessen/go-mail/internal/dkim"
)

// DKIMSigner represents the DKIM configuration
type DKIMSigner = dkim.Signer

type Canonicalization = dkim.Canonicalization

const (
	CanonicalizationSimple  Canonicalization = dkim.CanonicalizationSimple
	CanonicalizationRelaxed Canonicalization = dkim.CanonicalizationRelaxed
)

// SignWithDKIM enables DKIM signing for this Msg. The signature is produced
// over the final rendered bytes during WriteTo (after S/MIME and middlewares).
/*
func (m *Msg) SignWithDKIM(config *dkim.Signer) error {
	if config == nil {
		return errors.New("dkim: config must not be nil")
	}
	if err := config.ValidateConfig(); err != nil {
		return err
	}
	m.dkim = config
	return nil
}
*/

func NewDKIMSigner(domain, selector string, privKey crypto.Signer) *DKIMSigner {
	return dkim.NewSigner(domain, selector, privKey)
}

// PrivKeyFromPEM decodes a PEM-encoded RSA or Ed25519 private key block into a
// crypto.Signer. It accepts both PKCS#1 ("RSA PRIVATE KEY") and PKCS#8 ("PRIVATE KEY")
// byte slices
func PrivKeyFromPEM(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no valid PEM data found")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		switch key := key.(type) {
		case *rsa.PrivateKey:
			return key, nil
		case ed25519.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("unsupported key type %T", key)
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
}

// hasDKIM returns true if the Msg has a DKIM config.
func (m *Msg) hasDKIM() bool {
	return m.dkim != nil
}
