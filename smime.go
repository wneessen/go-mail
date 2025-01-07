// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/wneessen/go-mail/internal/pkcs7"
)

var (
	// ErrPrivateKeyMissing should be used if private key is invalid
	ErrPrivateKeyMissing = errors.New("private key is missing")

	// ErrCertificateMissing should be used if the certificate is invalid
	ErrCertificateMissing = errors.New("certificate is missing")
)

// SMIME represents the configuration used to sign messages with S/MIME.
//
// This struct encapsulates the private key, certificate, and optional intermediate certificate
// required for S/MIME signing.
//
// Fields:
//   - privateKey: The private key used for signing (implements crypto.PrivateKey).
//   - certificate: The x509 certificate associated with the private key.
//   - intermediateCert: An optional x509 intermediate certificate for chain validation.
//   - signatureWritten: A flag indicating whether the S/MIME the signature has already been written
type SMIME struct {
	privateKey       crypto.PrivateKey
	certificate      *x509.Certificate
	intermediateCert *x509.Certificate
	inProgress       bool
	isSigned         bool
}

// newSMIME constructs a new instance of SMIME with the provided parameters.
//
// This function initializes an SMIME object with a private key, certificate, and an optional
// intermediate certificate.
//
// Parameters:
//   - privateKey: The private key used for signing (must implement crypto.PrivateKey).
//   - certificate: The x509 certificate associated with the private key.
//   - intermediateCert: An optional x509 intermediate certificate for chain validation.
//
// Returns:
//   - An SMIME instance configured with the provided parameters.
//   - An error if the private key or certificate is missing.
func newSMIME(privateKey crypto.PrivateKey, certificate *x509.Certificate, intermediateCertificate *x509.Certificate) (*SMIME, error) {
	if privateKey == nil {
		return nil, ErrPrivateKeyMissing
	}
	if certificate == nil {
		return nil, ErrCertificateMissing
	}

	return &SMIME{
		privateKey:       privateKey,
		certificate:      certificate,
		intermediateCert: intermediateCertificate,
	}, nil
}

// signMessage signs the given message with S/MIME.
//
// This function uses the configured private key and certificate to create an S/MIME signature
// for the provided message. It optionally includes an intermediate certificate for chain validation.
// The resulting signature is returned in PEM format.
//
// Parameters:
//   - message: The string content of the message to be signed.
//
// Returns:
//   - A string containing the S/MIME signature in PEM format.
//   - An error if any step in the signing process fails, such as initializing signed data, adding a signer,
//     or encoding the signature.
func (s *SMIME) signMessage(message []byte) (string, error) {
	signedData, err := pkcs7.NewSignedData(message)
	if err != nil || signedData == nil {
		return "", fmt.Errorf("failed to initialize signed data: %w", err)
	}

	if err = signedData.AddSigner(s.certificate, s.privateKey, pkcs7.SignerInfoConfig{}); err != nil {
		return "", fmt.Errorf("could not add signer message: %w", err)
	}

	if s.intermediateCert != nil {
		signedData.AddCertificate(s.intermediateCert)
	}

	signedData.Detach()

	signatureDER, err := signedData.Finish()
	if err != nil {
		return "", fmt.Errorf("failed to finish signature: %w", err)
	}

	return string(signatureDER), nil
}

// getLeafCertificate retrieves the leaf certificate from a tls.Certificate.
//
// This function returns the parsed leaf certificate from the provided TLS certificate. If the Leaf field
// is nil, it parses and returns the first certificate in the chain.
//
// PLEASE NOTE: In Go versions prior to 1.23, the Certificate.Leaf field was left nil, and the parsed
// certificate was discarded. This behavior can be re-enabled by setting "x509keypairleaf=0" in the
// GODEBUG environment variable.
//
// Parameters:
//   - keyPairTlS: The *tls.Certificate containing the certificate chain.
//
// Returns:
//   - The parsed leaf x509 certificate.
//   - An error if the certificate could not be parsed.
func getLeafCertificate(keyPairTLS *tls.Certificate) (*x509.Certificate, error) {
	if keyPairTLS == nil {
		return nil, errors.New("provided certificate is nil")
	}
	if keyPairTLS.Leaf != nil {
		return keyPairTLS.Leaf, nil
	}

	if len(keyPairTLS.Certificate) == 0 {
		return nil, errors.New("certificate chain is empty")
	}
	cert, err := x509.ParseCertificate(keyPairTLS.Certificate[0])
	if err != nil {
		return nil, err
	}

	return cert, nil
}
