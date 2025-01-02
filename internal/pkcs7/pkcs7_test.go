// SPDX-FileCopyrightText: Copyright (c) 2015 Andrew Smith
// SPDX-FileCopyrightText: Copyright (c) 2017-2024 The mozilla services project (https://github.com/mozilla-services)
// SPDX-FileCopyrightText: Copyright (c) 2024-2025 The go-mail Authors
//
// Partially forked from https://github.com/mozilla-services/pkcs7, which in turn is also a fork
// of https://github.com/fullsailor/pkcs7.
// Use of the forked source code is, same as go-mail, governed by a MIT license.
//
// go-mail specific modifications by the go-mail Authors.
// Licensed under the MIT License.
// See [PROJECT ROOT]/LICENSES directory for more information.
//
// SPDX-License-Identifier: MIT

package pkcs7

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// TestSign_E2E tests S/MIME singing as e2e
func TestSign_E2E(t *testing.T) {
	cert, err := createTestCertificate()
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("Hello World")
	for _, testDetach := range []bool{false, true} {
		toBeSigned, serr := NewSignedData(content)
		if serr != nil {
			t.Fatalf("Cannot initialize signed data: %s", err)
		}
		if serr = toBeSigned.AddSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{}); serr != nil {
			t.Fatalf("Cannot add signer: %s", err)
		}
		if testDetach {
			toBeSigned.Detach()
		} else {
		}
		signed, serr := toBeSigned.Finish()
		if serr != nil {
			t.Fatalf("Cannot finish signing data: %s", err)
		}
		buf := bytes.NewBuffer(nil)
		if serr = pem.Encode(buf, &pem.Block{Type: "PKCS7", Bytes: signed}); serr != nil {
			t.Fatalf("Cannot write signed data: %s", err)
		}
	}
}

// certKeyPair represents a pair of an x509 certificate and its corresponding RSA private key.
type certKeyPair struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

// createTestCertificate generates a test certificate and private key pair.
func createTestCertificate() (*certKeyPair, error) {
	buf := bytes.NewBuffer(nil)
	signer, err := createTestCertificateByIssuer("Eddard Stark", nil)
	if err != nil {
		return nil, err
	}
	if err = pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: signer.Certificate.Raw}); err != nil {
		return nil, err
	}
	pair, err := createTestCertificateByIssuer("Jon Snow", signer)
	if err != nil {
		return nil, err
	}
	if err = pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate.Raw}); err != nil {
		return nil, err
	}
	return pair, nil
}

// createTestCertificateByIssuer generates a certificate and private key pair, optionally signed by an issuer.
func createTestCertificateByIssuer(name string, issuer *certKeyPair) (*certKeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 32)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber:       serialNumber,
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"Acme Co"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	var issuerCert *x509.Certificate
	var issuerKey crypto.PrivateKey
	if issuer != nil {
		issuerCert = issuer.Certificate
		issuerKey = issuer.PrivateKey
	} else {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		issuerCert = &template
		issuerKey = priv
	}
	cert, err := x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.Public(), issuerKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}
	return &certKeyPair{
		Certificate: leaf,
		PrivateKey:  priv,
	}, nil
}
