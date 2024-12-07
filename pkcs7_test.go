// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
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
		toBeSigned, err := newSignedData(content)
		if err != nil {
			t.Fatalf("Cannot initialize signed data: %s", err)
		}
		if err := toBeSigned.addSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{}); err != nil {
			t.Fatalf("Cannot add signer: %s", err)
		}
		if testDetach {
			t.Log("Testing detached signature")
			toBeSigned.detach()
		} else {
			t.Log("Testing attached signature")
		}
		signed, err := toBeSigned.finish()
		if err != nil {
			t.Fatalf("Cannot finish signing data: %s", err)
		}
		if err := pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed}); err != nil {
			t.Fatalf("Cannot write signed data: %s", err)
		}
	}
}

type certKeyPair struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

func createTestCertificate() (*certKeyPair, error) {
	signer, err := createTestCertificateByIssuer("Eddard Stark", nil)
	if err != nil {
		return nil, err
	}
	fmt.Println("Created root cert")
	if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: signer.Certificate.Raw}); err != nil {
		return nil, err
	}
	pair, err := createTestCertificateByIssuer("Jon Snow", signer)
	if err != nil {
		return nil, err
	}
	fmt.Println("Created signer cert")
	if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate.Raw}); err != nil {
		return nil, err
	}
	return pair, nil
}

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
