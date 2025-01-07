// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"testing"
)

const (
	dummyCertRSAPath   = "testdata/dummy-chain-cert-rsa.pem"
	dummyKeyRSAPath    = "testdata/dummy-child-key-rsa.pem"
	dummyCertECDSAPath = "testdata/dummy-chain-cert-ecdsa.pem"
	dummyKeyECDSAPath  = "testdata/dummy-child-key-ecdsa.pem"
)

// TestNewSMimeWithRSA tests the newSMime method with RSA crypto material
func TestNewSMIME(t *testing.T) {
	tests := []struct {
		name     string
		certFunc func() (crypto.PrivateKey, *x509.Certificate, *x509.Certificate, error)
	}{
		{"RSA", getDummyRSACryptoMaterial},
		{"ECDSA", getDummyECDSACryptoMaterial},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, certificate, intermediateCertificate, err := tt.certFunc()
			if err != nil {
				t.Errorf("Error getting dummy crypto material: %s", err)
			}

			sMime, err := newSMIME(privateKey, certificate, intermediateCertificate)
			if err != nil {
				t.Errorf("Error creating new SMIME from keyPair: %s", err)
			}

			if sMime.privateKey != privateKey {
				t.Errorf("NewSMime() did not return the same private key")
			}
			if sMime.certificate != certificate {
				t.Errorf("NewSMime() did not return the same certificate")
			}
			if sMime.intermediateCert != intermediateCertificate {
				t.Errorf("NewSMime() did not return the same intermedidate certificate")
			}
		})
	}
}

// TestSign tests the sign method
func TestSign(t *testing.T) {
	privateKey, certificate, intermediateCertificate, err := getDummyRSACryptoMaterial()
	if err != nil {
		t.Errorf("Error getting dummy crypto material: %s", err)
	}

	sMime, err := newSMIME(privateKey, certificate, intermediateCertificate)
	if err != nil {
		t.Errorf("Error creating new SMIME from keyPair: %s", err)
	}

	message := "This is a test message"
	singedMessage, err := sMime.signMessage([]byte(message))
	if err != nil {
		t.Errorf("Error creating singed message: %s", err)
	}

	if singedMessage == message {
		t.Errorf("Sign() did not work")
	}
}

// getDummyRSACryptoMaterial loads a certificate (RSA), the associated private key and certificate (RSA) is loaded
// from local disk for testing purposes
func getDummyRSACryptoMaterial() (crypto.PrivateKey, *x509.Certificate, *x509.Certificate, error) {
	keyPair, err := tls.LoadX509KeyPair(dummyCertRSAPath, dummyKeyRSAPath)
	if err != nil {
		return nil, nil, nil, err
	}

	privateKey := keyPair.PrivateKey.(*rsa.PrivateKey)

	certificate, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, nil, nil, err
	}

	intermediateCertificate, err := x509.ParseCertificate(keyPair.Certificate[1])
	if err != nil {
		return nil, nil, nil, err
	}

	return privateKey, certificate, intermediateCertificate, nil
}

// getDummyECDSACryptoMaterial loads a certificate (ECDSA), the associated private key and certificate (ECDSA) is
// loaded from local disk for testing purposes
func getDummyECDSACryptoMaterial() (crypto.PrivateKey, *x509.Certificate, *x509.Certificate, error) {
	keyPair, err := tls.LoadX509KeyPair(dummyCertECDSAPath, dummyKeyECDSAPath)
	if err != nil {
		return nil, nil, nil, err
	}

	privateKey := keyPair.PrivateKey.(*ecdsa.PrivateKey)

	certificate, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, nil, nil, err
	}

	intermediateCertificate, err := x509.ParseCertificate(keyPair.Certificate[1])
	if err != nil {
		return nil, nil, nil, err
	}

	return privateKey, certificate, intermediateCertificate, nil
}

// getDummyKeyPairTLS loads a certificate (ECDSA) as *tls.Certificate, the associated private key and certificate (ECDSA) is loaded from local disk for testing purposes
func getDummyKeyPairTLS() (*tls.Certificate, error) {
	keyPair, err := tls.LoadX509KeyPair(dummyCertRSAPath, dummyKeyRSAPath)
	if err != nil {
		return nil, err
	}
	return &keyPair, err
}
