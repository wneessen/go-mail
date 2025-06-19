// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"strings"
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
			privkey, certificate, intermediate, err := tt.certFunc()
			if err != nil {
				t.Errorf("failed getting dummy crypto material: %s", err)
			}
			smime, err := newSMIME(privkey, certificate, intermediate)
			if err != nil {
				t.Errorf("failed to initialize SMIME: %s", err)
			}

			switch key := privkey.(type) {
			case *rsa.PrivateKey:
				if !key.Equal(smime.privateKey) {
					t.Error("SMIME initialization failed. Private keys are not equal")
				}
			case *ecdsa.PrivateKey:
				if !key.Equal(smime.privateKey) {
					t.Error("SMIME initialization failed. Private keys are not equal")
				}
			default:
				t.Fatal("unsupported private key type")
			}

			if !bytes.Equal(certificate.Raw, smime.certificate.Raw) {
				t.Errorf("SMIME initialization failed. Expected public key: %x, got: %x", certificate.Raw,
					smime.certificate.Raw)
			}
			if !bytes.Equal(intermediate.Raw, smime.intermediateCert.Raw) {
				t.Errorf("SMIME initialization failed. Expected intermediate certificate: %x, got: %x",
					intermediate.Raw, smime.intermediateCert.Raw)
			}
		})
	}

	t.Run("newSMIME fails with nil private key", func(t *testing.T) {
		_, certificate, intermediate, err := getDummyRSACryptoMaterial()
		if err != nil {
			t.Errorf("failed getting dummy crypto material: %s", err)
		}
		_, err = newSMIME(nil, certificate, intermediate)
		if err == nil {
			t.Error("newSMIME with nil private key is expected to fail")
		}
		if !errors.Is(err, ErrPrivateKeyMissing) {
			t.Errorf("newSMIME with nil private key is expected to fail with ErrPrivateKeyMissing, got: %s", err)
		}
	})
	t.Run("newSMIME fails with nil public key", func(t *testing.T) {
		privkey, _, intermediate, err := getDummyRSACryptoMaterial()
		if err != nil {
			t.Errorf("failed getting dummy crypto material: %s", err)
		}
		_, err = newSMIME(privkey, nil, intermediate)
		if err == nil {
			t.Error("newSMIME with nil private key is expected to fail")
		}
		if !errors.Is(err, ErrCertificateMissing) {
			t.Errorf("newSMIME with nil public key is expected to fail with ErrCertificateMissing, got: %s", err)
		}
	})
}

func TestGetLeafCertificate(t *testing.T) {
	t.Run("getLeafCertificate works normally", func(t *testing.T) {
		keypair, err := getDummyKeyPairTLS()
		if err != nil {
			t.Errorf("failed to load dummy crypto material: %s", err)
		}
		leaf, err := x509.ParseCertificate(keypair.Certificate[0])
		if err != nil {
			t.Fatalf("failed to parse leaf certificate: %s", err)
		}
		keypair.Leaf = leaf

		leafCert, err := getLeafCertificate(keypair)
		if err != nil {
			t.Errorf("failed to get leaf certificate: %s", err)
		}
		if leafCert == nil {
			t.Fatal("failed to get leaf certificate, got nil")
		}
		if !bytes.Equal(leafCert.Raw, keypair.Leaf.Raw) {
			t.Errorf("failed to get leaf certificate, expected cert mismatch, expected: %x, got: %x",
				keypair.Leaf.Raw, leafCert.Raw)
		}
	})
	t.Run("getLeafCertificate fails with nil", func(t *testing.T) {
		_, err := getLeafCertificate(nil)
		if err == nil {
			t.Error("getLeafCertificate with nil is expected to fail")
		}
	})
	t.Run("getLeafCertificate without leaf should return first certificate in chain", func(t *testing.T) {
		keypair, err := getDummyKeyPairTLS()
		if err != nil {
			t.Errorf("failed to load dummy crypto material: %s", err)
		}
		keypair.Leaf = nil
		leafCert, err := getLeafCertificate(keypair)
		if err != nil {
			t.Errorf("failed to get leaf certificate: %s", err)
		}
		if leafCert == nil {
			t.Fatal("failed to get leaf certificate, got nil")
		}
		if !bytes.Equal(leafCert.Raw, keypair.Certificate[0]) {
			t.Errorf("failed to get leaf certificate, expected cert mismatch, expected: %x, got: %x",
				keypair.Leaf.Raw, leafCert.Raw)
		}
	})
	t.Run("getLeafCertificate with empty chain should fail", func(t *testing.T) {
		keypair, err := getDummyKeyPairTLS()
		if err != nil {
			t.Errorf("failed to load dummy crypto material: %s", err)
		}
		localpair := &tls.Certificate{
			Certificate:                  nil,
			PrivateKey:                   keypair.PrivateKey,
			Leaf:                         nil,
			SignedCertificateTimestamps:  keypair.SignedCertificateTimestamps,
			SupportedSignatureAlgorithms: keypair.SupportedSignatureAlgorithms,
		}
		_, err = getLeafCertificate(localpair)
		if err == nil {
			t.Errorf("expected getLeafCertificate to fail with empty chain, got: %s", err)
		}
		expErr := "certificate chain is empty"
		if !strings.EqualFold(err.Error(), expErr) {
			t.Errorf("getting leaf certificate was supposed to fail with: %s, got: %s", expErr, err.Error())
		}
	})
	t.Run("getLeafCertificate fails while parsing broken certificate", func(t *testing.T) {
		keypair, err := getDummyKeyPairTLS()
		if err != nil {
			t.Errorf("failed to load dummy crypto material: %s", err)
		}
		keypair.Leaf = nil
		keypair.Certificate[0] = []byte("broken certificate")

		_, err = getLeafCertificate(keypair)
		if err == nil {
			t.Errorf("expected getLeafCertificate to fail with broken cert, got: %s", err)
		}
		expErr := "x509: malformed certificate"
		if !strings.EqualFold(err.Error(), expErr) {
			t.Errorf("getting leaf certificate was supposed to fail with: %s, got: %s", expErr, err.Error())
		}
	})
}

func getOpenSSLPath() string {
	paths := []string{"/bin/openssl", "/usr/bin/openssl", "/usr/local/bin/openssl"}
	openSSL := ""
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil {
			if info.IsDir() || info.Mode()&0o111 == 0 {
				continue
			}
			openSSL = path
			break
		}
	}
	return openSSL
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
