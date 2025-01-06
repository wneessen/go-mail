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
	"encoding/base64"
	"fmt"
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
	singedMessage, err := sMime.signMessage(message)
	if err != nil {
		t.Errorf("Error creating singed message: %s", err)
	}

	if singedMessage == message {
		t.Errorf("Sign() did not work")
	}
}

// TestPrepareMessage tests the createMessage method
func TestPrepareMessage(t *testing.T) {
	privateKey, certificate, intermediateCertificate, err := getDummyRSACryptoMaterial()
	if err != nil {
		t.Errorf("Error getting dummy crypto material: %s", err)
	}

	sMime, err := newSMIME(privateKey, certificate, intermediateCertificate)
	if err != nil {
		t.Errorf("Error creating new SMIME from keyPair: %s", err)
	}

	encoding := EncodingB64
	contentType := TypeTextPlain
	charset := CharsetUTF8
	body := []byte("This is the body!")
	result, err := sMime.prepareMessage(encoding, contentType, charset, body)
	if err != nil {
		t.Errorf("Error preparing message: %s", err)
	}

	if !strings.Contains(result, encoding.String()) {
		t.Errorf("prepareMessage() did not return the correct encoding")
	}
	if !strings.Contains(result, contentType.String()) {
		t.Errorf("prepareMessage() did not return the correct contentType")
	}
	if !strings.Contains(result, string(body)) {
		t.Errorf("prepareMessage() did not return the correct body")
	}
	if result != fmt.Sprintf("Content-Transfer-Encoding: %s\r\nContent-Type: %s; charset=%s\r\n\r\n%s", encoding, contentType, charset, string(body)) {
		t.Errorf("prepareMessage() did not sucessfully create the message")
	}
}

// TestPrepareMessage_QuotedPrintable tests the prepareMessage method with quoted printable encoding
func TestPrepareMessage_QuotedPrintable(t *testing.T) {
	privateKey, certificate, intermediateCertificate, err := getDummyRSACryptoMaterial()
	if err != nil {
		t.Errorf("Error getting dummy crypto material: %s", err)
	}

	sMime, err := newSMIME(privateKey, certificate, intermediateCertificate)
	if err != nil {
		t.Errorf("Error creating new SMIME from keyPair: %s", err)
	}

	body := "This is the body with special chars like äöü ÄÖÜ ß!"
	quotedPrintableBody := "This is the body with special chars like =C3=A4=C3=B6=C3=BC =C3=84=C3=96=C3=\r\n=9C =C3=9F!"
	encoding := EncodingQP
	contentType := TypeTextPlain
	charset := CharsetUTF8
	result, err := sMime.prepareMessage(encoding, contentType, charset, []byte(body))
	if err != nil {
		t.Errorf("Error preparing message: %s", err)
	}

	if !strings.Contains(result, encoding.String()) {
		t.Errorf("prepareMessage() did not return the correct encoding")
	}
	if !strings.Contains(result, contentType.String()) {
		t.Errorf("prepareMessage() did not return the correct contentType")
	}
	if !strings.Contains(result, quotedPrintableBody) {
		t.Errorf("prepareMessage() did not return the correct body")
	}
	if result != fmt.Sprintf("Content-Transfer-Encoding: %s\r\nContent-Type: %s; charset=%s\r\n\r\n%s", encoding, contentType, charset, quotedPrintableBody) {
		t.Errorf("prepareMessage() did not sucessfully create the message")
	}
}

// TestEncodeMessage tests the TestEncodeMessage method without any encoding
func TestEncodeMessage(t *testing.T) {
	body := "This is the body with special chars like äöü ÄÖÜ ß!"
	encoding := EncodingUSASCII

	privateKey, certificate, intermediateCertificate, err := getDummyRSACryptoMaterial()
	if err != nil {
		t.Errorf("Error getting dummy crypto material: %s", err)
	}

	sMime, err := newSMIME(privateKey, certificate, intermediateCertificate)
	if err != nil {
		t.Errorf("Error creating new SMIME from keyPair: %s", err)
	}

	result, err := sMime.encodeMessage(encoding, []byte(body))
	if err != nil {
		t.Errorf("Error preparing message: %s", err)
	}

	if result != body {
		t.Errorf("encodeMessage() did not return the correct encoded message: %s", result)
	}
}

// TestEncodeMessage_QuotedPrintable tests the TestEncodeMessage method with quoted printable body
func TestEncodeMessage_QuotedPrintable(t *testing.T) {
	body := "This is the body with special chars like äöü ÄÖÜ ß!"
	quotedPrintableBody := "This is the body with special chars like =C3=A4=C3=B6=C3=BC =C3=84=C3=96=C3=\r\n=9C =C3=9F!"
	encoding := EncodingQP

	privateKey, certificate, intermediateCertificate, err := getDummyRSACryptoMaterial()
	if err != nil {
		t.Errorf("Error getting dummy crypto material: %s", err)
	}

	sMime, err := newSMIME(privateKey, certificate, intermediateCertificate)
	if err != nil {
		t.Errorf("Error creating new SMIME from keyPair: %s", err)
	}

	result, err := sMime.encodeMessage(encoding, []byte(body))
	if err != nil {
		t.Errorf("Error preparing message: %s", err)
	}

	if result != quotedPrintableBody {
		t.Errorf("encodeMessage() did not return the correct encoded message: %s", result)
	}
}

// TestEncodeToPEM tests the encodeToPEM method
func TestEncodeToPEM(t *testing.T) {
	message := []byte("This is a test message")

	pemMessage, err := encodeToPEM(message)
	if err != nil {
		t.Errorf("Error encoding message: %s", err)
	}

	base64Encoded := base64.StdEncoding.EncodeToString(message)
	if pemMessage != base64Encoded {
		t.Errorf("encodeToPEM() did not work")
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
	keyPair, err := tls.LoadX509KeyPair(dummyCertECDSAPath, dummyKeyECDSAPath)
	if err != nil {
		return nil, err
	}
	return &keyPair, err
}
