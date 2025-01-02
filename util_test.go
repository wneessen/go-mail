// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
)

const (
	certRSAFilePath = "dummy-chain-cert-rsa.pem"
	keyRSAFilePath  = "dummy-child-key-rsa.pem"

	certECDSAFilePath = "dummy-chain-cert-ecdsa.pem"
	keyECDSAFilePath  = "dummy-child-key-ecdsa.pem"
)

// getDummyRSACryptoMaterial loads a certificate (RSA), the associated private key and certificate (RSA) is loaded from local disk for testing purposes
func getDummyRSACryptoMaterial() (*rsa.PrivateKey, *x509.Certificate, *x509.Certificate, error) {
	keyPair, err := tls.LoadX509KeyPair(certRSAFilePath, keyRSAFilePath)
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

// getDummyECDSACryptoMaterial loads a certificate (ECDSA), the associated private key and certificate (ECDSA) is loaded from local disk for testing purposes
func getDummyECDSACryptoMaterial() (*ecdsa.PrivateKey, *x509.Certificate, *x509.Certificate, error) {
	keyPair, err := tls.LoadX509KeyPair(certECDSAFilePath, keyECDSAFilePath)
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
	keyPair, err := tls.LoadX509KeyPair(certECDSAFilePath, keyECDSAFilePath)
	if err != nil {
		return nil, err
	}
	return &keyPair, err
}
