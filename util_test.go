package mail

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
)

const (
	certFilePath = "dummy-chain-cert.pem"
	keyFilePath  = "dummy-child-key.pem"
)

// getDummyCryptoMaterial loads a certificate and a private key form local disk for testing purposes
func getDummyCryptoMaterial() (*rsa.PrivateKey, *x509.Certificate, *x509.Certificate, error) {
	keyPair, err := tls.LoadX509KeyPair(certFilePath, keyFilePath)
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
