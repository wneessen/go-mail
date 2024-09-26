package mail

import (
	"crypto/tls"
	"crypto/x509"
)

const (
	certFilePath = "dummy-chain-cert.pem"
	keyFilePath  = "dummy-child-key.pem"
)

func getDummyCertificate() (*tls.Certificate, error) {
	keyPair, err := tls.LoadX509KeyPair(certFilePath, keyFilePath)
	if err != nil {
		return nil, err
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])

	return &keyPair, nil
}
