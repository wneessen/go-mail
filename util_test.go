package mail

import (
	"crypto/tls"
)

const (
	certFilePath = "dummy-cert.pem"
	keyFilePath  = "dummy=key.pem"
)

func getDummyCertificate() (*tls.Certificate, error) {
	keyPair, err := tls.LoadX509KeyPair(certFilePath, keyFilePath)
	if err != nil {
		return nil, err
	}

	return &keyPair, nil
}
