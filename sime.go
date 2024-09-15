package mail

import (
	"crypto/rsa"
	"crypto/x509"
)

// SMimeAuthConfig represents the authentication type for s/mime crypto key material
type SMimeAuthConfig struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}
