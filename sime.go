package mail

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"go.mozilla.org/pkcs7"
)

var (
	// ErrInvalidPrivateKey should be used if private key is invalid
	ErrInvalidPrivateKey = errors.New("invalid private key")

	// ErrInvalidCertificate should be used if certificate is invalid
	ErrInvalidCertificate = errors.New("invalid certificate")

	// ErrCouldNotInitialize should be used if the signed data could not initialize
	ErrCouldNotInitialize = errors.New("could not initialize signed data")

	// ErrCouldNotAddSigner should be used if the signer could not be added
	ErrCouldNotAddSigner = errors.New("could not add signer message")

	// ErrCouldNotFinishSigning should be used if the signing could not be finished
	ErrCouldNotFinishSigning = errors.New("could not finish signing")
)

// SMime is used to sign messages with S/MIME
type SMime struct {
	privateKey  *rsa.PrivateKey
	certificate *x509.Certificate
}

// NewSMime construct a new instance of SMime with a provided *rsa.PrivateKey
func NewSMime(privateKey *rsa.PrivateKey, certificate *x509.Certificate) (*SMime, error) {
	if privateKey == nil {
		return nil, ErrInvalidPrivateKey
	}

	if certificate == nil {
		return nil, ErrInvalidCertificate
	}

	return &SMime{
		privateKey:  privateKey,
		certificate: certificate,
	}, nil
}

// Sign the content with the given privateKey of the method NewSMime
func (sm *SMime) Sign(content []byte) (*string, error) {
	toBeSigned, err := pkcs7.NewSignedData(content)

	toBeSigned.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err != nil {
		return nil, ErrCouldNotInitialize
	}

	if err = toBeSigned.AddSigner(sm.certificate, sm.privateKey, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, ErrCouldNotAddSigner
	}

	signed, err := toBeSigned.Finish()
	if err != nil {
		return nil, ErrCouldNotFinishSigning
	}

	signedData := string(signed)

	return &signedData, nil
}
