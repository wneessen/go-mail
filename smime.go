// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"mime/quotedprintable"

	"github.com/wneessen/go-mail/internal/pkcs7"
)

var (
	// ErrInvalidPrivateKey should be used if private key is invalid
	ErrInvalidPrivateKey = errors.New("invalid private key")

	// ErrInvalidCertificate should be used if the certificate is invalid
	ErrInvalidCertificate = errors.New("invalid certificate")
)

// privateKeyHolder is the representation of a private key
type privateKeyHolder struct {
	ecdsa *ecdsa.PrivateKey
	rsa   *rsa.PrivateKey
}

// get returns the private key of the privateKeyHolder
func (p privateKeyHolder) get() crypto.PrivateKey {
	if p.ecdsa != nil {
		return p.ecdsa
	}
	return p.rsa
}

// SMIME is used to sign messages with S/MIME
type SMIME struct {
	privateKey              privateKeyHolder
	certificate             *x509.Certificate
	intermediateCertificate *x509.Certificate
	isSigned                bool
}

// newSMIMEWithRSA construct a new instance of SMIME with provided parameters
// privateKey as *rsa.PrivateKey
// certificate as *x509.Certificate
// intermediateCertificate (optional) as *x509.Certificate
func newSMIMEWithRSA(privateKey *rsa.PrivateKey, certificate *x509.Certificate, intermediateCertificate *x509.Certificate) (*SMIME, error) {
	if privateKey == nil {
		return nil, ErrInvalidPrivateKey
	}

	if certificate == nil {
		return nil, ErrInvalidCertificate
	}

	return &SMIME{
		privateKey:              privateKeyHolder{rsa: privateKey},
		certificate:             certificate,
		intermediateCertificate: intermediateCertificate,
	}, nil
}

// newSMIMEWithECDSA construct a new instance of SMIME with provided parameters
// privateKey as *ecdsa.PrivateKey
// certificate as *x509.Certificate
// intermediateCertificate (optional) as *x509.Certificate
func newSMIMEWithECDSA(privateKey *ecdsa.PrivateKey, certificate *x509.Certificate, intermediateCertificate *x509.Certificate) (*SMIME, error) {
	if privateKey == nil {
		return nil, ErrInvalidPrivateKey
	}

	if certificate == nil {
		return nil, ErrInvalidCertificate
	}

	return &SMIME{
		privateKey:              privateKeyHolder{ecdsa: privateKey},
		certificate:             certificate,
		intermediateCertificate: intermediateCertificate,
	}, nil
}

// signMessage signs the message with S/MIME
func (sm *SMIME) signMessage(message string) (string, error) {
	toBeSigned := bytes.NewBufferString(message)
	signedData, err := pkcs7.NewSignedData(toBeSigned.Bytes())
	if err != nil || signedData == nil {
		return "", fmt.Errorf("failed to initialize signed data: %w", err)
	}

	if err = signedData.AddSigner(sm.certificate, sm.privateKey.get(), pkcs7.SignerInfoConfig{}); err != nil {
		return "", fmt.Errorf("could not add signer message: %w", err)
	}

	if sm.intermediateCertificate != nil {
		signedData.AddCertificate(sm.intermediateCertificate)
	}

	signedData.Detach()

	signatureDER, err := signedData.Finish()
	if err != nil {
		return "", fmt.Errorf("failed to finish signature: %w", err)
	}

	pemMsg, err := encodeToPEM(signatureDER)
	if err != nil {
		return "", fmt.Errorf("could not encode to PEM: %w", err)
	}

	return pemMsg, nil
}

// prepareMessage prepares the message that will be used for the sign method later
func (sm *SMIME) prepareMessage(encoding Encoding, contentType ContentType, charset Charset, body []byte) (*string, error) {
	encodedMessage, err := sm.encodeMessage(encoding, string(body))
	if err != nil {
		return nil, err
	}
	preparedMessage := fmt.Sprintf("Content-Transfer-Encoding: %s\r\nContent-Type: %s; charset=%s\r\n\r\n%s",
		encoding, contentType, charset, encodedMessage)
	return &preparedMessage, nil
}

// encodeMessage encodes the message with the given encoding
func (sm *SMIME) encodeMessage(encoding Encoding, message string) (string, error) {
	if encoding != EncodingQP {
		return message, nil
	}

	buffer := bytes.NewBuffer(nil)
	writer := quotedprintable.NewWriter(buffer)
	if _, err := writer.Write([]byte(message)); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	encodedMessage := buffer.String()
	return encodedMessage, nil
}

// encodeToPEM uses the method pem.Encode from the standard library but cuts the typical PEM preamble
func encodeToPEM(msg []byte) (string, error) {
	block := &pem.Block{Bytes: msg}

	buf := bytes.NewBuffer(nil)
	if err := pem.Encode(buf, block); err != nil {
		return "", err
	}

	return buf.String()[17 : buf.Len()-16], nil
}
