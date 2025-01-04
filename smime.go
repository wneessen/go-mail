// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"mime/quotedprintable"

	"github.com/wneessen/go-mail/internal/pkcs7"
)

var (
	// ErrPrivateKeyMissing should be used if private key is invalid
	ErrPrivateKeyMissing = errors.New("private key is missing")

	// ErrCertificateMissing should be used if the certificate is invalid
	ErrCertificateMissing = errors.New("certificate is missing")
)

// SMIME is used to sign messages with S/MIME
type SMIME struct {
	privateKey              crypto.PrivateKey
	certificate             *x509.Certificate
	intermediateCertificate *x509.Certificate
	isSigned                bool
}

// newSMIMEWithRSA construct a new instance of SMIME with provided parameters
// privateKey as *rsa.PrivateKey
// certificate as *x509.Certificate
// intermediateCertificate (optional) as *x509.Certificate
func newSMIME(privateKey crypto.PrivateKey, certificate *x509.Certificate, intermediateCertificate *x509.Certificate) (*SMIME, error) {
	if privateKey == nil {
		return nil, ErrPrivateKeyMissing
	}
	if certificate == nil {
		return nil, ErrCertificateMissing
	}

	return &SMIME{
		privateKey:              privateKey,
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
		return nil, ErrPrivateKeyMissing
	}
	if certificate == nil {
		return nil, ErrCertificateMissing
	}

	return &SMIME{
		privateKey:              privateKey,
		certificate:             certificate,
		intermediateCertificate: intermediateCertificate,
	}, nil
}

// signMessage signs the message with S/MIME
func (s *SMIME) signMessage(message string) (string, error) {
	toBeSigned := bytes.NewBufferString(message)
	signedData, err := pkcs7.NewSignedData(toBeSigned.Bytes())
	if err != nil || signedData == nil {
		return "", fmt.Errorf("failed to initialize signed data: %w", err)
	}

	if err = signedData.AddSigner(s.certificate, s.privateKey, pkcs7.SignerInfoConfig{}); err != nil {
		return "", fmt.Errorf("could not add signer message: %w", err)
	}

	if s.intermediateCertificate != nil {
		signedData.AddCertificate(s.intermediateCertificate)
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
func (s *SMIME) prepareMessage(encoding Encoding, contentType ContentType, charset Charset, body []byte) (string, error) {
	encodedMessage, err := s.encodeMessage(encoding, body)
	if err != nil {
		return "", err
	}
	preparedMessage := fmt.Sprintf("Content-Transfer-Encoding: %s\r\nContent-Type: %s; charset=%s\r\n\r\n%s",
		encoding, contentType, charset, encodedMessage)
	return preparedMessage, nil
}

// encodeMessage encodes the message with the given encoding
func (sm *SMIME) encodeMessage(encoding Encoding, message []byte) (string, error) {
	if encoding != EncodingQP {
		return string(message), nil
	}

	buffer := bytes.NewBuffer(nil)
	writer := quotedprintable.NewWriter(buffer)
	if _, err := writer.Write(message); err != nil {
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
	buffer := bytes.NewBuffer(nil)
	if err := pem.Encode(buffer, block); err != nil {
		return "", err
	}
	return buffer.String()[17 : buffer.Len()-16], nil
}
