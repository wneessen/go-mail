// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"crypto"
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

// SMIME represents the configuration used to sign messages with S/MIME.
//
// This struct encapsulates the private key, certificate, and optional intermediate certificate
// required for S/MIME signing.
//
// Fields:
//   - privateKey: The private key used for signing (implements crypto.PrivateKey).
//   - certificate: The x509 certificate associated with the private key.
//   - intermediateCert: An optional x509 intermediate certificate for chain validation.
//   - isSigned: A flag indicating whether the S/MIME signing is enabled.
type SMIME struct {
	privateKey       crypto.PrivateKey
	certificate      *x509.Certificate
	intermediateCert *x509.Certificate
	isSigned         bool
}

// newSMIME constructs a new instance of SMIME with the provided parameters.
//
// This function initializes an SMIME object with a private key, certificate, and an optional
// intermediate certificate.
//
// Parameters:
//   - privateKey: The private key used for signing (must implement crypto.PrivateKey).
//   - certificate: The x509 certificate associated with the private key.
//   - intermediateCert: An optional x509 intermediate certificate for chain validation.
//
// Returns:
//   - An SMIME instance configured with the provided parameters.
//   - An error if the private key or certificate is missing.
func newSMIME(privateKey crypto.PrivateKey, certificate *x509.Certificate, intermediateCertificate *x509.Certificate) (*SMIME, error) {
	if privateKey == nil {
		return nil, ErrPrivateKeyMissing
	}
	if certificate == nil {
		return nil, ErrCertificateMissing
	}

	return &SMIME{
		privateKey:       privateKey,
		certificate:      certificate,
		intermediateCert: intermediateCertificate,
	}, nil
}

// signMessage signs the given message with S/MIME.
//
// This function uses the configured private key and certificate to create an S/MIME signature
// for the provided message. It optionally includes an intermediate certificate for chain validation.
// The resulting signature is returned in PEM format.
//
// Parameters:
//   - message: The string content of the message to be signed.
//
// Returns:
//   - A string containing the S/MIME signature in PEM format.
//   - An error if any step in the signing process fails, such as initializing signed data, adding a signer,
//     or encoding the signature.
func (s *SMIME) signMessage(message string) (string, error) {
	toBeSigned := bytes.NewBufferString(message)
	signedData, err := pkcs7.NewSignedData(toBeSigned.Bytes())
	if err != nil || signedData == nil {
		return "", fmt.Errorf("failed to initialize signed data: %w", err)
	}

	if err = signedData.AddSigner(s.certificate, s.privateKey, pkcs7.SignerInfoConfig{}); err != nil {
		return "", fmt.Errorf("could not add signer message: %w", err)
	}

	if s.intermediateCert != nil {
		signedData.AddCertificate(s.intermediateCert)
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

// prepareMessage prepares the message for signing with S/MIME.
//
// This function formats the message body with the specified encoding, content type, and character set,
// creating a structured message suitable for S/MIME signing.
//
// Parameters:
//   - encoding: The encoding format to apply to the message body.
//   - contentType: The content type of the message body.
//   - charset: The character set used in the message body.
//   - body: The byte slice representing the message body to be prepared.
//
// Returns:
//   - A string containing the prepared message in the appropriate format.
//   - An error if the message encoding process fails.
func (s *SMIME) prepareMessage(encoding Encoding, contentType ContentType, charset Charset, body []byte) (string, error) {
	encodedMessage, err := s.encodeMessage(encoding, body)
	if err != nil {
		return "", err
	}
	preparedMessage := fmt.Sprintf("Content-Transfer-Encoding: %s\r\nContent-Type: %s; charset=%s\r\n\r\n%s",
		encoding, contentType, charset, encodedMessage)
	return preparedMessage, nil
}

// encodeMessage encodes the message using the specified encoding.
//
// This function applies the given encoding format to the message. If the encoding is not
// Quoted-Printable (QP), the original message is returned as a string.
//
// Parameters:
//   - encoding: The encoding format to apply (e.g., Quoted-Printable).
//   - message: The byte slice representing the message to be encoded.
//
// Returns:
//   - A string containing the encoded message.
//   - An error if the encoding process fails.
func (s *SMIME) encodeMessage(encoding Encoding, message []byte) (string, error) {
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

// encodeToPEM encodes the message to PEM format while removing the typical PEM preamble.
//
// This function uses the standard library's pem.Encode method to convert the message to PEM format.
// It then removes the PEM preamble and footer for a customized output.
//
// Parameters:
//   - msg: The byte slice representing the message to be encoded.
//
// Returns:
//   - A string containing the encoded message in PEM format without the typical preamble and footer.
//   - An error if the encoding process fails.
func encodeToPEM(msg []byte) (string, error) {
	block := &pem.Block{Bytes: msg}
	buffer := bytes.NewBuffer(nil)
	if err := pem.Encode(buffer, block); err != nil {
		return "", err
	}
	return buffer.String()[17 : buffer.Len()-16], nil
}
