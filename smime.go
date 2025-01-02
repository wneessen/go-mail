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
	"strings"

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
func (sm *SMIME) signMessage(message string) (*string, error) {
	lines := parseLines([]byte(message))
	toBeSigned := lines.bytesFromLines([]byte("\r\n"))

	signedData, err := pkcs7.NewSignedData(toBeSigned)
	if err != nil || signedData == nil {
		return nil, fmt.Errorf("could not initialize signed data: %w", err)
	}

	if err = signedData.AddSigner(sm.certificate, sm.privateKey.get(), pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("could not add signer message: %w", err)
	}

	if sm.intermediateCertificate != nil {
		signedData.AddCertificate(sm.intermediateCertificate)
	}

	signedData.Detach()

	signatureDER, err := signedData.Finish()
	if err != nil {
		return nil, fmt.Errorf("could not finish signing: %w", err)
	}

	pemMsg, err := encodeToPEM(signatureDER)
	if err != nil {
		return nil, fmt.Errorf("could not encode to PEM: %w", err)
	}

	return pemMsg, nil
}

// createMessage prepares the message that will be used for the sign method later
func (sm *SMIME) prepareMessage(encoding Encoding, contentType ContentType, charset Charset, body []byte) (*string, error) {
	encodedMessage, err := sm.encodeMessage(encoding, string(body))
	if err != nil {
		return nil, err
	}
	preparedMessage := fmt.Sprintf("Content-Transfer-Encoding: %v\r\nContent-Type: %v; charset=%v\r\n\r\n%v", encoding, contentType, charset, *encodedMessage)
	return &preparedMessage, nil
}

// encodeMessage encodes the message with the given encoding
func (sm *SMIME) encodeMessage(encoding Encoding, message string) (*string, error) {
	if encoding != EncodingQP {
		return &message, nil
	}

	buffer := bytes.Buffer{}
	writer := quotedprintable.NewWriter(&buffer)
	if _, err := writer.Write([]byte(message)); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	encodedMessage := buffer.String()

	return &encodedMessage, nil
}

// encodeToPEM uses the method pem.Encode from the standard library but cuts the typical PEM preamble
func encodeToPEM(msg []byte) (*string, error) {
	block := &pem.Block{Bytes: msg}

	var arrayBuffer bytes.Buffer
	if err := pem.Encode(&arrayBuffer, block); err != nil {
		return nil, err
	}

	r := arrayBuffer.String()
	r = strings.TrimPrefix(r, "-----BEGIN -----")
	r = strings.Trim(r, "\n")
	r = strings.TrimSuffix(r, "-----END -----")
	r = strings.Trim(r, "\n")

	return &r, nil
}

// line is the representation of one line of the message that will be used for signing purposes
type line struct {
	line      []byte
	endOfLine []byte
}

// lines is the representation of a message that will be used for signing purposes
type lines []line

// bytesFromLines creates the line representation with the given endOfLine char
func (ls lines) bytesFromLines(sep []byte) []byte {
	var raw []byte
	for i := range ls {
		raw = append(raw, ls[i].line...)
		if len(ls[i].endOfLine) != 0 && sep != nil {
			raw = append(raw, sep...)
		} else {
			raw = append(raw, ls[i].endOfLine...)
		}
	}
	return raw
}

// parseLines constructs the lines representation of a given message
func parseLines(raw []byte) lines {
	oneLine := line{raw, nil}
	lines := lines{oneLine}
	lines = lines.splitLine([]byte("\r\n"))
	lines = lines.splitLine([]byte("\r"))
	lines = lines.splitLine([]byte("\n"))
	return lines
}

// splitLine uses the given endOfLine to split the given line
func (ls lines) splitLine(sep []byte) lines {
	nl := lines{}
	for _, l := range ls {
		split := bytes.Split(l.line, sep)
		if len(split) > 1 {
			for i := 0; i < len(split)-1; i++ {
				nl = append(nl, line{split[i], sep})
			}
			nl = append(nl, line{split[len(split)-1], l.endOfLine})
		} else {
			nl = append(nl, l)
		}
	}
	return nl
}
