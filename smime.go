package mail

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"go.mozilla.org/pkcs7"
	"strings"
)

var (
	// ErrInvalidKeyPair should be used if key pair is invalid
	ErrInvalidKeyPair = errors.New("invalid key pair")

	// ErrCouldNotInitialize should be used if the signed data could not initialize
	ErrCouldNotInitialize = errors.New("could not initialize signed data")

	// ErrCouldNotAddSigner should be used if the signer could not be added
	ErrCouldNotAddSigner = errors.New("could not add signer message")

	// ErrCouldNotFinishSigning should be used if the signing could not be finished
	ErrCouldNotFinishSigning = errors.New("could not finish signing")

	// ErrCouldNoEncodeToPEM should be used if the signature could not be encoded to PEM
	ErrCouldNoEncodeToPEM = errors.New("could not encode to PEM")
)

// SMime is used to sign messages with S/MIME
type SMime struct {
	privateKey  *rsa.PrivateKey
	certificate *x509.Certificate
}

// NewSMime construct a new instance of SMime with a provided *tls.Certificate
func newSMime(keyPair *tls.Certificate) (*SMime, error) {
	if keyPair == nil {
		return nil, ErrInvalidKeyPair
	}

	return &SMime{
		privateKey:  keyPair.PrivateKey.(*rsa.PrivateKey),
		certificate: keyPair.Leaf,
	}, nil
}

// signMessage signs the message with S/MIME
func (sm *SMime) signMessage(message string) (*string, error) {
	lines := parseLines([]byte(message))
	toBeSigned := lines.bytesFromLines([]byte("\r\n"))

	signedData, err := pkcs7.NewSignedData(toBeSigned)
	signedData.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)
	if err != nil {
		return nil, ErrCouldNotInitialize
	}

	if err = signedData.AddSigner(sm.certificate, sm.privateKey, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, ErrCouldNotAddSigner
	}

	signedData.Detach()

	signatureDER, err := signedData.Finish()
	if err != nil {
		return nil, ErrCouldNotFinishSigning
	}

	pemMsg, err := encodeToPEM(signatureDER)
	if err != nil {
		return nil, ErrCouldNoEncodeToPEM
	}

	return pemMsg, nil
}

// createMessage prepares the message that will be used for the sign method later
func (sm *SMime) prepareMessage(encoding Encoding, contentType ContentType, charset Charset, body []byte) string {
	return fmt.Sprintf("Content-Transfer-Encoding: %v\r\nContent-Type: %v; charset=%v\r\n\r\n%v", encoding, contentType, charset, string(body))
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
