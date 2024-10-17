// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"testing"
	"time"
)

// TestSign_E2E tests S/MIME singing as e2e
func TestSign_E2E(t *testing.T) {
	cert, err := createTestCertificate()
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("Hello World")
	for _, testDetach := range []bool{false, true} {
		toBeSigned, err := newSignedData(content)
		if err != nil {
			t.Fatalf("Cannot initialize signed data: %s", err)
		}
		if err := toBeSigned.addSigner(cert.Certificate, cert.PrivateKey, SignerInfoConfig{}); err != nil {
			t.Fatalf("Cannot add signer: %s", err)
		}
		if testDetach {
			t.Log("Testing detached signature")
			toBeSigned.detach()
		} else {
			t.Log("Testing attached signature")
		}
		signed, err := toBeSigned.finish()
		if err != nil {
			t.Fatalf("Cannot finish signing data: %s", err)
		}
		if err := pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: signed}); err != nil {
			t.Fatalf("Cannot write signed data: %s", err)
		}
	}
}

func TestOpenSSLVerifyDetachedSignature(t *testing.T) {
	rootCert, err := createTestCertificateByIssuer("PKCS7 Test Root CA", nil)
	if err != nil {
		t.Fatalf("Cannot generate root cert: %s", err)
	}
	signerCert, err := createTestCertificateByIssuer("PKCS7 Test Signer Cert", rootCert)
	if err != nil {
		t.Fatalf("Cannot generate signer cert: %s", err)
	}
	content := []byte("Hello World")
	toBeSigned, err := newSignedData(content)
	if err != nil {
		t.Fatalf("Cannot initialize signed data: %s", err)
	}
	if err := toBeSigned.addSigner(signerCert.Certificate, signerCert.PrivateKey, SignerInfoConfig{}); err != nil {
		t.Fatalf("Cannot add signer: %s", err)
	}
	toBeSigned.detach()
	signed, err := toBeSigned.finish()
	if err != nil {
		t.Fatalf("Cannot finish signing data: %s", err)
	}

	// write the root cert to a temp file
	tmpRootCertFile, err := os.CreateTemp("", "pkcs7TestRootCA")
	if err != nil {
		t.Fatal(err)
	}
	defer func(name string) {
		if err := os.Remove(name); err != nil {
			t.Fatalf("Cannot write root cert: %s", err)
		}
	}(tmpRootCertFile.Name()) // clean up
	fd, err := os.OpenFile(tmpRootCertFile.Name(), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(fd, &pem.Block{Type: "CERTIFICATE", Bytes: rootCert.Certificate.Raw}); err != nil {
		t.Fatalf("Cannot write root cert: %s", err)
	}
	if err := fd.Close(); err != nil {
		t.Fatalf("Cannot write root cert: %s", err)
	}

	// write the signature to a temp file
	tmpSignatureFile, err := os.CreateTemp("", "pkcs7Signature")
	if err != nil {
		t.Fatal(err)
	}
	defer func(name string) {
		if err := os.Remove(name); err != nil {
			t.Fatalf("Cannot write signature: %s", err)
		}
	}(tmpSignatureFile.Name()) // clean up
	if err := os.WriteFile(tmpSignatureFile.Name(), signed, 0o755); err != nil {
		t.Fatalf("Cannot write signature: %s", err)
	}

	// write the content to a temp file
	tmpContentFile, err := os.CreateTemp("", "pkcs7Content")
	if err != nil {
		t.Fatal(err)
	}
	defer func(name string) {
		if err := os.Remove(name); err != nil {
			t.Fatalf("Cannot write content: %s", err)
		}
	}(tmpContentFile.Name()) // clean up
	if err := os.WriteFile(tmpContentFile.Name(), content, 0o755); err != nil {
		t.Fatalf("Cannot write content: %s", err)
	}

	// call openssl to verify the signature on the content using the root
	opensslCMD := exec.Command("openssl", "smime", "-verify",
		"-in", tmpSignatureFile.Name(), "-inform", "DER",
		"-content", tmpContentFile.Name(),
		"-CAfile", tmpRootCertFile.Name())
	out, err := opensslCMD.Output()
	t.Logf("%s", out)
	if err != nil {
		t.Fatalf("openssl command failed with %s", err)
	}
}

type certKeyPair struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

func createTestCertificate() (*certKeyPair, error) {
	signer, err := createTestCertificateByIssuer("Eddard Stark", nil)
	if err != nil {
		return nil, err
	}
	fmt.Println("Created root cert")
	if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: signer.Certificate.Raw}); err != nil {
		return nil, err
	}
	pair, err := createTestCertificateByIssuer("Jon Snow", signer)
	if err != nil {
		return nil, err
	}
	fmt.Println("Created signer cert")
	if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate.Raw}); err != nil {
		return nil, err
	}
	return pair, nil
}

func createTestCertificateByIssuer(name string, issuer *certKeyPair) (*certKeyPair, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 32)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber:       serialNumber,
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"Acme Co"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	var issuerCert *x509.Certificate
	var issuerKey crypto.PrivateKey
	if issuer != nil {
		issuerCert = issuer.Certificate
		issuerKey = issuer.PrivateKey
	} else {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		issuerCert = &template
		issuerKey = priv
	}
	cert, err := x509.CreateCertificate(rand.Reader, &template, issuerCert, priv.Public(), issuerKey)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(cert)
	if err != nil {
		return nil, err
	}
	return &certKeyPair{
		Certificate: leaf,
		PrivateKey:  priv,
	}, nil
}
