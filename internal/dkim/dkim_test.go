package dkim

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
)

// equaler is an interface for comparing public keys
type equaler interface {
	Equal(crypto.PublicKey) bool
}

const (
	testDomain   = "example.com"
	testSelector = "2026a"
)

var (
	testKeyEd25519 = []byte(`-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPEZCuuDQ2PIH1RDbMl92DIb8Vsqz2j7B26aHomVq1pU
-----END PRIVATE KEY-----`)

	testKeyRSA = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCqUtV4PV2kTmkW
ti9PxJ0atHVu7Jf5zMNMHNy+prWCqSqDlz8Tz6weRiuP7+a7vGliCQHr02etzz0r
lPJ+tTXw/18/B49+1BWu3ves2d7N67IIziRIOXkxdSjcfgDqzXrUmtnhMp8nVn1V
YPavr2J1OSuA5sBz3C5GFddurFeR5a3C1BEsqEU0BJtbwX2dreNWGvznK2WgP+nR
1K78uoAsVsviUEqaYvo8Ipvq7+oP2JQqjj7AKZ6JNaOSl9vc0MY89bveSW7NksyJ
W2YNAuGxhkbPzjYu/8UwPv7vS/zTZjzZ55d5MDVwafqVWNOqxmqLPKO4D2x6HaQ6
WVnmkcq7AgMBAAECggEABT0IoFWW1Vbgbliw1NH+h+kZRtqGlSHu+1ploR5GnCAO
jHJoPDQd0ZF62sbxqy8VUkGqVNP1hFSvJU9/q0S1Ciu0QHTqXyOFUxGzWNqB5YZM
8H+n59Bb6CnvRFsxeY/LB+NC8Vy7xxtiggl+gzT0uqArif29yCWmfo5Tv4bx4vFL
bv04dm5JIcWpsmBuXVQcjRI1axmwbBATvMagQ/iwEB5OHxG0Z5Xf/c6ivEDeVkVX
+CIDyMmj2wcqz0Ao98x1IOUtN1c6HTD1FaeLJHFg2l2aj6RBwcTFWfEpjHIQz3Ul
oe7FJxwi9RefoX/KNGmv46zc0Jssx3ZuPg0KjH00eQKBgQDLu9osJc+MfLw2vKlF
nwb+V8gf7cYZqw6fFLhbpugKe/Y/8lbvgmBUp19wEcGeD770MtY8NWVqEzqSOYkg
JQF9sxjOIotqad0ZAwYohVM9hHIcaMCgDfRPFYrrz5s6mSE/PIAr1bnAFO0LLChj
pcCHPi+dNzvpkPEODBCBui8PAwKBgQDWBMa6w9GXu7l2i64clU6EWgPrymKXxBq2
2m218r3B5ZJiKet+hHF3wC2w6kv0TAGdi3fj6FizVRqofQrlMgIydT2YvOjTByaJ
nXYupGvE6KLGQGgfIf1Tv0k+8cv04AlJLI2xnijPc+A2vDpnJU0B5tzcfS2ctsSa
7dFY/AgL6QKBgH/0Eyn29Ur+bBbUllsrbXEAIKgs5WXpkN1IXiDxynoLMLUotoDm
GSoRlFcGT9u9d+hWpUZbIr5kJT0A9aZCl5UijkmoWHcU1c+Hnq6ETastK528DH55
RR8GIKHJWWyMD91vWfAt4uNIQTfrG9K5nxlRbQYIUpB2f26bFSLkk/mRAoGAZtI4
n/YANkPMYLXO2pCo/lE43QmIwJ1IsFzUpLuQix0+bMbzCv+afAvqZ7rI7v+tLwGY
gfhY1R+oBRa+K0sRXyiQhVcNDIW88BSkeNgpppqVyWWcIIj16kxWZlVIxcb07yDm
mlUAClsDd4iLDo8PJkDCD3Rce5QbdMuY7oV3YDECgYA/nf2B5Qo2im4w9GiCMYIr
E6IylAS2062WYGJVnSNrcfWn8uO9Z2VSNCwTpsvdTxugpe5e8kLHr2BbLypUyyau
wJzNCYNbFNw2GX2AE4G9bjGigkRfzOzG465xsZ178EgqW05MFtdNSSSUyvNMdJtb
hcSTp1LpV7OWf4eUXzgnZQ==
-----END PRIVATE KEY-----`)
)

func TestNewSigner(t *testing.T) {
	t.Run("a signer is successfully returned", func(t *testing.T) {
		signer := NewSigner(testDomain, testSelector, nil)
		if signer == nil {
			t.Fatal("a nil signer was returned")
		}
		if signer.Domain != testDomain {
			t.Errorf("failed to create DKIM signer, expected domain: %s, got: %s", testDomain, signer.Domain)
		}
		if signer.Selector != testSelector {
			t.Errorf("failed to create DKIM signer, expected selector: %s, got: %s", testSelector, signer.Selector)
		}
	})
	t.Run("signer with different crypto.Signers", func(t *testing.T) {
		tests := []struct {
			name    string
			keyData []byte
		}{
			{"RSA", testKeyRSA},
			{"Ed25519", testKeyEd25519},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				privKey := pemToCryptoSigner(t, test.keyData)
				signer := NewSigner(testDomain, testSelector, privKey)
				if signer == nil {
					t.Fatal("a nil signer was returned")
				}
				if signer.Domain != testDomain {
					t.Errorf("failed to create DKIM signer, expected domain: %s, got: %s", testDomain, signer.Domain)
				}
				if signer.Selector != testSelector {
					t.Errorf("failed to create DKIM signer, expected selector: %s, got: %s", testSelector, signer.Selector)
				}
				if !privKey.Public().(equaler).Equal(signer.Signer.Public()) {
					t.Errorf("failed to create DKIM signer, expected signer: %v, got: %v", privKey.Public(), signer.Signer.Public())
				}
			})
		}
	})
}

func TestSigner_ValidateConfig(t *testing.T) {
	t.Run("valid signer config succeeds", func(t *testing.T) {
		tests := []struct {
			name    string
			keyData []byte
		}{
			{"RSA", testKeyRSA},
			{"Ed25519", testKeyEd25519},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				privKey := pemToCryptoSigner(t, test.keyData)
				signer := NewSigner(testDomain, testSelector, privKey)
				if signer == nil {
					t.Fatal("a nil signer was returned")
				}
				if err := signer.ValidateConfig(); err != nil {
					t.Errorf("failed to validate signer config: %s", err)
				}
			})
		}
	})
	t.Run("signer config with ecDSA private key fails", func(t *testing.T) {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ecDSA private key: %s", err)
		}
		signer := NewSigner(testDomain, testSelector, privKey)
		if signer == nil {
			t.Fatal("a nil signer was returned")
		}
		err = signer.ValidateConfig()
		if err == nil {
			t.Errorf("expected an error, got nil")
		}
		if !errors.Is(err, ErrDKIMInvalidSigner) {
			t.Errorf("expected ErrDKIMInvalidSigner, got %s", err)
		}
	})
}

func pemToCryptoSigner(t *testing.T, keyBytes []byte) crypto.Signer {
	t.Helper()
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		t.Fatalf("no valid PEM data found")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse PKCS8 private key: %s", err)
	}
	switch key := key.(type) {
	case *rsa.PrivateKey:
		return key
	case ed25519.PrivateKey:
		return key
	}
	t.Fatalf("invalid key type: %T", key)
	return nil
}
