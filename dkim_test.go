// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"testing"
)

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

	testKeyRSAPKCS1 = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDrR8LgINQIN+jUkt0+OYFlDqf4hT10x9jRUMMg/NrcG/h5mP9B
7KU2TGUIt3ItetSB/ltfaIsOeEtns2eAGVzz77cQodWC9qWkYbuou9xQNbL2jNFF
aFA30p5E8iupp9dndm2nJXws5EjCp/JEYRGeYW7kgAWFNvDFnTng7M1lXQIDAQAB
AoGAW2F90OsvLxn39kgsYfSXyxZMKvwlCGxuS63ge7l5j6/Va/T+fy5YZKR7QU1u
rTddvjd6aa4DBFW4g8hsVJaFQQKVRngIK5pMCk6wrBVW1glCAKeQ1ie2bZt0LvYs
9HLnthpaZxU/eaFpgwUvmZVPgV1uLRe4MxeotHi9cW27PUECQQD6eOHmCHnd6pmx
MBj5/xL86x3Ldyf/axyUC7SUIotIzsbkrmd6PSjFENFAKvTU/oOdleVpyAAgw92e
Ykey+NAlAkEA8HkMOUUk6RpCPTe3M76XMaje9Hf3yinyIZG3BjILue402rfaJ0m6
eRmGcsuRO5CIezz2GL3dHCvwfU3kOMw+2QJBAMH0a5FSzPPgX+VKhnzIXa7GbksJ
WUq7aeTmb44qdcsKfA/HUc/hnjmDvVXALdjlwYt88KqKOjclFO850aWwcJUCQA0M
RGGHIu2TAy0XLNWd7c4//3j8WXGavQydP3USmhhImI2VlDy1f2y6udTYvtSgjwdA
04mcI7c3myDxbQS38GECQQDnZMASDyQE+/CK8plckVrGGcy+X/8EGta+HeK0ZH3E
UDKil5X2rYZq+ADN7yEYh9f9i9da/ngzkaog1TvcLqpJ
-----END RSA PRIVATE KEY-----`)

	testKeyECDSA = []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINPqdWSVBy9EvOpJX4UY9jt4fGEsmluDZMpPIipdmLRloAoGCCqGSM49
AwEHoUQDQgAEcCgO5Z7nsPCejY8fNCBN7LGIA6QXxqERjQ5oC0aqp4UPpi/Le4zf
nVcSsVa47l739jl+jqC2yQYVjTvst/+Dyg==
-----END EC PRIVATE KEY-----`)

	testKeyECDSAPKCS8 = []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1ajprHhlC1/J4YXs
t1fwAS19v+kHh+UDcz/8ltM8XpChRANCAASoHEYSvB4X9KWX8eQ0spf+OLkIJg5v
4LXlgz/dkVsxbMM9zM9usBTi3WCTMggJvZemZQTW2MVV677Q4QynRqSG
-----END PRIVATE KEY-----`)
)

func TestNewDKIMSigner(t *testing.T) {
	tests := []struct {
		name    string
		keyData []byte
	}{
		{"Signer with RSA key", testKeyRSA},
		{"Signer with Ed25519 key", testKeyEd25519},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			privKey, err := PrivKeyFromPEM(test.keyData)
			if err != nil {
				t.Fatalf("failed to read private key from PEM: %s", err)
			}
			signer := NewDKIMSigner(testDomain, testSelector, privKey)
			if signer == nil {
				t.Fatal("signer is nil")
			}
		})
	}
}

func TestPrivKeyFromPEM(t *testing.T) {
	t.Run("RSA key succeeds", func(t *testing.T) {
		_, err := PrivKeyFromPEM(testKeyRSA)
		if err != nil {
			t.Fatalf("failed to read private key from PEM: %s", err)
		}
	})
	t.Run("RSA key succeeds (PKCS#1)", func(t *testing.T) {
		_, err := PrivKeyFromPEM(testKeyRSAPKCS1)
		if err != nil {
			t.Fatalf("failed to read private key from PEM: %s", err)
		}
	})
	t.Run("Ed25519 key succeeds", func(t *testing.T) {
		_, err := PrivKeyFromPEM(testKeyEd25519)
		if err != nil {
			t.Fatalf("failed to read private key from PEM: %s", err)
		}
	})
	t.Run("ecDSA key is not supported", func(t *testing.T) {
		_, err := PrivKeyFromPEM(testKeyECDSA)
		if err == nil {
			t.Fatal("expected ecDSA to fail as unsupported")
		}
	})
	t.Run("ecDSA key is not supported (PKCS#8)", func(t *testing.T) {
		_, err := PrivKeyFromPEM(testKeyECDSAPKCS8)
		if err == nil {
			t.Fatal("expected ecDSA to fail as unsupported")
		}
	})
	t.Run("nil byte key fails", func(t *testing.T) {
		_, err := PrivKeyFromPEM(nil)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})
}
