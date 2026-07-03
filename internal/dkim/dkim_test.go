// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

package dkim

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
	"time"
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

	testHeaders                           = []byte("Date: Fri, 03 Jul 2026 22:02:09 +0200\r\nMIME-Version: 1.0\r\nMessage-ID: <hCwhmZssh1Pjbj0_iSP9jx@example.com>\r\nPrecedence: bulk\r\nSubject: This is a DKIM test mail\r\nUser-Agent: go-mail v0.7.3 // https://github.com/wneessen/go-mail\r\nX-Auto-Response-Suppress: All\r\nX-Mailer: go-mail v0.7.3 // https://github.com/wneessen/go-mail\r\nFrom: \"Toni Tester\" <toni.tester@example.com>\r\nTo: \"Tina Tester\" <tina.tester@example.com>\r\nContent-Type: text/plain\r\n")
	testHeadersLineBreak                  = []byte("Date: Fri, 03 Jul 2026 22:02:09 +0200\r\nMIME-Version: 1.0\r\nMessage-ID: <hCwhmZssh1Pjbj0_iSP9jx@example.com>\r\nPrecedence: bulk\r\nSubject: This is a DKIM test mail\r\nUser-Agent: go-mail v0.7.3 //\r\n https://github.com/wneessen/go-mail\r\nX-Auto-Response-Suppress: All\r\nX-Mailer: go-mail v0.7.3 //\r\n https://github.com/wneessen/go-mail\r\nFrom: \"Toni Tester\" <toni.tester@example.com>\r\nTo: \"Tina Tester\" <tina.tester@example.com>\r\nContent-Type: text/plain\r\n")
	testSignatureRSARelaxedRelaxed        = "DKIM-Signature: v=1; c=relaxed/relaxed; d=example.com; s=2026a; \r\n a=rsa-sha256; t=1735689600; \r\n h=From:To:Subject:Date:Message-ID:Content-Type:MIME-Version; \r\n bh=2mAkmyqm5RGR3nEPPQFq6mUlRBUWmTYQzNyx4qVNL+4=; b=FFSkJLeSbG7bB1orMrGBRCXF\r\n laP8F5sRHa7hpy5uffrW487wOmR0SzuS81nUwTmW37WNs8OCjloiVEPCeSwkHOw8vnGawdoL9x+\r\n iRh2cKuwBmc1aUx31HPGMFynmq+eZ4BogiABxdPNxLSEzoJgcr6PyJ1u7W0ZX8fPNKMJ8fPbxXK\r\n FeQbV3iLr7HQupfOVOuGC7VJG7bW1Nf+e2hmUQlbqTnPOB5hU3sgFf3vDsEb4GfWTRmaZc1xfJG\r\n eDpWe+62K9kWsoycln0Ch+pK1pEAU/+0ricmUsYVs2FDEvLr44cjqqKReA6QzMgd6Z29sb4UoOo\r\n EsMGbcLRd3h/yKVnfA==\r\n"
	testSignatureRSASimpleRelaxed         = "DKIM-Signature: v=1; c=simple/relaxed; d=example.com; s=2026a; a=rsa-sha256; t=1735689600; h=From:To:Subject:Date:Message-ID:Content-Type:MIME-Version; bh=2mAkmyqm5RGR3nEPPQFq6mUlRBUWmTYQzNyx4qVNL+4=; b=kc+1KwdV74Phm1/ocb3FJa8rEaI6GRq3V6/qZ13qCuhJ+DaG8UEcaajNzuTYO2axAO/EVMpuNDbX/RV5TB7rp15skNFDsyvs4pKUz48vXRBAK6pg3f1l9aisJ8XbPrVmCsreoyxM7PhgJ4oykcmDPU/YjO6sXqHnabW8GTLRNVZ0GC9JX4U5HCQjPJgVWKPqlJ2I30AHQ81CFCoAa8aeSHU6QG8l3FWvOSLwSXZMwrF8l3LFzlTgetVrAGNdI93lNTMoDSiIP0UkbBMYhM5eFlTFFrO2waScKhiYuuqNYxEu4D0HVhnFk071ZTILJqj4+ujBoPlD3CWM/K40SqDANQ==\r\n"
	testSignatureRSARelaxedSimple         = "DKIM-Signature: v=1; c=relaxed/simple; d=example.com; s=2026a; \r\n a=rsa-sha256; t=1735689600; \r\n h=From:To:Subject:Date:Message-ID:Content-Type:MIME-Version; \r\n bh=2mAkmyqm5RGR3nEPPQFq6mUlRBUWmTYQzNyx4qVNL+4=; b=QYziNCWpxrnscm5zlBcilCrN\r\n 9O35n2EFNOt5XPI1SrW5NJ5OKg9g0HuIavGkm2Ss7khGKBKrbvdFP4K5rOyFCSV+7x73GywbBrg\r\n wkdGJhaflCl3istCQSN6mXezvIjY8Cthj238Hka49Yn3++QorcaNwjSGBVB86x/zt7cxozCbr9M\r\n wFeC7My6wVGuXl2poxdmrOmb33oNdRPWNfcoH65BRoZAtzSqwJSHRwxvwjy+n6zeRxgYjrCRtLZ\r\n 54NbX8Hx9+IcE2nLYK5zODHh8/NJ06FSQDVsmxOZaNKlT7UwzKIT1kBsLI3B21qrz7PPwDEQpb5\r\n xe/zNJNLWPeKGQXLHQ==\r\n"
	testSignatureRSASimpleSimple          = "DKIM-Signature: v=1; c=simple/simple; d=example.com; s=2026a; a=rsa-sha256; t=1735689600; h=From:To:Subject:Date:Message-ID:Content-Type:MIME-Version; bh=2mAkmyqm5RGR3nEPPQFq6mUlRBUWmTYQzNyx4qVNL+4=; b=prudIg0nHjZJCwrVi4PCCOKkZpD5vIX4tFS7MNOcOp6IB2WOZx76luotJ5fMSNl54Hkr+dOv2/0V19FdgEc741GC2aHl+g/6vXGlF++ecksmq0a9Gb5mkxuqmZi8bqF4ef7lCEgiw9TST7/9AICVGJ2zXKk5/4ZoFZv+/MNklCj9sr1Ua3lWupMHJ4Szlp4SbCUWNdBQF3KfvvtIhTCgr1BftSuYUxDU4x5QLWIZkzm29crorMxQFyvsXTE/5KpoAHdhbPr6Vgtztdz0vAEabv+ruggeWFM/c6E8zpXmRt1gVr7WjiwuwfeMOtpXbvwgvCUNt2Ifc2E7jn3+9XcOJQ==\r\n"
	testSignatureEd25519RelaxedRelaxed    = "DKIM-Signature: v=1; c=relaxed/relaxed; d=example.com; s=2026a; \r\n a=ed25519-sha256; t=1735689600; \r\n h=From:To:Subject:Date:Message-ID:Content-Type:MIME-Version; \r\n bh=2mAkmyqm5RGR3nEPPQFq6mUlRBUWmTYQzNyx4qVNL+4=; b=B8QM+ik8Bw/2aLaxpNx1CdyO\r\n L9Dwr2afhXJbD2sqHrdSOHYSZquAH8tFLbwtgAywqGqIVKRDWSknSSvNpWLKAg==\r\n"
	testSignatureEd25519SimpleRelaxed     = "DKIM-Signature: v=1; c=simple/relaxed; d=example.com; s=2026a; a=ed25519-sha256; t=1735689600; h=From:To:Subject:Date:Message-ID:Content-Type:MIME-Version; bh=2mAkmyqm5RGR3nEPPQFq6mUlRBUWmTYQzNyx4qVNL+4=; b=x94WyMS99YlHYqtMirhl8HLaHPIFbodhDudhIYqUEZPU3i5jyiubOURPkPIiZOm42yvVVAnfy39UJwEf7OmCDQ==\r\n"
	testSignatureEd25519RelaxedSimple     = "DKIM-Signature: v=1; c=relaxed/simple; d=example.com; s=2026a; \r\n a=ed25519-sha256; t=1735689600; \r\n h=From:To:Subject:Date:Message-ID:Content-Type:MIME-Version; \r\n bh=2mAkmyqm5RGR3nEPPQFq6mUlRBUWmTYQzNyx4qVNL+4=; b=mMdQWCsbPTLmnQFDEcm/xTbS\r\n 69OLlmwJjmVa++01Up0Vw1A9UdQncaxsynWTfvyb8HdaMX3jrxWxGqlju1lgAA==\r\n"
	testSignatureEd25519SimpleSimple      = "DKIM-Signature: v=1; c=simple/simple; d=example.com; s=2026a; a=ed25519-sha256; t=1735689600; h=From:To:Subject:Date:Message-ID:Content-Type:MIME-Version; bh=2mAkmyqm5RGR3nEPPQFq6mUlRBUWmTYQzNyx4qVNL+4=; b=wLva31jPps/gZDbz8T93iS/aW0Xf27wOBCCMf4l8zppW4f0hI3xUzlBWybjebN8LMILMYtSz2V8/4/3D1wCuDQ==\r\n"
	testSignatureRSARelaxedRelaxedAllOpts = "DKIM-Signature: v=1; c=relaxed/relaxed; d=example.com; s=2026a; \r\n a=rsa-sha256; t=1735689600; \r\n h=From:To:Subject:Date:Message-ID:Content-Type:MIME-Version:From:Subject; \r\n bh=nXffKnoOpS7WvIq5EyR20wBzUQYoH5gEEw3eJeAKYus=; x=1735776000; \r\n i=toni.tester@example.com; l=10; b=pCZY4uSwiPIFJqQR/8rtej8sQs2LEh39hp9ex+hx\r\n 75fcFQBA7Xth4UCOUa8mh5TRCx5NaLpWWBztD+U63PXtmyV/UJxK++OFK6olQ+oyKHIhDiM0gdk\r\n 7EUgVzCXUqELDiIyZTJ+GzuKvMR6RV3twCw/WYFziygY+x2mgkAwEs/3pg32+6FMQO4SvcEca/9\r\n AFIdFdReQOxMVDcO466v+SYf79dvk3MIvR9uECIuNBPD3/JIufgdH8EqiZbbNaXLH6ykXCCHO6y\r\n 1GXzR9mtf8EX5n03JB6Az9WDl4bauuf4Orzf+xzULqYBGi8faEM1PQcMifXAgEawiSts0n9l5y1\r\n TQ==\r\n"
	testSignatureHeaderLineBreak          = "DKIM-Signature: v=1; c=relaxed/relaxed; d=example.com; s=2026a; \r\n a=rsa-sha256; t=1735689600; \r\n h=From:To:Subject:Date:Message-ID:Content-Type:MIME-Version; \r\n bh=2mAkmyqm5RGR3nEPPQFq6mUlRBUWmTYQzNyx4qVNL+4=; b=FFSkJLeSbG7bB1orMrGBRCXF\r\n laP8F5sRHa7hpy5uffrW487wOmR0SzuS81nUwTmW37WNs8OCjloiVEPCeSwkHOw8vnGawdoL9x+\r\n iRh2cKuwBmc1aUx31HPGMFynmq+eZ4BogiABxdPNxLSEzoJgcr6PyJ1u7W0ZX8fPNKMJ8fPbxXK\r\n FeQbV3iLr7HQupfOVOuGC7VJG7bW1Nf+e2hmUQlbqTnPOB5hU3sgFf3vDsEb4GfWTRmaZc1xfJG\r\n eDpWe+62K9kWsoycln0Ch+pK1pEAU/+0ricmUsYVs2FDEvLr44cjqqKReA6QzMgd6Z29sb4UoOo\r\n EsMGbcLRd3h/yKVnfA==\r\n"
)

func TestNewSigner(t *testing.T) {
	t.Run("a signer is successfully returned", func(t *testing.T) {
		signer := testSigner(t, testKeyRSA)
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
				signer := testSigner(t, test.keyData)
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
				signer := testSigner(t, test.keyData)
				if err := signer.ValidateConfig(); err != nil {
					t.Errorf("failed to validate signer config: %s", err)
				}
			})
		}
	})
	t.Run("signer config is missing domain", func(t *testing.T) {
		signer := NewSigner("", testSelector, nil)
		if signer == nil {
			t.Fatal("a nil signer was returned")
		}
		if err := signer.ValidateConfig(); err == nil {
			t.Errorf("expected signer config validation to fail with no domain, but got nil")
		}
	})
	t.Run("signer config is missing selector", func(t *testing.T) {
		signer := NewSigner(testDomain, "", nil)
		if signer == nil {
			t.Fatal("a nil signer was returned")
		}
		if err := signer.ValidateConfig(); err == nil {
			t.Errorf("expected signer config validation to fail with no selector, but got nil")
		}
	})
	t.Run("signer config is missing the crypto.Signer", func(t *testing.T) {
		signer := NewSigner(testDomain, testSelector, nil)
		if signer == nil {
			t.Fatal("a nil signer was returned")
		}
		if err := signer.ValidateConfig(); err == nil {
			t.Errorf("expected signer config validation to fail with no signer, but got nil")
		}
	})
	t.Run("signer config is missing the FROM in the headers list", func(t *testing.T) {
		signer := testSigner(t, testKeyRSA)
		signer.SignHeaders("Subject", "To")
		if err := signer.ValidateConfig(); err == nil {
			t.Errorf("expected signer config validation to fail with no signer, but got nil")
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

func TestSigner_AUID(t *testing.T) {
	want := "AUID"
	signer := testSigner(t, testKeyRSA)
	signer.AUID(want)
	if signer.auid != want {
		t.Errorf("expected AUID to be %s, got %s", want, signer.auid)
	}
}

func TestSigner_BodyCanonicalization(t *testing.T) {
	tests := []struct {
		name string
		mode Canonicalization
		want Canonicalization
	}{
		{"relaxed", CanonicalizationRelaxed, CanonicalizationRelaxed},
		{"simple", CanonicalizationSimple, CanonicalizationSimple},
		{"invalid", "invalid", CanonicalizationRelaxed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signer := testSigner(t, testKeyRSA)
			signer.BodyCanonicalization(test.mode)
			if signer.bodyCanonicalization != test.want {
				t.Errorf("expected body canonicalization to be %s, got %s", test.want, signer.bodyCanonicalization)
			}
		})
	}
}

func TestSigner_HeaderCanonicalization(t *testing.T) {
	tests := []struct {
		name string
		mode Canonicalization
		want Canonicalization
	}{
		{"relaxed", CanonicalizationRelaxed, CanonicalizationRelaxed},
		{"simple", CanonicalizationSimple, CanonicalizationSimple},
		{"invalid", "invalid", CanonicalizationRelaxed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signer := testSigner(t, testKeyRSA)
			signer.HeaderCanonicalization(test.mode)
			if signer.headerCanonicalization != test.want {
				t.Errorf("expected header canonicalization to be %s, got %s", test.want, signer.headerCanonicalization)
			}
		})
	}
}

func TestSigner_ExpiresIn(t *testing.T) {
	tests := []struct {
		name       string
		expiration time.Duration
		want       time.Duration
	}{
		{"valid", 3600, 3600},
		{"negative", -1, 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signer := testSigner(t, testKeyRSA)
			signer.ExpiresIn(test.expiration)
			if signer.expiration != test.want {
				t.Errorf("expected expiration to be %s, got %s", test.want, signer.expiration)
			}
		})
	}
}

func TestSigner_OversignHeaders(t *testing.T) {
	t.Run("valid oversign headers", func(t *testing.T) {
		signer := testSigner(t, testKeyRSA)
		signer.OversignHeaders("From", "To", "Subject")
		if len(signer.oversignHeaders) != 3 {
			t.Errorf("expected 3 oversign headers, got %d", len(signer.oversignHeaders))
		}
		for _, header := range signer.oversignHeaders {
			if header != "From" && header != "To" && header != "Subject" {
				t.Errorf("expected oversign header to be one of From, To, Subject, got %s", header)
			}
		}
	})
	t.Run("empty oversign header list", func(t *testing.T) {
		signer := testSigner(t, testKeyRSA)
		signer.OversignHeaders()
		if len(signer.oversignHeaders) != 0 {
			t.Errorf("expected 0 oversign headers, got %d", len(signer.oversignHeaders))
		}
	})
}

func TestSigner_SignHeaders(t *testing.T) {
	t.Run("valid sign headers", func(t *testing.T) {
		signer := testSigner(t, testKeyRSA)
		signer.SignHeaders("From", "To", "Subject")
		if len(signer.signedHeaders) != 3 {
			t.Errorf("expected 3 sign headers, got %d", len(signer.signedHeaders))
		}
		for _, header := range signer.signedHeaders {
			if header != "From" && header != "To" && header != "Subject" {
				t.Errorf("expected sign header to be one of From, To, Subject, got %s", header)
			}
		}
	})
	t.Run("empty sign header list", func(t *testing.T) {
		signer := testSigner(t, testKeyRSA)
		signer.SignHeaders()
		if len(signer.signedHeaders) != 0 {
			t.Errorf("expected 0 sign headers, got %d", len(signer.signedHeaders))
		}
	})
}

func TestSigner_headerListForTag(t *testing.T) {
	t.Run("sign headers only", func(t *testing.T) {
		signer := testSigner(t, testKeyRSA)
		headers := signer.headerListForTag()
		for _, header := range defaultHeader {
			if !slices.Contains(headers, header) {
				t.Errorf("expected default header %q to be part of the tags, but didn't find it", header)
			}
		}
	})
	t.Run("sign headers and oversign headers", func(t *testing.T) {
		signer := testSigner(t, testKeyRSA)
		signer.OversignHeaders("Cc", "From", "Subject")
		headers := signer.headerListForTag()
		for _, header := range append(defaultHeader, "Cc", "From", "Subject") {
			if !slices.Contains(headers, header) {
				t.Errorf("expected default header %q to be part of the tags, but didn't find it", header)
			}
		}
		headerCount := make(map[string]int)
		for _, header := range headers {
			headerCount[header]++
		}
		for _, val := range []string{"From", "Subject"} {
			count, ok := headerCount[val]
			if !ok {
				t.Fatalf("expected header %q to be in the header tags list", val)
			}
			if count != 2 {
				t.Errorf("expected oversign header %q to be in the header tag list twice, got: %d", val, count)
			}
		}
	})
}

func TestSigner_now(t *testing.T) {
	t.Run("now with no value set returns time.Now", func(t *testing.T) {
		signer := testSigner(t, testKeyRSA)
		now := signer.now()
		if now.IsZero() {
			t.Errorf("expected now to be set, got zero value")
		}
	})
	t.Run("nowfunc is set", func(t *testing.T) {
		want := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
		signer := testSigner(t, testKeyRSA)
		signer.NowFunc = func() time.Time {
			return want
		}
		now := signer.now()
		if !now.Equal(want) {
			t.Errorf("expected now to be %s, got %s", want, now)
		}
	})
}

func TestSigner_Sign(t *testing.T) {
	mail, err := os.Open("../../testdata/RFC5322-A1-1.eml")
	if err != nil {
		t.Fatalf("failed to open test mail: %s", err)
	}
	mailBuffer := bytes.NewBuffer(nil)
	if _, err := mailBuffer.ReadFrom(mail); err != nil {
		t.Fatalf("failed reading test mail into memory: %s", err)
	}
	if err := mail.Close(); err != nil {
		t.Errorf("failed to close test mail: %s", err)
	}
	now := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name          string
		privkKey      []byte
		headerCanon   Canonicalization
		bodyCanon     Canonicalization
		changeFunc    func(*Signer)
		wantSignature string
	}{
		{"RSA relaxed/relaxed", testKeyRSA, CanonicalizationRelaxed, CanonicalizationRelaxed, nil, testSignatureRSARelaxedRelaxed},
		{"RSA simple/relaxed", testKeyRSA, CanonicalizationSimple, CanonicalizationRelaxed, nil, testSignatureRSASimpleRelaxed},
		{"RSA relaxed/simple", testKeyRSA, CanonicalizationRelaxed, CanonicalizationSimple, nil, testSignatureRSARelaxedSimple},
		{"RSA simple/simple", testKeyRSA, CanonicalizationSimple, CanonicalizationSimple, nil, testSignatureRSASimpleSimple},
		{"Ed25519 relaxed/relaxed", testKeyEd25519, CanonicalizationRelaxed, CanonicalizationRelaxed, nil, testSignatureEd25519RelaxedRelaxed},
		{"Ed25519 simple/relaxed", testKeyEd25519, CanonicalizationSimple, CanonicalizationRelaxed, nil, testSignatureEd25519SimpleRelaxed},
		{"Ed25519 relaxed/simple", testKeyEd25519, CanonicalizationRelaxed, CanonicalizationSimple, nil, testSignatureEd25519RelaxedSimple},
		{"Ed25519 simple/simple", testKeyEd25519, CanonicalizationSimple, CanonicalizationSimple, nil, testSignatureEd25519SimpleSimple},
		{
			"RSA relaxed/relaxed with all options", testKeyRSA, CanonicalizationRelaxed, CanonicalizationRelaxed,
			func(s *Signer) {
				s.ExpiresIn(time.Hour * 24)
				s.AUID("toni.tester@example.com")
				s.OversignHeaders("From", "Subject")
				s.Bodylength(10)
			},
			testSignatureRSARelaxedRelaxedAllOpts,
		},
		{
			"RSA with default canonicalization", testKeyRSA, CanonicalizationRelaxed, CanonicalizationRelaxed,
			func(s *Signer) {
				s.headerCanonicalization = ""
				s.bodyCanonicalization = ""
			},
			testSignatureRSARelaxedRelaxed,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			signer := testSigner(t, test.privkKey)
			signer.NowFunc = func() time.Time {
				return now
			}
			signer.HeaderCanonicalization(test.headerCanon)
			signer.BodyCanonicalization(test.bodyCanon)

			if test.changeFunc != nil {
				test.changeFunc(signer)
			}

			signature, err := signer.Sign(testHeaders, mailBuffer.Bytes())
			if err != nil {
				t.Errorf("failed to sign mail: %s", err)
			}
			if !strings.EqualFold(signature, test.wantSignature) {
				t.Errorf("signature mismatch: got\n%q\nwant\n%q", signature, test.wantSignature)
			}
		})
	}
	t.Run("Sign with line-broken headers succeeds", func(t *testing.T) {
		signer := testSigner(t, testKeyRSA)
		signer.NowFunc = func() time.Time {
			return now
		}
		signature, err := signer.Sign(testHeadersLineBreak, mailBuffer.Bytes())
		if err != nil {
			t.Errorf("failed to sign message: %s", err)
		}
		if !strings.EqualFold(signature, testSignatureHeaderLineBreak) {
			t.Errorf("signature mismatch: got\n%q\nwant\n%q", signature, testSignatureHeaderLineBreak)
		}
	})
	t.Run("Sign with invalid crypto.Signer fails", func(t *testing.T) {
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ecDSA private key: %s", err)
		}
		signer := NewSigner(testDomain, testSelector, privKey)
		if signer == nil {
			t.Fatal("a nil signer was returned")
		}
		_, err = signer.Sign(testHeaders, mailBuffer.Bytes())
		if err == nil {
			t.Errorf("expected error when signing with invalid crypto.Signer, got nil")
		}
	})
}

func Test_writeFolded(t *testing.T) {
	t.Run("writefold on a normal string", func(t *testing.T) {
		has := "first string "
		want := "hello world"
		wantPosition := len(has) + len(want)

		builder := strings.Builder{}
		builder.WriteString(has)
		position := writeFolded(&builder, want, len(has))
		if position != wantPosition {
			t.Errorf("expected new position to be at %d bytes, got %d", wantPosition, position)
		}
		if builder.String() != has+want {
			t.Errorf("expected folded string %q, got %q", has+want, builder.String())
		}
	})
	t.Run("writefold folds a long string", func(t *testing.T) {
		has := "the first part is already pretty long- and concatinating it, should fold the "
		want := "the additional text"
		wantPosition := len(want) + 1 // the space after the line break

		builder := strings.Builder{}
		builder.WriteString(has)
		position := writeFolded(&builder, want, len(has))
		if position != wantPosition {
			t.Errorf("expected new position to be at %d bytes, got %d", wantPosition, position)
		}
		if builder.String() != has+"\r\n "+want {
			t.Errorf("expected folded string %q, got %q", has+"\r\n "+want, builder.String())
		}
	})
	t.Run("writefold hard-wraps a token longer than a line", func(t *testing.T) {
		has := "start here"
		want := strings.Repeat("x", maxLineLength+20)

		builder := strings.Builder{}
		builder.WriteString(has)
		position := writeFolded(&builder, want, len(has))

		room := maxLineLength - len(has)
		wantOutput := has + want[:room] + "\r\n " + want[room:]
		wantPosition := 1 + len(want) - room

		if position != wantPosition {
			t.Errorf("expected new position at %d bytes, got %d", wantPosition, position)
		}
		if builder.String() != wantOutput {
			t.Errorf("expected folded string %q, got %q", wantOutput, builder.String())
		}
	})
	t.Run("writefold with nil data returns the current position", func(t *testing.T) {
		builder := strings.Builder{}
		position := writeFolded(&builder, "", 0)
		if position != 0 {
			t.Errorf("expected position to be 0, got %d", position)
		}
	})
}

func Test_appendFoldedBase64(t *testing.T) {
	const prefix = len("DKIM-Signature: ")

	t.Run("appends short base64 without folding", func(t *testing.T) {
		foldedTags := "v=1; a=rsa-sha256; c=relaxed/relaxed; "
		sig := "b=shortsig"
		want := foldedTags + sig

		got := appendFoldedBase64(foldedTags, sig)
		if got != want {
			t.Errorf("expected %q, got %q", want, got)
		}
	})
	t.Run("folds base64 when the first line is full", func(t *testing.T) {
		foldedTags := "v=1; a=rsa-sha256; "
		col := prefix + len(foldedTags)
		room := maxLineLength - col
		sig := strings.Repeat("A", room+10)
		want := foldedTags + sig[:room] + "\r\n " + sig[room:]

		got := appendFoldedBase64(foldedTags, sig)
		if got != want {
			t.Errorf("expected %q, got %q", want, got)
		}
	})
	t.Run("computes column from the last CRLF in foldedTags", func(t *testing.T) {
		foldedTags := "v=1; a=rsa-sha256;\r\n c=relaxed/relaxed; "
		i := strings.LastIndex(foldedTags, "\r\n")
		col := len(foldedTags) - (i + 2)
		room := maxLineLength - col
		sig := strings.Repeat("B", room+5)
		want := foldedTags + sig[:room] + "\r\n " + sig[room:]

		got := appendFoldedBase64(foldedTags, sig)
		if got != want {
			t.Errorf("expected %q, got %q", want, got)
		}
	})
	t.Run("hard wraps a long base64 across multiple lines", func(t *testing.T) {
		foldedTags := "b="
		col := prefix + len(foldedTags)
		room := maxLineLength - col
		sig := strings.Repeat("C", room+maxLineLength)

		want := foldedTags + sig[:room] + "\r\n "
		rest := sig[room:]
		for len(rest) > maxLineLength-1 {
			want += rest[:maxLineLength-1] + "\r\n "
			rest = rest[maxLineLength-1:]
		}
		want += rest

		got := appendFoldedBase64(foldedTags, sig)
		if got != want {
			t.Errorf("expected %q, got %q", want, got)
		}
	})
	t.Run("folds immediately when foldedTags already fills the line", func(t *testing.T) {
		lastLine := strings.Repeat("x", maxLineLength-1)
		foldedTags := "v=1;\r\n " + lastLine
		sig := "b=abc"
		want := foldedTags + "\r\n " + sig

		got := appendFoldedBase64(foldedTags, sig)
		if got != want {
			t.Errorf("expected %q, got %q", want, got)
		}
	})
	t.Run("returns foldedTags unchanged for empty signature", func(t *testing.T) {
		foldedTags := "v=1; a=rsa-sha256; b="
		if got := appendFoldedBase64(foldedTags, ""); got != foldedTags {
			t.Errorf("expected %q, got %q", foldedTags, got)
		}
	})
}

// testSigner returns a Signer for testing purposes.
func testSigner(t *testing.T, keyData []byte) *Signer {
	t.Helper()

	privKey := pemToCryptoSigner(t, keyData)
	signer := NewSigner(testDomain, testSelector, privKey)
	if signer == nil {
		t.Fatal("a nil signer was returned")
	}
	return signer
}

// pemToCryptoSigner converts a PEM-encoded private key to a crypto.Signer.
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
