// SPDX-FileCopyrightText: Copyright (c) 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package smtp

import "fmt"

// XOAuth2Variant describes a int alias for the different XOAuth2 variants we support
type XOAuth2Variant int

// Supported XOAuth2 variants
const (
	// XOAuth2VariantGoogle is the Google variant for "XOAUTH2" SASL authentication mechanism.
	// https://developers.google.com/gmail/imap/xoauth2-protocol
	XOAuth2VariantGoogle XOAuth2Variant = iota

	// XOAuth2VariantMicrosoft is the Microsoft variant for "XOAUTH2" SASL authentication mechanism.
	// https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth
	XOAuth2VariantMicrosoft
)

// String is a standard method to convert a XOAuth2Variant into a printable format
func (v XOAuth2Variant) String() string {
	switch v {
	case XOAuth2VariantGoogle:
		return "Google"
	case XOAuth2VariantMicrosoft:
		return "Microsoft"
	default:
		return "Unknown XOAuth2 variant"
	}
}

type xoauth2Auth struct {
	username, token string
	variant         XOAuth2Variant
}

func XOAuth2Auth(username, token string, variant XOAuth2Variant) Auth {
	return &xoauth2Auth{username, token, variant}
}

func (a *xoauth2Auth) getToken() []byte {
	return []byte("user=" + a.username + "\x01" + "auth=Bearer " + a.token + "\x01\x01")
}

func (a *xoauth2Auth) Start(_ *ServerInfo) (string, []byte, error) {
	switch a.variant {
	case XOAuth2VariantGoogle:
		return "XOAUTH2", a.getToken(), nil
	case XOAuth2VariantMicrosoft:
		return "XOAUTH2", nil, nil
	default:
		return "", nil, fmt.Errorf("unsupported XOAuth2 variant %d", a.variant)
	}
}

func (a *xoauth2Auth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		switch a.variant {
		case XOAuth2VariantGoogle:
			return []byte(""), nil
		case XOAuth2VariantMicrosoft:
			return a.getToken(), nil
		default:
			return nil, fmt.Errorf("unsupported XOAuth2 variant %d", a.variant)
		}
	}
	return nil, nil
}
