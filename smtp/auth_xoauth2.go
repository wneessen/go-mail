// SPDX-FileCopyrightText: Copyright (c) The go-mail Authors
//
// SPDX-License-Identifier: MIT

package smtp

type xoauth2Auth struct {
	username, token string
}

// XOAuth2Auth returns an [Auth] that implements the XOAuth2 authentication
// mechanism as defined in the following specs:
//
// https://developers.google.com/gmail/imap/xoauth2-protocol
// https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth
func XOAuth2Auth(username, token string) Auth {
	return &xoauth2Auth{username, token}
}

func (a *xoauth2Auth) Start(server *ServerInfo) (string, []byte, error) {
	// TLS is enforced following RFC 6750 and RFC 7628. Google (developer of
	// the protocol) requires TLS for XOAUTH2. Since it's basically a subtype
	// of a OAUTH2 Bearer token, it should be treated like such secret and
	// transmission via non secure connections should be rejected.
	if !server.TLS {
		return "", nil, ErrUnencrypted
	}
	return "XOAUTH2", []byte("user=" + a.username + "\x01" + "auth=Bearer " + a.token + "\x01\x01"), nil
}

func (a *xoauth2Auth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return []byte(""), nil
	}
	return nil, nil
}
