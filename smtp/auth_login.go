// SPDX-FileCopyrightText: Copyright (c) 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package smtp

import (
	"errors"
	"fmt"
)

// loginAuth is the type that satisfies the Auth interface for the "SMTP LOGIN" auth
type loginAuth struct {
	username, password string
	host               string
}

const (
	// LoginXUsernameChallenge represents the Username Challenge response sent by the SMTP server per the AUTH LOGIN
	// extension.
	//
	// See: https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-xlogin/.
	LoginXUsernameChallenge = "Username:"

	// LoginXPasswordChallenge represents the Password Challenge response sent by the SMTP server per the AUTH LOGIN
	// extension.
	//
	//	See: https://learn.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-xlogin/.
	LoginXPasswordChallenge = "Password:"

	// LoginXDraftUsernameChallenge represents the Username Challenge response sent by the SMTP server per the IETF
	// draft AUTH LOGIN extension. It should be noted this extension is an expired draft which was never formally
	// published and was deprecated in favor of the AUTH PLAIN extension.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login-00.
	LoginXDraftUsernameChallenge = "User Name\x00"

	// LoginXDraftPasswordChallenge represents the Password Challenge response sent by the SMTP server per the IETF
	// draft AUTH LOGIN extension. It should be noted this extension is an expired draft which was never formally
	// published and was deprecated in favor of the AUTH PLAIN extension.
	//
	// See: https://datatracker.ietf.org/doc/html/draft-murchison-sasl-login-00.
	LoginXDraftPasswordChallenge = "Password\x00"
)

// LoginAuth returns an Auth that implements the LOGIN authentication
// mechanism as it is used by MS Outlook. The Auth works similar to PLAIN
// but instead of sending all in one response, the login is handled within
// 3 steps:
// - Sending AUTH LOGIN (server responds with "Username:")
// - Sending the username (server responds with "Password:")
// - Sending the password (server authenticates)
//
// LoginAuth will only send the credentials if the connection is using TLS
// or is connected to localhost. Otherwise authentication will fail with an
// error, without sending the credentials.
func LoginAuth(username, password, host string) Auth {
	return &loginAuth{username, password, host}
}

func (a *loginAuth) Start(server *ServerInfo) (string, []byte, error) {
	// Must have TLS, or else localhost server.
	// Note: If TLS is not true, then we can't trust ANYTHING in ServerInfo.
	// In particular, it doesn't matter if the server advertises LOGIN auth.
	// That might just be the attacker saying
	// "it's ok, you can trust me with your password."
	if !server.TLS && !isLocalhost(server.Name) {
		return "", nil, errors.New("unencrypted connection")
	}
	if server.Name != a.host {
		return "", nil, errors.New("wrong host name")
	}
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case LoginXUsernameChallenge, LoginXDraftUsernameChallenge:
			return []byte(a.username), nil
		case LoginXPasswordChallenge, LoginXDraftPasswordChallenge:
			return []byte(a.password), nil
		default:
			return nil, fmt.Errorf("unexpected server response: %s", string(fromServer))
		}
	}
	return nil, nil
}
