// Package auth implements the LOGIN and MD5-DIGEST smtp authentication mechanisms
package auth

import (
	"errors"
	"fmt"
	"net/smtp"
)

type loginAuth struct {
	username, password string
	host               string
}

const (
	// ServerRespUsername represents the "Username:" response by the SMTP server
	ServerRespUsername = "Username:"

	// ServerRespPassword represents the "Password:" response by the SMTP server
	ServerRespPassword = "Password:"
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
func LoginAuth(username, password, host string) smtp.Auth {
	return &loginAuth{username, password, host}
}

func isLocalhost(name string) bool {
	return name == "localhost" || name == "127.0.0.1" || name == "::1"
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
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
		case ServerRespUsername:
			return []byte(a.username), nil
		case ServerRespPassword:
			return []byte(a.password), nil
		}
	}
	return nil, fmt.Errorf("unexpected server response: %s", string(fromServer))
}
