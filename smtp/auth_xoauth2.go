// SPDX-FileCopyrightText: Copyright (c) 2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package smtp

type xoauth2Auth struct {
	username, token string
}

func XOAuth2Auth(username, token string) Auth {
	return &xoauth2Auth{username, token}
}

func (a *xoauth2Auth) Start(_ *ServerInfo) (string, []byte, error) {
	return "XOAUTH2", []byte("user=" + a.username + "\x01" + "auth=Bearer " + a.token + "\x01\x01"), nil
}

func (a *xoauth2Auth) Next(_ []byte, more bool) ([]byte, error) {
	if more {
		return []byte(""), nil
	}
	return nil, nil
}
