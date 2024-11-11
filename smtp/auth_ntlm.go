// SPDX-FileCopyrightText: Copyright (c) 2024 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package smtp

import (
	"fmt"

	"github.com/Azure/go-ntlmssp"
)

// ErrNTLMChallangeEmpty is returned when the NTLMv2 ChallengeMessage received from the server is empty.
var ErrNTLMChallangeEmpty = fmt.Errorf("NTLMv2 ChallengeMessage is empty")

// ntlmAuth represents a NTLM client and satisfies the smtp.Auth interface.
type ntlmAuth struct {
	domain, password, username, workstation string
	domainNeeded                            bool
}

// NTLMv2Auth creates and returns a new NTLMv2 authentication mechanism with the given
// username and password.
func NTLMv2Auth(username, password, workstation string) Auth {
	user, domain, domainNeeded := ntlmssp.GetDomain(username)
	return &ntlmAuth{
		domain:       domain,
		password:     password,
		username:     user,
		workstation:  workstation,
		domainNeeded: domainNeeded,
	}
}

// Start initializes the NTLMv2 authentication process and returns the algorithm, the negotiation data, and
// a potential error
func (a *ntlmAuth) Start(_ *ServerInfo) (string, []byte, error) {
	negotiateMessage, err := ntlmssp.NewNegotiateMessage(a.domain, a.workstation)
	return "NTLM", negotiateMessage, err
}

// Next processes the server's challenge and returns the client's response for NTLMv2 authentication.
func (a *ntlmAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		if len(fromServer) == 0 {
			return nil, ErrNTLMChallangeEmpty
		}
		authenticateMessage, err := ntlmssp.ProcessChallenge(fromServer, a.username, a.password, a.domainNeeded)
		return authenticateMessage, err
	}
	return nil, nil
}
