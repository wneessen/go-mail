package smtp

import (
	"fmt"

	"github.com/songxiang93/go-ntlm/ntlm"
)

// NTLMCustomAuth implements the NTLM authentication mechanism for SMTP.
// It holds the necessary information to perform NTLM authentication.
type NTLMCustomAuth struct {
	// session is the NTLM client session used for authentication.
	session ntlm.ClientSession

	// UserName is the username for NTLM authentication.
	UserName string

	// Password is the password for NTLM authentication.
	Password string

	// Domain is the domain name for NTLM authentication.
	Domain string
}

// Start initiates the NTLM authentication process for SMTP.
// It checks if the server supports NTLM, creates an NTLM client session,
// and generates the initial negotiation message.
//
// Parameters:
//   - info: A pointer to ServerInfo containing information about the SMTP server,
//     including supported authentication methods.
//
// Returns:
//   - proto: A string indicating the authentication protocol used ("NTLM").
//   - toServer: A byte slice containing the NTLM negotiate message to be sent to the server.
//   - err: An error if the NTLM authentication method is not supported or if there's an issue
//     creating the NTLM session or generating the negotiation message.
func (a *NTLMCustomAuth) Start(info *ServerInfo) (proto string, toServer []byte, err error) {
	if len(info.Auth) > 0 {
		// check NTLM support in the server's authentication methods
		supported := false
		for _, method := range info.Auth {
			if method == "NTLM" {
				supported = true
			}
		}
		if !supported {
			return "", nil, fmt.Errorf("NTLM auth method not supported")
		}

		// create and configure the NTLM client session
		a.session, err = ntlm.CreateClientSession(ntlm.Version2, ntlm.ConnectionlessMode)
		if err != nil {
			return "", nil, fmt.Errorf("failed to create NTLM client session: %v", err)
		}
		a.session.SetUserInfo(a.UserName, a.Password, a.Domain)
		negotiate, err := a.session.GenerateNegotiateMessage()
		if err != nil {
			return "", nil, fmt.Errorf("failed to generate negotiate message: %v", err)
		}
		return "NTLM", negotiate.Bytes(), nil
	}
	return "NTLM", nil, nil
}

// Next continues the NTLM authentication process by handling the challenge from the server.
// It parses the challenge message, processes it, and generates an "authenticate" message in response.
//
// Parameters:
//   - challengeBytes: A byte slice containing the NTLM challenge message from the server.
//   - more: A boolean indicating whether more authentication steps are expected.
//
// Returns:
//   - toServer: A byte slice containing the NTLM authenticate message to be sent to the server,
//     or nil if no further authentication steps are needed.
//   - err: An error if there's an issue parsing the challenge, processing it, or generating
//     the "authenticate" message. Returns nil if successful or if no further steps are needed.
func (a *NTLMCustomAuth) Next(challengeBytes []byte, more bool) (toServer []byte, err error) {
	// continue the authentication process if more steps are expected (more = true)
	if more {
		// parse the challenge message and process it
		challenge, err := ntlm.ParseChallengeMessage(challengeBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse challenge message: %v", err)
		}
		err = a.session.ProcessChallengeMessage(challenge)
		if err != nil {
			return nil, fmt.Errorf("failed to process challenge message: %v", err)
		}

		// generate the authenticate message in response to the challenge
		authenticate, err := a.session.GenerateAuthenticateMessage()
		if err != nil {
			return nil, fmt.Errorf("failed to generate authenticate message: %v", err)
		}
		return authenticate.Bytes(), nil
	}
	// no further authentication steps are needed, return nil
	return nil, nil
}
