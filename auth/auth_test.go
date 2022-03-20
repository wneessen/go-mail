package auth

import (
	"bytes"
	"net/smtp"
	"testing"
)

func TestAuth(t *testing.T) {
	type authTest struct {
		auth       smtp.Auth
		challenges []string
		name       string
		responses  []string
		shouldfail []bool
	}

	authTests := []authTest{
		{LoginAuth("user", "pass", "testserver"),
			[]string{"Username:", "Password:", "2.7.0 Authentication successful", "Invalid:"}, "LOGIN",
			[]string{"", "user", "pass", "", ""}, []bool{false, false, false, true}},
	}

testLoop:
	for i, test := range authTests {
		name, resp, err := test.auth.Start(&smtp.ServerInfo{Name: "testserver", TLS: true, Auth: nil})
		if name != test.name {
			t.Errorf("#%d got name %s, expected %s", i, name, test.name)
		}
		if !bytes.Equal(resp, []byte(test.responses[0])) {
			t.Errorf("#%d got response %s, expected %s", i, resp, test.responses[0])
		}
		if err != nil {
			t.Errorf("#%d error: %s", i, err)
		}
		for j := range test.challenges {
			challenge := []byte(test.challenges[j])
			expected := []byte(test.responses[j+1])
			resp, err := test.auth.Next(challenge, true)
			if err != nil && !test.shouldfail[j] {
				t.Errorf("#%d error: %s", i, err)
				continue testLoop
			}
			if !bytes.Equal(resp, expected) {
				t.Errorf("#%d got %s, expected %s", i, resp, expected)
				continue testLoop
			}
		}
	}
}

func TestAuthLogin(t *testing.T) {
	tests := []struct {
		authName string
		server   *smtp.ServerInfo
		err      string
	}{
		{
			authName: "servername",
			server:   &smtp.ServerInfo{Name: "servername", TLS: true},
		},
		{
			// OK to use LoginAuth on localhost without TLS
			authName: "localhost",
			server:   &smtp.ServerInfo{Name: "localhost", TLS: false},
		},
		{
			// NOT OK on non-localhost, even if server says PLAIN is OK.
			// (We don't know that the server is the real server.)
			authName: "servername",
			server:   &smtp.ServerInfo{Name: "servername", Auth: []string{"PLAIN"}},
			err:      "unencrypted connection",
		},
		{
			authName: "servername",
			server:   &smtp.ServerInfo{Name: "servername", Auth: []string{"CRAM-MD5"}},
			err:      "unencrypted connection",
		},
		{
			authName: "servername",
			server:   &smtp.ServerInfo{Name: "attacker", TLS: true},
			err:      "wrong host name",
		},
	}
	for i, tt := range tests {
		auth := LoginAuth("foo", "bar", tt.authName)
		_, _, err := auth.Start(tt.server)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if got != tt.err {
			t.Errorf("%d. got error = %q; want %q", i, got, tt.err)
		}
	}
}
