// SPDX-FileCopyrightText: Copyright (c) 2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package smtp

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/secure/precis"
)

type scramAuth struct {
	username, password, algorithm               string
	firstBareMsg, nonce, saltedPwd, authMessage []byte
	iterations                                  int
	h                                           func() hash.Hash
	isPlus                                      bool
	tlsConnState                                *tls.ConnectionState
	bindData                                    []byte
}

func ScramSHA256Auth(username, password string) Auth {
	return &scramAuth{
		username:  username,
		password:  password,
		algorithm: "SCRAM-SHA-256",
		h:         sha256.New,
	}
}

func ScramSHA256PlusAuth(username, password string, tlsConnState *tls.ConnectionState) Auth {
	return &scramAuth{
		username:     username,
		password:     password,
		algorithm:    "SCRAM-SHA-256-PLUS",
		h:            sha256.New,
		isPlus:       true,
		tlsConnState: tlsConnState,
	}
}

func ScramSHA1Auth(username, password string) Auth {
	return &scramAuth{
		username:  username,
		password:  password,
		algorithm: "SCRAM-SHA-1",
		h:         sha1.New,
	}
}

func ScramSHA1PlusAuth(username, password string, tlsConnState *tls.ConnectionState) Auth {
	return &scramAuth{
		username:     username,
		password:     password,
		algorithm:    "SCRAM-SHA-1-PLUS",
		h:            sha1.New,
		isPlus:       true,
		tlsConnState: tlsConnState,
	}
}

func (a *scramAuth) Start(_ *ServerInfo) (string, []byte, error) {
	fmt.Printf("algo: %s\n", a.algorithm)
	return a.algorithm, nil, nil
}

func (a *scramAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		if len(fromServer) == 0 {
			a.reset()
			return a.initialClientMessage()
		}
		switch {
		case bytes.HasPrefix(fromServer, []byte("r=")):
			resp, err := a.handleServerFirstResponse(fromServer)
			if err != nil {
				a.reset()
				return nil, err
			}
			return resp, nil
		case bytes.HasPrefix(fromServer, []byte("v=")):
			resp, err := a.handleServerValidationMessage(fromServer)
			if err != nil {
				a.reset()
				return nil, err
			}
			return resp, nil
		default:
			a.reset()
			return nil, errors.New("unexpected server response")
		}
	}
	return nil, nil
}

func (a *scramAuth) reset() {
	a.nonce = nil
	a.firstBareMsg = nil
	a.saltedPwd = nil
	a.authMessage = nil
	a.iterations = 0
}

func (a *scramAuth) initialClientMessage() ([]byte, error) {
	username, err := a.normalizeUsername()
	if err != nil {
		return nil, fmt.Errorf("username normalization failed: %w", err)
	}

	nonceBuffer := make([]byte, 24)
	if _, err := io.ReadFull(rand.Reader, nonceBuffer); err != nil {
		return nil, fmt.Errorf("unable to generate client secret: %w", err)
	}
	a.nonce = make([]byte, base64.StdEncoding.EncodedLen(len(nonceBuffer)))
	base64.StdEncoding.Encode(a.nonce, nonceBuffer)

	a.firstBareMsg = []byte("n=" + username + ",r=" + string(a.nonce))
	returnBytes := []byte("n,," + string(a.firstBareMsg))

	if a.isPlus {
		bindType := "tls-unique"
		connState := a.tlsConnState
		bindData := connState.TLSUnique
		if connState.Version == tls.VersionTLS13 {
			bindType = "tls-exporter"
			bindData, err = connState.ExportKeyingMaterial("EXPORTER-Channel-Binding", []byte{}, 32)
			if err != nil {
				return nil, fmt.Errorf("unable to export keying material: %w", err)
			}
		}
		bindData = []byte("p=" + bindType + ",," + string(bindData))
		a.bindData = make([]byte, base64.StdEncoding.EncodedLen(len(bindData)))
		base64.StdEncoding.Encode(a.bindData, bindData)
		returnBytes = []byte("p=" + bindType + ",," + string(a.firstBareMsg))
	}

	return returnBytes, nil
}

func (a *scramAuth) handleServerFirstResponse(fromServer []byte) ([]byte, error) {
	parts := bytes.Split(fromServer, []byte(","))
	if len(parts) < 3 {
		return nil, errors.New("not enough fields in the first server response")
	}
	if !bytes.HasPrefix(parts[0], []byte("r=")) {
		return nil, errors.New("first part of the server response does not start with r=")
	}
	if !bytes.HasPrefix(parts[1], []byte("s=")) {
		return nil, errors.New("second part of the server response does not start with s=")
	}
	if !bytes.HasPrefix(parts[2], []byte("i=")) {
		return nil, errors.New("third part of the server response does not start with i=")
	}

	combinedNonce := parts[0][2:]
	if len(a.nonce) == 0 || !bytes.HasPrefix(combinedNonce, a.nonce) {
		return nil, errors.New("server nonce does not start with our nonce")
	}
	a.nonce = combinedNonce

	encodedSalt := parts[1][2:]
	salt := make([]byte, base64.StdEncoding.DecodedLen(len(encodedSalt)))
	n, err := base64.StdEncoding.Decode(salt, encodedSalt)
	if err != nil {
		return nil, fmt.Errorf("invalid encoded salt: %w", err)
	}
	salt = salt[:n]

	iterations, err := strconv.Atoi(string(parts[2][2:]))
	if err != nil {
		return nil, fmt.Errorf("invalid iterations: %w", err)
	}
	a.iterations = iterations

	password, err := a.normalizeString(a.password)
	if err != nil {
		return nil, fmt.Errorf("unable to normalize password: %w", err)
	}

	a.saltedPwd = pbkdf2.Key([]byte(password), salt, a.iterations, a.h().Size(), a.h)

	msgWithoutProof := []byte("c=biws,r=" + string(a.nonce))
	if a.isPlus {
		msgWithoutProof = []byte("c=" + string(a.bindData) + ",r=" + string(a.nonce))
	}
	a.authMessage = []byte(string(a.firstBareMsg) + "," + string(fromServer) + "," + string(msgWithoutProof))

	clientProof := a.computeClientProof()

	return []byte(string(msgWithoutProof) + ",p=" + string(clientProof)), nil
}

func (a *scramAuth) handleServerValidationMessage(fromServer []byte) ([]byte, error) {
	serverSignature := fromServer[2:]
	computedServerSignature := a.computeServerSignature()

	if !hmac.Equal(serverSignature, computedServerSignature) {
		return nil, errors.New("invalid server signature")
	}
	return []byte(""), nil
}

func (a *scramAuth) computeHMAC(key, msg []byte) []byte {
	mac := hmac.New(a.h, key)
	mac.Write(msg)
	return mac.Sum(nil)
}

func (a *scramAuth) computeHash(key []byte) []byte {
	hasher := a.h()
	hasher.Write(key)
	return hasher.Sum(nil)
}

func (a *scramAuth) computeClientProof() []byte {
	clientKey := a.computeHMAC(a.saltedPwd, []byte("Client Key"))
	storedKey := a.computeHash(clientKey)
	clientSignature := a.computeHMAC(storedKey[:], a.authMessage)
	clientProof := make([]byte, len(clientSignature))
	for i := 0; i < len(clientSignature); i++ {
		clientProof[i] = clientKey[i] ^ clientSignature[i]
	}
	buf := make([]byte, base64.StdEncoding.EncodedLen(len(clientProof)))
	base64.StdEncoding.Encode(buf, clientProof)
	return buf
}

func (a *scramAuth) computeServerSignature() []byte {
	serverKey := a.computeHMAC(a.saltedPwd, []byte("Server Key"))
	serverSignature := a.computeHMAC(serverKey, a.authMessage)
	buf := make([]byte, base64.StdEncoding.EncodedLen(len(serverSignature)))
	base64.StdEncoding.Encode(buf, serverSignature)
	return buf
}

func (a *scramAuth) normalizeUsername() (string, error) {
	// RFC 5802 section 5.1: the characters ',' or '=' in usernames are
	// sent as '=2C' and '=3D' respectively.
	replacer := strings.NewReplacer("=", "=3D", ",", "=2C")
	username := replacer.Replace(a.username)
	// RFC 5802 section 5.1: before sending the username to the server,
	// the client SHOULD prepare the username using the "SASLprep"
	// profile [RFC4013] of the "stringprep" algorithm [RFC3454]
	// treating it as a query string (i.e., unassigned Unicode code
	// points are allowed). If the preparation of the username fails or
	// results in an empty string, the client SHOULD abort the
	// authentication exchange.
	//
	// Since RFC 8265 obsoletes RFC 4013 we use it instead.
	username, err := a.normalizeString(username)
	if err != nil {
		return "", fmt.Errorf("unable to normalize username: %w", err)
	}
	return username, nil
}

func (a *scramAuth) normalizeString(s string) (string, error) {
	s, err := precis.OpaqueString.String(s)
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", errors.New("normalized string is empty")
	}
	return s, nil
}
