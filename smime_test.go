package mail

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// TestNewSMime tests the newSMime method
func TestNewSMime(t *testing.T) {
	keyPair, err := getDummyCertificate()
	if err != nil {
		t.Errorf("Error getting dummy certificate: %s", err)
	}

	sMime, err := newSMime(keyPair)
	if err != nil {
		t.Errorf("Error creating new SMime from keyPair: %s", err)
	}

	if sMime.privateKey != keyPair.PrivateKey {
		t.Errorf("NewSMime() did not return the same private key")
	}
	if sMime.certificate != keyPair.Leaf {
		t.Errorf("NewSMime() did not return the same leaf certificate")
	}
}

// TestSign tests the sign method
func TestSign(t *testing.T) {
	keyPair, err := getDummyCertificate()
	if err != nil {
		t.Errorf("Error getting dummy certificate: %s", err)
	}

	sMime, err := newSMime(keyPair)
	if err != nil {
		t.Errorf("Error creating new SMime from keyPair: %s", err)
	}

	message := "This is a test message"
	singedMessage, err := sMime.signMessage(message)
	if err != nil {
		t.Errorf("Error creating singed message: %s", err)
	}

	if *singedMessage == message {
		t.Errorf("Sign() did not work")
	}
}

// TestPrepareMessage tests the createMessage method
func TestPrepareMessage(t *testing.T) {
	keyPair, err := getDummyCertificate()
	if err != nil {
		t.Errorf("Error getting dummy certificate: %s", err)
	}

	sMime, err := newSMime(keyPair)
	if err != nil {
		t.Errorf("Error creating new SMime from keyPair: %s", err)
	}

	encoding := EncodingB64
	contentType := TypeTextPlain
	charset := CharsetUTF8
	body := []byte("This is the body!")
	result := sMime.prepareMessage(encoding, contentType, charset, body)

	if !strings.Contains(result, encoding.String()) {
		t.Errorf("createMessage() did not return the correct encoding")
	}
	if !strings.Contains(result, contentType.String()) {
		t.Errorf("createMessage() did not return the correct contentType")
	}
	if !strings.Contains(result, string(body)) {
		t.Errorf("createMessage() did not return the correct body")
	}
	if result != fmt.Sprintf("Content-Transfer-Encoding: %s\r\nContent-Type: %s; charset=%s\r\n\r\n%s", encoding, contentType, charset, string(body)) {
		t.Errorf("createMessage() did not sucessfully create the message")
	}
}

// TestEncodeToPEM tests the encodeToPEM method
func TestEncodeToPEM(t *testing.T) {
	message := []byte("This is a test message")

	pemMessage, err := encodeToPEM(message)
	if err != nil {
		t.Errorf("Error encoding message: %s", err)
	}

	base64Encoded := base64.StdEncoding.EncodeToString(message)
	if *pemMessage != base64Encoded {
		t.Errorf("encodeToPEM() did not work")
	}
}

// TestBytesFromLines tests the bytesFromLines method
func TestBytesFromLines(t *testing.T) {
	ls := lines{
		{line: []byte("Hello"), endOfLine: []byte("\n")},
		{line: []byte("World"), endOfLine: []byte("\n")},
	}
	expected := []byte("Hello\nWorld\n")

	result := ls.bytesFromLines([]byte("\n"))
	if !bytes.Equal(result, expected) {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

// FuzzBytesFromLines tests the bytesFromLines method with fuzzing
func FuzzBytesFromLines(f *testing.F) {
	f.Add([]byte("Hello"), []byte("\n"))
	f.Fuzz(func(t *testing.T, lineData, sep []byte) {
		ls := lines{
			{line: lineData, endOfLine: sep},
		}
		_ = ls.bytesFromLines(sep)
	})
}

// TestParseLines tests the parseLines method
func TestParseLines(t *testing.T) {
	input := []byte("Hello\r\nWorld\nHello\rWorld")
	expected := lines{
		{line: []byte("Hello"), endOfLine: []byte("\r\n")},
		{line: []byte("World"), endOfLine: []byte("\n")},
		{line: []byte("Hello"), endOfLine: []byte("\r")},
		{line: []byte("World"), endOfLine: []byte("")},
	}

	result := parseLines(input)
	if len(result) != len(expected) {
		t.Errorf("Expected %d lines, but got %d", len(expected), len(result))
	}

	for i := range result {
		if !bytes.Equal(result[i].line, expected[i].line) || !bytes.Equal(result[i].endOfLine, expected[i].endOfLine) {
			t.Errorf("Line %d mismatch. Expected line: %s, endOfLine: %s, got line: %s, endOfLine: %s",
				i, expected[i].line, expected[i].endOfLine, result[i].line, result[i].endOfLine)
		}
	}
}

// FuzzParseLines tests the parseLines method with fuzzing
func FuzzParseLines(f *testing.F) {
	f.Add([]byte("Hello\nWorld\r\nAnother\rLine"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_ = parseLines(input)
	})
}

// TestSplitLine tests the splitLine method
func TestSplitLine(t *testing.T) {
	ls := lines{
		{line: []byte("Hello\r\nWorld\r\nAnotherLine"), endOfLine: []byte("")},
	}
	expected := lines{
		{line: []byte("Hello"), endOfLine: []byte("\r\n")},
		{line: []byte("World"), endOfLine: []byte("\r\n")},
		{line: []byte("AnotherLine"), endOfLine: []byte("")},
	}

	result := ls.splitLine([]byte("\r\n"))
	if len(result) != len(expected) {
		t.Errorf("Expected %d lines, but got %d", len(expected), len(result))
	}

	for i := range result {
		if !bytes.Equal(result[i].line, expected[i].line) || !bytes.Equal(result[i].endOfLine, expected[i].endOfLine) {
			t.Errorf("Line %d mismatch. Expected line: %s, endOfLine: %s, got line: %s, endOfLine: %s",
				i, expected[i].line, expected[i].endOfLine, result[i].line, result[i].endOfLine)
		}
	}
}

// FuzzSplitLine tests the parseLsplitLineines method with fuzzing
func FuzzSplitLine(f *testing.F) {
	f.Add([]byte("Hello\r\nWorld"), []byte("\r\n"))
	f.Fuzz(func(t *testing.T, input, sep []byte) {
		ls := lines{
			{line: input, endOfLine: []byte("")},
		}
		_ = ls.splitLine(sep)
	})
}
