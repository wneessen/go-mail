package mail

import (
	"errors"
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
	if len(sMime.parentCertificates) != len(keyPair.Certificate)-1 {
		t.Errorf("NewSMime() did not return the same number of parentCertificates")
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
	fmt.Println(sMime)
}

// TestCreateMessage tests the createMessage method
func TestCreateMessage(t *testing.T) {
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
	result := sMime.createMessage(encoding, contentType, body)

	if !strings.Contains(result, encoding.String()) {
		t.Errorf("createMessage() did not return the correct encoding")
	}
	if !strings.Contains(result, contentType.String()) {
		t.Errorf("createMessage() did not return the correct contentType")
	}
	if !strings.Contains(result, string(body)) {
		t.Errorf("createMessage() did not return the correct body")
	}
	if result != fmt.Sprintf("Content-Transfer-Encoding: %v\r\nContent-Type: %v; charset=%v\r\n\r\n%v", encoding, contentType, charset, string(body)) {
		t.Errorf("createMessage() did not sucessfully create the message")
	}
}

// TestEncodeToPEM tests the encodeToPEM method
func TestEncodeToPEM(t *testing.T) {

	keyPair, err := getDummyCertificate()
	if err != nil {
		t.Errorf("Error getting dummy certificate: %s", err)
	}

	sMime, err := newSMime(keyPair)
	if err != nil {
		t.Errorf("Error creating new SMime from keyPair: %s", err)
	}
	fmt.Println(sMime)
}

// TestBytesFromLines tests the bytesFromLines method
func TestBytesFromLines(t *testing.T) {

}

// TestParseLines tests the parseLines method
func TestParseLines(t *testing.T) {

}

// TestSplitLine tests the splitLine method
func TestSplitLine(t *testing.T) {

}

func foo(t *testing.T) {
	tl := []struct {
		n  string
		r  SendErrReason
		te bool
	}{
		{"ErrGetSender/temp", ErrGetSender, true},
		{"ErrGetSender/perm", ErrGetSender, false},
		{"ErrGetRcpts/temp", ErrGetRcpts, true},
		{"ErrGetRcpts/perm", ErrGetRcpts, false},
		{"ErrSMTPMailFrom/temp", ErrSMTPMailFrom, true},
		{"ErrSMTPMailFrom/perm", ErrSMTPMailFrom, false},
		{"ErrSMTPRcptTo/temp", ErrSMTPRcptTo, true},
		{"ErrSMTPRcptTo/perm", ErrSMTPRcptTo, false},
		{"ErrSMTPData/temp", ErrSMTPData, true},
		{"ErrSMTPData/perm", ErrSMTPData, false},
		{"ErrSMTPDataClose/temp", ErrSMTPDataClose, true},
		{"ErrSMTPDataClose/perm", ErrSMTPDataClose, false},
		{"ErrSMTPReset/temp", ErrSMTPReset, true},
		{"ErrSMTPReset/perm", ErrSMTPReset, false},
		{"ErrWriteContent/temp", ErrWriteContent, true},
		{"ErrWriteContent/perm", ErrWriteContent, false},
		{"ErrConnCheck/temp", ErrConnCheck, true},
		{"ErrConnCheck/perm", ErrConnCheck, false},
		{"ErrNoUnencoded/temp", ErrNoUnencoded, true},
		{"ErrNoUnencoded/perm", ErrNoUnencoded, false},
		{"ErrAmbiguous/temp", ErrAmbiguous, true},
		{"ErrAmbiguous/perm", ErrAmbiguous, false},
		{"Unknown/temp", 9999, true},
		{"Unknown/perm", 9999, false},
	}

	for _, tt := range tl {
		t.Run(tt.n, func(t *testing.T) {
			if err := returnSendError(tt.r, tt.te); err != nil {
				exp := &SendError{Reason: tt.r, isTemp: tt.te}
				if !errors.Is(err, exp) {
					t.Errorf("error mismatch, expected: %s (temp: %t), got: %s (temp: %t)", tt.r, tt.te,
						exp.Error(), exp.isTemp)
				}
				if !strings.Contains(fmt.Sprintf("%s", err), tt.r.String()) {
					t.Errorf("error string mismatch, expected: %s, got: %s",
						tt.r.String(), fmt.Sprintf("%s", err))
				}
			}
		})
	}
}
