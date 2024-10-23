// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"testing"
)

var (
	errClosedWriter = errors.New("writer is already closed")
	errMockDefault  = errors.New("mock write error")
	errMockNewline  = errors.New("mock newline error")
)

func TestBase64LineBreaker(t *testing.T) {
	t.Run("write, copy and close", func(t *testing.T) {
		logoWriter := &bytes.Buffer{}
		lineBreaker := &Base64LineBreaker{out: logoWriter}
		t.Cleanup(func() {
			if err := lineBreaker.Close(); err != nil {
				t.Errorf("failed to close line breaker: %s", err)
			}
		})
		if _, err := lineBreaker.Write([]byte("testdata")); err != nil {
			t.Errorf("failed to write to line breaker: %s", err)
		}
	})
	t.Run("write actual data and compare with expected results", func(t *testing.T) {
		logo, err := os.Open("testdata/logo.svg")
		if err != nil {
			t.Fatalf("failed to open test data file: %s", err)
		}
		t.Cleanup(func() {
			if err := logo.Close(); err != nil {
				t.Errorf("failed to close test data file: %s", err)
			}
		})

		logoWriter := &bytes.Buffer{}
		lineBreaker := &Base64LineBreaker{out: logoWriter}
		t.Cleanup(func() {
			if err := lineBreaker.Close(); err != nil {
				t.Errorf("failed to close line breaker: %s", err)
			}
		})
		base64Encoder := base64.NewEncoder(base64.StdEncoding, lineBreaker)
		t.Cleanup(func() {
			if err := base64Encoder.Close(); err != nil {
				t.Errorf("failed to close base64 encoder: %s", err)
			}
		})
		copiedBytes, err := io.Copy(base64Encoder, logo)
		if err != nil {
			t.Errorf("failed to copy test data to line breaker: %s", err)
		}
		if err = base64Encoder.Close(); err != nil {
			t.Errorf("failed to close base64 encoder: %s", err)
		}
		if err = lineBreaker.Close(); err != nil {
			t.Errorf("failed to close line breaker: %s", err)
		}

		logoStat, err := os.Stat("testdata/logo.svg")
		if err != nil {
			t.Fatalf("failed to stat test data file: %s", err)
		}
		if logoStat.Size() != copiedBytes {
			t.Errorf("copied %d bytes, but expected %d bytes", copiedBytes, logoStat.Size())
		}

		expectedRaw, err := os.ReadFile("testdata/logo.svg.base64")
		if err != nil {
			t.Errorf("failed to read expected base64 data from file: %s", err)
		}
		expected := removeNewLines(t, expectedRaw)
		got := removeNewLines(t, logoWriter.Bytes())
		if !bytes.EqualFold(expected, got) {
			t.Errorf("generated line breaker output differs from expected data")
		}
	})
	t.Run("fail with no writer defined", func(t *testing.T) {
		lineBreaker := &Base64LineBreaker{}
		_, err := lineBreaker.Write([]byte("testdata"))
		if err == nil {
			t.Errorf("writing to Base64LineBreaker with no output io.Writer was supposed to failed, but didn't")
		}
		if !errors.Is(err, ErrNoOutWriter) {
			t.Errorf("unexpected error while writing to empty Base64LineBreaker: %s", err)
		}
		if err := lineBreaker.Close(); err != nil {
			t.Errorf("failed to close Base64LineBreaker: %s", err)
		}
	})
	t.Run("write on an already closed output writer", func(t *testing.T) {
		logo, err := os.Open("testdata/logo.svg")
		if err != nil {
			t.Fatalf("failed to open test data file: %s", err)
		}
		t.Cleanup(func() {
			if err := logo.Close(); err != nil {
				t.Errorf("failed to close test data file: %s", err)
			}
		})

		writeBuffer := &errorWriter{}
		lineBreaker := &Base64LineBreaker{out: writeBuffer}
		_, err = io.Copy(lineBreaker, logo)
		if err == nil {
			t.Errorf("writing to Base64LineBreaker with an already closed output io.Writer was " +
				"supposed to failed, but didn't")
		}
		if !errors.Is(err, errClosedWriter) {
			t.Errorf("unexpected error while writing to Base64LineBreaker: %s", err)
		}
	})
	t.Run("fail on different scenarios with mock writer", func(t *testing.T) {
		tests := []struct {
			name   string
			data   []byte
			writer io.Writer
		}{
			{
				name:   "write data within MaxBodyLength",
				data:   []byte("testdata"),
				writer: &mockWriterExcess{writeError: errMockDefault},
			},
			{
				name: "write data exceeds MaxBodyLength",
				data: []byte("verylongtestdataverylongtestdataverylongtestdata" +
					"verylongtestdataverylongtestdataverylongtestdata"),
				writer: &mockWriterExcess{writeError: errMockDefault},
			},
			{
				name: "write data exceeds MaxBodyLength with newline",
				data: []byte("verylongtestdataverylongtestdataverylongtestdata" +
					"verylongtestdataverylongtestdataverylongtestdata"),
				writer: &mockWriterNewline{writeError: errMockDefault},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				lineBreaker := &Base64LineBreaker{out: tt.writer}

				_, err := lineBreaker.Write(tt.data)
				if err != nil && !errors.Is(err, errMockDefault) && !errors.Is(err, errMockNewline) {
					t.Errorf("unexpected error while writing to mock writer: %s", err)
				}
				err = lineBreaker.Close()
				if err != nil && !errors.Is(err, errMockDefault) && !errors.Is(err, errMockNewline) {
					t.Errorf("unexpected error while closing mock writer: %s", err)
				}
			})
		}
	})
}

// removeNewLines is a test helper thatremoves all newline characters ('\r' and '\n') from the given byte slice.
func removeNewLines(t *testing.T, data []byte) []byte {
	t.Helper()
	result := make([]byte, len(data))
	n := 0

	for _, b := range data {
		if b == '\r' || b == '\n' {
			continue
		}
		result[n] = b
		n++
	}

	return result[0:n]
}

type errorWriter struct{}

func (e errorWriter) Write([]byte) (int, error) {
	return 0, errClosedWriter
}

func (e errorWriter) Close() error {
	return errClosedWriter
}

type mockWriterExcess struct {
	writeError error
}
type mockWriterNewline struct {
	writeError error
}

func (w *mockWriterExcess) Write(p []byte) (n int, err error) {
	switch len(p) {
	case 0:
		return 0, nil
	case 2:
		return 2, nil
	default:
		return len(p), errMockDefault
	}
}

func (w *mockWriterNewline) Write(p []byte) (n int, err error) {
	switch len(p) {
	case 0:
		return 0, nil
	case 2:
		return 2, errMockNewline
	default:
		return len(p), nil
	}
}

func FuzzBase64LineBreaker(f *testing.F) {
	seedData := [][]byte{
		//[]byte(""),
		[]byte("abc"),
		[]byte("def"),
		[]byte("Hello, World!"),
		[]byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!§$%&/()=?`{[]}\\|^~*+#-._'"),
		[]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
		bytes.Repeat([]byte("A"), MaxBodyLength-1),  // Near the line length limit
		bytes.Repeat([]byte("A"), MaxBodyLength),    // Exactly the line length limit
		bytes.Repeat([]byte("A"), MaxBodyLength+1),  // Slightly above the line length limit
		bytes.Repeat([]byte("A"), MaxBodyLength*3),  // Tripple exceed the line length limit
		bytes.Repeat([]byte("A"), MaxBodyLength*10), // Tenfold exceed the line length limit
		{0o0, 0o1, 0o2, 30, 255},
	}
	for _, data := range seedData {
		f.Add(data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var buffer bytes.Buffer
		lineBreaker := &Base64LineBreaker{
			out: &buffer,
		}
		base64Encoder := base64.NewEncoder(base64.StdEncoding, lineBreaker)

		_, err := base64Encoder.Write(data)
		if err != nil {
			t.Errorf("failed to write test data to base64 encoder: %s", err)
		}
		if err = base64Encoder.Close(); err != nil {
			t.Errorf("failed to close base64 encoder: %s", err)
		}
		if err = lineBreaker.Close(); err != nil {
			t.Errorf("failed to close base64 line breaker: %s", err)
		}

		decode, err := base64.StdEncoding.DecodeString(buffer.String())
		if !bytes.Equal(data, decode) {
			t.Error("generated line breaker output differs from original data")
		}
	})
}
