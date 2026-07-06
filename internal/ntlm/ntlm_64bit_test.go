// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

//go:build amd64 || arm64 || ppc64 || ppc64le || mips64 || mips64le || s390x || riscv64 || loong64 || wasm

package ntlm

import (
	"math"
	"testing"
)

func Test_toUint32_64bitonly(t *testing.T) {
	tests := []struct {
		name    string
		input   int
		want    uint32
		wantErr bool
	}{
		// These test cases only make sense where int is wider than 32 bits
		// (i.e. 64-bit platforms). On 32-bit, int can't hold these values.
		// https://github.com/wneessen/go-mail/issues/588
		{"max uint32 fits", math.MaxUint32, math.MaxUint32, false},
		{"max uint32 + 1 overflows and fails", math.MaxUint32 + 1, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := toUint32(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("failed to convert int to uint16, got: %s", err)
			}
			if got != tt.want {
				t.Errorf("failed to convert int to uint16, got: %d, want: %d", got, tt.want)
			}
		})
	}
}
