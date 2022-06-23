// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

package dkim

import (
	"fmt"
	"testing"
)

func TestCanonicalization_String(t *testing.T) {
	tests := []struct {
		n string
		c Canonicalization
		e string
	}{
		{"Relaxed canonizalization", CanonicalizationRelaxed, "relaxed"},
		{"Simple canonizalization", CanonicalizationSimple, "simple"},
		{"Unknown canonizalization", 2, ""},
	}

	for _, tt := range tests {
		t.Run(tt.n, func(t *testing.T) {
			cs := fmt.Sprintf("%s", tt.c)
			if cs != tt.e {
				t.Errorf("Canonizaliation to string conversion failed. Expected: %s, got: %s", tt.e, cs)
			}
		})
	}
}
