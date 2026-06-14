// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

package helper

import "testing"

func TestGoVersion(t *testing.T) {
	t.Run("get only major version", func(t *testing.T) {
		tests := []struct {
			version string
			major   float64
			minor   float64
			wantErr bool
		}{
			{
				version: "go1.25.0",
				major:   1.25,
				minor:   1.250,
				wantErr: false,
			},
			{
				version: "go1.25.7",
				major:   1.25,
				minor:   1.2507,
				wantErr: false,
			},
			{
				version: "go1.25.11",
				major:   1.25,
				minor:   1.2511,
				wantErr: false,
			},
			{
				version: "go1.26.1",
				major:   1.26,
				minor:   1.2601,
				wantErr: false,
			},
			{
				version: "go1.26.10",
				major:   1.26,
				minor:   1.261,
				wantErr: false,
			},
		}
		for _, tt := range tests {
			t.Run("get major version: "+tt.version, func(t *testing.T) {
				curVersion = tt.version
				version, err := GetGoVersion(false)
				if (err != nil) != tt.wantErr {
					t.Fatalf("failed to get major Go version: %s", err)
				}
				if version != tt.major {
					t.Fatalf("expected major version %f, got %f", tt.major, version)
				}
			})
			t.Run("get major/minor version: "+tt.version, func(t *testing.T) {
				curVersion = tt.version
				version, err := GetGoVersion(true)
				if (err != nil) != tt.wantErr {
					t.Fatalf("failed to get major Go version: %s", err)
				}
				if version != tt.minor {
					t.Fatalf("expected major/minor version %f, got %f", tt.minor, version)
				}
			})
		}
	})
	t.Run("getting major version fails", func(t *testing.T) {
		curVersion = "go1.26,1"
		_, err := GetGoVersion(false)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})
	t.Run("getting minor version fails", func(t *testing.T) {
		curVersion = "go1.26.a"
		_, err := GetGoVersion(true)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})
	t.Run("non-standard go version string fails", func(t *testing.T) {
		curVersion = "unknown"
		_, err := GetGoVersion(false)
		if err == nil {
			t.Fatalf("expected error, got nil")
		}
	})
}
