// SPDX-FileCopyrightText: The go-mail Authors
//
// SPDX-License-Identifier: MIT

package dkim

import "strings"

// headerStore holds parsed DKIM headers, keyed by lowercased field name.
type headerStore struct {
	byName map[string][]string
}

// parseHeader parses the raw header block into a headerStore
func parseHeaders(raw []byte) *headerStore {
	store := &headerStore{
		byName: map[string][]string{},
	}
	var cur strings.Builder
	for line := range strings.SplitSeq(string(raw), "\r\n") {
		if line == "" {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' { // continuation
			cur.WriteString("\r\n")
			cur.WriteString(line)
			continue
		}
		store.add(cur.String())
		cur.Reset()
		cur.WriteString(line)
	}
	store.add(cur.String())
	return store
}

// add adds a parsed line to the headerStore
func (vals *headerStore) add(line string) {
	if line == "" {
		return
	}
	if key, _, ok := strings.Cut(line, ":"); ok {
		key = strings.ToLower(strings.TrimSpace(key))
		vals.byName[key] = append(vals.byName[key], line)
	}
}

// pop removes and returns the bottom-most occurrence, enabling oversigning
// RFC 6376 signs duplicates bottom-up
//
// See: https://www.rfc-editor.org/info/rfc6376/#section-4.2
func (hs *headerStore) pop(name string) (string, bool) {
	key := strings.ToLower(name)
	vals := hs.byName[key]
	if len(vals) == 0 {
		return "", false
	}
	last := vals[len(vals)-1]
	hs.byName[key] = vals[:len(vals)-1]
	return last, true
}

// foldHeader wraps the value on "; " boundaries; verifiers strip folding
// whitespaces from b=, so any folding is safe
func foldHeader(value string) string {
	const limit = 76
	var builder strings.Builder
	length := len("DKIM-Signature: ")
	for _, part := range strings.SplitAfter(value, "; ") {
		if length+len(part) > limit {
			builder.WriteString("\r\n\t")
			length = 1
		}
		builder.WriteString(part)
		length += len(part)
	}
	return builder.String()
}
