// SPDX-FileCopyrightText: 2022 Winni Neessen <winni@neessen.dev>
//
// SPDX-License-Identifier: MIT

package mail

import "testing"

// TestFile_SetGetHeader tests the set-/getHeader method of the File object
func TestFile_SetGetHeader(t *testing.T) {
	f := File{
		Name:   "testfile.txt",
		Header: make(map[string][]string),
	}
	f.setHeader(HeaderContentType, "text/plain")
	fi, ok := f.getHeader(HeaderContentType)
	if !ok {
		t.Errorf("getHeader method of File did not return a value")
		return
	}
	if fi != "text/plain" {
		t.Errorf("getHeader returned wrong value. Expected: %s, got: %s", "text/plain", fi)
	}
	fi, ok = f.getHeader(HeaderContentTransferEnc)
	if ok {
		t.Errorf("getHeader method of File did return a value, but wasn't supposed to")
		return
	}
	if fi != "" {
		t.Errorf("getHeader returned wrong value. Expected: %s, got: %s", "", fi)
	}
}
