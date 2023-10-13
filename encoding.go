// SPDX-FileCopyrightText: 2022-2023 The go-mail Authors
//
// SPDX-License-Identifier: MIT

package mail

// Charset represents a character set for the encoding
type Charset string

// ContentType represents a content type for the Msg
type ContentType string

// Encoding represents a MIME encoding scheme like quoted-printable or Base64.
type Encoding string

// MIMEVersion represents the MIME version for the mail
type MIMEVersion string

// MIMEType represents the MIME type for the mail
type MIMEType string

// List of supported encodings
const (
	// EncodingB64 represents the Base64 encoding as specified in RFC 2045.
	EncodingB64 Encoding = "base64"

	// EncodingQP represents the "quoted-printable" encoding as specified in RFC 2045.
	EncodingQP Encoding = "quoted-printable"

	// NoEncoding avoids any character encoding (except of the mail headers)
	NoEncoding Encoding = "8bit"
)

// List of common charsets
const (
	// CharsetUTF7 represents the "UTF-7" charset
	CharsetUTF7 Charset = "UTF-7"

	// CharsetUTF8 represents the "UTF-8" charset
	CharsetUTF8 Charset = "UTF-8"

	// CharsetASCII represents the "US-ASCII" charset
	CharsetASCII Charset = "US-ASCII"

	// CharsetISO88591 represents the "ISO-8859-1" charset
	CharsetISO88591 Charset = "ISO-8859-1"

	// CharsetISO88592 represents the "ISO-8859-2" charset
	CharsetISO88592 Charset = "ISO-8859-2"

	// CharsetISO88593 represents the "ISO-8859-3" charset
	CharsetISO88593 Charset = "ISO-8859-3"

	// CharsetISO88594 represents the "ISO-8859-4" charset
	CharsetISO88594 Charset = "ISO-8859-4"

	// CharsetISO88595 represents the "ISO-8859-5" charset
	CharsetISO88595 Charset = "ISO-8859-5"

	// CharsetISO88596 represents the "ISO-8859-6" charset
	CharsetISO88596 Charset = "ISO-8859-6"

	// CharsetISO88597 represents the "ISO-8859-7" charset
	CharsetISO88597 Charset = "ISO-8859-7"

	// CharsetISO88599 represents the "ISO-8859-9" charset
	CharsetISO88599 Charset = "ISO-8859-9"

	// CharsetISO885913 represents the "ISO-8859-13" charset
	CharsetISO885913 Charset = "ISO-8859-13"

	// CharsetISO885914 represents the "ISO-8859-14" charset
	CharsetISO885914 Charset = "ISO-8859-14"

	// CharsetISO885915 represents the "ISO-8859-15" charset
	CharsetISO885915 Charset = "ISO-8859-15"

	// CharsetISO885916 represents the "ISO-8859-16" charset
	CharsetISO885916 Charset = "ISO-8859-16"

	// CharsetISO2022JP represents the "ISO-2022-JP" charset
	CharsetISO2022JP Charset = "ISO-2022-JP"

	// CharsetISO2022KR represents the "ISO-2022-KR" charset
	CharsetISO2022KR Charset = "ISO-2022-KR"

	// CharsetWindows1250 represents the "windows-1250" charset
	CharsetWindows1250 Charset = "windows-1250"

	// CharsetWindows1251 represents the "windows-1251" charset
	CharsetWindows1251 Charset = "windows-1251"

	// CharsetWindows1252 represents the "windows-1252" charset
	CharsetWindows1252 Charset = "windows-1252"

	// CharsetWindows1255 represents the "windows-1255" charset
	CharsetWindows1255 Charset = "windows-1255"

	// CharsetWindows1256 represents the "windows-1256" charset
	CharsetWindows1256 Charset = "windows-1256"

	// CharsetKOI8R represents the "KOI8-R" charset
	CharsetKOI8R Charset = "KOI8-R"

	// CharsetKOI8U represents the "KOI8-U" charset
	CharsetKOI8U Charset = "KOI8-U"

	// CharsetBig5 represents the "Big5" charset
	CharsetBig5 Charset = "Big5"

	// CharsetGB18030 represents the "GB18030" charset
	CharsetGB18030 Charset = "GB18030"

	// CharsetGB2312 represents the "GB2312" charset
	CharsetGB2312 Charset = "GB2312"

	// CharsetTIS620 represents the "TIS-620" charset
	CharsetTIS620 Charset = "TIS-620"

	// CharsetEUCKR represents the "EUC-KR" charset
	CharsetEUCKR Charset = "EUC-KR"

	// CharsetShiftJIS represents the "Shift_JIS" charset
	CharsetShiftJIS Charset = "Shift_JIS"

	// CharsetUnknown represents the "Unknown" charset
	CharsetUnknown Charset = "Unknown"

	// CharsetGBK represents the "GBK" charset
	CharsetGBK Charset = "GBK"
)

// List of MIME versions
const (
	// MIME10 is the MIME Version 1.0
	MIME10 MIMEVersion = "1.0"
)

// List of common content types
const (
	TypeTextPlain      ContentType = "text/plain"
	TypeTextHTML       ContentType = "text/html"
	TypeAppOctetStream ContentType = "application/octet-stream"
	TypePGPSignature   ContentType = "application/pgp-signature"
	TypePGPEncrypted   ContentType = "application/pgp-encrypted"
)

// List of MIMETypes
const (
	MIMEAlternative MIMEType = "alternative"
	MIMEMixed       MIMEType = "mixed"
	MIMERelated     MIMEType = "related"
)

// String is a standard method to convert an Charset into a printable format
func (c Charset) String() string {
	return string(c)
}

// String is a standard method to convert an ContentType into a printable format
func (c ContentType) String() string {
	return string(c)
}

// String is a standard method to convert an Encoding into a printable format
func (e Encoding) String() string {
	return string(e)
}
