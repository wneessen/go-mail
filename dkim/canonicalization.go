package dkim

// Canonicalization implements the different Canonicalization types as described in
// https://datatracker.ietf.org/doc/html/rfc6376#section-3.4
type Canonicalization uint8

const (
	CanonicalizationSimple  Canonicalization = iota // Represents the simple Canonicalization
	CanonicalizationRelaxed                         // Represents the relaxed Canonicalization
)

// String returns the string representation of a given Canonicalization
func (c Canonicalization) String() string {
	switch c {
	case 0:
		return "simple"
	case 1:
		return "relaxed"
	default:
		return ""
	}
}
