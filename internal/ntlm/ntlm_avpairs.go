package ntlm

import (
	"encoding/binary"
	"errors"
)

// AVPairType represents the type of an Attribute-Value pair
type AVPairType uint16

// AVPair represents an Attribute-Value pair
type AVPair struct {
	Id    AVPairType
	Len   uint16
	Value []byte
}

// AVPairs represents a list of Attribute-Value pairs
type AVPairs struct {
	List     []AVPair
	Reserved []byte
}

// Attribute-Value enumeration according to MSV1_0_AVID
//
// See: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ne-ntifs-msv1_0_avid
const (
	// MsvAvEOL indicates that this is the last AV_PAIR in the list
	MsvAvEOL AVPairType = iota

	// MsvAvNbComputerName represents the server's NetBIOS computer name
	MsvAvNbComputerName

	// MsvAvNbDomainName represents the server's NetBIOS domain name
	MsvAvNbDomainName

	// MsvAvDnsComputerName represents the fully qualified domain name (FQDN) of the computer
	MsvAvDnsComputerName

	// MsvAvDnsDomainName represents the FQDN of the domain
	MsvAvDnsDomainName

	// MsvAvDnsTreeName represents the FQDN of the forest / DNS tree name
	MsvAvDnsTreeName

	// MsvAvFlags represents a 32-bit value of flag bits indicating server or client configuration
	MsvAvFlags

	// MsvAvTimestamp represents a FILETIME structure (64-bit) holding the server's local time
	MsvAvTimestamp

	// MsvAvRestrictions represents a Single_Host_Data structure (a.k.a. MsvAvSingleHost) describing client restrictions
	MsvAvRestrictions

	// MsvAvTargetName represents the SPN (service principal name) of the target server (unterminated Unicode string)
	MsvAvTargetName

	// MsvAvChannelBindings represents an MD5 hash of channel bindings (Channel Binding Token / EPA support)
	MsvAvChannelBindings
)

var (
	// ErrNTLMInvalidAVPair indicates that an invalid NTLM attribute-value pair was encountered
	ErrNTLMInvalidAVPair = errors.New("invalid NTLM attribute-value pair")
)

// ReadAvPair reads an AVPair from the given byte slice at the given offset.
func ReadAvPair(data []byte, offset int) (*AVPair, error) {
	if len(data) < offset+4 {
		return nil, ErrNTLMInvalidAVPair
	}
	pair := new(AVPair)
	pair.Id = AVPairType(binary.LittleEndian.Uint16(data[offset : offset+2]))
	pair.Len = binary.LittleEndian.Uint16(data[offset+2 : offset+4])
	if len(data) < offset+4+int(pair.Len) {
		return nil, ErrNTLMInvalidAVPair
	}
	pair.Value = data[offset+4 : offset+4+int(pair.Len)]
	return pair, nil
}

// ReadAvPairs reads AVPairs from the given byte slice.
func ReadAvPairs(data []byte) (*AVPairs, error) {
	pairs := new(AVPairs)
	offset := 0

	for {
		pair, err := ReadAvPair(data, offset)
		if err != nil {
			return nil, err
		}

		offset += 4 + int(pair.Len)
		if offset > len(data) {
			return nil, ErrNTLMInvalidPayload
		}

		pairs.List = append(pairs.List, *pair)

		if pair.Id == MsvAvEOL {
			pairs.Reserved = data[offset:]
			return pairs, nil
		}
	}
}

// Bytes returns the AVPairs as a byte slice.
func (p *AVPairs) Bytes() []byte {
	total := len(p.Reserved)
	for i := range p.List {
		total += int(p.List[i].Len) + 4
	}
	result := make([]byte, 0, total)
	for i := range p.List {
		result = append(result, p.List[i].Bytes()...)
	}
	return append(result, p.Reserved...)
}

// Find returns the AVPair with the given type, or nil if not found.
func (p *AVPairs) Find(avType AVPairType) *AVPair {
	for i := range p.List {
		if p.List[i].Id == avType {
			return &p.List[i]
		}
	}
	return nil
}

// Bytes returns the AVPair as a byte slice.
func (a *AVPair) Bytes() []byte {
	result := make([]byte, 4, int(a.Len)+4)
	binary.LittleEndian.PutUint16(result[0:2], uint16(a.Id))
	binary.LittleEndian.PutUint16(result[2:4], a.Len)
	return append(result, a.Value...)
}
