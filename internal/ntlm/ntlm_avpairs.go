package ntlm

import (
	"encoding/binary"
	"errors"
)

type AVPairType uint16

// Attribute - Value pair
type AVPair struct {
	Id    AVPairType
	Len   uint16
	Value []byte
}

type AVPairs struct {
	List     []AVPair
	Reserved []byte
}

const (
	MsvAvEOL AVPairType = iota
	MsvAvNbComputerName
	MsvAvNbDomainName
	MsvAvDnsComputerName
	MsvAvDnsDomainName
	MsvAvDnsTreeName
	MsvAvFlags
	MsvAvTimestamp
)

var (
	ErrNTLMInvalidAVPair = errors.New("invalid NTLM attribute-value pair")
)

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

func ReadAvPairs(data []byte) (*AVPairs, error) {
	pairs := new(AVPairs)
	offset := 0
	for i := 0; len(data) > 0 && i < 11; i++ {
		pair, err := ReadAvPair(data, offset)
		if err != nil {
			return nil, err
		}
		offset += 4 + int(pair.Len)
		pairs.List = append(pairs.List, *pair)
		if pair.Id == MsvAvEOL {
			pairs.Reserved = data[offset:]
			break
		}
	}
	return pairs, nil
}

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

func (p *AVPairs) Find(avType AVPairType) *AVPair {
	for i := range p.List {
		if p.List[i].Id == avType {
			pair := p.List[i]
			return &pair
		}
	}
	return nil
}

func (a *AVPair) Bytes() []byte {
	result := make([]byte, 4, int(a.Len)+4)
	result[0] = byte(a.Id)
	result[1] = byte(a.Id >> 8)
	result[2] = byte(a.Len)
	result[3] = byte(a.Len >> 8)
	return append(result, a.Value...)
}
