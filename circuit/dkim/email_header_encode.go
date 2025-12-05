package dkim

import (
	"github.com/consensys/gnark/frontend"
)

type CustomEmailHeader struct {
	PrefixData  PaddingSlice
	SpecifyData PaddingSlice
	SuffixData  PaddingSlice
}

func NewCustomEmailHeaderEncode(api frontend.API) CustomEmailHeaderEncode {
	return CustomEmailHeaderEncode{api: api}
}

type CustomEmailHeaderEncode struct {
	api frontend.API
}

// Encode concatenates the email header parts into a single PaddingSlice.
func (ce CustomEmailHeaderEncode) Encode(header CustomEmailHeader) (PaddingSlice, error) {
	sliceApi := NewSliceApi(ce.api)
	resultSlice := header.PrefixData
	resultSlice = sliceApi.concat(resultSlice, header.SpecifyData, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, header.SuffixData, resultSlice.IsLittleEndian)
	return resultSlice, nil
}

// GetHeaderHash computes the hash of the full email header with trimmed parts.
func (ce CustomEmailHeaderEncode) GetHeaderHash(header CustomEmailHeader, trimmedHeader PaddingSlice) ([]frontend.Variable, error) {
	sliceApi := NewSliceApi(ce.api)
	resultSlice, err := ce.Encode(header)
	if err != nil {
		return nil, err
	}
	resultSlice = sliceApi.concat(resultSlice, trimmedHeader, resultSlice.IsLittleEndian)
	resultHash, err := resultSlice.GetSliceHash(ce.api)
	if err != nil {
		return nil, err
	}
	return resultHash, nil
}
