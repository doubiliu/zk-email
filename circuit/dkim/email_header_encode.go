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

func (ce CustomEmailHeaderEncode) Encode(header CustomEmailHeader) (PaddingSlice, error) {
	api := ce.api
	sliceApi := NewSliceApi(api)
	resultSlice := header.PrefixData
	resultSlice = sliceApi.concat(resultSlice, header.SpecifyData, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, header.SuffixData, resultSlice.IsLittleEndian)
	return resultSlice, nil
}

func (ce CustomEmailHeaderEncode) GetHeaderHash(header CustomEmailHeader, trimmedHeader PaddingSlice) ([]frontend.Variable, error) {
	api := ce.api
	sliceApi := NewSliceApi(api)
	resultSlice, err := ce.Encode(header)
	if err != nil {
		return nil, err
	}
	resultSlice = sliceApi.concat(resultSlice, trimmedHeader, resultSlice.IsLittleEndian)
	resultHash, err := resultSlice.GetSliceHash(api)
	if err != nil {
		return nil, err
	}
	return resultHash, nil
}
