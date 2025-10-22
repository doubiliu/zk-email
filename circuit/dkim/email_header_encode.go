package dkim

import (
	"github.com/consensys/gnark/frontend"
)

type FixEmailHeader struct {
	MimeVersion PaddingSlice
	From        PaddingSlice
	Date        PaddingSlice
	MessageId   PaddingSlice
	Subject     PaddingSlice
	To          PaddingSlice
	ContentType PaddingSlice
}

func NewFixEmailHeaderEncode(api frontend.API) FixEmailHeaderEncode {
	return FixEmailHeaderEncode{api: api}
}

type FixEmailHeaderEncode struct {
	api frontend.API
}

func (fe FixEmailHeaderEncode) Encode(header FixEmailHeader) (PaddingSlice, error) {
	api := fe.api
	sliceApi := NewSliceApi(api)
	resultSlice := header.MimeVersion
	resultSlice = sliceApi.concat(resultSlice, header.From, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, header.Date, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, header.MessageId, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, header.Subject, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, header.To, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, header.ContentType, resultSlice.IsLittleEndian)
	return resultSlice, nil
}

func (fe FixEmailHeaderEncode) GetHeaderHash(header FixEmailHeader, trimmedHeader PaddingSlice) ([]frontend.Variable, error) {
	api := fe.api
	sliceApi := NewSliceApi(api)
	resultSlice, err := fe.Encode(header)
	if err != nil {
		return nil, err
	}
	resultSlice = sliceApi.concat(resultSlice, trimmedHeader, resultSlice.IsLittleEndian)
	headerHash, err := resultSlice.GetSliceHash(api)
	if err != nil {
		return nil, err
	}
	return headerHash, nil
}

func (fe FixEmailHeaderEncode) GetToAddressHash(header FixEmailHeader) ([]frontend.Variable, error) {
	api := fe.api
	resultSlice := header.To
	toAddressHash, err := resultSlice.GetSliceHash(api)
	if err != nil {
		return nil, err
	}
	return toAddressHash, nil
}

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
