package dkim

import (
	"github.com/consensys/gnark/frontend"
)

type EmailSig struct {
	SigPrefix  PaddingSlice
	BodyHash   [32]frontend.Variable
	SigSuffix  PaddingSlice
	SigContent []frontend.Variable
}

func NewEmailSigEncode(api frontend.API) EmailSigEncode {
	return EmailSigEncode{api: api}
}

type EmailSigEncode struct {
	api frontend.API
}

func (es EmailSigEncode) GetTrimmedHeader(sig EmailSig) (PaddingSlice, error) {
	api := es.api
	b64encoder := NewBase64Encode(api)
	boyHashinB64 := b64encoder.EncodeRule2(sig.BodyHash[:])
	tempSlice := PaddingSlice{
		IsLittleEndian: false,
		Padding:        frontend.Variable(-1),
		Slice:          boyHashinB64,
	}
	sliceApi := NewSliceApi(api)
	resultSlice := sliceApi.New(api, make([]frontend.Variable, 0), false)
	resultSlice = sliceApi.concat(sig.SigPrefix, tempSlice, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, sig.SigSuffix, resultSlice.IsLittleEndian)
	return resultSlice, nil
}
