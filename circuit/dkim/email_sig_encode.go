package dkim

import (
	"github.com/consensys/gnark/frontend"
)

type EmailSig struct {
	SigPrefix  PaddingSlice
	BodyHash   [32]frontend.Variable
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
	suffixString := []byte("; b=")
	suffixData := make([]frontend.Variable, len(suffixString))
	for i, _ := range suffixData {
		suffixData[i] = frontend.Variable(suffixString[i])
	}
	tempData := append(boyHashinB64, suffixData...)
	tempSlice := PaddingSlice{
		IsLittleEndian: false,
		Padding:        frontend.Variable(-1),
		Slice:          tempData,
	}
	sliceApi := NewSliceApi(api)
	//make email sig dynamic slice
	resultSlice := sig.SigPrefix
	resultSlice = sliceApi.concat(resultSlice, tempSlice, tempSlice.IsLittleEndian)
	return resultSlice, nil
}
