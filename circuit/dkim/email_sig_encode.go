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

// GetTrimmedHeader constructs the trimmed email header used for signature verification.
func (es EmailSigEncode) GetTrimmedHeader(sig EmailSig) (PaddingSlice, error) {
	b64encoder := NewBase64Encode(es.api)
	boyHashinB64 := b64encoder.EncodeRule2(sig.BodyHash[:])
	tempSlice := PaddingSlice{
		IsLittleEndian: false,
		Padding:        frontend.Variable(-1),
		Slice:          boyHashinB64,
	}
	sliceApi := NewSliceApi(es.api)
	resultSlice := sliceApi.New(es.api, make([]frontend.Variable, 0), false)
	resultSlice = sliceApi.concat(sig.SigPrefix, tempSlice, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, sig.SigSuffix, resultSlice.IsLittleEndian)
	return resultSlice, nil
}
