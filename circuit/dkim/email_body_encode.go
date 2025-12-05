package dkim

import (
	"github.com/consensys/gnark/frontend"
)

type EmailBody struct {
	PrefixContent PaddingSlice
	TextContent   PaddingSlice
	SuffixContent PaddingSlice
}

func NewEmailBodyEncode(api frontend.API) EmailBodyEncode {
	return EmailBodyEncode{api: api}
}

type EmailBodyEncode struct {
	api frontend.API
}

// GetBodyHash computes the hash of the full email body.
func (eb EmailBodyEncode) GetBodyHash(body EmailBody) ([]frontend.Variable, error) {
	sliceApi := NewSliceApi(eb.api)
	// Concat the body slices.
	bodySlice := body.PrefixContent
	bodySlice = sliceApi.concat(bodySlice, body.TextContent, bodySlice.IsLittleEndian)
	bodySlice = sliceApi.concat(bodySlice, body.SuffixContent, bodySlice.IsLittleEndian)
	// Compute hash.
	emailBodyHash, err := bodySlice.GetSliceHash(eb.api)
	if err != nil {
		return nil, err
	}
	return emailBodyHash, nil
}

// GetSpecifyDataHash computes the hash of the specified part of the email body.
func (eb EmailBodyEncode) GetSpecifyDataHash(body EmailBody) ([]frontend.Variable, error) {
	specifyDataHash, err := body.TextContent.GetSliceHash(eb.api)
	if err != nil {
		return nil, err
	}
	return specifyDataHash, nil
}
