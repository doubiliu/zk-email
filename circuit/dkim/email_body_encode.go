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

func (eb EmailBodyEncode) GetBodyHash(body EmailBody) ([]frontend.Variable, error) {
	api := eb.api
	sliceApi := NewSliceApi(api)
	//拼凑email正文(body)动态分片
	bodySlice := body.PrefixContent
	bodySlice = sliceApi.concat(bodySlice, body.TextContent, bodySlice.IsLittleEndian)
	bodySlice = sliceApi.concat(bodySlice, body.SuffixContent, bodySlice.IsLittleEndian)
	//拼凑email全文动态分片
	resultSlice := bodySlice
	emailBodyHash, err := resultSlice.GetSliceHash(api)
	if err != nil {
		return nil, err
	}
	return emailBodyHash, nil
}

func (eb EmailBodyEncode) GetSpecifyDataHash(body EmailBody) ([]frontend.Variable, error) {
	api := eb.api
	resultSlice := body.TextContent
	specifyDataHash, err := resultSlice.GetSliceHash(api)
	if err != nil {
		return nil, err
	}
	return specifyDataHash, nil
}
