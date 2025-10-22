package dkim

import (
	"errors"
	"fmt"
	"github.com/bane-labs/dbft-verifier/algorithm"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"testing"
)

type FixEmailHeaderEncodeWrapper struct {
	Header        FixEmailHeader
	TrimmedHeader PaddingSlice
	Expect        []frontend.Variable
}

func (c *FixEmailHeaderEncodeWrapper) Define(api frontend.API) error {
	encode := NewFixEmailHeaderEncode(api)
	expectHashInCircuit, err := encode.GetHeaderHash(c.Header, c.TrimmedHeader)
	if err != nil {
		return err
	}
	expectHash := c.Expect
	for i, _ := range c.Expect {
		api.AssertIsEqual(expectHashInCircuit[i], expectHash[i])
	}
	return nil
}

func TestFixEmailHeaderEncode(t *testing.T) {
	assert := test.NewAssert(t)
	email := algorithm.ParseEmail(headersOnly)
	var signatureHeader string
	for _, header := range email.Headers() {
		// headers
		if algorithm.IsSignatureHeader(header) {
			if signatureHeader != "" {
				panic(errors.New("multiple DKIM headers"))
			}
			signatureHeader = header
		}
	}
	signature, err := algorithm.ParseSignature(signatureHeader)
	if err != nil {
		panic(err)
	}
	signedHeaders := algorithm.ExtractHeaders(email.Headers(), signature.HeaderNames())

	h := signature.Algo().Hasher()()
	for _, header := range signedHeaders {
		header = signature.Canon().Header()(header)
		h.Write([]byte(header))
	}
	tHeader := signature.Canon().Header()(signature.TrimmedHeader())
	fmt.Println("trimmedHeader:" + tHeader)
	h.Write([]byte(tHeader))
	headersHash := h.Sum(nil)

	mimeVersion := []byte(signature.Canon().Header()(signedHeaders[0]))
	from := []byte(signature.Canon().Header()(signedHeaders[1]))
	date := []byte(signature.Canon().Header()(signedHeaders[2]))
	messageId := []byte(signature.Canon().Header()(signedHeaders[3]))
	subject := []byte(signature.Canon().Header()(signedHeaders[4]))
	to := []byte(signature.Canon().Header()(signedHeaders[5]))
	contentType := []byte(signature.Canon().Header()(signedHeaders[6]))
	trimmedHeader := []byte(tHeader)

	ch := FixEmailHeader{
		MimeVersion: Byte2FixPadding(mimeVersion, false, len(mimeVersion)),
		From:        Byte2FixPadding(from, false, len(from)),
		Date:        Byte2FixPadding(date, false, len(date)),
		MessageId:   Byte2FixPadding(messageId, false, len(messageId)),
		Subject:     Byte2FixPadding(subject, false, len(subject)),
		To:          Byte2FixPadding(to, false, len(to)),
		ContentType: Byte2FixPadding(contentType, false, len(contentType)),
	}
	TrimmedHeader := Byte2FixPadding(trimmedHeader, false, len(trimmedHeader))
	expect := Byte2FrontVariable(headersHash)
	circuit := FixEmailHeaderEncodeWrapper{
		Header:        ch,
		TrimmedHeader: TrimmedHeader,
		Expect:        expect,
	}
	assignment := FixEmailHeaderEncodeWrapper{
		Header:        ch,
		TrimmedHeader: TrimmedHeader,
		Expect:        expect,
	}
	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type CustomEmailHeaderWrapper struct {
	Header        CustomEmailHeader
	TrimmedHeader PaddingSlice
	Expect        []frontend.Variable
}

func (c *CustomEmailHeaderWrapper) Define(api frontend.API) error {
	encode := NewCustomEmailHeaderEncode(api)
	expectHashInCircuit, err := encode.GetHeaderHash(c.Header, c.TrimmedHeader)
	if err != nil {
		return err
	}
	expectHash := c.Expect
	for i, _ := range c.Expect {
		api.AssertIsEqual(expectHashInCircuit[i], expectHash[i])
	}
	return nil
}

func TestCustomEmailHeaderEncode(t *testing.T) {
	assert := test.NewAssert(t)
	email := algorithm.ParseEmail(headersOnly)
	var signatureHeader string
	for _, header := range email.Headers() {
		// headers
		if algorithm.IsSignatureHeader(header) {
			if signatureHeader != "" {
				panic(errors.New("multiple DKIM headers"))
			}
			signatureHeader = header
		}
	}
	signature, err := algorithm.ParseSignature(signatureHeader)
	if err != nil {
		panic(err)
	}
	signedHeaders := algorithm.ExtractHeaders(email.Headers(), signature.HeaderNames())

	h := signature.Algo().Hasher()()
	for _, header := range signedHeaders {
		header = signature.Canon().Header()(header)
		h.Write([]byte(header))
	}
	tHeader := signature.Canon().Header()(signature.TrimmedHeader())
	fmt.Println("trimmedHeader:" + tHeader)
	h.Write([]byte(tHeader))
	headersHash := h.Sum(nil)

	mimeVersion := []byte(signature.Canon().Header()(signedHeaders[0]))
	from := []byte(signature.Canon().Header()(signedHeaders[1]))
	date := []byte(signature.Canon().Header()(signedHeaders[2]))
	message_id := []byte(signature.Canon().Header()(signedHeaders[3]))
	subject := []byte(signature.Canon().Header()(signedHeaders[4]))
	to := []byte(signature.Canon().Header()(signedHeaders[5]))
	content_type := []byte(signature.Canon().Header()(signedHeaders[6]))

	predixData := mimeVersion
	predixData = append(predixData, from...)
	predixData = append(predixData, date...)
	predixData = append(predixData, message_id...)
	predixData = append(predixData, subject...)
	specifyData := to
	suffixData := content_type

	trimmedHeader := []byte(tHeader)

	ch := CustomEmailHeader{
		PrefixData:  Byte2FixPadding(predixData, false, len(predixData)),
		SpecifyData: Byte2FixPadding(specifyData, false, len(specifyData)),
		SuffixData:  Byte2FixPadding(suffixData, false, len(suffixData)),
	}
	TrimmedHeader := Byte2FixPadding(trimmedHeader, false, len(trimmedHeader))
	expect := Byte2FrontVariable(headersHash)
	circuit := CustomEmailHeaderWrapper{
		Header:        ch,
		TrimmedHeader: TrimmedHeader,
		Expect:        expect,
	}
	assignment := CustomEmailHeaderWrapper{
		Header:        ch,
		TrimmedHeader: TrimmedHeader,
		Expect:        expect,
	}
	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
