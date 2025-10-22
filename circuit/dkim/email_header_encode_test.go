package dkim

import (
	"errors"
	"fmt"
	"testing"

	"github.com/bane-labs/dbft-verifier/algorithm"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type FixEmailHeaderEncodeWrapper struct {
	Header        FixEmailHeader
	TrimmedHeader PaddingSlice
	Expect        []frontend.Variable
}

func (c *FixEmailHeaderEncodeWrapper) Define(api frontend.API) error {
	encode := NewFixEmailHeaderEncode(api)
	expectHash, err := encode.GetHeaderHash(c.Header, c.TrimmedHeader)
	if err != nil {
		return err
	}
	for i := range c.Expect {
		api.AssertIsEqual(expectHash[i], c.Expect[i])
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
		MimeVersion: BytesToFixPadding(mimeVersion, false, len(mimeVersion)),
		From:        BytesToFixPadding(from, false, len(from)),
		Date:        BytesToFixPadding(date, false, len(date)),
		MessageId:   BytesToFixPadding(messageId, false, len(messageId)),
		Subject:     BytesToFixPadding(subject, false, len(subject)),
		To:          BytesToFixPadding(to, false, len(to)),
		ContentType: BytesToFixPadding(contentType, false, len(contentType)),
	}
	TrimmedHeader := BytesToFixPadding(trimmedHeader, false, len(trimmedHeader))
	expect := BytesToFrontVariable(headersHash)
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
	expectHash, err := encode.GetHeaderHash(c.Header, c.TrimmedHeader)
	if err != nil {
		return err
	}
	for i := range c.Expect {
		api.AssertIsEqual(expectHash[i], c.Expect[i])
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
	messageId := []byte(signature.Canon().Header()(signedHeaders[3]))
	subject := []byte(signature.Canon().Header()(signedHeaders[4]))
	to := []byte(signature.Canon().Header()(signedHeaders[5]))
	contentType := []byte(signature.Canon().Header()(signedHeaders[6]))

	predixData := mimeVersion
	predixData = append(predixData, from...)
	predixData = append(predixData, date...)
	predixData = append(predixData, messageId...)
	predixData = append(predixData, subject...)
	specifyData := to
	suffixData := contentType

	trimmedHeader := []byte(tHeader)

	ch := CustomEmailHeader{
		PrefixData:  BytesToFixPadding(predixData, false, len(predixData)),
		SpecifyData: BytesToFixPadding(specifyData, false, len(specifyData)),
		SuffixData:  BytesToFixPadding(suffixData, false, len(suffixData)),
	}
	TrimmedHeader := BytesToFixPadding(trimmedHeader, false, len(trimmedHeader))
	expect := BytesToFrontVariable(headersHash)
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
