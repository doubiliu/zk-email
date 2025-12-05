package dkim

import (
	"errors"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/doubiliu/zk-email/algorithm"
)

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

	ch := CustomEmailHeader{
		PrefixData:  BytesToFixPadding(predixData, false, len(predixData)),
		SpecifyData: BytesToFixPadding(specifyData, false, len(specifyData)),
		SuffixData:  BytesToFixPadding(suffixData, false, len(suffixData)),
	}
	expect := BytesToFrontVariable(headersHash)
	circuit := CustomEmailHeaderWrapper{
		Header:        ch,
		TrimmedHeader: BytesToFixPadding([]byte(tHeader), false, len([]byte(tHeader))),
		Expect:        expect,
	}
	assignment := CustomEmailHeaderWrapper{
		Header:        ch,
		TrimmedHeader: BytesToFixPadding([]byte(tHeader), false, len([]byte(tHeader))),
		Expect:        expect,
	}
	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
