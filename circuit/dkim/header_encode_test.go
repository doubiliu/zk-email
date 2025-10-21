package dkim

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/bane-labs/dbft-verifier/algorithm"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"testing"
)

func TestHeaderEncode_Encode(t *testing.T) {
	assert := test.NewAssert(t)
	email := algorithm.ParseEmail(headersOnly)
	var signatureHeader string
	for _, header := range email.Headers() {
		// we don't support DKIM-Signature headers signing other DKIM-Signature
		// headers
		if algorithm.IsSignatureHeader(header) {
			if signatureHeader != "" {
				panic(errors.New("multiple DKIM headers"))
			}
			signatureHeader = header
		}
	}
	if signatureHeader == "" {
		panic(errors.New("no DKIM header found"))
	}

	signature, err := algorithm.ParseSignature(signatureHeader)
	if err != nil {
		panic(err)
	}

	signedHeaders := algorithm.ExtractHeaders(email.Headers(), signature.HeaderNames())
	for _, ele := range signedHeaders {
		temp := signature.Canon().Header()(ele)
		fmt.Println(temp)
	}

	h := signature.Algo().Hasher()()
	for _, header := range signedHeaders {
		header = signature.Canon().Header()(header)
		h.Write([]byte(header))
	}
	header := signature.Canon().Header()(signature.TrimmedHeader())
	fmt.Println("TrimmedHeader:" + header)
	h.Write([]byte(header))
	headersHash := h.Sum(nil)

	//从DNS查找RSA公钥
	txtRecords, err := client.LookupTxt(signature.TxtRecordName())
	if err != nil {
		panic(err)
	}
	//验签
	txtRecord := txtRecords[0]
	fmt.Println(txtRecord)
	pubkey := algorithm.ParsePubkey(txtRecord)
	err = signature.Algo().CheckSig()(pubkey.Key(), headersHash, signature.Signature())
	if err != nil {
		panic(err)
	}
	fmt.Println("DKIM signature verify success")
	fmt.Println(base64.StdEncoding.EncodeToString(signature.Signature()))

	mimeVersion := []byte(signature.Canon().Header()(signedHeaders[0]))
	from := []byte(signature.Canon().Header()(signedHeaders[1]))
	date := []byte(signature.Canon().Header()(signedHeaders[2]))
	message_id := []byte(signature.Canon().Header()(signedHeaders[3]))
	subject := []byte(signature.Canon().Header()(signedHeaders[4]))
	to := []byte(signature.Canon().Header()(signedHeaders[5]))
	content_type := []byte(signature.Canon().Header()(signedHeaders[6]))
	trimmedHeader := []byte(header)

	MimeVersion := make([]frontend.Variable, len(mimeVersion))
	From := make([]frontend.Variable, len(from))
	Date := make([]frontend.Variable, len(date))
	Message_id := make([]frontend.Variable, len(message_id))
	Subject := make([]frontend.Variable, len(subject))
	To := make([]frontend.Variable, len(to))
	Content_type := make([]frontend.Variable, len(content_type))
	TrimmedHeader := make([]frontend.Variable, len(trimmedHeader))

	ch := Header{}
	for i, _ := range mimeVersion {
		MimeVersion[i] = frontend.Variable(mimeVersion[i])
	}
	ch.Mime_Version = PaddingSlice{
		IsLittleEndian: false,
		Padding:        frontend.Variable(-1),
		Slice:          MimeVersion,
	}
	for i, _ := range from {
		From[i] = frontend.Variable(from[i])
	}
	ch.From = PaddingSlice{
		IsLittleEndian: false,
		Padding:        frontend.Variable(-1),
		Slice:          From,
	}
	for i, _ := range date {
		Date[i] = frontend.Variable(date[i])
	}
	ch.Date = PaddingSlice{
		IsLittleEndian: false,
		Padding:        frontend.Variable(-1),
		Slice:          Date,
	}
	for i, _ := range message_id {
		Message_id[i] = frontend.Variable(message_id[i])
	}
	ch.Message_id = PaddingSlice{
		IsLittleEndian: false,
		Padding:        frontend.Variable(-1),
		Slice:          Message_id,
	}
	for i, _ := range subject {
		Subject[i] = frontend.Variable(subject[i])
	}
	ch.Subject = PaddingSlice{
		IsLittleEndian: false,
		Padding:        frontend.Variable(-1),
		Slice:          Subject,
	}
	for i, _ := range to {
		To[i] = frontend.Variable(to[i])
	}
	ch.To = PaddingSlice{
		IsLittleEndian: false,
		Padding:        frontend.Variable(-1),
		Slice:          To,
	}
	for i, _ := range content_type {
		Content_type[i] = frontend.Variable(content_type[i])
	}
	ch.Content_Type = PaddingSlice{
		IsLittleEndian: false,
		Padding:        frontend.Variable(-1),
		Slice:          Content_type,
	}
	for i, _ := range trimmedHeader {
		TrimmedHeader[i] = frontend.Variable(trimmedHeader[i])
	}
	ch.TrimmedHeader = PaddingSlice{
		IsLittleEndian: false,
		Padding:        frontend.Variable(-1),
		Slice:          TrimmedHeader,
	}
	sha := sha256.New()
	for _, ele := range signedHeaders {
		temp := signature.Canon().Header()(ele)
		sha.Write([]byte(temp))
	}
	sha.Write([]byte(header))
	//shaSum := sha.Sum(nil)
	expect := make([]frontend.Variable, 32)
	for i, _ := range expect {
		expect[i] = headersHash[i]
	}
	circuit := HeaderEncodeWrapper{
		Header: ch,
		Expect: expect,
	}
	assignment := HeaderEncodeWrapper{
		Header: ch,
		Expect: expect,
	}
	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)

}

type HeaderEncodeWrapper struct {
	Header Header
	Expect []frontend.Variable
}

func (c *HeaderEncodeWrapper) Define(api frontend.API) error {
	encode := NewHeaderEncode(api)
	edata, err := encode.Encode(c.Header)
	if err != nil {
		return err
	}
	expectdata := c.Expect
	for i, _ := range c.Expect {
		api.AssertIsEqual(expectdata[i], edata[i])
	}
	return nil
}
