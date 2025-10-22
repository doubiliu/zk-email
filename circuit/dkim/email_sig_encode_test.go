package dkim

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type EmailSigEncodeWrapper struct {
	Sig        EmailSig
	ExpectHash []frontend.Variable
}

const testSigPrefixData = "dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=vandenhooff.name; s=google; h=mime-version:from:date:message-id:subject:to:content-type; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b="
const testSigPrefix = "dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=vandenhooff.name; s=google; h=mime-version:from:date:message-id:subject:to:content-type; bh="
const testBodyHash = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
const testSigData = "NCOUEepJZ6cdKYtq61hifQ9K0fimliTNcDVDBQ8C1OQToNxNGQuGifUxWQ/6odRnmm+TGraJoXyKu2WwVl2auHW6Hug/9QBWg6JIQrUl3TLK5Z07IZHpqBFrXjqV/fd6Yl/1+LZSaJ9lwo6YW6LvwoAq4AUwPDZqXeak7i5pj2U="

func (c *EmailSigEncodeWrapper) Define(api frontend.API) error {
	sigEncode := NewEmailSigEncode(api)
	sigPrexSlice, err := sigEncode.GetTrimmedHeader(c.Sig)
	if err != nil {
		return err
	}
	resultHash, err := sigPrexSlice.GetSliceHash(api)
	if err != nil {
		return err
	}
	expectHash := c.ExpectHash
	for i := range c.ExpectHash {
		api.AssertIsEqual(expectHash[i], resultHash[i])
	}
	return nil
}

func TestEmailSigEncode(t *testing.T) {
	assert := test.NewAssert(t)
	//The email sig will be split into multiple paragraphs to facilitate more flexible verification.
	tBodyHash, err := base64.StdEncoding.DecodeString(testBodyHash)
	if err != nil {
		return
	}
	fmt.Println("tBodyHash:", tBodyHash)
	fmt.Println([]byte(testSigPrefix))
	hasher := sha256.New()
	hasher.Write([]byte(testSigPrefixData))
	trimmedHash := hasher.Sum(nil)
	fmt.Println("TrimmedHeaderHash:", trimmedHash)
	//dynamic length, big endian complement forward0x00...
	/*	temp := []byte{0x00, 0x00, 0x00, 0x00}
		temp = append(temp, text_prex...)*/
	bodyHash := [32]frontend.Variable{}
	for i := range bodyHash {
		bodyHash[i] = tBodyHash[i]
	}
	circuit := EmailSigEncodeWrapper{
		Sig: EmailSig{
			SigPrefix:  BytesToFixPadding([]byte(testSigPrefix), false, len([]byte(testSigPrefix))),
			BodyHash:   bodyHash,
			SigContent: BytesToFrontVariable([]byte(testSigData)),
		},
		ExpectHash: BytesToFrontVariable(trimmedHash),
	}
	assignment := EmailSigEncodeWrapper{
		Sig: EmailSig{
			SigPrefix:  BytesToFixPadding([]byte(testSigPrefix), false, len([]byte(testSigPrefix))),
			BodyHash:   bodyHash,
			SigContent: BytesToFrontVariable([]byte(testSigData)),
		},
		ExpectHash: BytesToFrontVariable(trimmedHash),
	}
	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
