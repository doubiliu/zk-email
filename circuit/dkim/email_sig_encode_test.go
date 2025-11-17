package dkim

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type EmailSigEncodeWrapper struct {
	Sig        EmailSig
	ExpectHash []frontend.Variable
}

const testTrimmedHeader = "dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=vandenhooff.name; s=google; h=mime-version:from:date:message-id:subject:to:content-type; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b="
const testSigPrefix = "dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=vandenhooff.name; s=google; h=mime-version:from:date:message-id:subject:to:content-type; bh="
const testBodyHash = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
const testSigData = "NCOUEepJZ6cdKYtq61hifQ9K0fimliTNcDVDBQ8C1OQToNxNGQuGifUxWQ/6odRnmm+TGraJoXyKu2WwVl2auHW6Hug/9QBWg6JIQrUl3TLK5Z07IZHpqBFrXjqV/fd6Yl/1+LZSaJ9lwo6YW6LvwoAq4AUwPDZqXeak7i5pj2U="

func (c *EmailSigEncodeWrapper) Define(api frontend.API) error {
	sigEncode := NewEmailSigEncode(api)
	trimmedHeader, err := sigEncode.GetTrimmedHeader(c.Sig)
	if err != nil {
		return err
	}
	resultHash, err := trimmedHeader.GetSliceHash(api)
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
	hasher := sha256.New()
	hasher.Write([]byte(testTrimmedHeader))
	trimmedHash := hasher.Sum(nil)
	SigPrefix := testTrimmedHeader[0 : strings.Index(testTrimmedHeader, "bh=")+3]
	SigSuffix := testTrimmedHeader[strings.Index(testTrimmedHeader, "bh=")+3+len(testBodyHash) : strings.Index(testTrimmedHeader, "b=")+2]
	bodyHash := [32]frontend.Variable{}
	for i := range bodyHash {
		bodyHash[i] = tBodyHash[i]
	}
	circuit := EmailSigEncodeWrapper{
		Sig: EmailSig{
			SigPrefix:  BytesToPadding([]byte(SigPrefix), false, -1),
			BodyHash:   bodyHash,
			SigSuffix:  BytesToPadding([]byte(SigSuffix), false, -1),
			SigContent: BytesToFrontVariable([]byte(testSigData)),
		},
		ExpectHash: BytesToFrontVariable(trimmedHash),
	}
	assignment := EmailSigEncodeWrapper{
		Sig: EmailSig{
			SigPrefix:  BytesToPadding([]byte(SigPrefix), false, -1),
			BodyHash:   bodyHash,
			SigSuffix:  BytesToPadding([]byte(SigSuffix), false, -1),
			SigContent: BytesToFrontVariable([]byte(testSigData)),
		},
		ExpectHash: BytesToFrontVariable(trimmedHash),
	}
	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
