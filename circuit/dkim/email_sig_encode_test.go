package dkim

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/selector"
	"github.com/consensys/gnark/test"
	"testing"
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
	resultSlice := sigPrexSlice
	generator := func(api frontend.API) []UndeterminedSlice {
		slices := make([]UndeterminedSlice, 0)
		isEmpty := api.And(api.IsZero(api.Sub(len(resultSlice.Slice)-2, resultSlice.Padding)), api.IsZero(selector.Mux(api, len(resultSlice.Slice)-1, resultSlice.Slice...))) // == 0
		for i := 0; i < len(resultSlice.Slice); i++ {
			slices = append(slices, UndeterminedSlice{
				Variables: resultSlice.Slice[i:],
				// zeroNumber == len(hbytes) - 1 - i && !isZero
				// isZero == 1 -> isSelect = 0
				// isZero == 0, len(hbytes) - 1 - i - zeroNumber == 0 -> isSelect = 1
				IsSelected: api.Mul(api.IsZero(isEmpty), api.IsZero(api.Sub(i-1, resultSlice.Padding))), // suffix = 1, and current = 1
			})
		}
		slices = append(slices, UndeterminedSlice{
			Variables:  []frontend.Variable{},
			IsSelected: isEmpty,
		})
		return slices
	}
	sliceComposer := NewSliceComposer(api)
	fn := func(api frontend.API, slices ...UndeterminedSlice) (DeterminedSlice, error) {
		data := slices[0].Variables
		hasher, err := sha2.New(api)
		if err != nil {
			return nil, err
		}
		dataU8 := make([]uints.U8, len(data))
		u8api, err := uints.New[uints.U32](api)
		if err != nil {
			return nil, err
		}
		for i := 0; i < len(data); i++ {
			dataU8[i] = u8api.ByteValueOf(data[i])
		}
		hasher.Write(dataU8)
		ru8 := hasher.Sum()
		r := make([]frontend.Variable, len(ru8))
		for i := 0; i < len(r); i++ {
			r[i] = ru8[i].Val
		}
		return r, nil
	}
	resultHash, err := sliceComposer.Process(32, fn, generator)
	if err != nil {
		return err
	}
	expectHash_in_circuit := c.ExpectHash
	for i, _ := range c.ExpectHash {
		api.AssertIsEqual(expectHash_in_circuit[i], resultHash[i])
	}
	return nil
}

func TestEmailSigEncode_Encode(t *testing.T) {
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
	for i, _ := range bodyHash {
		bodyHash[i] = tBodyHash[i]
	}

	circuit := EmailSigEncodeWrapper{
		Sig: EmailSig{
			Sig_Prefix: PaddingSlice{
				Padding:        frontend.Variable(-1),
				Slice:          Byte2FrontVariable([]byte(testSigPrefix)),
				IsLittleEndian: false,
			},
			BodyHash:    bodyHash,
			Sig_Content: Byte2FrontVariable([]byte(testSigData)),
		},
		ExpectHash: Byte2FrontVariable(trimmedHash),
	}
	assignment := EmailSigEncodeWrapper{
		Sig: EmailSig{
			Sig_Prefix: PaddingSlice{
				Padding:        frontend.Variable(-1),
				Slice:          Byte2FrontVariable([]byte(testSigPrefix)),
				IsLittleEndian: false,
			},
			BodyHash:    bodyHash,
			Sig_Content: Byte2FrontVariable([]byte(testSigData)),
		},
		ExpectHash: Byte2FrontVariable(trimmedHash),
	}
	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
