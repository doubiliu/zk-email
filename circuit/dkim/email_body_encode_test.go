package dkim

import (
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"testing"
)

type EmailBodyEncodeWrapper struct {
	Body       EmailBody
	ExpectHash []frontend.Variable
}

func (c *EmailBodyEncodeWrapper) Define(api frontend.API) error {
	encode := NewEmailBodyEncode(api)
	edata, err := encode.GetBodyHash(c.Body)
	if err != nil {
		return err
	}
	expectHash_in_circuit := c.ExpectHash
	for i, _ := range c.ExpectHash {
		api.AssertIsEqual(expectHash_in_circuit[i], edata[i])
	}
	return nil
}

func TestEmailBodyEncode_Encode(t *testing.T) {
	assert := test.NewAssert(t)
	//The email text will be split into multiple paragraphs to facilitate more flexible verification.
	text_prex := "This is the first paragraph of the email body,"
	text_suffix := "This is the last paragraph of the email body"
	text := "special content"
	email_body := text_prex + text + text_suffix
	hasher := sha256.New()
	hasher.Write([]byte(email_body))
	bodyHash := hasher.Sum(nil)
	fmt.Println("body: ", email_body)
	fmt.Println("bodyHash:", bodyHash)
	//dynamic length, big endian complement forward0x00...
	/*	temp := []byte{0x00, 0x00, 0x00, 0x00}
		temp = append(temp, text_prex...)*/
	circuit := EmailBodyEncodeWrapper{
		Body: EmailBody{
			Prefix_Content: PaddingSlice{
				Padding:        frontend.Variable(-1),
				Slice:          Byte2FrontVariable([]byte(text_prex)),
				IsLittleEndian: false,
			},
			Suffix_Content: PaddingSlice{
				Padding:        frontend.Variable(-1),
				Slice:          Byte2FrontVariable([]byte(text_suffix)),
				IsLittleEndian: false,
			},
			Text_Content: PaddingSlice{
				Padding:        frontend.Variable(-1),
				Slice:          Byte2FrontVariable([]byte(text)),
				IsLittleEndian: false,
			},
		},
		ExpectHash: Byte2FrontVariable(bodyHash),
	}
	assignment := EmailBodyEncodeWrapper{
		Body: EmailBody{
			Prefix_Content: PaddingSlice{
				Padding:        frontend.Variable(-1),
				Slice:          Byte2FrontVariable([]byte(text_prex)),
				IsLittleEndian: false,
			},
			Suffix_Content: PaddingSlice{
				Padding:        frontend.Variable(-1),
				Slice:          Byte2FrontVariable([]byte(text_suffix)),
				IsLittleEndian: false,
			},
			Text_Content: PaddingSlice{
				Padding:        frontend.Variable(-1),
				Slice:          Byte2FrontVariable([]byte(text)),
				IsLittleEndian: false,
			},
		},
		ExpectHash: Byte2FrontVariable(bodyHash),
	}
	err := test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func Byte2FrontVariable(src []byte) []frontend.Variable {
	result := make([]frontend.Variable, len(src))
	for i, _ := range result {
		result[i] = src[i]
	}
	return result
}

func Byte2Padding(src []byte, isLittleEndian bool, padding int) PaddingSlice {
	return PaddingSlice{
		Padding:        frontend.Variable(padding),
		Slice:          Byte2FrontVariable(src),
		IsLittleEndian: isLittleEndian,
	}
}
