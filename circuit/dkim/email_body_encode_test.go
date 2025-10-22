package dkim

import (
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
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
	expectHash := c.ExpectHash
	for i := range c.ExpectHash {
		api.AssertIsEqual(expectHash[i], edata[i])
	}
	return nil
}

func TestEmailBodyEncode(t *testing.T) {
	assert := test.NewAssert(t)
	//The email text will be split into multiple paragraphs to facilitate more flexible verification.
	textPrex := "This is the first paragraph of the email body,"
	textSuffix := "This is the last paragraph of the email body"
	text := "special content"
	emailBody := textPrex + text + textSuffix
	hasher := sha256.New()
	hasher.Write([]byte(emailBody))
	bodyHash := hasher.Sum(nil)
	fmt.Println("body: ", emailBody)
	fmt.Println("bodyHash:", bodyHash)
	//dynamic length, big endian complement forward0x00...
	/*	temp := []byte{0x00, 0x00, 0x00, 0x00}
		temp = append(temp, textPrex...)*/
	circuit := EmailBodyEncodeWrapper{
		Body: EmailBody{
			PrefixContent: BytesToFixPadding([]byte(textPrex), false, len([]byte(textPrex))),
			SuffixContent: BytesToFixPadding([]byte(textSuffix), false, len([]byte(textSuffix))),
			TextContent:   BytesToFixPadding([]byte(text), false, len([]byte(text))),
		},
		ExpectHash: BytesToFrontVariable(bodyHash),
	}
	assignment := EmailBodyEncodeWrapper{
		Body: EmailBody{
			PrefixContent: BytesToFixPadding([]byte(textPrex), false, len([]byte(textPrex))),
			SuffixContent: BytesToFixPadding([]byte(textSuffix), false, len([]byte(textSuffix))),
			TextContent:   BytesToFixPadding([]byte(text), false, len([]byte(text))),
		},
		ExpectHash: BytesToFrontVariable(bodyHash),
	}
	err := test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
