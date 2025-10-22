package dkim

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

func NewDKIMVerifier[T emulated.FieldParams](api frontend.API) DKIMVerifier[T] {
	return DKIMVerifier[T]{api: api}
}

type DKIMVerifier[T emulated.FieldParams] struct {
	api frontend.API
}

func (dk *DKIMVerifier[T]) Verify(header FixEmailHeader, body EmailBody, sig EmailSig, publicKey PublicKey[T]) error {
	api := dk.api
	headerEncode := NewFixEmailHeaderEncode(api)
	//bodyEncode := NewEmailBodyEncode(api)
	sigEncode := NewEmailSigEncode(api)

	/*	bodyHash, err := bodyEncode.GetBodyHash(body)
		if err != nil {
			return err
		}
		for i, _ := range bodyHash {
			api.AssertIsEqual(bodyHash[i], sig.BodyHash[i])
		}*/

	trimmedHeader, err := sigEncode.GetTrimmedHeader(sig)
	if err != nil {
		return err
	}
	headerHash, err := headerEncode.GetHeaderHash(header, trimmedHeader)
	if err != nil {
		return err
	}
	rsa := NewRSA[T](api)
	err = rsa.VerifyPkcs1v15(&publicKey, sig.SigContent, headerHash)
	if err != nil {
		return err
	}
	return nil
}

type DKIMVerifierWrapper[T emulated.FieldParams] struct {
	ToAddressHash   []frontend.Variable `gnark:",public"`
	SpecifyDataHash []frontend.Variable `gnark:",public"`
	PublicKey       *PublicKey[T]       `gnark:",public"`
	Header          FixEmailHeader
	Body            EmailBody
	Signature       EmailSig
}

// Define declares the circuit's constraints
func (c *DKIMVerifierWrapper[T]) Define(api frontend.API) error {
	//check
	bodyEncode := NewEmailBodyEncode(api)
	specifyDataHash_in_circuit, err := bodyEncode.GetSpecifyDataHash(c.Body)
	if err != nil {
		return err
	}
	for i, _ := range c.SpecifyDataHash {
		api.AssertIsEqual(c.SpecifyDataHash[i], specifyDataHash_in_circuit[i])
	}
	headerEncode := NewFixEmailHeaderEncode(api)
	toAddressHash_in_circuit, err := headerEncode.GetToAddressHash(c.Header)
	if err != nil {
		return err
	}
	for i, _ := range toAddressHash_in_circuit {
		api.AssertIsEqual(toAddressHash_in_circuit[i], c.ToAddressHash[i])
	}
	v := NewDKIMVerifier[T](api)
	err = v.Verify(c.Header, c.Body, c.Signature, *c.PublicKey)
	if err != nil {
		return err
	}
	return nil
}
