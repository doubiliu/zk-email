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

func (dk *DKIMVerifier[T]) VerifyCustomEmail(header CustomEmailHeader, sig EmailSig, publicKey PublicKey[T]) error {
	api := dk.api
	headerEncode := NewCustomEmailHeaderEncode(api)
	//bodyEncode := NewEmailBodyEncode(api)
	sigEncode := NewEmailSigEncode(api)
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
