package dkim

import (
	"github.com/consensys/gnark/frontend"
)

func NewDKIM(api frontend.API) DKIM {
	return DKIM{api: api}
}

type DKIM struct {
	api frontend.API
}

func (dk *DKIM) Verify(srcData []frontend.Variable) error {
	/*	remainder := b64enc.checkRemainder(srcData, 0)
		splitBits := b64enc.split(srcData, remainder)
		encodeData := b64enc.encode(splitBits)
		return encodeData*/
	return nil
}

type DKIMWrapper struct {
}

// Define declares the circuit's constraints
func (c *DKIMWrapper) Define(api frontend.API) error {
	return nil
}
