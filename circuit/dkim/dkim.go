package dkim

import (
	"github.com/consensys/gnark/frontend"
)

func NewDKIMCircuit(api frontend.API) DKIMCircuit {
	return DKIMCircuit{api: api}
}

type DKIMCircuit struct {
	api frontend.API
}

func (dk *DKIMCircuit) Verify(sig, sigB64 []frontend.Variable) error {
	api := dk.api
	//检查签名base64转换正确
	b64encode := NewBase64Encode(api)
	sig_b64_in_circuit := b64encode.EncodeRule2(sig)
	for i := 0; i < len(sig_b64_in_circuit); i++ {
		api.AssertIsEqual(sig_b64_in_circuit[i], sigB64[i])
	}
	return nil
}

type DKIMWrapper struct {
	SigB64    []frontend.Variable `gnark:",public"`
	Sig       []frontend.Variable
	Header    Header
	PublicKey *PublicKey[T]
}

// Define declares the circuit's constraints
func (c *DKIMWrapper) Define(api frontend.API) error {
	return nil
}
