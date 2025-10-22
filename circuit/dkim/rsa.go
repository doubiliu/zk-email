package dkim

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

func NewRSA[T emulated.FieldParams](api frontend.API) RSA[T] {
	return RSA[T]{api: api}
}

type PublicKey[T emulated.FieldParams] struct {
	N emulated.Element[T] // modulus
	E emulated.Element[T]
}

type RSA[T emulated.FieldParams] struct {
	api frontend.API
}

func (rsa *RSA[T]) VerifyPkcs1v15(pubKey *PublicKey[T], sign, hashed []frontend.Variable) error {
	em, err := rsa.encrypt(pubKey, sign)
	if err != nil {
		return err
	}
	expected, err := rsa.pkcs1v15ConstructEM(rsa.api, hashed, len(sign))
	if err != nil {
		return err
	}
	if len(em) < len(expected) {
		// Impossible case, otherwise the pub.N has an overflow when input
		panic("em overflow")
	}
	for i := 0; i < len(expected); i++ {
		rsa.api.AssertIsEqual(em[i], expected[i])
	}
	return nil
}

func (rsa *RSA[T]) encrypt(pub *PublicKey[T], sign []frontend.Variable) ([]frontend.Variable, error) {
	f, err := emulated.NewField[T](rsa.api)
	if err != nil {
		return nil, err
	}
	// Ensure the bitlength of pub.N is not larger than sign, here checks the value directly
	p := f.FromBits(ByteToBits(rsa.api, sign)...)
	f.AssertIsLessOrEqual(p, &pub.N)
	// Compute p = sign^e mod n
	em := f.ToBits(f.ModExp(p, &pub.E, &pub.N))
	return em, nil
}

func (rsa *RSA[T]) pkcs1v15ConstructEM(api frontend.API, hashed []frontend.Variable, k int) ([]frontend.Variable, error) {
	prefix := []frontend.Variable{frontend.Variable(0x30), frontend.Variable(0x31), frontend.Variable(0x30), frontend.Variable(0x0d), frontend.Variable(0x06), frontend.Variable(0x09), frontend.Variable(0x60), frontend.Variable(0x86), frontend.Variable(0x48), frontend.Variable(0x01), frontend.Variable(0x65), frontend.Variable(0x03), frontend.Variable(0x04), frontend.Variable(0x02), frontend.Variable(0x01), frontend.Variable(0x05), frontend.Variable(0x00), frontend.Variable(0x04), frontend.Variable(0x20)}
	// EM = 0x00 || 0x01 || PS || 0x00 || T
	em := make([]frontend.Variable, k)
	for i := 0; i < k; i++ {
		em[i] = 0x00
	}
	em[1] = 0x01
	for i := 2; i < k-len(prefix)-len(hashed)-1; i++ {
		em[i] = 0xff
	}
	copy(em[k-len(prefix)-len(hashed):], prefix)
	copy(em[k-len(hashed):], hashed)
	return ByteToBits(api, em), nil
}
