package dkim

import (
	"errors"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
)

func NewRSA[T emulated.FieldParams](api frontend.API) RSA[T] {
	return RSA[T]{api: api}
}

type PublicKey[T emulated.FieldParams] struct {
	N []frontend.Variable // modulus
	E frontend.Variable
}

type RSA[T emulated.FieldParams] struct {
	api frontend.API
}

func (pub *PublicKey[T]) Size(api frontend.API) int {
	/*	bitsN := byte2bits(api, pub.N)
		bitsLength := len(bitsN)
		return (bitsLength + 7) / 8*/
	return (len(pub.N)*8 + 7) / 8
}

func (rsa *RSA[T]) VerifyPkcs1v15(publicKey *PublicKey[T], sign, hashed []frontend.Variable) error {
	api := rsa.api
	f, err := emulated.NewField[T](api)
	encrypt := rsa.encrypt(publicKey, sign)
	em := rsa.pkcs1v15ConstructEM(publicKey, hashed)
	if err != nil {
		return err
	}
	bitsN := byte2bits(api, publicKey.N)
	nelet := f.FromBits(bitsN...)
	f.ModAssertIsEqual(encrypt, em, nelet)
	return nil
}

func (rsa *RSA[T]) encrypt(pub *PublicKey[T], plaintext []frontend.Variable) *emulated.Element[T] {
	api := rsa.api
	f, err := emulated.NewField[T](api)
	if err != nil {
		panic(err)
	}
	bitsN := byte2bits(api, pub.N)
	nelet := f.FromBits(bitsN...)
	eelet := f.FromBits(bits.ToBinary(api, pub.E)...)
	bitsPtt := byte2bits(api, plaintext)
	pelet := f.FromBits(bitsPtt...)
	em := f.ModExp(pelet, nelet, eelet)
	return em
}

func (rsa *RSA[T]) pkcs1v15ConstructEM(pub *PublicKey[T], hashed []frontend.Variable) *emulated.Element[T] {
	api := rsa.api
	// Special case: crypto.Hash(0) is used to indicate that the data is
	// signed directly.
	prefix := []frontend.Variable{frontend.Variable(0x30), frontend.Variable(0x31), frontend.Variable(0x30), frontend.Variable(0x0d), frontend.Variable(0x06), frontend.Variable(0x09), frontend.Variable(0x60), frontend.Variable(0x86), frontend.Variable(0x48), frontend.Variable(0x01), frontend.Variable(0x65), frontend.Variable(0x03), frontend.Variable(0x04), frontend.Variable(0x02), frontend.Variable(0x01), frontend.Variable(0x05), frontend.Variable(0x00), frontend.Variable(0x04), frontend.Variable(0x20)}
	// EM = 0x00 || 0x01 || PS || 0x00 || T
	k := pub.Size(api)
	if k < len(prefix)+len(hashed)+2+8+1 {
		panic(errors.New("public key too small"))
	}
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
	embits := byte2bits(api, em)
	f, err := emulated.NewField[T](api)
	if err != nil {
		panic(err)
	}
	return f.FromBits(embits...)
}

func byte2bits(api frontend.API, bytesData []frontend.Variable) []frontend.Variable {
	bitsData := make([]frontend.Variable, 0)
	for i := 0; i < len(bytesData); i++ {
		bitsData = append(bitsData, bits.ToBinary(api, bytesData[i], bits.WithNbDigits(8))...)
	}
	return bitsData
}

type RSAWrapper[T emulated.FieldParams] struct {
	PublicKey    *PublicKey[T]
	Sign, Hashed []frontend.Variable
}

// Define declares the circuit's constraints
func (c *RSAWrapper[T]) Define(api frontend.API) error {
	rsa := NewRSA[T](api)
	err := rsa.VerifyPkcs1v15(c.PublicKey, c.Sign, c.Hashed)
	if err != nil {
		return err
	}
	return nil
}
