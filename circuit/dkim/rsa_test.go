package dkim

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

func TestRSACircuit(t *testing.T) {
	assert := test.NewAssert(t)
	prvkey, pubkey, err, structPubKey := GenRsaKey(2048)
	if err != nil {
		panic(err)
	}
	data := []byte("foo")
	// Using SHA256 to hash msg and then use rsa private key to Sign.
	sig, err := RsaSign(prvkey, crypto.SHA256, data)
	if err != nil {
		panic(err)
	}
	if len(sig) != 2048/8 {
		panic("signature len not equal to key length")
	}
	// Using public key to verify signature.
	err = RsaVerifySign(pubkey, crypto.SHA256, data, sig)
	if err != nil {
		panic(err)
	}
	fmt.Println("verify signature succeeded")

	sign_array := make([]frontend.Variable, len(sig))
	for i := 0; i < len(sig); i++ {
		sign_array[i] = sig[i]
	}
	hash := sha256.New()
	hash.Write(data)
	hashSum := hash.Sum(nil)
	hash_array := make([]frontend.Variable, len(hashSum))
	for i := 0; i < len(hashSum); i++ {
		hash_array[i] = hashSum[i]
	}

	circuit := RSAWrapper[emparams.Mod1e4096]{
		PublicKey: &PublicKey[emparams.Mod1e4096]{
			N: emulated.ValueOf[emparams.Mod1e4096](structPubKey.N),
			E: emulated.ValueOf[emparams.Mod1e4096](structPubKey.E),
		},
		Sign:   sign_array,
		Hashed: hash_array,
	}
	assignment := RSAWrapper[emparams.Mod1e4096]{
		PublicKey: &PublicKey[emparams.Mod1e4096]{
			N: emulated.ValueOf[emparams.Mod1e4096](structPubKey.N),
			E: emulated.ValueOf[emparams.Mod1e4096](structPubKey.E),
		},
		Sign:   sign_array,
		Hashed: hash_array,
	}
	//ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	//assert.NoError(err)
	//fmt.Println(ccs.GetNbConstraints())
	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}
