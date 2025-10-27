package dkim

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
)

func NewDKIMVerifier[T emulated.FieldParams](api frontend.API) DKIMVerifier[T] {
	return DKIMVerifier[T]{api: api}
}

type DKIMVerifier[T emulated.FieldParams] struct {
	api frontend.API
}

func (dk *DKIMVerifier[T]) Verify(header FixEmailHeader, sig EmailSig, publicKey PublicKey[T]) error {
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

func (dk *DKIMVerifier[T]) VerifyCustomEmail(header CustomEmailHeader, sig EmailSig, publicKey PublicKey[T]) error {
	api := dk.api
	headerEncode := NewCustomEmailHeaderEncode(api)
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
	PubInputHash []frontend.Variable `gnark:",public"`
	PublicKey    *PublicKey[T]
	Header       FixEmailHeader
	//Body         EmailBody
	Signature EmailSig
}

// Define declares the circuit's constraints
func (c *DKIMVerifierWrapper[T]) Define(api frontend.API) error {
	//check public input
	// pubkey N and E
	f, err := emulated.NewField[T](api)
	if err != nil {
		return err
	}
	u8Api, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	nBytes := BitsToBytes(api, f.ToBits(&c.PublicKey.N))
	eBytes := BitsToBytes(api, f.ToBits(&c.PublicKey.E))
	// Print N bytes and E bytes for debug
	/*	fmt.Println("N bytes (in circuit)", BitsToBytes(api, f.ToBits(&c.PublicKey.N)))
		fmt.Println("E bytes (in circuit)", BitsToBytes(api, f.ToBits(&c.PublicKey.E)))*/
	toHash, err := c.Header.To.GetSliceHash(api)
	if err != nil {
		return err
	}
	pubInput := nBytes
	pubInput = append(pubInput, eBytes...)
	pubInput = append(pubInput, c.Signature.BodyHash[:]...)
	pubInput = append(pubInput, toHash...)
	pubInputU8 := make([]uints.U8, len(pubInput))
	for i, _ := range pubInput {
		pubInputU8[i] = u8Api.ByteValueOf(pubInput[i])
	}
	hasher, err := sha2.New(api)
	if err != nil {
		return err
	}
	hasher.Write(pubInputU8)
	pubInputHash := hasher.Sum()
	/*	nSlice := PaddingSlice{
			Padding:        frontend.Variable(-1),
			Slice:          nBytes,
			IsLittleEndian: false,
		}
		eSlice := PaddingSlice{
			Padding:        frontend.Variable(-1),
			Slice:          eBytes,
			IsLittleEndian: false,
		}
		to := c.Header.To
		specifyData := c.Signature.BodyHash
		sliceApi := NewSliceApi(api)
		inputSlice := nSlice
		inputSlice = sliceApi.concat(inputSlice, eSlice, inputSlice.IsLittleEndian)
		inputSlice = sliceApi.concat(inputSlice, specifyData, inputSlice.IsLittleEndian)
		inputSlice = sliceApi.concat(inputSlice, to, inputSlice.IsLittleEndian)
		inputHash, err := inputSlice.GetSliceHash(api)
		if err != nil {
			return err
		}*/
	for i := range c.PubInputHash {
		api.AssertIsEqual(c.PubInputHash[i], pubInputHash[i].Val)
	}
	/*	fmt.Println("N bytes (in circuit)", BitsToBytes(api, f.ToBits(&c.PublicKey.N)))
		fmt.Println("E bytes (in circuit)", BitsToBytes(api, f.ToBits(&c.PublicKey.E)))*/
	v := NewDKIMVerifier[T](api)
	err = v.Verify(c.Header, c.Signature, *c.PublicKey)
	if err != nil {
		return err
	}
	return nil
}

type CustomDKIMVerifierWrapper[T emulated.FieldParams] struct {
	PubInputHash []frontend.Variable `gnark:",public"`
	PublicKey    *PublicKey[T]
	Header       CustomEmailHeader
	Signature    EmailSig
}

// Define declares the circuit's constraints
func (c *CustomDKIMVerifierWrapper[T]) Define(api frontend.API) error {
	//check public input
	// pubkey N and E
	f, err := emulated.NewField[T](api)
	if err != nil {
		return err
	}
	u8Api, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	nBytes := BitsToBytes(api, f.ToBits(&c.PublicKey.N))
	eBytes := BitsToBytes(api, f.ToBits(&c.PublicKey.E))
	// Print N bytes and E bytes for debug
	/*	fmt.Println("N bytes (in circuit)", BitsToBytes(api, f.ToBits(&c.PublicKey.N)))
		fmt.Println("E bytes (in circuit)", BitsToBytes(api, f.ToBits(&c.PublicKey.E)))*/
	toHash, err := c.Header.SpecifyData.GetSliceHash(api)
	if err != nil {
		return err
	}
	pubInput := nBytes
	pubInput = append(pubInput, eBytes...)
	pubInput = append(pubInput, c.Signature.BodyHash[:]...)
	pubInput = append(pubInput, toHash...)
	pubInputU8 := make([]uints.U8, len(pubInput))
	for i, _ := range pubInput {
		pubInputU8[i] = u8Api.ByteValueOf(pubInput[i])
	}
	hasher, err := sha2.New(api)
	if err != nil {
		return err
	}
	hasher.Write(pubInputU8)
	pubInputHash := hasher.Sum()
	/*	nSlice := PaddingSlice{
			Padding:        frontend.Variable(-1),
			Slice:          nBytes,
			IsLittleEndian: false,
		}
		eSlice := PaddingSlice{
			Padding:        frontend.Variable(-1),
			Slice:          eBytes,
			IsLittleEndian: false,
		}
		to := c.Header.To
		specifyData := c.Signature.BodyHash
		sliceApi := NewSliceApi(api)
		inputSlice := nSlice
		inputSlice = sliceApi.concat(inputSlice, eSlice, inputSlice.IsLittleEndian)
		inputSlice = sliceApi.concat(inputSlice, specifyData, inputSlice.IsLittleEndian)
		inputSlice = sliceApi.concat(inputSlice, to, inputSlice.IsLittleEndian)
		inputHash, err := inputSlice.GetSliceHash(api)
		if err != nil {
			return err
		}*/
	for i := range c.PubInputHash {
		api.AssertIsEqual(c.PubInputHash[i], pubInputHash[i].Val)
	}
	/*	fmt.Println("N bytes (in circuit)", BitsToBytes(api, f.ToBits(&c.PublicKey.N)))
		fmt.Println("E bytes (in circuit)", BitsToBytes(api, f.ToBits(&c.PublicKey.E)))*/
	v := NewDKIMVerifier[T](api)
	err = v.VerifyCustomEmail(c.Header, c.Signature, *c.PublicKey)
	if err != nil {
		return err
	}
	return nil
}
