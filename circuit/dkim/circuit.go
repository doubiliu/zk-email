package dkim

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/doubiliu/zk-email/algorithm"
)

type CustomDKIMVerifierWrapper[T emulated.FieldParams] struct {
	PubInputHash []frontend.Variable `gnark:",public"`
	PublicKey    *PublicKey[T]
	Header       CustomEmailHeader
	Signature    EmailSig
}

// Define declares the circuit's constraints.
func (c *CustomDKIMVerifierWrapper[T]) Define(api frontend.API) error {
	// compute and check with public input hash
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
	fromHash, err := c.Header.SpecifyData.GetSliceHash(api)
	if err != nil {
		return err
	}
	pubInput := append(nBytes, eBytes...)
	pubInput = append(pubInput, c.Signature.BodyHash[:]...)
	pubInput = append(pubInput, fromHash...)
	pubInputU8 := make([]uints.U8, len(pubInput))
	for i, v := range pubInput {
		pubInputU8[i] = u8Api.ByteValueOf(v)
	}
	hasher, err := sha2.New(api)
	if err != nil {
		return err
	}
	hasher.Write(pubInputU8)
	pubInputHash := hasher.Sum()
	for i := range c.PubInputHash {
		api.AssertIsEqual(c.PubInputHash[i], pubInputHash[i].Val)
	}
	return verifyCustomEmail(api, c.Header, c.Signature, *c.PublicKey)
}

// verifyCustomEmail verifies the DKIM signature within the circuit.
func verifyCustomEmail[T emulated.FieldParams](api frontend.API, header CustomEmailHeader, sig EmailSig, publicKey PublicKey[T]) error {
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

// GetCustomDKIMVerifierWrapper returns a DKIM verifier circuit template for the specified mail type.
func GetCustomDKIMVerifierWrapper(mailType string) (*CustomDKIMVerifierWrapper[emparams.Mod1e4096], error) {
	var template string
	switch mailType {
	case "gmail":
		template = GmailTemplate
	case "outlook":
		template = OutlookTemplate
	case "foxmail":
		template = FoxmailTemplate
	case "icloud":
		template = ICloudTemplate
	default:
		return nil, errors.New("unknown mail type")
	}
	result, err := newCircuit[emparams.Mod1e4096](template, rsaPubkeyTemplate)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// NewAssignment creates a new assignment for the DKIM verifier circuit.
func NewAssignment[T emulated.FieldParams](message string, txtRecord string, templateCircuit *CustomDKIMVerifierWrapper[T]) (frontend.Circuit, error) {
	assignment, err := newCircuit[T](message, txtRecord)
	if err != nil {
		return nil, err
	}
	// Pad 0.
	prefixDataPaddingLength := len(templateCircuit.Header.PrefixData.Slice) - len(assignment.Header.PrefixData.Slice)
	specifyDataPaddingLength := len(templateCircuit.Header.SpecifyData.Slice) - len(assignment.Header.SpecifyData.Slice)
	suffixDataPaddingLength := len(templateCircuit.Header.SuffixData.Slice) - len(assignment.Header.SuffixData.Slice)
	sigPrefixPaddingLength := len(templateCircuit.Signature.SigPrefix.Slice) - len(assignment.Signature.SigPrefix.Slice)
	sigSuffixPaddingLength := len(templateCircuit.Signature.SigSuffix.Slice) - len(assignment.Signature.SigSuffix.Slice)

	if prefixDataPaddingLength < 0 {
		return nil, errors.New("prefix data size is too big")
	}
	if specifyDataPaddingLength < 0 {
		return nil, errors.New("specify data size is too big")
	}
	if suffixDataPaddingLength < 0 {
		return nil, errors.New("suffix data size is too big")
	}
	if sigPrefixPaddingLength < 0 {
		return nil, errors.New("sigPrefix data size is too big")
	}
	if sigSuffixPaddingLength < 0 {
		return nil, errors.New("sigSuffix data size is too big")
	}
	prefixDataZeroPadding := BytesToFrontVariable(make([]byte, prefixDataPaddingLength))
	specifyDataZeroPadding := BytesToFrontVariable(make([]byte, specifyDataPaddingLength))
	suffixDataZeroPadding := BytesToFrontVariable(make([]byte, suffixDataPaddingLength))

	assignment.Header.PrefixData.Slice = append(prefixDataZeroPadding, assignment.Header.PrefixData.Slice...)
	assignment.Header.SpecifyData.Slice = append(specifyDataZeroPadding, assignment.Header.SpecifyData.Slice...)
	assignment.Header.SuffixData.Slice = append(suffixDataZeroPadding, assignment.Header.SuffixData.Slice...)

	assignment.Header.PrefixData.Padding = frontend.Variable(prefixDataPaddingLength - 1)
	assignment.Header.SpecifyData.Padding = frontend.Variable(specifyDataPaddingLength - 1)
	assignment.Header.SuffixData.Padding = frontend.Variable(suffixDataPaddingLength - 1)

	sigPrefixZeroPadding := BytesToFrontVariable(make([]byte, sigPrefixPaddingLength))
	assignment.Signature.SigPrefix.Slice = append(sigPrefixZeroPadding, assignment.Signature.SigPrefix.Slice...)
	assignment.Signature.SigPrefix.Padding = frontend.Variable(sigPrefixPaddingLength - 1)

	sigSuffixZeroPadding := BytesToFrontVariable(make([]byte, sigSuffixPaddingLength))
	assignment.Signature.SigSuffix.Slice = append(sigSuffixZeroPadding, assignment.Signature.SigSuffix.Slice...)
	assignment.Signature.SigSuffix.Padding = frontend.Variable(sigSuffixPaddingLength - 1)

	return assignment, nil
}

// newCircuit creates a new DKIM verifier circuit from the email message and DNS TXT record.
func newCircuit[T emulated.FieldParams](message string, txtRecord string) (*CustomDKIMVerifierWrapper[T], error) {
	email := algorithm.ParseEmail(message)
	var signatureHeader string
	fromHeaderIndex := -1
	for index, header := range email.Headers() {
		// We don't support DKIM-Signature headers signing other DKIM-Signature.
		if algorithm.IsFromHeader(header) {
			fromHeaderIndex = index
		}
		// Check and find DKIM-Signature header.
		if algorithm.IsSignatureHeader(header) {
			if signatureHeader != "" {
				return nil, errors.New("multiple DKIM headers")
			}
			signatureHeader = header
		}
	}
	if fromHeaderIndex == -1 {
		return nil, errors.New("no from address header found")
	}
	if signatureHeader == "" {
		return nil, errors.New("no DKIM header found")
	}
	signature, err := algorithm.ParseSignature(signatureHeader)
	if err != nil {
		return nil, err
	}
	signatureHeaderNames := make([]string, len(signature.HeaderNames()))
	for i, name := range signature.HeaderNames() {
		signatureHeaderNames[i] = strings.ToLower(name)
	}
	signedHeaders := algorithm.ExtractHeaders(email.Headers(), signatureHeaderNames)
	predixData := make([]byte, 0)
	specifyData := make([]byte, 0)
	suffixData := make([]byte, 0)
	for index, header := range signedHeaders {
		if index < fromHeaderIndex {
			predixData = append(predixData, []byte(signature.Canon().Header()(header))...)
		}
		if index == fromHeaderIndex {
			specifyData = append(specifyData, []byte(signature.Canon().Header()(header))...)
		}
		if index > fromHeaderIndex {
			suffixData = append(suffixData, []byte(signature.Canon().Header()(header))...)
		}
	}
	trimmedHeader := signature.Canon().Header()(signature.TrimmedHeader())
	sigPrefix := trimmedHeader[0 : strings.Index(trimmedHeader, "bh=")+3]
	sigSuffix := trimmedHeader[strings.Index(trimmedHeader, "bh=")+3+len(base64.StdEncoding.EncodeToString(signature.BodyHash())) : strings.Index(trimmedHeader, "b=")+2]
	bodyHash := [32]frontend.Variable{}
	for i := range bodyHash {
		bodyHash[i] = signature.BodyHash()[i]
	}
	// From DNS txt record to RSA pubkey.
	key := algorithm.ParsePubkey(txtRecord)
	pubKey, err := x509.ParsePKIXPublicKey(key.Key())
	if err != nil {
		return nil, err
	}
	// Compute publicInputHash.
	nBytes := pubKey.(*rsa.PublicKey).N.FillBytes(make([]byte, 512))
	eBytes := new(big.Int).SetInt64(int64(pubKey.(*rsa.PublicKey).E)).FillBytes(make([]byte, 512))
	fromHash := GetHash(specifyData)
	pubInputHash := GetHash(nBytes, eBytes, signature.BodyHash(), fromHash)
	return &CustomDKIMVerifierWrapper[T]{
		PublicKey: &PublicKey[T]{
			N: emulated.ValueOf[T](pubKey.(*rsa.PublicKey).N),
			E: emulated.ValueOf[T](pubKey.(*rsa.PublicKey).E),
		},
		Header: CustomEmailHeader{
			PrefixData:  BytesToPadding(predixData, false, -1),
			SpecifyData: BytesToPadding(specifyData, false, -1),
			SuffixData:  BytesToPadding(suffixData, false, -1),
		},
		Signature: EmailSig{
			SigPrefix:  BytesToPadding([]byte(sigPrefix), false, -1),
			BodyHash:   bodyHash,
			SigSuffix:  BytesToPadding([]byte(sigSuffix), false, -1),
			SigContent: BytesToFrontVariable(signature.Signature()),
		},
		PubInputHash: BytesToFrontVariable(pubInputHash),
	}, nil
}
