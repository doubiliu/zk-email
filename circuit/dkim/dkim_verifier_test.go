package dkim

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bane-labs/dbft-verifier/algorithm"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
	"github.com/containerd/containerd/pkg/hasher"
)

var headersOnly = fixupNewlines(`mime-version:1.0
from:Jelle van den Hooff <jelle@vandenhooff.name>
date:Sun, 29 Mar 2015 22:39:03 -0400
message-id:<CAP=Jqubpoizbfg+Fb_+ycEkhqrgMBE=qozKrRubUuimQ717wKw@mail.gmail.com>
subject:vnsy7km1hn4crbyp0h32m3932p38qtgbhpxf9mp01s6w40mvk2jg
to:1v443yp1p8@keytree.io
content-type:text/plain; charset=UTF-8
dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=vandenhooff.name; s=google; h=mime-version:from:date:message-id:subject:to:content-type; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b=NCOUEepJZ6cdKYtq61hifQ9K0fimliTNcDVDBQ8C1OQToNxNGQuGifUxWQ/6odRnmm+TGraJoXyKu2WwVl2auHW6Hug/9QBWg6JIQrUl3TLK5Z07IZHpqBFrXjqV/fd6Yl/1+LZSaJ9lwo6YW6LvwoAq4AUwPDZqXeak7i5pj2U=`)

var client = &fakeDnsClient{
	results: map[string][]string{
		"google._domainkey.vandenhooff.name.": {
			`v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCl2Qrp5KF1uJnQSO0YuwInVPISQRrUciXtg/5hnQl6ed+UmYvWreLyuiyaiSd9X9Zu+aZQoeKm67HCxSMpC6G2ar0NludsXW69QdfzUpB5I6fzaLW8rl/RyeGkiQ3D66kvadK1wlNfUI7Dt9WtnUs8AFz/15xvODzgTMFJDiAcAwIDAQAB`,
		},
	},
}

type fakeDnsClient struct {
	results map[string][]string
}

func (c *fakeDnsClient) LookupTxt(hostname string) ([]string, error) {
	if result, found := c.results[hostname]; found {
		return result, nil
	} else {
		return nil, errors.New("hostname not found")
	}
}

func fixupNewlines(s string) string {
	return strings.Replace(s, "\n", "\r\n", -1)
}

func TestDKIMCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	email := algorithm.ParseEmail(headersOnly)
	var signatureHeader string
	for _, header := range email.Headers() {
		// we don't support DKIM-Signature headers signing other DKIM-Signature
		// headers
		if algorithm.IsSignatureHeader(header) {
			if signatureHeader != "" {
				panic(errors.New("multiple DKIM headers"))
			}
			signatureHeader = header
		}
	}
	if signatureHeader == "" {
		panic(errors.New("no DKIM header found"))
	}
	signature, err := algorithm.ParseSignature(signatureHeader)
	if err != nil {
		panic(err)
	}
	signedHeaders := algorithm.ExtractHeaders(email.Headers(), signature.HeaderNames())
	//从DNS查找RSA公钥
	txtRecords, err := client.LookupTxt(signature.TxtRecordName())
	if err != nil {
		panic(err)
	}
	//验签
	txtRecord := txtRecords[0]
	fmt.Println("public key:" + txtRecord)
	key := algorithm.ParsePubkey(txtRecord)
	/*	err = signature.Algo().CheckSig()(pubkey.Key(), headersHash, signature.Signature())
		if err != nil {
			panic(err)
		}
		fmt.Println("DKIM signature verify success")*/
	fmt.Println("DKIM signature:" + base64.StdEncoding.EncodeToString(signature.Signature()))
	pubKey, err := x509.ParsePKIXPublicKey(key.Key())
	if err != nil {
		panic(err)
	}

	mimeVersion := []byte(signature.Canon().Header()(signedHeaders[0]))
	from := []byte(signature.Canon().Header()(signedHeaders[1]))
	date := []byte(signature.Canon().Header()(signedHeaders[2]))
	message_id := []byte(signature.Canon().Header()(signedHeaders[3]))
	subject := []byte(signature.Canon().Header()(signedHeaders[4]))
	to := []byte(signature.Canon().Header()(signedHeaders[5]))
	content_type := []byte(signature.Canon().Header()(signedHeaders[6]))

	bodyHash := [32]frontend.Variable{}
	for i := range bodyHash {
		temp, err := base64.StdEncoding.DecodeString(testBodyHash)
		if err != nil {
			panic(err)
		}
		bodyHash[i] = temp[i]
	}
	sha256 := hasher.NewSHA256()
	sha256.Write(to)
	toAddressHash := sha256.Sum(nil)

	sha256.Reset()
	sha256.Write([]byte("SpecifyData"))
	specifyDataHash := sha256.Sum(nil)

	circuit := DKIMVerifierWrapper[emparams.Mod1e4096]{
		PublicKey: &PublicKey[emparams.Mod1e4096]{
			N: emulated.ValueOf[emparams.Mod1e4096](pubKey.(*rsa.PublicKey).N),
			E: emulated.ValueOf[emparams.Mod1e4096](pubKey.(*rsa.PublicKey).E),
		},
		Header: FixEmailHeader{
			MimeVersion: BytesToPadding(mimeVersion, false, -1),
			From:        BytesToPadding(from, false, -1),
			Date:        BytesToPadding(date, false, -1),
			MessageId:   BytesToPadding(message_id, false, -1),
			Subject:     BytesToPadding(subject, false, -1),
			To:          BytesToPadding(to, false, -1),
			ContentType: BytesToPadding(content_type, false, -1),
		},
		Body: EmailBody{
			PrefixContent: PaddingSlice{
				Padding:        frontend.Variable(-1),
				Slice:          BytesToFrontVariable([]byte("test data1")),
				IsLittleEndian: false,
			},
			SuffixContent: PaddingSlice{
				Padding:        frontend.Variable(-1),
				Slice:          BytesToFrontVariable([]byte("test data2")),
				IsLittleEndian: false,
			},
			TextContent: PaddingSlice{
				Padding:        frontend.Variable(-1),
				Slice:          BytesToFrontVariable([]byte("SpecifyData")),
				IsLittleEndian: false,
			},
		},
		Signature: EmailSig{
			SigPrefix: PaddingSlice{
				Padding:        frontend.Variable(-1),
				Slice:          BytesToFrontVariable([]byte(testSigPrefix)),
				IsLittleEndian: false,
			},
			BodyHash:   bodyHash,
			SigContent: BytesToFrontVariable(signature.Signature()),
		},
		SpecifyDataHash: BytesToFrontVariable(specifyDataHash),
		ToAddressHash:   BytesToFrontVariable(toAddressHash),
	}
	assignment := DKIMVerifierWrapper[emparams.Mod1e4096]{
		PublicKey: &PublicKey[emparams.Mod1e4096]{
			N: emulated.ValueOf[emparams.Mod1e4096](pubKey.(*rsa.PublicKey).N),
			E: emulated.ValueOf[emparams.Mod1e4096](pubKey.(*rsa.PublicKey).E),
		},
		Header: FixEmailHeader{
			MimeVersion: BytesToPadding(mimeVersion, false, -1),
			From:        BytesToPadding(from, false, -1),
			Date:        BytesToPadding(date, false, -1),
			MessageId:   BytesToPadding(message_id, false, -1),
			Subject:     BytesToPadding(subject, false, -1),
			To:          BytesToPadding(to, false, -1),
			ContentType: BytesToPadding(content_type, false, -1),
		},
		Body: EmailBody{
			PrefixContent: PaddingSlice{
				Padding:        frontend.Variable(-1),
				Slice:          BytesToFrontVariable([]byte("test data1")),
				IsLittleEndian: false,
			},
			SuffixContent: PaddingSlice{
				Padding:        frontend.Variable(-1),
				Slice:          BytesToFrontVariable([]byte("test data2")),
				IsLittleEndian: false,
			},
			TextContent: PaddingSlice{
				Padding:        frontend.Variable(-1),
				Slice:          BytesToFrontVariable([]byte("SpecifyData")),
				IsLittleEndian: false,
			},
		},
		Signature: EmailSig{
			SigPrefix: PaddingSlice{
				Padding:        frontend.Variable(-1),
				Slice:          BytesToFrontVariable([]byte(testSigPrefix)),
				IsLittleEndian: false,
			},
			BodyHash:   bodyHash,
			SigContent: BytesToFrontVariable(signature.Signature()),
		},
		SpecifyDataHash: BytesToFrontVariable(specifyDataHash),
		ToAddressHash:   BytesToFrontVariable(toAddressHash),
	}
	/*	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
		assert.NoError(err)*/
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	fmt.Println(ccs.GetNbConstraints())
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	start := time.Now()
	proof, err := groth16.Prove(ccs, pk, witness, backend.WithProverHashToFieldFunction(hasher.NewSHA256()))
	if err != nil {
		panic(err)
	}
	fmt.Println("Prove Time: ", time.Since(start))
	publicWitness, err := witness.Public()
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, vk, publicWitness, backend.WithVerifierHashToFieldFunction(hasher.NewSHA256()))
	if err != nil {
		panic(err)
	}

	assert.NoError(err)
}
