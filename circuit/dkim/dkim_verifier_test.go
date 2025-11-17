package dkim

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
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
	"math/big"
	"strings"
	"testing"
	"time"
)

var GmailTestData = FixupNewlines(`to:Shili Hu <799498265@qq.com>
subject:Test
message-id:<CAM1mABt3Ds8Fh7siVUDBg89ejujDu6iRA4xg6zCQEygfHhCgqw@mail.gmail.com>
date:Fri, 7 Nov 2025 17:36:42 +0800
from:Shili Hu <foxsama0315@gmail.com>
mime-version:1.0
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762508214; x=1763113014; darn=qq.com;
        h=to:subject:message-id:date:from:mime-version:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Zw3hRkOx46aqHBgt2igwYFtlepgC6pfEZvcSrep7ftU=;
        b=bmJsyZdPshkWt3r/dcQXW5pSN4vS2h7vScI/IyevUlUqsatvPjgffjQmt8ZYzvC/dd
         Zy2WEuIcRhHBhxyOqz2sQgyyBJnpn3XyhxqJErpk06EAzQPyAVGRn8t0AKg3a2Oq4lHf
         UGMnSFM2955aidNpApPoONYSq46zo/sRheBzYKVDFYxvZtE7pv2PG5qHT4k34NWi5S3T
         QeExQ3rgIX2OU4QE3jfxhdo+9i8oHOES80YneT7VfM8CFFxV0N4Hllm7pUvwjJKvgqIt
         FioIk9ArYy79wYUPka3OZ4Xu4okl9vmznBakrYev2yPFdyGoERtZcStiBnUNu290cdeN
         8a6A==`)

var NGDTestData = FixupNewlines(`To: foxsama0315@gmail.com
From: =?utf-8?B?6IOh5LiW5Yqb?= <teumessian@icloud.com>
Subject: Test
Date: Thu, 30 Oct 2025 03:17:50 +0000 (GMT)
Message-id: <5adbbd00-c957-414f-ba51-a78658b6bf18@me.com>
Content-Type: multipart/alternative; boundary=Apple-Webmail-42--8c3353c6-96e9-4ac5-bbf4-ecacc113256b
MIME-Version: 1.0
Dkim-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=icloud.com; s=1a1hai; bh=ezxyzBzRGSBXS5S4lWvXBCnLY6s83Ja07W1HwKIi4fQ=; h=To:From:Subject:Date:Message-id:Content-Type:MIME-Version:x-icloud-hme; b=gmuFpMQyDOF03EDvmmN2USYrlaASH8Z6hlkd90U7P5/83hGrUs2CEPgQfQWLnSOu9WBNPEx71KFrUY/wyZTJemmrlVjKGZtH74w3hlZV0eosltCfDc07cteVs3k0CImxWokRQlnpzUmI7PZRFhAUXuDX1PbQ1TuFm+onlDd1XAIDSfG4fnGdNdfK23estXJDCJhms7vFQzDX5Fv99LT3a/wi/9w1vV2AtMSiRO55PO1d6EFck0z1+G0o21+iQOpC3PkaPB2xru50QrKKKa4AfNqtCSvLiTHY20bDWHMKGY0292dHMSmF3r9T9PGMMGP3DmnmZfv/tTu+/a00MO9jtg==
`)

var OutLookTestData = FixupNewlines(`From: mengyu <mengyu@neo.link>
Date: Fri, 7 Nov 2025 07:14:53 +0000
Subject: Test dk
Message-ID: <PSAPR03MB527104A6E1E590D927033F1ABDC3A@PSAPR03MB5271.apcprd03.prod.outlook.com>
Content-Type: multipart/alternative; boundary="_000_PSAPR03MB527104A6E1E590D927033F1ABDC3APSAPR03MB5271apcp_"
MIME-Version: 1.0
x-ms-exchange-senderadcheck: 1
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=neo.link; s=selector1; h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-SenderADCheck; bh=GGsDC64gLwrxyhYYdbSXAU59KMqyyAQCWjIk7sn+QVo=; b=fCYL+eOzOO0xNLZsZbjaa6lo++gu0ETc67ivaFD48ZLxX8i5Aq9SklhSSIo4S889yWQ0h203A+yVW9bihnW2wohnXW00UzhK2w/XnVANW0KlerWfIhJ447UOoQ5Bk/P9XfUSWszu1R9FU7UJIYJEHD8IGvGPpHeOJQRQ/u0VQ8MliqPgtEo3OVLw1odSNSX/Tukoke8/o1tikxWrcGMYhm+L6Q0KUMg6oPkp+GN4bXZEabKkfGpEQ5/ZnphWlHVKVd3d326QPlZXUBd7smfODnU9VfvmroI9uWcrg/FKCofooSKqSL4TH/W9Rj8Yc/TkZt3aHFZBja4J23NHp0mMaA==`)

var ICloudTestData = FixupNewlines(`To: foxsama0315@gmail.com
From: =?utf-8?B?6IOh5LiW5Yqb?= <teumessian@icloud.com>
Subject: Test
Date: Thu, 30 Oct 2025 03:17:50 +0000 (GMT)
Message-id: <5adbbd00-c957-414f-ba51-a78658b6bf18@me.com>
Content-Type: multipart/alternative; boundary=Apple-Webmail-42--8c3353c6-96e9-4ac5-bbf4-ecacc113256b
MIME-Version: 1.0
Dkim-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=icloud.com; s=1a1hai; bh=ezxyzBzRGSBXS5S4lWvXBCnLY6s83Ja07W1HwKIi4fQ=; h=To:From:Subject:Date:Message-id:Content-Type:MIME-Version:x-icloud-hme; b=gmuFpMQyDOF03EDvmmN2USYrlaASH8Z6hlkd90U7P5/83hGrUs2CEPgQfQWLnSOu9WBNPEx71KFrUY/wyZTJemmrlVjKGZtH74w3hlZV0eosltCfDc07cteVs3k0CImxWokRQlnpzUmI7PZRFhAUXuDX1PbQ1TuFm+onlDd1XAIDSfG4fnGdNdfK23estXJDCJhms7vFQzDX5Fv99LT3a/wi/9w1vV2AtMSiRO55PO1d6EFck0z1+G0o21+iQOpC3PkaPB2xru50QrKKKa4AfNqtCSvLiTHY20bDWHMKGY0292dHMSmF3r9T9PGMMGP3DmnmZfv/tTu+/a00MO9jtg==
`)

var FoxmailTestData = FixupNewlines(`From: "=?utf-8?B?c3RyaW5nIExWPeKAnOaaluWGsOKAnQ==?=" <jinghui.liao@foxmail.com>
To: "=?utf-8?B?bGl1bWVuZ3l1MDkzMA==?=" <liumengyu0930@gmail.com>
Subject: zkemail test
Date: Tue, 4 Nov 2025 16:28:38 +0800
dkim-signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=foxmail.com; s=s201512; t=1762244918; bh=puPE4wrCV5YcrcfuFwepbL9s4gzEO/Omu6K0zc+lG5k=; h=From:To:Subject:Date; b=puBeLAmUrZcLTca/kAoDQaW1lUTidBFWtU5oEwIA3dJoeF/8wol9exglsHJFq58budhpmES0VTMpCr4v3rb4TH0gJ+r/Z3k1009nMQlBh3gTWJAG6LUgvXDxlQQBZRM4NlhrgenWw7yebQlbltmOfdY3Uy/mkiidj8fMNEfI3I4=`)

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
		"s201512._domainkey.foxmail.com.": {
			"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPsFIOSteMStsN615gUWK2RpNJ/B/ekmm4jVlu2fNzXADFkjF8mCMgh0uYe8w46FVqxUS97habZq6P5jmCj/WvtPGZAX49jmdaB38hzZ5cUmwYZkdue6dM17sWocPZO8e7HVdq7bQwfGuUjVuMKfeTB3iNeo6/hFhb9TmUgnwjpQIDAQAB",
		},
		"1a1hai._domainkey.icloud.com.": {
			"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1ZEfbkf4TbO2TDZI67WhJ6G8Dwk3SJyAbBlE/QKdyXFZB4HfEU7AcuZBzcXSJFE03DlmyOkUAmaaR8yFlwooHyaKRLIaT3epGlL5YGowyfItLly2k0Jj0IOICRxWrB378b7qMeimE8KlH1UNaVpRTTi0XIYjIKAOpTlBmkM9a/3Rl4NWy8pLYApXD+WCkYxPcxoAAgaN8osqGTCJ5r+VHFU7Wm9xqq3MZmnfo0bzInF4UajCKjJAQa+HNuh95DWIYP/wV77/PxkEakOtzkbJMlFJiK/hMJ+HQUvTbtKW2s+t4uDK8DI16Rotsn6e0hS8xuXPmVte9ZzplD0fQgm2qwIDAQAB",
		},
		"20230601._domainkey.gmail.com.": {
			"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAntvSKT1hkqhKe0xcaZ0x+QbouDsJuBfby/S82jxsoC/SodmfmVs2D1KAH3mi1AqdMdU12h2VfETeOJkgGYq5ljd996AJ7ud2SyOLQmlhaNHH7Lx+Mdab8/zDN1SdxPARDgcM7AsRECHwQ15R20FaKUABGu4NTbR2fDKnYwiq5jQyBkLWP+LgGOgfUF4T4HZb2PY2bQtEP6QeqOtcW4rrsH24L7XhD+HSZb1hsitrE0VPbhJzxDwI4JF815XMnSVjZgYUXP8CxI1Y0FONlqtQYgsorZ9apoW1KPQe8brSSlRsi9sXB/tu56LmG7tEDNmrZ5XUwQYUUADBOu7t1niwXwIDAQAB",
		},
		"selector1._domainkey.neo.link.": {
			"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArqlcwDWpSexGyw8ISmtbx3zcLwue2qBVsADdOzDRgm5ZbGm648Rz/+ClZQE1VGkY0SGcWp7WfN7YH8PR8M/UqnV7rlT5uGvrJ3h/ZHd/dCq/NqpPpH1aBT6eISptgnD5vXG/yiJVjqOmIHVlI2UHmce2JEl6uS1b3Ksn86svQtuTFWmGv8TiyXZLXJaYfI8ZZn7VAQ7qjpMt15+PBfGYw0ykNEgyTkjpYHSX241WhyLU0kgEcIxLulMOykeE+46bwx5Wl0IN9F90QXDZHLiAVJD03+sWSP9ZKIM9oLzWJvOoMNIT8VZrGQy1X0102ACdRn2x661s8Fst9Rwo+3W3FQIDAQAB;",
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

func TestDKIMCircuitByCustomedHeader(t *testing.T) {
	assert := test.NewAssert(t)
	email := algorithm.ParseEmail(headersOnly)
	var signatureHeader string
	toHeaderIndex := -1
	for index, header := range email.Headers() {
		if algorithm.IsToHeader(header) {
			toHeaderIndex = index
		}
		// headers
		if algorithm.IsSignatureHeader(header) {
			if signatureHeader != "" {
				panic(errors.New("multiple DKIM headers"))
			}
			signatureHeader = header
		}
	}
	if toHeaderIndex == -1 {
		panic(errors.New("no to header found"))
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
	txtRecord := txtRecords[1]
	fmt.Println("public key:" + txtRecord)
	key := algorithm.ParsePubkey(txtRecord)
	fmt.Println("DKIM signature:" + base64.StdEncoding.EncodeToString(signature.Signature()))
	pubKey, err := x509.ParsePKIXPublicKey(key.Key())
	if err != nil {
		panic(err)
	}
	predixData := make([]byte, 0)
	specifyData := make([]byte, 0)
	suffixData := make([]byte, 0)
	for index, header := range signedHeaders {
		if index < toHeaderIndex {
			predixData = append(predixData, []byte(signature.Canon().Header()(header))...)
		}
		if index == toHeaderIndex {
			specifyData = append(specifyData, []byte(signature.Canon().Header()(header))...)
		}
		if index > toHeaderIndex {
			suffixData = append(suffixData, []byte(signature.Canon().Header()(header))...)
		}
	}
	trimmedHeader := signature.Canon().Header()(signature.TrimmedHeader())
	trimmedHeader = trimmedHeader[0 : strings.Index(trimmedHeader, "bh=")+3]
	bodyHash := [32]frontend.Variable{}
	for i := range bodyHash {
		bodyHash[i] = signature.BodyHash()[i]
	}
	//compute publicInputHash
	nBytes := pubKey.(*rsa.PublicKey).N.FillBytes(make([]byte, 512))
	eBytes := new(big.Int).SetInt64(int64(pubKey.(*rsa.PublicKey).E)).FillBytes(make([]byte, 512))
	fmt.Println("N bytes:", nBytes)
	fmt.Println("E bytes:", eBytes)
	fmt.Println("N bytes Length:", len(nBytes))
	fmt.Println("E bytes Length:", len(eBytes))
	fmt.Println("bodyHash:", signature.BodyHash())
	to := specifyData
	sha256 := hasher.NewSHA256()
	sha256.Write(to)
	toHash := sha256.Sum(nil)
	sha256.Reset()
	fmt.Println("toHah:", toHash)
	sha256.Write(nBytes)
	sha256.Write(eBytes)
	sha256.Write(signature.BodyHash())
	sha256.Write(toHash)
	pubInputHash := sha256.Sum(nil)
	circuit := CustomDKIMVerifierWrapper[emparams.Mod1e4096]{
		PublicKey: &PublicKey[emparams.Mod1e4096]{
			N: emulated.ValueOf[emparams.Mod1e4096](pubKey.(*rsa.PublicKey).N),
			E: emulated.ValueOf[emparams.Mod1e4096](pubKey.(*rsa.PublicKey).E),
		},
		Header: CustomEmailHeader{
			PrefixData:  BytesToPadding(predixData, false, -1),
			SpecifyData: BytesToPadding(specifyData, false, -1),
			SuffixData:  BytesToPadding(suffixData, false, -1),
		},
		Signature: EmailSig{
			SigPrefix: PaddingSlice{
				Padding:        frontend.Variable(-1),
				Slice:          BytesToFrontVariable([]byte(trimmedHeader)),
				IsLittleEndian: false,
			},
			BodyHash:   bodyHash,
			SigContent: BytesToFrontVariable(signature.Signature()),
		},
		PubInputHash: BytesToFrontVariable(pubInputHash),
	}
	assignment := CustomDKIMVerifierWrapper[emparams.Mod1e4096]{
		PublicKey: &PublicKey[emparams.Mod1e4096]{
			N: emulated.ValueOf[emparams.Mod1e4096](pubKey.(*rsa.PublicKey).N),
			E: emulated.ValueOf[emparams.Mod1e4096](pubKey.(*rsa.PublicKey).E),
		},
		Header: CustomEmailHeader{
			PrefixData:  BytesToPadding(predixData, false, -1),
			SpecifyData: BytesToPadding(specifyData, false, -1),
			SuffixData:  BytesToPadding(suffixData, false, -1),
		},
		Signature: EmailSig{
			SigPrefix: PaddingSlice{
				Padding:        frontend.Variable(-1),
				Slice:          BytesToFrontVariable([]byte(trimmedHeader)),
				IsLittleEndian: false,
			},
			BodyHash:   bodyHash,
			SigContent: BytesToFrontVariable(signature.Signature()),
		},
		PubInputHash: BytesToFrontVariable(pubInputHash),
	}
	err = test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	//assert.NoError(err)
	/*	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
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
		}*/
	assert.NoError(err)
}

func TestTemp1(t *testing.T) {
	assert := test.NewAssert(t)
	email := algorithm.ParseEmail(GmailTestData)
	var signatureHeader string
	for _, header := range email.Headers() {
		// headers
		if algorithm.IsSignatureHeader(header) {
			if signatureHeader != "" {
				panic(errors.New("multiple DKIM headers"))
			}
			signatureHeader = header
		}
		fmt.Println("headers:" + header)
	}
	if signatureHeader == "" {
		panic(errors.New("no DKIM header found"))
	}
	signature, err := algorithm.ParseSignature(signatureHeader)
	if err != nil {
		panic(err)
	}
	fmt.Println("signature:", signature.Signature())
	signatureHeaderNames := make([]string, len(signature.HeaderNames()))
	for i, name := range signature.HeaderNames() {
		signatureHeaderNames[i] = strings.ToLower(name)
	}
	signedHeaders := algorithm.ExtractHeaders(email.Headers(), signatureHeaderNames)
	h := signature.Algo().Hasher()()
	for _, header := range signedHeaders {
		header = signature.Canon().Header()(header)
		fmt.Println("signedHeaders:" + header)
		h.Write([]byte(header))
	}
	header := signature.Canon().Header()(signature.TrimmedHeader())
	fmt.Println("TrimmedHeader:" + header)
	h.Write([]byte(header))
	headersHash := h.Sum(nil)
	fmt.Println("header hash:" + base64.StdEncoding.EncodeToString(headersHash))
	fmt.Println(headersHash)
	txtRecords, err := client.LookupTxt(signature.TxtRecordName())
	if err != nil {
		panic(err)
	}
	//验签
	txtRecord := txtRecords[0]
	fmt.Println("txt record:" + txtRecord)
	fmt.Println("public key:" + txtRecord)
	key := algorithm.ParsePubkey(txtRecord)
	fmt.Println("DKIM signature:" + base64.StdEncoding.EncodeToString(signature.Signature()))
	err = signature.Algo().CheckSig()(key.Key(), headersHash, signature.Signature())
	assert.NoError(err)
}

func TestTemp2(t *testing.T) {
	assert := test.NewAssert(t)
	email := algorithm.ParseEmail(ICloudTestData)
	var signatureHeader string
	fromHeaderIndex := -1
	for index, header := range email.Headers() {
		// we don't support DKIM-Signature headers signing other DKIM-Signature
		if algorithm.IsFromHeader(header) {
			fromHeaderIndex = index
		}
		// headers
		if algorithm.IsSignatureHeader(header) {
			if signatureHeader != "" {
				panic(errors.New("multiple DKIM headers"))
			}
			signatureHeader = header
		}
	}
	if fromHeaderIndex == -1 {
		panic(errors.New("no to header found"))
	}
	if signatureHeader == "" {
		panic(errors.New("no DKIM header found"))
	}
	signature, err := algorithm.ParseSignature(signatureHeader)
	if err != nil {
		panic(err)
	}
	signatureHeaderNames := make([]string, len(signature.HeaderNames()))
	for i, name := range signature.HeaderNames() {
		signatureHeaderNames[i] = strings.ToLower(name)
	}
	signedHeaders := algorithm.ExtractHeaders(email.Headers(), signatureHeaderNames)
	h := signature.Algo().Hasher()()
	for _, header := range signedHeaders {
		header = signature.Canon().Header()(header)
		fmt.Println("signedHeaders:" + header)
		h.Write([]byte(header))
	}
	header := signature.Canon().Header()(signature.TrimmedHeader())
	fmt.Println("TrimmedHeader:" + header)
	h.Write([]byte(header))
	headersHash := h.Sum(nil)
	//fmt.Println("header hash:" + base64.StdEncoding.EncodeToString(headersHash))
	fmt.Println("header hash:")
	fmt.Println(headersHash)

	//从DNS查找RSA公钥
	txtRecords, err := client.LookupTxt(signature.TxtRecordName())
	if err != nil {
		panic(err)
	}
	//验签
	txtRecord := txtRecords[0]
	circuit, err := new(CustomDKIMVerifierWrapper[emparams.Mod1e4096]).Circuit(GmailTemplate, txtRecord)
	if err != nil {
		panic(err)
	}
	assignment, err := new(CustomDKIMVerifierWrapper[emparams.Mod1e4096]).Assignment(GmailTestData, txtRecord, *circuit.(*CustomDKIMVerifierWrapper[emparams.Mod1e4096]))
	if err != nil {
		panic(err)
	}
	//err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		panic(err)
	}
	fmt.Println(ccs.GetNbConstraints())
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
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

func TestTemp(t *testing.T) {
	assert := test.NewAssert(t)
	email := algorithm.ParseEmail(GmailTestData)
	var signatureHeader string
	toHeaderIndex := -1
	for index, header := range email.Headers() {
		// we don't support DKIM-Signature headers signing other DKIM-Signature
		if algorithm.IsToHeader(header) {
			toHeaderIndex = index
		}
		// headers
		if algorithm.IsSignatureHeader(header) {
			if signatureHeader != "" {
				panic(errors.New("multiple DKIM headers"))
			}
			signatureHeader = header
		}
	}
	if toHeaderIndex == -1 {
		panic(errors.New("no to header found"))
	}
	if signatureHeader == "" {
		panic(errors.New("no DKIM header found"))
	}
	signature, err := algorithm.ParseSignature(signatureHeader)
	if err != nil {
		panic(err)
	}
	//从DNS查找RSA公钥
	txtRecords, err := client.LookupTxt(signature.TxtRecordName())
	if err != nil {
		panic(err)
	}
	//验签
	txtRecord := txtRecords[0]
	circuit, err := new(CustomDKIMVerifierWrapper[emparams.Mod1e4096]).Circuit(headersOnly, txtRecord)
	if err != nil {
		panic(err)
	}
	assignment, err := new(CustomDKIMVerifierWrapper[emparams.Mod1e4096]).Assignment(headersOnly, txtRecord, *circuit.(*CustomDKIMVerifierWrapper[emparams.Mod1e4096]))
	if err != nil {
		panic(err)
	}
	err = test.IsSolved(circuit, assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

var headOnly2 = fixupNewlines("From: Reddit <noreply@redditmail.com>\nTo: liumengyu0930@gmail.com\nSubject: \"What do I do in this position?\"\nMIME-Version: 1.0\nContent-Type: text/html; charset=UTF-8\nContent-Transfer-Encoding: 7bit\nMessage-ID: <0100018a0530c62f-2e703fc5-2678-4834-9c12-f38e02a666aa-000000@email.amazonses.com>\nDate: Thu, 17 Aug 2023 20:29:57 +0000\nDKIM-Signature: v=1; a=rsa-sha256; q=dns/txt; c=relaxed/simple; s=xilmjaesmk3m6dhldmzc75r7654i2ch4; d=redditmail.com; t=1692304197; h=From:To:Subject:MIME-Version:Content-Type:Content-Transfer-Encoding:Message-ID:Date; bh=+D602nP4NifkpYu48HSrNmgylr5W5itqRmQ8F+3/1eQ=; b=Whynv5UIqHB5K3jtELbIGwDMyiomSBucmRVlRx4yGrGUKzBSwhMPvKHTZHex1TkW /8113aEEoolqlXP1JllwwAIqDvNPpyqHT6CBdiw/0sHDyemvOHYL482A8BkFqyU34PL v15rdBW+5TjEsFqhoVJfWDDPD2642ZkzaRxqgMqQ=")
