package dkim

import (
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
)

func NewBase64Encode(api frontend.API) Base64Encode {
	t := logderivlookup.New(api)
	base64Arr := []frontend.Variable{
		frontend.Variable(byte('A')), frontend.Variable(byte('B')), frontend.Variable(byte('C')), frontend.Variable(byte('D')), frontend.Variable(byte('E')), frontend.Variable(byte('F')),
		frontend.Variable(byte('G')), frontend.Variable(byte('H')), frontend.Variable(byte('I')), frontend.Variable(byte('J')), frontend.Variable(byte('K')), frontend.Variable(byte('L')),
		frontend.Variable(byte('M')), frontend.Variable(byte('N')), frontend.Variable(byte('O')), frontend.Variable(byte('P')), frontend.Variable(byte('Q')), frontend.Variable(byte('R')),
		frontend.Variable(byte('S')), frontend.Variable(byte('T')), frontend.Variable(byte('U')), frontend.Variable(byte('V')), frontend.Variable(byte('W')), frontend.Variable(byte('X')),
		frontend.Variable(byte('Y')), frontend.Variable(byte('Z')), frontend.Variable(byte('a')), frontend.Variable(byte('b')), frontend.Variable(byte('c')), frontend.Variable(byte('d')),
		frontend.Variable(byte('e')), frontend.Variable(byte('f')), frontend.Variable(byte('g')), frontend.Variable(byte('h')), frontend.Variable(byte('i')), frontend.Variable(byte('j')),
		frontend.Variable(byte('k')), frontend.Variable(byte('l')), frontend.Variable(byte('m')), frontend.Variable(byte('n')), frontend.Variable(byte('o')), frontend.Variable(byte('p')),
		frontend.Variable(byte('q')), frontend.Variable(byte('r')), frontend.Variable(byte('s')), frontend.Variable(byte('t')), frontend.Variable(byte('u')), frontend.Variable(byte('v')),
		frontend.Variable(byte('w')), frontend.Variable(byte('x')), frontend.Variable(byte('y')), frontend.Variable(byte('z')), frontend.Variable(byte('0')), frontend.Variable(byte('1')),
		frontend.Variable(byte('2')), frontend.Variable(byte('3')), frontend.Variable(byte('4')), frontend.Variable(byte('5')), frontend.Variable(byte('6')), frontend.Variable(byte('7')),
		frontend.Variable(byte('8')), frontend.Variable(byte('9')), frontend.Variable(byte('+')), frontend.Variable(byte('/')),
	}
	for i := range base64Arr {
		t.Insert(base64Arr[i])
	}
	return Base64Encode{api: api, t: t}
}

type Base64Encode struct {
	api frontend.API
	t   logderivlookup.Table
}

// original data length is evenly divisible by 6 and the remainder is 0
func (b64enc *Base64Encode) EncodeRule1(srcData []frontend.Variable) []frontend.Variable {
	remainder := b64enc.checkRemainder(srcData, 0)
	splitBits := b64enc.split(srcData, remainder)
	encodeData := b64enc.encode(splitBits)
	return encodeData
}

// original data length is divided by 6 and the remainder is 4
func (b64enc *Base64Encode) EncodeRule2(srcData []frontend.Variable) []frontend.Variable {
	remainder := b64enc.checkRemainder(srcData, 4)
	splitBits := b64enc.split(srcData, 6-remainder)
	encodeData := b64enc.encode(splitBits)
	encodeData = append(encodeData, frontend.Variable(byte('=')))
	return encodeData
}

// original data length is divided by 6 and the remainder is 2
func (b64enc *Base64Encode) EncodeRule3(srcData []frontend.Variable) []frontend.Variable {
	remainder := b64enc.checkRemainder(srcData, 2)
	splitBits := b64enc.split(srcData, 6-remainder)
	encodeData := b64enc.encode(splitBits)
	encodeData = append(encodeData, frontend.Variable(byte('=')))
	encodeData = append(encodeData, frontend.Variable(byte('=')))
	return encodeData
}

func (b64enc *Base64Encode) encode(splitBits []frontend.Variable) []frontend.Variable {
	api := b64enc.api
	encodeData := make([]frontend.Variable, 0)
	for i := 0; i < len(splitBits); i = i + 6 {
		aggregationBits := make([]frontend.Variable, 8)
		aggregationBits[0] = 0
		aggregationBits[1] = 0
		aggregationBits[2] = splitBits[i]
		aggregationBits[3] = splitBits[i+1]
		aggregationBits[4] = splitBits[i+2]
		aggregationBits[5] = splitBits[i+3]
		aggregationBits[6] = splitBits[i+4]
		aggregationBits[7] = splitBits[i+5]
		slices.Reverse(aggregationBits)
		newData := api.FromBinary(aggregationBits...)
		vals := b64enc.t.Lookup(newData)
		encodeData = append(encodeData, vals...)
	}
	return encodeData
}

// convert bytes into bits,and append padding 0
func (b64enc *Base64Encode) split(srcData []frontend.Variable, padding int) []frontend.Variable {
	api := b64enc.api
	splitBits := make([]frontend.Variable, 0)
	for i := 0; i < len(srcData); i++ {
		bits := api.ToBinary(srcData[i], 8)
		slices.Reverse(bits)
		splitBits = append(splitBits, bits...)
	}
	//add padding 0
	for i := 0; i < padding; i++ {
		splitBits = append(splitBits, frontend.Variable(0))
	}
	return splitBits
}

func (b64enc *Base64Encode) checkRemainder(srcData []frontend.Variable, aim frontend.Variable) int {
	api := b64enc.api
	srcDataLength := len(srcData)
	remainder := (srcDataLength * 8) % 6
	api.AssertIsEqual(aim, remainder)
	return remainder
}
