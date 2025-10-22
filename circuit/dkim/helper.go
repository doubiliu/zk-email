package dkim

import (
	"errors"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"slices"
)

// ByteToBits converts a byte array (MSB) to a Gnark bit array (LSB)
func ByteToBits(api frontend.API, bytesData []frontend.Variable) []frontend.Variable {
	bitsData := make([]frontend.Variable, 0)
	for i := 0; i < len(bytesData); i++ {
		v := bits.ToBinary(api, bytesData[i], bits.WithNbDigits(8))
		slices.Reverse(v)
		bitsData = append(bitsData, v...)
	}
	slices.Reverse(bitsData)
	return bitsData
}

func Byte2FrontVariable(src []byte) []frontend.Variable {
	result := make([]frontend.Variable, len(src))
	for i, _ := range result {
		result[i] = src[i]
	}
	return result
}

func Byte2Padding(src []byte, isLittleEndian bool, padding int) PaddingSlice {
	return PaddingSlice{
		Padding:        frontend.Variable(padding),
		Slice:          Byte2FrontVariable(src),
		IsLittleEndian: isLittleEndian,
	}
}

func Byte2FixPadding(src []byte, isLittleEndian bool, maxLength int) PaddingSlice {
	if len(src) > maxLength {
		panic(errors.New("input length exceeds max length"))
	}
	paddingLength := maxLength - len(src)
	paddingZero := make([]byte, paddingLength)
	resultArray := append(paddingZero, src...)
	return PaddingSlice{
		Padding:        frontend.Variable(paddingLength - 1),
		Slice:          Byte2FrontVariable(resultArray),
		IsLittleEndian: isLittleEndian,
	}
}
