package dkim

import (
	"errors"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

// BytesToBits converts a byte array (MSB) to a Gnark bit array (LSB)
func BytesToBits(api frontend.API, bytesData []frontend.Variable) []frontend.Variable {
	bitsData := make([]frontend.Variable, 0)
	for i := 0; i < len(bytesData); i++ {
		v := bits.ToBinary(api, bytesData[i], bits.WithNbDigits(8))
		slices.Reverse(v)
		bitsData = append(bitsData, v...)
	}
	slices.Reverse(bitsData)
	return bitsData
}

// BitsToBytes converts a Gnark bit array (LSB) to a byte array (MSB)
func BitsToBytes(api frontend.API, bitsData []frontend.Variable) []frontend.Variable {
	if len(bitsData)%8 != 0 {
		panic("bits length is not multiple of 8")
	}
	byteLength := len(bitsData) / 8
	bytesData := make([]frontend.Variable, byteLength)
	for i := 0; i < byteLength; i++ {
		byteBits := bitsData[i*8 : (i+1)*8]
		bytesData[i] = bits.FromBinary(api, byteBits, bits.WithNbDigits(8))
	}
	slices.Reverse(bytesData)
	return bytesData
}

func BytesToFrontVariable(src []byte) []frontend.Variable {
	result := make([]frontend.Variable, len(src))
	for i, _ := range result {
		result[i] = src[i]
	}
	return result
}

func BytesToPadding(src []byte, isLittleEndian bool, padding int) PaddingSlice {
	return PaddingSlice{
		Padding:        frontend.Variable(padding),
		Slice:          BytesToFrontVariable(src),
		IsLittleEndian: isLittleEndian,
	}
}

func BytesToFixPadding(src []byte, isLittleEndian bool, maxLength int) PaddingSlice {
	if len(src) > maxLength {
		panic(errors.New("input length exceeds max length"))
	}
	paddingLength := maxLength - len(src)
	paddingZero := make([]byte, paddingLength)
	resultArray := append(paddingZero, src...)
	return PaddingSlice{
		Padding:        frontend.Variable(paddingLength - 1),
		Slice:          BytesToFrontVariable(resultArray),
		IsLittleEndian: isLittleEndian,
	}
}
