package dkim

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestBase64EncodeCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	data1 := make([]frontend.Variable, 3)
	data1[0] = byte('P')
	data1[1] = byte('C')
	data1[2] = byte('B')
	aim1 := make([]frontend.Variable, 4)
	aim1[0] = byte('U')
	aim1[1] = byte('E')
	aim1[2] = byte('N')
	aim1[3] = byte('C')

	data2 := make([]frontend.Variable, 2)
	data2[0] = byte('P')
	data2[1] = byte('C')
	aim2 := make([]frontend.Variable, 4)
	aim2[0] = byte('U')
	aim2[1] = byte('E')
	aim2[2] = byte('M')
	aim2[3] = byte('=')

	data3 := make([]frontend.Variable, 1)
	data3[0] = byte('P')
	aim3 := make([]frontend.Variable, 4)
	aim3[0] = byte('U')
	aim3[1] = byte('A')
	aim3[2] = byte('=')
	aim3[3] = byte('=')

	circuit := Base64EncodeWrapper{
		Data1: data1,
		Aim1:  aim1,
		Data2: data2,
		Aim2:  aim2,
		Data3: data3,
		Aim3:  aim3,
	}
	assignment := Base64EncodeWrapper{
		Data1: data1,
		Aim1:  aim1,
		Data2: data2,
		Aim2:  aim2,
		Data3: data3,
		Aim3:  aim3,
	}
	err := test.IsSolved(&circuit, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type Base64EncodeWrapper struct {
	Data1 []frontend.Variable
	Aim1  []frontend.Variable

	Data2 []frontend.Variable
	Aim2  []frontend.Variable

	Data3 []frontend.Variable
	Aim3  []frontend.Variable
}

// Define declares the circuit's constraints.
func (c *Base64EncodeWrapper) Define(api frontend.API) error {
	encode := NewBase64Encode(api)
	encodeData1 := encode.EncodeRule1(c.Data1)
	for i := 0; i < len(encodeData1); i++ {
		api.AssertIsEqual(encodeData1[i], c.Aim1[i])
	}
	encodeData2 := encode.EncodeRule2(c.Data2)
	for i := 0; i < len(encodeData2); i++ {
		api.AssertIsEqual(encodeData2[i], c.Aim2[i])
	}
	encodeData3 := encode.EncodeRule3(c.Data3)
	for i := 0; i < len(encodeData3); i++ {
		api.AssertIsEqual(encodeData3[i], c.Aim3[i])
	}
	return nil
}
