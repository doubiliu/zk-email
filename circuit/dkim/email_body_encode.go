package dkim

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/selector"
)

type EmailBody struct {
	Prefix_Content PaddingSlice
	Text_Content   PaddingSlice
	Suffix_Content PaddingSlice
}

func NewEmailBodyEncode(api frontend.API) EmailBodyEncode {
	return EmailBodyEncode{api: api}
}

type EmailBodyEncode struct {
	api frontend.API
}

func (eb EmailBodyEncode) GetBodyHash(body EmailBody) ([]frontend.Variable, error) {
	api := eb.api
	sliceApi := NewSliceApi(api)
	//拼凑email正文(body)动态分片
	bodySlice := body.Prefix_Content
	bodySlice = sliceApi.concat(bodySlice, body.Text_Content, bodySlice.IsLittleEndian)
	bodySlice = sliceApi.concat(bodySlice, body.Suffix_Content, bodySlice.IsLittleEndian)
	//拼凑email全文动态分片
	resultSlice := bodySlice
	generator := func(api frontend.API) []UndeterminedSlice {
		slices := make([]UndeterminedSlice, 0)
		isEmpty := api.And(api.IsZero(api.Sub(len(resultSlice.Slice)-2, resultSlice.Padding)), api.IsZero(selector.Mux(api, len(resultSlice.Slice)-1, resultSlice.Slice...))) // == 0
		for i := 0; i < len(resultSlice.Slice); i++ {
			slices = append(slices, UndeterminedSlice{
				Variables: resultSlice.Slice[i:],
				// zeroNumber == len(hbytes) - 1 - i && !isZero
				// isZero == 1 -> isSelect = 0
				// isZero == 0, len(hbytes) - 1 - i - zeroNumber == 0 -> isSelect = 1
				IsSelected: api.Mul(api.IsZero(isEmpty), api.IsZero(api.Sub(i-1, resultSlice.Padding))), // suffix = 1, and current = 1
			})
		}
		slices = append(slices, UndeterminedSlice{
			Variables:  []frontend.Variable{},
			IsSelected: isEmpty,
		})
		return slices
	}
	sliceComposer := NewSliceComposer(api)
	fn := func(api frontend.API, slices ...UndeterminedSlice) (DeterminedSlice, error) {
		data := slices[0].Variables
		hasher, err := sha2.New(api)
		if err != nil {
			return nil, err
		}
		dataU8 := make([]uints.U8, len(data))
		u8api, err := uints.New[uints.U32](api)
		if err != nil {
			return nil, err
		}
		for i := 0; i < len(data); i++ {
			dataU8[i] = u8api.ByteValueOf(data[i])
		}
		hasher.Write(dataU8)
		ru8 := hasher.Sum()
		r := make([]frontend.Variable, len(ru8))
		for i := 0; i < len(r); i++ {
			r[i] = ru8[i].Val
		}
		return r, nil
	}
	emailBodyHash, err := sliceComposer.Process(32, fn, generator)
	if err != nil {
		return nil, err
	}
	return emailBodyHash, nil
}

func (eb EmailBodyEncode) GetSpecifyDataHash(body EmailBody) ([]frontend.Variable, error) {
	api := eb.api
	resultSlice := body.Text_Content
	//拼凑email全文动态分片
	generator := func(api frontend.API) []UndeterminedSlice {
		slices := make([]UndeterminedSlice, 0)
		isEmpty := api.And(api.IsZero(api.Sub(len(resultSlice.Slice)-2, resultSlice.Padding)), api.IsZero(selector.Mux(api, len(resultSlice.Slice)-1, resultSlice.Slice...))) // == 0
		for i := 0; i < len(resultSlice.Slice); i++ {
			slices = append(slices, UndeterminedSlice{
				Variables: resultSlice.Slice[i:],
				// zeroNumber == len(hbytes) - 1 - i && !isZero
				// isZero == 1 -> isSelect = 0
				// isZero == 0, len(hbytes) - 1 - i - zeroNumber == 0 -> isSelect = 1
				IsSelected: api.Mul(api.IsZero(isEmpty), api.IsZero(api.Sub(i-1, resultSlice.Padding))), // suffix = 1, and current = 1
			})
		}
		slices = append(slices, UndeterminedSlice{
			Variables:  []frontend.Variable{},
			IsSelected: isEmpty,
		})
		return slices
	}
	sliceComposer := NewSliceComposer(api)
	fn := func(api frontend.API, slices ...UndeterminedSlice) (DeterminedSlice, error) {
		data := slices[0].Variables
		hasher, err := sha2.New(api)
		if err != nil {
			return nil, err
		}
		dataU8 := make([]uints.U8, len(data))
		u8api, err := uints.New[uints.U32](api)
		if err != nil {
			return nil, err
		}
		for i := 0; i < len(data); i++ {
			dataU8[i] = u8api.ByteValueOf(data[i])
		}
		hasher.Write(dataU8)
		ru8 := hasher.Sum()
		r := make([]frontend.Variable, len(ru8))
		for i := 0; i < len(r); i++ {
			r[i] = ru8[i].Val
		}
		return r, nil
	}
	specifyDataHash, err := sliceComposer.Process(32, fn, generator)
	if err != nil {
		return nil, err
	}
	return specifyDataHash, nil
}
