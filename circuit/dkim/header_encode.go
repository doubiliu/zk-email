package dkim

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/selector"
)

type Header struct {
	Mime_Version  PaddingSlice
	From          PaddingSlice
	Date          PaddingSlice
	Message_id    PaddingSlice
	Subject       PaddingSlice
	To            PaddingSlice
	Content_Type  PaddingSlice
	TrimmedHeader PaddingSlice
}

func NewHeaderEncode(api frontend.API) HeaderEncode {
	return HeaderEncode{api: api}
}

type HeaderEncode struct {
	api frontend.API
}

func (he HeaderEncode) Encode(header Header) ([]frontend.Variable, error) {
	api := he.api
	sliceApi := NewSliceApi(api)
	resultSlice := header.Mime_Version
	resultSlice = sliceApi.concat(resultSlice, header.From, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, header.Date, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, header.Message_id, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, header.Subject, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, header.To, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, header.Content_Type, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, header.TrimmedHeader, resultSlice.IsLittleEndian)
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
	encodeheader, err := sliceComposer.Process(32, fn, generator)
	if err != nil {
		return nil, err
	}
	return encodeheader, nil
}
