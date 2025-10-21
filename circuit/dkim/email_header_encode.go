package dkim

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/selector"
)

type FixEmailHeader struct {
	Mime_Version PaddingSlice
	From         PaddingSlice
	Date         PaddingSlice
	Message_id   PaddingSlice
	Subject      PaddingSlice
	To           PaddingSlice
	Content_Type PaddingSlice
}

func NewFixEmailHeaderEncode(api frontend.API) FixEmailHeaderEncode {
	return FixEmailHeaderEncode{api: api}
}

type FixEmailHeaderEncode struct {
	api frontend.API
}

func (fe FixEmailHeaderEncode) Encode(header FixEmailHeader) (PaddingSlice, error) {
	api := fe.api
	sliceApi := NewSliceApi(api)
	resultSlice := header.Mime_Version
	resultSlice = sliceApi.concat(resultSlice, header.From, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, header.Date, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, header.Message_id, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, header.Subject, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, header.To, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, header.Content_Type, resultSlice.IsLittleEndian)
	return resultSlice, nil
}

func (fe FixEmailHeaderEncode) GetHeaderHash(header FixEmailHeader, trimmedHeader PaddingSlice) ([]frontend.Variable, error) {
	api := fe.api
	sliceApi := NewSliceApi(api)
	resultSlice, err := fe.Encode(header)
	if err != nil {
		return nil, err
	}
	resultSlice = sliceApi.concat(resultSlice, trimmedHeader, resultSlice.IsLittleEndian)
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
	headerHash, err := sliceComposer.Process(32, fn, generator)
	if err != nil {
		return nil, err
	}
	return headerHash, nil
}

func (fe FixEmailHeaderEncode) GetToAddressHash(header FixEmailHeader) ([]frontend.Variable, error) {
	api := fe.api
	resultSlice := header.To
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
	toAddressHash, err := sliceComposer.Process(32, fn, generator)
	if err != nil {
		return nil, err
	}
	return toAddressHash, nil
}

type CustomEmailHeader struct {
	PrefixData  PaddingSlice
	SpecifyData PaddingSlice
	SuffixData  PaddingSlice
}

func NewCustomEmailHeaderEncode(api frontend.API) CustomEmailHeaderEncode {
	return CustomEmailHeaderEncode{api: api}
}

type CustomEmailHeaderEncode struct {
	api frontend.API
}

func (ce CustomEmailHeaderEncode) Encode(header CustomEmailHeader) (PaddingSlice, error) {
	api := ce.api
	sliceApi := NewSliceApi(api)
	resultSlice := header.PrefixData
	resultSlice = sliceApi.concat(resultSlice, header.SpecifyData, resultSlice.IsLittleEndian)
	resultSlice = sliceApi.concat(resultSlice, header.SuffixData, resultSlice.IsLittleEndian)
	return resultSlice, nil
}

func (ce CustomEmailHeaderEncode) GetHeaderHash(header CustomEmailHeader, trimmedHeader PaddingSlice) ([]frontend.Variable, error) {
	api := ce.api
	sliceApi := NewSliceApi(api)
	resultSlice, err := ce.Encode(header)
	if err != nil {
		return nil, err
	}
	resultSlice = sliceApi.concat(resultSlice, trimmedHeader, resultSlice.IsLittleEndian)
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
	resultHash, err := sliceComposer.Process(32, fn, generator)
	if err != nil {
		return nil, err
	}
	return resultHash, nil
}
