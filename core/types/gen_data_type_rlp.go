// Code generated by rlpgen. DO NOT EDIT.

//go:build !norlpgen
// +build !norlpgen

package types

import "github.com/ethereum/go-ethereum/rlp"
import "io"

func (obj *DataType) EncodeRLP(_w io.Writer) error {
	w := rlp.NewEncoderBuffer(_w)
	_tmp0 := w.List()
	w.WriteString(obj.Type)
	w.WriteString(obj.Base)
	w.WriteString(obj.Encoding)
	w.WriteUint64(obj.NumberOfBytes)
	w.ListEnd(_tmp0)
	return w.Flush()
}