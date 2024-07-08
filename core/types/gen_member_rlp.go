// Code generated by rlpgen. DO NOT EDIT.

//go:build !norlpgen
// +build !norlpgen

package types

import "github.com/ethereum/go-ethereum/rlp"
import "io"

func (obj *Member) EncodeRLP(_w io.Writer) error {
	w := rlp.NewEncoderBuffer(_w)
	_tmp0 := w.List()
	w.WriteUint64(obj.PrevOffset)
	w.WriteUint64(obj.NewOffset)
	w.WriteBytes(obj.PrevSlot[:])
	w.WriteBytes(obj.NewSlot[:])
	w.WriteString(obj.Type)
	w.ListEnd(_tmp0)
	return w.Flush()
}