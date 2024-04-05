// Code generated by rlpgen. DO NOT EDIT.

//go:build !norlpgen
// +build !norlpgen

package types

import "github.com/ethereum/go-ethereum/rlp"
import "io"

func (obj *StateAccount) EncodeRLP(_w io.Writer) error {
	w := rlp.NewEncoderBuffer(_w)
	_tmp0 := w.List()
	w.WriteUint64(obj.Nonce)
	if obj.Balance == nil {
		w.Write(rlp.EmptyString)
	} else {
		if obj.Balance.Sign() == -1 {
			return rlp.ErrNegativeBigInt
		}
		w.WriteBigInt(obj.Balance)
	}
	w.WriteBytes(obj.Root[:])
	w.WriteBytes(obj.ProposalRoot[:])
	w.WriteBytes(obj.BallotRoot[:])
	w.WriteBytes(obj.CodeHash)
	_tmp1 := w.List()
	for _, _tmp2 := range obj.Stakeholders {
		w.WriteBytes(_tmp2[:])
	}
	w.ListEnd(_tmp1)
	w.WriteUint64(obj.ProposalNumber)
	w.WriteUint64(obj.VotesNeededTowin)
	w.ListEnd(_tmp0)
	return w.Flush()
}