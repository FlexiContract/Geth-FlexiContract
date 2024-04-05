package types

import (
	"bytes"

	"github.com/ethereum/go-ethereum/common"
)

//go:generate go run ../../rlp/rlpgen -type Vote -out gen_vote_rlp.go

type Vote struct {
	TxHash common.Hash
	Type   uint8
}

func (v Vote) Equals(other Vote) bool {
	return v.Type == other.Type && bytes.Equal(v.TxHash[:], other.TxHash[:])
}
