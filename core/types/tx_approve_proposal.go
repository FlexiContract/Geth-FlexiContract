package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// ApproveProposalTx is used to vote in favour of update
type ApproveProposalTx struct {
	ChainID          *big.Int        // destination chain ID
	Nonce            uint64          // nonce of sender account
	GasPrice         *big.Int        // wei per gas
	Gas              uint64          // gas limit
	To               *common.Address `rlp:"nil"` // nil means contract creation
	Value            *big.Int        // wei amount
	Data             []byte          // contract invocation input data
	AccessList       AccessList      // EIP-2930 access list
	ReorgList        ReorgList
	DataTypes        DataTypes
	Stakeholders     []common.Address //List of stakeholders
	ProposalNumber   uint64
	VotesNeededToWin uint64
	V, R, S          *big.Int // signature values
}

func (tx *ApproveProposalTx) copy() TxData {
	cpy := &ApproveProposalTx{
		Nonce:            tx.Nonce,
		To:               copyAddressPtr(tx.To),
		Data:             common.CopyBytes(tx.Data),
		Gas:              tx.Gas,
		ProposalNumber:   tx.ProposalNumber,
		VotesNeededToWin: tx.VotesNeededToWin,
		// These are initialized below.
		AccessList: make(AccessList, len(tx.AccessList)),
		ReorgList:  make(ReorgList, len(tx.ReorgList)),
		DataTypes:  make(DataTypes, len(tx.DataTypes)),
		Value:      new(big.Int),
		ChainID:    new(big.Int),
		GasPrice:   new(big.Int),
		V:          new(big.Int),
		R:          new(big.Int),
		S:          new(big.Int),
	}
	copy(cpy.AccessList, tx.AccessList)
	copy(cpy.ReorgList, tx.ReorgList)
	copy(cpy.DataTypes, tx.DataTypes)
	for _, stkhldr := range tx.Stakeholders {
		cpy.Stakeholders = append(cpy.Stakeholders, stkhldr)
	}

	if tx.Value != nil {
		cpy.Value.Set(tx.Value)
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.GasPrice != nil {
		cpy.GasPrice.Set(tx.GasPrice)
	}
	if tx.V != nil {
		cpy.V.Set(tx.V)
	}
	if tx.R != nil {
		cpy.R.Set(tx.R)
	}
	if tx.S != nil {
		cpy.S.Set(tx.S)
	}
	return cpy
}

// accessors for innerTx.
func (tx *ApproveProposalTx) txType() byte                   { return ApproveProposalTxType }
func (tx *ApproveProposalTx) chainID() *big.Int              { return tx.ChainID }
func (tx *ApproveProposalTx) accessList() AccessList         { return tx.AccessList }
func (tx *ApproveProposalTx) reorgList() ReorgList           { return tx.ReorgList }
func (tx *ApproveProposalTx) dataTypes() DataTypes           { return tx.DataTypes }
func (tx *ApproveProposalTx) data() []byte                   { return tx.Data }
func (tx *ApproveProposalTx) gas() uint64                    { return tx.Gas }
func (tx *ApproveProposalTx) gasPrice() *big.Int             { return tx.GasPrice }
func (tx *ApproveProposalTx) gasTipCap() *big.Int            { return tx.GasPrice }
func (tx *ApproveProposalTx) gasFeeCap() *big.Int            { return tx.GasPrice }
func (tx *ApproveProposalTx) value() *big.Int                { return tx.Value }
func (tx *ApproveProposalTx) nonce() uint64                  { return tx.Nonce }
func (tx *ApproveProposalTx) to() *common.Address            { return tx.To }
func (tx *ApproveProposalTx) stakeholders() []common.Address { return tx.Stakeholders }
func (tx *ApproveProposalTx) proposalNumber() uint64         { return tx.ProposalNumber }
func (tx *ApproveProposalTx) votesNeededToWin() uint64       { return tx.VotesNeededToWin }

func (tx *ApproveProposalTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *ApproveProposalTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID, tx.V, tx.R, tx.S = chainID, v, r, s
}
