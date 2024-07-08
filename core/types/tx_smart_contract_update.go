package types

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

//go:generate go run github.com/fjl/gencodec -type ReorgInfo -out gen_reorg_info.go

//go:generate go run github.com/fjl/gencodec -type DataType -out gen_data_type.go
//go:generate go run github.com/fjl/gencodec -type Member -out gen_member.go

//go:generate go run ../../rlp/rlpgen -type ReorgInfo -out gen_reorg_info_rlp.go
//go:generate go run ../../rlp/rlpgen -type DataType -out gen_data_type_rlp.go
//go:generate go run ../../rlp/rlpgen -type Member -out gen_member_rlp.go

type ReorgInfo struct {
	Type       string      `json:"type"        gencodec:"required"`
	PrevSlot   common.Hash `json:"oldSlot"     gencodec:"required"`
	NewSlot    common.Hash `json:"newSlot"     gencodec:"required"`
	PrevOffset uint64      `json:"oldOffset"   gencodec:"required"`
	NewOffset  uint64      `json:"newOffset"   gencodec:"required"`
}

type Member struct {
	PrevOffset uint64      `json:"oldOffset"   gencodec:"required"`
	NewOffset  uint64      `json:"newOffset"   gencodec:"required"`
	PrevSlot   common.Hash `json:"oldSlot"     gencodec:"required"`
	NewSlot    common.Hash `json:"newSlot"     gencodec:"required"`
	Type       string      `json:"type"        gencodec:"required"`
}

type DataType struct {
	Type              string   `json:"type"                 gencodec:"required"`
	Base              string   `json:"base"`
	Encoding          string   `json:"encoding"             gencodec:"required"`
	PrevNumberOfBytes uint64   `json:"oldNumberOfBytes"        gencodec:"required"`
	NewNumberOfBytes  uint64   `json:"newNumberOfBytes"        gencodec:"required"`
	Members           []Member `json:"members"`
}

type ReorgList []ReorgInfo
type DataTypes []DataType

// SmartContractUpdateTx is used to update smart contract code
type SmartContractUpdateTx struct {
	ChainID                 *big.Int        // destination chain ID
	Nonce                   uint64          // nonce of sender account
	GasPrice                *big.Int        // wei per gas
	Gas                     uint64          // gas limit
	To                      *common.Address `rlp:"nil"` // nil means contract creation
	Value                   *big.Int        // wei amount
	Data                    []byte          // contract invocation input data
	AccessList              AccessList      // EIP-2930 access list
	ReorgList               ReorgList
	DataTypes               DataTypes
	Stakeholders            []common.Address //List of stakeholders
	ProposalNumber          uint64
	VotesNeededToWin        uint64
	TimeOut                 uint64
	VotesNeededToDeactivate uint64
	V, R, S                 *big.Int // signature values
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *SmartContractUpdateTx) copy() TxData {
	cpy := &SmartContractUpdateTx{
		Nonce:                   tx.Nonce,
		To:                      copyAddressPtr(tx.To),
		Data:                    common.CopyBytes(tx.Data),
		Gas:                     tx.Gas,
		ProposalNumber:          tx.ProposalNumber,
		VotesNeededToWin:        tx.VotesNeededToWin,
		TimeOut:                 tx.TimeOut,
		VotesNeededToDeactivate: tx.VotesNeededToDeactivate,
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
func (tx *SmartContractUpdateTx) txType() byte                    { return SmartContractUpdateTxType }
func (tx *SmartContractUpdateTx) chainID() *big.Int               { return tx.ChainID }
func (tx *SmartContractUpdateTx) accessList() AccessList          { return tx.AccessList }
func (tx *SmartContractUpdateTx) reorgList() ReorgList            { return tx.ReorgList }
func (tx *SmartContractUpdateTx) dataTypes() DataTypes            { return tx.DataTypes }
func (tx *SmartContractUpdateTx) data() []byte                    { return tx.Data }
func (tx *SmartContractUpdateTx) gas() uint64                     { return tx.Gas }
func (tx *SmartContractUpdateTx) gasPrice() *big.Int              { return tx.GasPrice }
func (tx *SmartContractUpdateTx) gasTipCap() *big.Int             { return tx.GasPrice }
func (tx *SmartContractUpdateTx) gasFeeCap() *big.Int             { return tx.GasPrice }
func (tx *SmartContractUpdateTx) value() *big.Int                 { return tx.Value }
func (tx *SmartContractUpdateTx) nonce() uint64                   { return tx.Nonce }
func (tx *SmartContractUpdateTx) to() *common.Address             { return tx.To }
func (tx *SmartContractUpdateTx) stakeholders() []common.Address  { return tx.Stakeholders }
func (tx *SmartContractUpdateTx) proposalNumber() uint64          { return tx.ProposalNumber }
func (tx *SmartContractUpdateTx) votesNeededToWin() uint64        { return tx.VotesNeededToWin }
func (tx *SmartContractUpdateTx) timeOut() uint64                 { return tx.TimeOut }
func (tx *SmartContractUpdateTx) votesNeededToDeactivate() uint64 { return tx.VotesNeededToDeactivate }

func (tx *SmartContractUpdateTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *SmartContractUpdateTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID, tx.V, tx.R, tx.S = chainID, v, r, s
}
