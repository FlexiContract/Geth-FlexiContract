package types

import (
	"bytes"

	"github.com/ethereum/go-ethereum/common"
)

//go:generate go run ../../rlp/rlpgen -type Proposal -out gen_proposal_rlp.go
const (
	AcceptingVotes = iota
	ProposalRejected
	ProposalPassed
	ChangesApplied
)

type Proposal struct {
	InFavourOf       uint64
	Against          uint64
	Stakeholders     []common.Address
	VotesNeededToWin uint64
	ProposedCodeHash []byte
	CurrentState     uint8
	ReorgInfoList    []ReorgInfo
	DataTypeList     []DataType
}

func EqualStakeholders(list1 []common.Address, list2 []common.Address) bool {

	if len(list1) != len(list2) {

		return false
	}

	seen := make(map[common.Address]bool)

	for _, address := range list1 {
		seen[address] = true
	}

	for _, address := range list2 {

		if _, exist := seen[address]; !exist {

			return false
		}
	}

	return true
}

func EqualReorgInfoList(list1 []ReorgInfo, list2 []ReorgInfo) bool {

	if len(list1) != len(list2) {

		return false
	}

	seen := make(map[ReorgInfo]bool)

	for _, reorgInfo := range list1 {
		seen[reorgInfo] = true
	}

	for _, reorgInfo := range list2 {

		if _, exist := seen[reorgInfo]; !exist {

			return false
		}
	}

	return true
}

func EqualDataTypes(list1 []DataType, list2 []DataType) bool {

	if len(list1) != len(list2) {

		return false
	}

	seen := make(map[DataType]bool)

	for _, dataType := range list1 {
		seen[dataType] = true
	}

	for _, dataType := range list2 {

		if _, exist := seen[dataType]; !exist {

			return false
		}
	}

	return true
}

func (p Proposal) Equals(other Proposal) bool {

	return p.InFavourOf == other.InFavourOf && p.Against == other.Against && p.VotesNeededToWin == other.VotesNeededToWin && bytes.Equal(p.ProposedCodeHash, other.ProposedCodeHash) && p.CurrentState == other.CurrentState && EqualStakeholders(p.Stakeholders, other.Stakeholders) == true && EqualReorgInfoList(p.ReorgInfoList, other.ReorgInfoList) == true && EqualDataTypes(p.DataTypeList, other.DataTypeList) == true
}
