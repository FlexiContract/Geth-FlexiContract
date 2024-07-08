// Copyright 2019 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package snapshot

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
)

// Account is a modified version of a state.Account, where the root is replaced
// with a byte slice. This format can be used to represent full-consensus format
// or slim-snapshot format which replaces the empty root and code hash as nil
// byte slice.
type Account struct {
	Nonce                   uint64
	Balance                 *big.Int
	Root                    []byte
	ProposalRoot            []byte
	BallotRoot              []byte
	CodeHash                []byte
	Stakeholders            []common.Address
	VotesNeededToWin        uint64
	ProposalNumber          uint64
	VotesNeededToDeactivate uint64
	TimeOut                 uint64
}

// SlimAccount converts a state.Account content into a slim snapshot account
func SlimAccount(nonce uint64, balance *big.Int, root common.Hash, proposalroot common.Hash, ballotroot common.Hash, codehash []byte, stakeholders []common.Address, proposalnumber uint64, votesneededtowin uint64, votesneededtodeactivate uint64, timeout uint64) Account {
	slim := Account{
		Nonce:                   nonce,
		Balance:                 balance,
		Stakeholders:            stakeholders,
		ProposalNumber:          proposalnumber,
		VotesNeededToWin:        votesneededtowin,
		VotesNeededToDeactivate: votesneededtodeactivate,
		TimeOut:                 timeout,
	}
	if root != emptyRoot {
		slim.Root = root[:]
	}
	if proposalroot != emptyRoot {
		slim.ProposalRoot = proposalroot[:]
	}
	if ballotroot != emptyRoot {
		slim.BallotRoot = ballotroot[:]
	}
	if !bytes.Equal(codehash, emptyCode[:]) {
		slim.CodeHash = codehash
	}
	return slim
}

// SlimAccountRLP converts a state.Account content into a slim snapshot
// version RLP encoded.
func SlimAccountRLP(nonce uint64, balance *big.Int, root common.Hash, proposalroot common.Hash, ballotroot common.Hash, codehash []byte, stakeholders []common.Address, proposalnumber uint64, votesneededtowin uint64, votesneededtodeactivate uint64, timeout uint64) []byte {
	data, err := rlp.EncodeToBytes(SlimAccount(nonce, balance, root, proposalroot, ballotroot, codehash, stakeholders, proposalnumber, votesneededtowin, votesneededtodeactivate, timeout))
	if err != nil {
		panic(err)
	}
	return data
}

// FullAccount decodes the data on the 'slim RLP' format and return
// the consensus format account.
func FullAccount(data []byte) (Account, error) {
	var account Account
	if err := rlp.DecodeBytes(data, &account); err != nil {
		return Account{}, err
	}
	if len(account.Root) == 0 {
		account.Root = emptyRoot[:]
	}
	if len(account.ProposalRoot) == 0 {
		account.ProposalRoot = emptyRoot[:]
	}
	if len(account.BallotRoot) == 0 {
		account.BallotRoot = emptyRoot[:]
	}
	if len(account.CodeHash) == 0 {
		account.CodeHash = emptyCode[:]
	}
	return account, nil
}

// FullAccountRLP converts data on the 'slim RLP' format into the full RLP-format.
func FullAccountRLP(data []byte) ([]byte, error) {
	account, err := FullAccount(data)
	if err != nil {
		return nil, err
	}
	return rlp.EncodeToBytes(account)
}
