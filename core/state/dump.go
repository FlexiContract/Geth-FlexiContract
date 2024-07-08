// Copyright 2014 The go-ethereum Authors
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

package state

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

// DumpConfig is a set of options to control what portions of the state will be
// iterated and collected.
type DumpConfig struct {
	SkipCode          bool
	SkipStorage       bool
	OnlyWithAddresses bool
	Start             []byte
	Max               uint64
}

// DumpCollector interface which the state trie calls during iteration
type DumpCollector interface {
	// OnRoot is called with the state root
	OnRoot(common.Hash)
	// OnAccount is called once for each account in the trie
	OnAccount(common.Address, DumpAccount)
}

// DumpAccount represents an account in the state.
type DumpAccount struct {
	ProposalNumber          uint64                       `json:"proposalnumber"`
	Balance                 string                       `json:"balance"`
	Nonce                   uint64                       `json:"nonce"`
	Root                    hexutil.Bytes                `json:"root"`
	ProposalRoot            hexutil.Bytes                `json:"proposalroot"`
	BallotRoot              hexutil.Bytes                `json:"ballotroot"`
	VotesNeededToWin        uint64                       `json:"votesneededtowin"`
	VotesNeededToDeactivate uint64                       `json:"votesneededtodeactivate"`
	TimeOut                 uint64                       `json:"timeout"`
	CodeHash                hexutil.Bytes                `json:"codeHash"`
	Stakeholders            []hexutil.Bytes              `json:"stakeholders"`
	Code                    hexutil.Bytes                `json:"code,omitempty"`
	Storage                 map[common.Hash]string       `json:"storage,omitempty"`
	Proposals               map[common.Hash]DumpProposal `json:"proposals,omitempty"`
	Votes                   map[common.Hash]DumpVote     `json:"votes,omitempty"`
	Address                 *common.Address              `json:"address,omitempty"` // Address only present in iterative (line-by-line) mode
	SecureKey               hexutil.Bytes                `json:"key,omitempty"`     // If we don't have address, we can output the key

}
type DumpReorgInfo struct {
	Type       string        `json:"type"`
	PrevSlot   hexutil.Bytes `json:"oldSlot"`
	NewSlot    hexutil.Bytes `json:"newSlot"`
	PrevOffset uint64        `json:"oldOffset"`
	NewOffset  uint64        `json:"newOffset"`
}

type DumpMember struct {
	PrevOffset uint64        `json:"oldOffset"`
	NewOffset  uint64        `json:"newOffset"`
	PrevSlot   hexutil.Bytes `json:"oldSlot"`
	NewSlot    hexutil.Bytes `json:"newSlot"`
	Type       string        `json:"type"`
}

type DumpDataType struct {
	Type              string       `json:"type"`
	Base              string       `json:"base,omitempty"`
	Encoding          string       `json:"encoding"`
	PrevNumberOfBytes uint64       `json:"prevNumberOfBytes"`
	NewNumberOfBytes  uint64       `json:"newNumberOfBytes"`
	Members           []DumpMember `json:"members,omitempty"`
}

type DumpProposal struct {
	InFavourOf       uint64           `json:"infavourof"`
	Against          uint64           `json:"against"`
	Stakeholders     []common.Address `json:"stakeholders"`
	VotesNeededToWin uint64           `json:"votesneededtowin"`
	ProposedCodeHash hexutil.Bytes    `json:"proposedcode"`
	CurrentState     uint8            `json:"currentstate"`
	ReorgInfos       []DumpReorgInfo  `json:"reorgInfos"`
	Datatypes        []DumpDataType   `json:"dataTypes"`
}

type DumpVote struct {
	TxHash hexutil.Bytes `json:"txhash"`
	Type   uint8         `json:"type"`
}

// Dump represents the full dump in a collected format, as one large map.
type Dump struct {
	Root     string                         `json:"root"`
	Accounts map[common.Address]DumpAccount `json:"accounts"`
}

// OnRoot implements DumpCollector interface
func (d *Dump) OnRoot(root common.Hash) {
	d.Root = fmt.Sprintf("%x", root)
}

// OnAccount implements DumpCollector interface
func (d *Dump) OnAccount(addr common.Address, account DumpAccount) {
	d.Accounts[addr] = account
}

// IteratorDump is an implementation for iterating over data.
type IteratorDump struct {
	Root     string                         `json:"root"`
	Accounts map[common.Address]DumpAccount `json:"accounts"`
	Next     []byte                         `json:"next,omitempty"` // nil if no more accounts
}

// OnRoot implements DumpCollector interface
func (d *IteratorDump) OnRoot(root common.Hash) {
	d.Root = fmt.Sprintf("%x", root)
}

// OnAccount implements DumpCollector interface
func (d *IteratorDump) OnAccount(addr common.Address, account DumpAccount) {
	d.Accounts[addr] = account
}

// iterativeDump is a DumpCollector-implementation which dumps output line-by-line iteratively.
type iterativeDump struct {
	*json.Encoder
}

// OnAccount implements DumpCollector interface
func (d iterativeDump) OnAccount(addr common.Address, account DumpAccount) {
	dumpAccount := &DumpAccount{
		ProposalNumber:          account.ProposalNumber,
		Balance:                 account.Balance,
		Nonce:                   account.Nonce,
		Root:                    account.Root,
		ProposalRoot:            account.ProposalRoot,
		BallotRoot:              account.BallotRoot,
		VotesNeededToWin:        account.VotesNeededToWin,
		VotesNeededToDeactivate: account.VotesNeededToDeactivate,
		TimeOut:                 account.TimeOut,
		CodeHash:                account.CodeHash,
		Stakeholders:            account.Stakeholders,
		Code:                    account.Code,
		Storage:                 account.Storage,
		SecureKey:               account.SecureKey,
		Proposals:               account.Proposals,
		Votes:                   account.Votes,
		Address:                 nil,
	}
	if addr != (common.Address{}) {
		dumpAccount.Address = &addr
	}
	d.Encode(dumpAccount)
}

// OnRoot implements DumpCollector interface
func (d iterativeDump) OnRoot(root common.Hash) {
	d.Encode(struct {
		Root common.Hash `json:"root"`
	}{root})
}

// DumpToCollector iterates the state according to the given options and inserts
// the items into a collector for aggregation or serialization.
func (s *StateDB) DumpToCollector(c DumpCollector, conf *DumpConfig) (nextKey []byte) {
	// Sanitize the input to allow nil configs
	if conf == nil {
		conf = new(DumpConfig)
	}
	var (
		missingPreimages int
		accounts         uint64
		start            = time.Now()
		logged           = time.Now()
	)
	log.Info("Trie dumping started", "root", s.trie.Hash())
	c.OnRoot(s.trie.Hash())

	it := trie.NewIterator(s.trie.NodeIterator(conf.Start))
	for it.Next() {
		var data types.StateAccount
		if err := rlp.DecodeBytes(it.Value, &data); err != nil {
			panic(err)
		}
		stkhldrs := make([]hexutil.Bytes, len(data.Stakeholders))
		for i, stkhldr := range data.Stakeholders {
			stkhldrs[i] = stkhldr.Bytes()
		}

		account := DumpAccount{
			ProposalNumber:          data.ProposalNumber,
			Balance:                 data.Balance.String(),
			VotesNeededToWin:        data.VotesNeededTowin,
			VotesNeededToDeactivate: data.VotesNeededToDeactivate,
			TimeOut:                 data.TimeOut,
			Nonce:                   data.Nonce,
			Root:                    data.Root[:],
			CodeHash:                data.CodeHash,
			ProposalRoot:            data.ProposalRoot[:],
			BallotRoot:              data.BallotRoot[:],
			Stakeholders:            stkhldrs,
			SecureKey:               it.Key,
		}
		addrBytes := s.trie.GetKey(it.Key)
		if addrBytes == nil {
			// Preimage missing
			missingPreimages++
			if conf.OnlyWithAddresses {
				continue
			}
			account.SecureKey = it.Key
		}
		addr := common.BytesToAddress(addrBytes)
		obj := newObject(s, addr, data)
		if !conf.SkipCode {
			account.Code = obj.Code(s.db)
		}
		if !conf.SkipStorage {
			account.Storage = make(map[common.Hash]string)
			storageIt := trie.NewIterator(obj.getTrie(s.db).NodeIterator(nil))
			for storageIt.Next() {
				_, content, _, err := rlp.Split(storageIt.Value)
				if err != nil {
					log.Error("Failed to decode the value returned by iterator", "error", err)
					continue
				}
				account.Storage[common.BytesToHash(s.trie.GetKey(storageIt.Key))] = common.Bytes2Hex(content)
			}
		}
		account.Proposals = make(map[common.Hash]DumpProposal)
		proposalIt := trie.NewIterator(obj.getProposalTrie(s.db).NodeIterator(nil))
		for proposalIt.Next() {
			var proposal types.Proposal
			err := rlp.DecodeBytes(proposalIt.Value, &proposal)
			if err != nil {
				log.Error("Failed to decode the value returned by iterator", "error", err)
				continue
			}
			var reorgInfos []DumpReorgInfo
			for _, reorgInfo := range proposal.ReorgInfoList {
				reorgInfos = append(reorgInfos, DumpReorgInfo{Type: reorgInfo.Type, PrevSlot: reorgInfo.PrevSlot[:], NewSlot: reorgInfo.NewSlot[:], PrevOffset: reorgInfo.PrevOffset, NewOffset: reorgInfo.NewOffset})
			}

			var dataTypes []DumpDataType
			for _, dataType := range proposal.DataTypeList {
				var members []DumpMember
				for _, member := range dataType.Members {

					members = append(members, DumpMember{Type: member.Type, PrevOffset: member.PrevOffset, NewOffset: member.NewOffset, PrevSlot: member.PrevSlot[:], NewSlot: member.NewSlot[:]})
				}
				dataTypes = append(dataTypes, DumpDataType{Type: dataType.Type, Base: dataType.Base, Encoding: dataType.Encoding, PrevNumberOfBytes: dataType.PrevNumberOfBytes, NewNumberOfBytes: dataType.NewNumberOfBytes, Members: members})
			}
			account.Proposals[common.BytesToHash(s.trie.GetKey(proposalIt.Key))] = DumpProposal{InFavourOf: proposal.InFavourOf, Against: proposal.Against, Stakeholders: proposal.Stakeholders, VotesNeededToWin: proposal.VotesNeededToWin, CurrentState: proposal.CurrentState, ProposedCodeHash: proposal.ProposedCodeHash, ReorgInfos: reorgInfos, Datatypes: dataTypes}
		}
		account.Votes = make(map[common.Hash]DumpVote)
		ballotIt := trie.NewIterator(obj.getBallotTrie(s.db).NodeIterator(nil))

		for ballotIt.Next() {
			var vote types.Vote
			err := rlp.DecodeBytes(ballotIt.Value, &vote)
			if err != nil {
				log.Error("Failed to decode the value returned by iterator", "error", err)
				continue
			}

			account.Votes[common.BytesToHash(s.trie.GetKey(ballotIt.Key))] = DumpVote{Type: vote.Type, TxHash: vote.TxHash[:]}

		}

		c.OnAccount(addr, account)
		accounts++
		if time.Since(logged) > 8*time.Second {
			log.Info("Trie dumping in progress", "at", it.Key, "accounts", accounts,
				"elapsed", common.PrettyDuration(time.Since(start)))
			logged = time.Now()
		}
		if conf.Max > 0 && accounts >= conf.Max {
			if it.Next() {
				nextKey = it.Key
			}
			break
		}
	}
	if missingPreimages > 0 {
		log.Warn("Dump incomplete due to missing preimages", "missing", missingPreimages)
	}
	log.Info("Trie dumping complete", "accounts", accounts,
		"elapsed", common.PrettyDuration(time.Since(start)))

	return nextKey
}

// RawDump returns the entire state an a single large object
func (s *StateDB) RawDump(opts *DumpConfig) Dump {
	dump := &Dump{
		Accounts: make(map[common.Address]DumpAccount),
	}
	s.DumpToCollector(dump, opts)
	return *dump
}

// Dump returns a JSON string representing the entire state as a single json-object
func (s *StateDB) Dump(opts *DumpConfig) []byte {
	dump := s.RawDump(opts)
	json, err := json.MarshalIndent(dump, "", "    ")
	if err != nil {
		fmt.Println("Dump err", err)
	}
	return json
}

// IterativeDump dumps out accounts as json-objects, delimited by linebreaks on stdout
func (s *StateDB) IterativeDump(opts *DumpConfig, output *json.Encoder) {
	s.DumpToCollector(iterativeDump{output}, opts)
}

// IteratorDump dumps out a batch of accounts starts with the given start key
func (s *StateDB) IteratorDump(opts *DumpConfig) IteratorDump {
	iterator := &IteratorDump{
		Accounts: make(map[common.Address]DumpAccount),
	}
	iterator.Next = s.DumpToCollector(iterator, opts)
	return *iterator
}
