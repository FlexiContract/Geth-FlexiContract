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
	"bytes"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)

var emptyCodeHash = crypto.Keccak256(nil)

type Code []byte

func (c Code) String() string {
	return string(c) //strings.Join(Disassemble(c), " ")
}

type Storage map[common.Hash]common.Hash

func (s Storage) String() (str string) {
	for key, value := range s {
		str += fmt.Sprintf("%X : %X\n", key, value)
	}

	return
}

func (s Storage) Copy() Storage {
	cpy := make(Storage, len(s))
	for key, value := range s {
		cpy[key] = value
	}

	return cpy
}

type ProposalCache map[common.Hash]types.Proposal

func (s ProposalCache) Copy() ProposalCache {
	cpy := make(ProposalCache, len(s))
	for key, value := range s {
		cpy[key] = value
	}

	return cpy
}

type VoteCache map[common.Hash]types.Vote

func (s VoteCache) Copy() VoteCache {
	cpy := make(VoteCache, len(s))
	for key, value := range s {
		cpy[key] = value
	}

	return cpy
}

// stateObject represents an Ethereum account which is being modified.
//
// The usage pattern is as follows:
// First you need to obtain a state object.
// Account values can be accessed and modified through the object.
// Finally, call commitTrie to write the modified storage trie into a database.
type stateObject struct {
	address  common.Address
	addrHash common.Hash // hash of ethereum address of the account
	data     types.StateAccount
	db       *StateDB

	// DB error.
	// State objects are used by the consensus core and VM which are
	// unable to deal with database-level errors. Any error that occurs
	// during a database read is memoized here and will eventually be returned
	// by StateDB.Commit.
	dbErr error

	// Write caches.
	trie         Trie // storage trie, which becomes non-nil on first access
	proposalTrie Trie
	ballotTrie   Trie
	code         Code // contract bytecode, which gets set when code is loaded

	originStorage  Storage // Storage cache of original entries to dedup rewrites, reset for every transaction
	pendingStorage Storage // Storage entries that need to be flushed to disk, at the end of an entire block
	dirtyStorage   Storage // Storage entries that have been modified in the current transaction execution
	fakeStorage    Storage // Fake storage which constructed by caller for debugging purpose.

	originProposal  ProposalCache
	pendingProposal ProposalCache
	dirtyProposal   ProposalCache

	originVote  VoteCache
	pendingVote VoteCache
	dirtyVote   VoteCache
	// Cache flags.
	// When an object is marked suicided it will be delete from the trie
	// during the "update" phase of the state transition.
	dirtyCode bool // true if the code was updated
	suicided  bool
	deleted   bool
}

// empty returns whether the account is considered empty.
func (s *stateObject) empty() bool {
	return s.data.Nonce == 0 && s.data.Balance.Sign() == 0 && bytes.Equal(s.data.CodeHash, emptyCodeHash)
}

// newObject creates a state object.
func newObject(db *StateDB, address common.Address, data types.StateAccount) *stateObject {
	if data.Balance == nil {
		data.Balance = new(big.Int)
	}
	if data.CodeHash == nil {
		data.CodeHash = emptyCodeHash
	}
	if data.Root == (common.Hash{}) {
		data.Root = emptyRoot
	}
	if data.ProposalRoot == (common.Hash{}) {
		data.ProposalRoot = emptyRoot
	}
	if data.BallotRoot == (common.Hash{}) {
		data.BallotRoot = emptyRoot
	}
	if data.Stakeholders == nil {
		data.Stakeholders = make([]common.Address, 0)
	}
	return &stateObject{
		db:              db,
		address:         address,
		addrHash:        crypto.Keccak256Hash(address[:]),
		data:            data,
		originStorage:   make(Storage),
		pendingStorage:  make(Storage),
		dirtyStorage:    make(Storage),
		originProposal:  make(ProposalCache),
		pendingProposal: make(ProposalCache),
		dirtyProposal:   make(ProposalCache),
		originVote:      make(VoteCache),
		pendingVote:     make(VoteCache),
		dirtyVote:       make(VoteCache),
	}
}

// EncodeRLP implements rlp.Encoder.
func (s *stateObject) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, &s.data)
}

// setError remembers the first non-nil error it is called with.
func (s *stateObject) setError(err error) {
	if s.dbErr == nil {
		s.dbErr = err
	}
}

func (s *stateObject) markSuicided() {
	s.suicided = true
}

func (s *stateObject) touch() {
	s.db.journal.append(touchChange{
		account: &s.address,
	})
	if s.address == ripemd {
		// Explicitly put it in the dirty-cache, which is otherwise generated from
		// flattened journals.
		s.db.journal.dirty(s.address)
	}
}

func (s *stateObject) getTrie(db Database) Trie {
	if s.trie == nil {
		// Try fetching from prefetcher first
		// We don't prefetch empty tries
		if s.data.Root != emptyRoot && s.db.prefetcher != nil {
			// When the miner is creating the pending state, there is no
			// prefetcher
			s.trie = s.db.prefetcher.trie(s.addrHash, s.data.Root)
		}
		if s.trie == nil {
			var err error
			s.trie, err = db.OpenStorageTrie(s.db.originalRoot, s.addrHash, s.data.Root)
			if err != nil {
				s.trie, _ = db.OpenStorageTrie(s.db.originalRoot, s.addrHash, common.Hash{})
				s.setError(fmt.Errorf("can't create storage trie: %v", err))
			}
		}
	}
	return s.trie
}

func (s *stateObject) getProposalTrie(db Database) Trie {
	if s.proposalTrie == nil {
		// Try fetching from prefetcher first
		// We don't prefetch empty tries
		if s.data.ProposalRoot != emptyRoot && s.db.prefetcher != nil {
			// When the miner is creating the pending state, there is no
			// prefetcher
			s.proposalTrie = s.db.prefetcher.trie(s.addrHash, s.data.ProposalRoot)
		}
		if s.proposalTrie == nil {
			var err error
			s.proposalTrie, err = db.OpenProposalTrie(s.db.originalRoot, s.addrHash, s.data.ProposalRoot)
			if err != nil {
				s.proposalTrie, _ = db.OpenProposalTrie(s.db.originalRoot, s.addrHash, common.Hash{})
				s.setError(fmt.Errorf("can't create proposal trie: %v", err))
			}
		}
	}
	return s.proposalTrie
}

func (s *stateObject) getBallotTrie(db Database) Trie {
	if s.ballotTrie == nil {
		// Try fetching from prefetcher first
		// We don't prefetch empty tries
		if s.data.BallotRoot != emptyRoot && s.db.prefetcher != nil {
			// When the miner is creating the pending state, there is no
			// prefetcher
			s.ballotTrie = s.db.prefetcher.trie(s.addrHash, s.data.BallotRoot)
		}
		if s.ballotTrie == nil {
			var err error
			s.ballotTrie, err = db.OpenBallotTrie(s.db.originalRoot, s.addrHash, s.data.BallotRoot)
			if err != nil {
				s.ballotTrie, _ = db.OpenBallotTrie(s.db.originalRoot, s.addrHash, common.Hash{})
				s.setError(fmt.Errorf("can't create ballot trie: %v", err))
			}
		}
	}
	return s.ballotTrie
}

// GetState retrieves a value from the account storage trie.
func (s *stateObject) GetState(db Database, key common.Hash) common.Hash {
	// If the fake storage is set, only lookup the state here(in the debugging mode)
	if s.fakeStorage != nil {
		return s.fakeStorage[key]
	}
	// If we have a dirty value for this state entry, return it
	value, dirty := s.dirtyStorage[key]
	if dirty {
		return value
	}
	// Otherwise return the entry's original value
	return s.GetCommittedState(db, key)
}

func (s *stateObject) GetProposal(db Database, key common.Hash) types.Proposal {

	// If we have a dirty value for this state entry, return it
	value, dirty := s.dirtyProposal[key]
	if dirty {
		return value
	}
	// Otherwise return the entry's original value
	return s.GetCommittedProposal(db, key)
}

func (s *stateObject) GetVote(db Database, key common.Hash) types.Vote {

	// If we have a dirty value for this state entry, return it
	value, dirty := s.dirtyVote[key]
	if dirty {
		return value
	}
	// Otherwise return the entry's original value
	return s.GetCommittedVote(db, key)
}

// GetCommittedState retrieves a value from the committed account storage trie.
func (s *stateObject) GetCommittedState(db Database, key common.Hash) common.Hash {
	// If the fake storage is set, only lookup the state here(in the debugging mode)
	if s.fakeStorage != nil {
		return s.fakeStorage[key]
	}
	// If we have a pending write or clean cached, return that
	if value, pending := s.pendingStorage[key]; pending {
		return value
	}
	if value, cached := s.originStorage[key]; cached {
		return value
	}
	// If no live objects are available, attempt to use snapshots
	var (
		enc []byte
		err error
	)
	if s.db.snap != nil {
		// If the object was destructed in *this* block (and potentially resurrected),
		// the storage has been cleared out, and we should *not* consult the previous
		// snapshot about any storage values. The only possible alternatives are:
		//   1) resurrect happened, and new slot values were set -- those should
		//      have been handles via pendingStorage above.
		//   2) we don't have new values, and can deliver empty response back
		if _, destructed := s.db.snapDestructs[s.addrHash]; destructed {
			return common.Hash{}
		}
		start := time.Now()
		enc, err = s.db.snap.Storage(s.addrHash, crypto.Keccak256Hash(key.Bytes()))
		if metrics.EnabledExpensive {
			s.db.SnapshotStorageReads += time.Since(start)
		}
	}
	// If the snapshot is unavailable or reading from it fails, load from the database.
	if s.db.snap == nil || err != nil {
		start := time.Now()
		enc, err = s.getTrie(db).TryGet(key.Bytes())
		if metrics.EnabledExpensive {
			s.db.StorageReads += time.Since(start)
		}
		if err != nil {
			s.setError(err)
			return common.Hash{}
		}
	}
	var value common.Hash
	if len(enc) > 0 {
		_, content, _, err := rlp.Split(enc)
		if err != nil {
			s.setError(err)
		}
		value.SetBytes(content)
	}
	s.originStorage[key] = value
	return value
}

func (s *stateObject) GetCommittedProposal(db Database, key common.Hash) types.Proposal {

	if value, pending := s.pendingProposal[key]; pending {
		return value
	}
	if value, cached := s.originProposal[key]; cached {
		return value
	}

	var (
		enc []byte
		err error
	)

	enc, err = s.getProposalTrie(db).TryGet(key.Bytes())

	if err != nil {
		s.setError(err)
		return types.Proposal{}
	}

	var value types.Proposal
	if len(enc) > 0 {
		err := rlp.DecodeBytes(enc, &value)
		if err != nil {
			s.setError(err)
		}
	}
	s.originProposal[key] = value
	return value
}

func (s *stateObject) GetCommittedVote(db Database, key common.Hash) types.Vote {

	if value, pending := s.pendingVote[key]; pending {
		return value
	}
	if value, cached := s.originVote[key]; cached {
		return value
	}

	var (
		enc []byte
		err error
	)

	enc, err = s.getBallotTrie(db).TryGet(key.Bytes())

	if err != nil {
		s.setError(err)
		return types.Vote{}
	}

	var value types.Vote
	if len(enc) > 0 {
		err := rlp.DecodeBytes(enc, &value)
		if err != nil {
			s.setError(err)
		}
	}
	s.originVote[key] = value
	return value
}

// SetState updates a value in account storage.
func (s *stateObject) SetState(db Database, key, value common.Hash) {
	// If the fake storage is set, put the temporary state update here.
	if s.fakeStorage != nil {
		s.fakeStorage[key] = value
		return
	}
	// If the new value is the same as old, don't set
	prev := s.GetState(db, key)
	if prev == value {
		return
	}
	// New value is different, update and journal the change
	s.db.journal.append(storageChange{
		account:  &s.address,
		key:      key,
		prevalue: prev,
	})
	s.setState(key, value)
}

func (s *stateObject) SetProposal(db Database, key common.Hash, value types.Proposal) {

	// If the new value is the same as old, don't set
	prev := s.GetProposal(db, key)
	if prev.Equals(value) {
		return
	}
	// New value is different, update and journal the change
	s.db.journal.append(proposalChange{
		account: &s.address,
		key:     key,
		prev:    prev,
	})
	s.setProposal(key, value)
}

func (s *stateObject) SetVote(db Database, key common.Hash, value types.Vote) {

	// If the new value is the same as old, don't set
	prev := s.GetVote(db, key)
	if prev.Equals(value) {
		return
	}
	// New value is different, update and journal the change
	s.db.journal.append(voteChange{
		account: &s.address,
		key:     key,
		prev:    prev,
	})
	s.setVote(key, value)
}

// SetStorage replaces the entire state storage with the given one.
//
// After this function is called, all original state will be ignored and state
// lookup only happens in the fake state storage.
//
// Note this function should only be used for debugging purpose.
func (s *stateObject) SetStorage(storage map[common.Hash]common.Hash) {
	// Allocate fake storage if it's nil.
	if s.fakeStorage == nil {
		s.fakeStorage = make(Storage)
	}
	for key, value := range storage {
		s.fakeStorage[key] = value
	}
	// Don't bother journal since this function should only be used for
	// debugging and the `fake` storage won't be committed to database.
}

func (s *stateObject) setState(key, value common.Hash) {
	s.dirtyStorage[key] = value
}

func (s *stateObject) setProposal(key common.Hash, value types.Proposal) {
	s.dirtyProposal[key] = value
}

func (s *stateObject) setVote(key common.Hash, value types.Vote) {
	s.dirtyVote[key] = value
}

// finalise moves all dirty storage slots into the pending area to be hashed or
// committed later. It is invoked at the end of every transaction.
func (s *stateObject) finalise(prefetch bool) {
	slotsToPrefetch := make([][]byte, 0, len(s.dirtyStorage))
	for key, value := range s.dirtyStorage {
		s.pendingStorage[key] = value
		if value != s.originStorage[key] {
			slotsToPrefetch = append(slotsToPrefetch, common.CopyBytes(key[:])) // Copy needed for closure
		}
	}
	if s.db.prefetcher != nil && prefetch && len(slotsToPrefetch) > 0 && s.data.Root != emptyRoot {
		s.db.prefetcher.prefetch(s.addrHash, s.data.Root, slotsToPrefetch)
	}
	if len(s.dirtyStorage) > 0 {
		s.dirtyStorage = make(Storage)
	}
}

func (s *stateObject) finalisePrposals(prefetch bool) {
	proposalsToPrefetch := make([][]byte, 0, len(s.dirtyProposal))
	for key, value := range s.dirtyProposal {
		s.pendingProposal[key] = value
		if !value.Equals(s.originProposal[key]) {
			proposalsToPrefetch = append(proposalsToPrefetch, common.CopyBytes(key[:])) // Copy needed for closure
		}
	}
	if s.db.prefetcher != nil && prefetch && len(proposalsToPrefetch) > 0 && s.data.ProposalRoot != emptyRoot {
		s.db.prefetcher.prefetch(s.addrHash, s.data.ProposalRoot, proposalsToPrefetch)
	}
	if len(s.dirtyProposal) > 0 {
		s.dirtyProposal = make(ProposalCache)
	}
}

func (s *stateObject) finaliseVotes(prefetch bool) {
	votesToPrefetch := make([][]byte, 0, len(s.dirtyVote))
	for key, value := range s.dirtyVote {
		s.pendingVote[key] = value
		if !value.Equals(s.originVote[key]) {
			votesToPrefetch = append(votesToPrefetch, common.CopyBytes(key[:])) // Copy needed for closure
		}
	}
	if s.db.prefetcher != nil && prefetch && len(votesToPrefetch) > 0 && s.data.BallotRoot != emptyRoot {
		s.db.prefetcher.prefetch(s.addrHash, s.data.BallotRoot, votesToPrefetch)
	}
	if len(s.dirtyVote) > 0 {
		s.dirtyVote = make(VoteCache)
	}
}

// updateTrie writes cached storage modifications into the object's storage trie.
// It will return nil if the trie has not been loaded and no changes have been made
func (s *stateObject) updateTrie(db Database) Trie {
	// Make sure all dirty slots are finalized into the pending storage area
	s.finalise(false) // Don't prefetch anymore, pull directly if need be
	if len(s.pendingStorage) == 0 {
		return s.trie
	}
	// Track the amount of time wasted on updating the storage trie
	if metrics.EnabledExpensive {
		defer func(start time.Time) { s.db.StorageUpdates += time.Since(start) }(time.Now())
	}
	// The snapshot storage map for the object
	var storage map[common.Hash][]byte
	// Insert all the pending updates into the trie
	tr := s.getTrie(db)
	hasher := s.db.hasher

	usedStorage := make([][]byte, 0, len(s.pendingStorage))
	for key, value := range s.pendingStorage {
		// Skip noop changes, persist actual changes
		if value == s.originStorage[key] {
			continue
		}
		s.originStorage[key] = value

		var v []byte
		if (value == common.Hash{}) {
			s.setError(tr.TryDelete(key[:]))
			s.db.StorageDeleted += 1
		} else {
			// Encoding []byte cannot fail, ok to ignore the error.
			v, _ = rlp.EncodeToBytes(common.TrimLeftZeroes(value[:]))
			s.setError(tr.TryUpdate(key[:], v))
			s.db.StorageUpdated += 1
		}
		// If state snapshotting is active, cache the data til commit
		if s.db.snap != nil {
			if storage == nil {
				// Retrieve the old storage map, if available, create a new one otherwise
				if storage = s.db.snapStorage[s.addrHash]; storage == nil {
					storage = make(map[common.Hash][]byte)
					s.db.snapStorage[s.addrHash] = storage
				}
			}
			storage[crypto.HashData(hasher, key[:])] = v // v will be nil if it's deleted
		}
		usedStorage = append(usedStorage, common.CopyBytes(key[:])) // Copy needed for closure
	}
	if s.db.prefetcher != nil {
		s.db.prefetcher.used(s.addrHash, s.data.Root, usedStorage)
	}
	if len(s.pendingStorage) > 0 {
		s.pendingStorage = make(Storage)
	}
	return tr
}

func (s *stateObject) updateProposalTrie(db Database) Trie {
	// Make sure all dirty proposals are finalized into the pending proposal area
	s.finalisePrposals(false) // Don't prefetch anymore, pull directly if need be
	if len(s.pendingProposal) == 0 {
		return s.proposalTrie
	}

	// Insert all the pending updates into the trie
	tr := s.getProposalTrie(db)

	usedProposal := make([][]byte, 0, len(s.pendingProposal))

	for key, value := range s.pendingProposal {
		// Skip noop changes, persist actual changes
		if value.Equals(s.originProposal[key]) {

			continue
		}
		s.originProposal[key] = value

		var v []byte
		if (value.Equals(types.Proposal{})) {

			s.setError(tr.TryDelete(key[:]))

		} else {
			// Encoding []byte cannot fail, ok to ignore the error.
			v, _ = rlp.EncodeToBytes(&value)
			s.setError(tr.TryUpdate(key[:], v))
		}
		// If state snapshotting is active, cache the data til commit

		usedProposal = append(usedProposal, common.CopyBytes(key[:])) // Copy needed for closure
	}
	if s.db.prefetcher != nil {
		s.db.prefetcher.used(s.addrHash, s.data.ProposalRoot, usedProposal)
	}
	if len(s.pendingProposal) > 0 {
		s.pendingProposal = make(ProposalCache)
	}
	return tr
}

func (s *stateObject) updateBallotTrie(db Database) Trie {
	// Make sure all dirty proposals are finalized into the pending proposal area
	s.finaliseVotes(false) // Don't prefetch anymore, pull directly if need be
	if len(s.pendingVote) == 0 {
		return s.ballotTrie
	}

	// Insert all the pending updates into the trie
	tr := s.getBallotTrie(db)

	usedVote := make([][]byte, 0, len(s.pendingVote))
	for key, value := range s.pendingVote {
		// Skip noop changes, persist actual changes
		if value.Equals(s.originVote[key]) {
			continue
		}
		s.originVote[key] = value

		var v []byte
		if (value.Equals(types.Vote{})) {
			s.setError(tr.TryDelete(key[:]))

		} else {
			// Encoding []byte cannot fail, ok to ignore the error.
			v, _ = rlp.EncodeToBytes(&value)
			s.setError(tr.TryUpdate(key[:], v))

		}
		// If state snapshotting is active, cache the data til commit

		usedVote = append(usedVote, common.CopyBytes(key[:])) // Copy needed for closure
	}
	if s.db.prefetcher != nil {
		s.db.prefetcher.used(s.addrHash, s.data.BallotRoot, usedVote)
	}
	if len(s.pendingVote) > 0 {
		s.pendingVote = make(VoteCache)
	}
	return tr
}

// UpdateRoot sets the trie root to the current root hash of
func (s *stateObject) updateRoot(db Database) {
	// If nothing changed, don't bother with hashing anything
	if s.updateTrie(db) == nil {
		return
	}
	// Track the amount of time wasted on hashing the storage trie
	if metrics.EnabledExpensive {
		defer func(start time.Time) { s.db.StorageHashes += time.Since(start) }(time.Now())
	}
	s.data.Root = s.trie.Hash()
}

func (s *stateObject) updateProposalRoot(db Database) {
	// If nothing changed, don't bother with hashing anything
	if s.updateProposalTrie(db) == nil {
		return
	}

	s.data.ProposalRoot = s.proposalTrie.Hash()
}

func (s *stateObject) updateBallotRoot(db Database) {
	// If nothing changed, don't bother with hashing anything
	if s.updateBallotTrie(db) == nil {
		return
	}

	s.data.BallotRoot = s.ballotTrie.Hash()
}

// commitTrie submits the storage changes into the storage trie and re-computes
// the root. Besides, all trie changes will be collected in a nodeset and returned.
func (s *stateObject) commitTrie(db Database) (*trie.NodeSet, error) {
	// If nothing changed, don't bother with hashing anything
	if s.updateTrie(db) == nil {
		return nil, nil
	}
	if s.dbErr != nil {
		return nil, s.dbErr
	}
	// Track the amount of time wasted on committing the storage trie
	if metrics.EnabledExpensive {
		defer func(start time.Time) { s.db.StorageCommits += time.Since(start) }(time.Now())
	}
	root, nodes, err := s.trie.Commit(false)
	if err == nil {
		s.data.Root = root
	}
	return nodes, err
}

func (s *stateObject) commitProposalTrie(db Database) (*trie.NodeSet, error) {
	// If nothing changed, don't bother with hashing anything
	if s.updateProposalTrie(db) == nil {
		return nil, nil
	}
	if s.dbErr != nil {
		return nil, s.dbErr
	}

	root, nodes, err := s.proposalTrie.Commit(false)
	if err == nil {
		s.data.ProposalRoot = root
	}
	return nodes, err
}

func (s *stateObject) commitBallotTrie(db Database) (*trie.NodeSet, error) {
	// If nothing changed, don't bother with hashing anything
	if s.updateBallotTrie(db) == nil {
		return nil, nil
	}
	if s.dbErr != nil {
		return nil, s.dbErr
	}

	root, nodes, err := s.ballotTrie.Commit(false)
	if err == nil {
		s.data.BallotRoot = root
	}
	return nodes, err
}

// AddBalance adds amount to s's balance.
// It is used to add funds to the destination account of a transfer.
func (s *stateObject) AddBalance(amount *big.Int) {
	// EIP161: We must check emptiness for the objects such that the account
	// clearing (0,0,0 objects) can take effect.
	if amount.Sign() == 0 {
		if s.empty() {
			s.touch()
		}
		return
	}
	s.SetBalance(new(big.Int).Add(s.Balance(), amount))
}

// SubBalance removes amount from s's balance.
// It is used to remove funds from the origin account of a transfer.
func (s *stateObject) SubBalance(amount *big.Int) {
	if amount.Sign() == 0 {
		return
	}
	s.SetBalance(new(big.Int).Sub(s.Balance(), amount))
}

func (s *stateObject) SetBalance(amount *big.Int) {
	s.db.journal.append(balanceChange{
		account: &s.address,
		prev:    new(big.Int).Set(s.data.Balance),
	})
	s.setBalance(amount)
}

func (s *stateObject) setBalance(amount *big.Int) {
	s.data.Balance = amount
}

func (s *stateObject) deepCopy(db *StateDB) *stateObject {
	stateObject := newObject(db, s.address, s.data)
	if s.trie != nil {
		stateObject.trie = db.db.CopyTrie(s.trie)
	}
	if s.proposalTrie != nil {
		stateObject.proposalTrie = db.db.CopyTrie(s.proposalTrie)
	}
	if s.ballotTrie != nil {
		stateObject.ballotTrie = db.db.CopyTrie(s.ballotTrie)
	}
	stateObject.code = s.code

	stateObject.dirtyStorage = s.dirtyStorage.Copy()
	stateObject.originStorage = s.originStorage.Copy()
	stateObject.pendingStorage = s.pendingStorage.Copy()

	stateObject.dirtyProposal = s.dirtyProposal.Copy()
	stateObject.originProposal = s.originProposal.Copy()
	stateObject.pendingProposal = s.pendingProposal.Copy()

	stateObject.dirtyVote = s.dirtyVote.Copy()
	stateObject.originVote = s.originVote.Copy()
	stateObject.pendingVote = s.pendingVote.Copy()

	stateObject.suicided = s.suicided
	stateObject.dirtyCode = s.dirtyCode
	stateObject.deleted = s.deleted
	return stateObject
}

//
// Attribute accessors
//

// Address returns the address of the contract/account
func (s *stateObject) Address() common.Address {
	return s.address
}

// Code returns the contract code associated with this object, if any.
func (s *stateObject) Code(db Database) []byte {
	if s.code != nil {
		return s.code
	}
	if bytes.Equal(s.CodeHash(), emptyCodeHash) {
		return nil
	}
	code, err := db.ContractCode(s.addrHash, common.BytesToHash(s.CodeHash()))
	if err != nil {
		s.setError(fmt.Errorf("can't load code hash %x: %v", s.CodeHash(), err))
	}
	s.code = code
	return code
}

// CodeSize returns the size of the contract code associated with this object,
// or zero if none. This method is an almost mirror of Code, but uses a cache
// inside the database to avoid loading codes seen recently.
func (s *stateObject) CodeSize(db Database) int {
	if s.code != nil {
		return len(s.code)
	}
	if bytes.Equal(s.CodeHash(), emptyCodeHash) {
		return 0
	}
	size, err := db.ContractCodeSize(s.addrHash, common.BytesToHash(s.CodeHash()))
	if err != nil {
		s.setError(fmt.Errorf("can't load code size %x: %v", s.CodeHash(), err))
	}
	return size
}

func (s *stateObject) SetCode(codeHash common.Hash, code []byte) {
	prevcode := s.Code(s.db.db)
	s.db.journal.append(codeChange{
		account:  &s.address,
		prevhash: s.CodeHash(),
		prevcode: prevcode,
	})
	s.setCode(codeHash, code)
}

func (s *stateObject) setCode(codeHash common.Hash, code []byte) {
	s.code = code
	s.data.CodeHash = codeHash[:]
	s.dirtyCode = true
}

func (s *stateObject) SetStakeholders(stakeholders []common.Address) {
	s.db.journal.append(stakeholdersChange{
		account: &s.address,
		prev:    s.data.Stakeholders,
	})
	s.setStakeholders(stakeholders)
}

func (s *stateObject) setStakeholders(stakeholders []common.Address) {
	s.data.Stakeholders = stakeholders
}

func (s *stateObject) SetNonce(nonce uint64) {
	s.db.journal.append(nonceChange{
		account: &s.address,
		prev:    s.data.Nonce,
	})
	s.setNonce(nonce)
}

func (s *stateObject) setNonce(nonce uint64) {
	s.data.Nonce = nonce
}

func (s *stateObject) SetProposalNumber(number uint64) {
	s.db.journal.append(proposalNumberChange{
		account: &s.address,
		prev:    s.data.ProposalNumber,
	})
	s.setProposalNumber(number)
}

func (s *stateObject) SetVotesNeededToWin(number uint64) {
	s.db.journal.append(votesNeededToWinChange{
		account: &s.address,
		prev:    s.data.VotesNeededTowin,
	})
	s.setVotesNeededToWin(number)
}

func (s *stateObject) setProposalNumber(number uint64) {
	s.data.ProposalNumber = number
}

func (s *stateObject) setVotesNeededToWin(number uint64) {
	s.data.VotesNeededTowin = number
}

func (s *stateObject) CodeHash() []byte {
	return s.data.CodeHash
}

func (s *stateObject) Balance() *big.Int {
	return s.data.Balance
}

func (s *stateObject) Nonce() uint64 {
	return s.data.Nonce
}

func (s *stateObject) Stakeholders() []common.Address {
	return s.data.Stakeholders
}

func (s *stateObject) ProposalNumber() uint64 {
	return s.data.ProposalNumber
}

func (s *stateObject) VotesNeededToWin() uint64 {
	return s.data.VotesNeededTowin
}

// Value is never called, but must be present to allow stateObject to be used
// as a vm.Account interface that also satisfies the vm.ContractRef
// interface. Interfaces are awesome.
func (s *stateObject) Value() *big.Int {
	panic("Value on stateObject should never be called")
}
