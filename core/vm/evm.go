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

package vm

import (
	"bytes"
	"fmt"
	"math/big"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// emptyCodeHash is used by create to ensure deployment is disallowed to already
// deployed contract addresses (relevant after the account abstraction).
var emptyCodeHash = crypto.Keccak256Hash(nil)

type (
	// CanTransferFunc is the signature of a transfer guard function
	CanTransferFunc func(StateDB, common.Address, *big.Int) bool
	// TransferFunc is the signature of a transfer function
	TransferFunc func(StateDB, common.Address, common.Address, *big.Int)
	// GetHashFunc returns the n'th block hash in the blockchain
	// and is used by the BLOCKHASH EVM op code.
	GetHashFunc func(uint64) common.Hash
	// IsStakeholder is the signature of a stakeholder guard function
	IsStakeholderFunc func(StateDB, common.Address, common.Address) bool
)

func (evm *EVM) precompile(addr common.Address) (PrecompiledContract, bool) {
	var precompiles map[common.Address]PrecompiledContract
	switch {
	case evm.chainRules.IsBerlin:
		precompiles = PrecompiledContractsBerlin
	case evm.chainRules.IsIstanbul:
		precompiles = PrecompiledContractsIstanbul
	case evm.chainRules.IsByzantium:
		precompiles = PrecompiledContractsByzantium
	default:
		precompiles = PrecompiledContractsHomestead
	}
	p, ok := precompiles[addr]
	return p, ok
}

// BlockContext provides the EVM with auxiliary information. Once provided
// it shouldn't be modified.
type BlockContext struct {
	// CanTransfer returns whether the account contains
	// sufficient ether to transfer the value
	CanTransfer CanTransferFunc
	// Transfer transfers ether from one account to the other
	Transfer TransferFunc
	// GetHash returns the hash corresponding to n
	GetHash GetHashFunc

	// Block information
	Coinbase    common.Address // Provides information for COINBASE
	GasLimit    uint64         // Provides information for GASLIMIT
	BlockNumber *big.Int       // Provides information for NUMBER
	Time        *big.Int       // Provides information for TIME
	Difficulty  *big.Int       // Provides information for DIFFICULTY
	BaseFee     *big.Int       // Provides information for BASEFEE
	Random      *common.Hash   // Provides information for PREVRANDAO
}

// TxContext provides the EVM with information about a transaction.
// All fields can change between transactions.
type TxContext struct {
	// Message information
	Origin   common.Address // Provides information for ORIGIN
	GasPrice *big.Int       // Provides information for GASPRICE
}

// EVM is the Ethereum Virtual Machine base object and provides
// the necessary tools to run a contract on the given state with
// the provided context. It should be noted that any error
// generated through any of the calls should be considered a
// revert-state-and-consume-all-gas operation, no checks on
// specific errors should ever be performed. The interpreter makes
// sure that any errors generated are to be considered faulty code.
//
// The EVM should never be reused and is not thread safe.
type EVM struct {
	// Context provides auxiliary blockchain related information
	Context BlockContext
	TxContext
	// StateDB gives access to the underlying state
	StateDB StateDB
	// Depth is the current call stack
	depth int

	// chainConfig contains information about the current chain
	chainConfig *params.ChainConfig
	// chain rules contains the chain rules for the current epoch
	chainRules params.Rules
	// virtual machine configuration options used to initialise the
	// evm.
	Config Config
	// global (to this context) ethereum virtual machine
	// used throughout the execution of the tx.
	interpreter *EVMInterpreter
	// abort is used to abort the EVM calling operations
	// NOTE: must be set atomically
	abort int32
	// callGasTemp holds the gas available for the current call. This is needed because the
	// available gas is calculated in gasCall* according to the 63/64 rule and later
	// applied in opCall*.
	callGasTemp uint64
}

// NewEVM returns a new EVM. The returned EVM is not thread safe and should
// only ever be used *once*.
func NewEVM(blockCtx BlockContext, txCtx TxContext, statedb StateDB, chainConfig *params.ChainConfig, config Config) *EVM {
	evm := &EVM{
		Context:     blockCtx,
		TxContext:   txCtx,
		StateDB:     statedb,
		Config:      config,
		chainConfig: chainConfig,
		chainRules:  chainConfig.Rules(blockCtx.BlockNumber, blockCtx.Random != nil),
	}
	evm.interpreter = NewEVMInterpreter(evm, config)
	return evm
}

// Reset resets the EVM with a new transaction context.Reset
// This is not threadsafe and should only be done very cautiously.
func (evm *EVM) Reset(txCtx TxContext, statedb StateDB) {
	evm.TxContext = txCtx
	evm.StateDB = statedb
}

// Cancel cancels any running EVM operation. This may be called concurrently and
// it's safe to be called multiple times.
func (evm *EVM) Cancel() {
	atomic.StoreInt32(&evm.abort, 1)
}

// Cancelled returns true if Cancel has been called
func (evm *EVM) Cancelled() bool {
	return atomic.LoadInt32(&evm.abort) == 1
}

// Interpreter returns the current interpreter
func (evm *EVM) Interpreter() *EVMInterpreter {
	return evm.interpreter
}

// Call executes the contract associated with the addr with the given input as
// parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
func (evm *EVM) Call(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	if value.Sign() != 0 && !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}
	snapshot := evm.StateDB.Snapshot()
	p, isPrecompile := evm.precompile(addr)

	if !evm.StateDB.Exist(addr) {
		if !isPrecompile && evm.chainRules.IsEIP158 && value.Sign() == 0 {
			// Calling a non existing account, don't do anything, but ping the tracer
			if evm.Config.Debug {
				if evm.depth == 0 {
					evm.Config.Tracer.CaptureStart(evm, caller.Address(), addr, false, input, gas, value)
					evm.Config.Tracer.CaptureEnd(ret, 0, nil)
				} else {
					evm.Config.Tracer.CaptureEnter(CALL, caller.Address(), addr, input, gas, value)
					evm.Config.Tracer.CaptureExit(ret, 0, nil)
				}
			}
			return nil, gas, nil
		}
		evm.StateDB.CreateAccount(addr)
	}
	evm.Context.Transfer(evm.StateDB, caller.Address(), addr, value)

	// Capture the tracer start/end events in debug mode
	if evm.Config.Debug {
		if evm.depth == 0 {
			evm.Config.Tracer.CaptureStart(evm, caller.Address(), addr, false, input, gas, value)
			defer func(startGas uint64) { // Lazy evaluation of the parameters
				evm.Config.Tracer.CaptureEnd(ret, startGas-gas, err)
			}(gas)
		} else {
			// Handle tracer events for entering and exiting a call frame
			evm.Config.Tracer.CaptureEnter(CALL, caller.Address(), addr, input, gas, value)
			defer func(startGas uint64) {
				evm.Config.Tracer.CaptureExit(ret, startGas-gas, err)
			}(gas)
		}
	}

	if isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas)
	} else {
		// Initialise a new contract and set the code that is to be used by the EVM.
		// The contract is a scoped environment for this execution context only.
		code := evm.StateDB.GetCode(addr)
		if len(code) == 0 {
			ret, err = nil, nil // gas is unchanged
		} else {
			executable := true
			currentProposlaNumber := evm.StateDB.GetProposalNumber(addr)
			if currentProposlaNumber != 0 {
				currentState := evm.StateDB.GetProposal(addr, currentProposlaNumber).CurrentState
				if currentState != types.ChangesApplied && currentState != types.ProposalRejected {

					ret, err, executable = nil, ErrNotExecutable, false
				}
			}

			if executable {

				addrCopy := addr
				// If the account has no code, we can abort here
				// The depth-check is already done, and precompiles handled above
				contract := NewContract(caller, AccountRef(addrCopy), value, gas)
				contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), code)
				ret, err = evm.interpreter.Run(contract, input, false)
				gas = contract.Gas
			}

		}
	}
	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			gas = 0
		}
		// TODO: consider clearing up unused snapshots:
		//} else {
		//	evm.StateDB.DiscardSnapshot(snapshot)
	}
	return ret, gas, err
}

// CallCode executes the contract associated with the addr with the given input
// as parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
//
// CallCode differs from Call in the sense that it executes the given address'
// code with the caller as context.
func (evm *EVM) CallCode(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	// Note although it's noop to transfer X ether to caller itself. But
	// if caller doesn't have enough balance, it would be an error to allow
	// over-charging itself. So the check here is necessary.
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}
	var snapshot = evm.StateDB.Snapshot()

	// Invoke tracer hooks that signal entering/exiting a call frame
	if evm.Config.Debug {
		evm.Config.Tracer.CaptureEnter(CALLCODE, caller.Address(), addr, input, gas, value)
		defer func(startGas uint64) {
			evm.Config.Tracer.CaptureExit(ret, startGas-gas, err)
		}(gas)
	}

	// It is allowed to call precompiles, even via delegatecall
	if p, isPrecompile := evm.precompile(addr); isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas)
	} else {
		addrCopy := addr
		// Initialise a new contract and set the code that is to be used by the EVM.
		// The contract is a scoped environment for this execution context only.
		contract := NewContract(caller, AccountRef(caller.Address()), value, gas)
		contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), evm.StateDB.GetCode(addrCopy))
		ret, err = evm.interpreter.Run(contract, input, false)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			gas = 0
		}
	}
	return ret, gas, err
}

// DelegateCall executes the contract associated with the addr with the given input
// as parameters. It reverses the state in case of an execution error.
//
// DelegateCall differs from CallCode in the sense that it executes the given address'
// code with the caller as context and the caller is set to the caller of the caller.
func (evm *EVM) DelegateCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	var snapshot = evm.StateDB.Snapshot()

	// Invoke tracer hooks that signal entering/exiting a call frame
	if evm.Config.Debug {
		evm.Config.Tracer.CaptureEnter(DELEGATECALL, caller.Address(), addr, input, gas, nil)
		defer func(startGas uint64) {
			evm.Config.Tracer.CaptureExit(ret, startGas-gas, err)
		}(gas)
	}

	// It is allowed to call precompiles, even via delegatecall
	if p, isPrecompile := evm.precompile(addr); isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas)
	} else {
		addrCopy := addr
		// Initialise a new contract and make initialise the delegate values
		contract := NewContract(caller, AccountRef(caller.Address()), nil, gas).AsDelegate()
		contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), evm.StateDB.GetCode(addrCopy))
		ret, err = evm.interpreter.Run(contract, input, false)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			gas = 0
		}
	}
	return ret, gas, err
}

// StaticCall executes the contract associated with the addr with the given input
// as parameters while disallowing any modifications to the state during the call.
// Opcodes that attempt to perform such modifications will result in exceptions
// instead of performing the modifications.
func (evm *EVM) StaticCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// We take a snapshot here. This is a bit counter-intuitive, and could probably be skipped.
	// However, even a staticcall is considered a 'touch'. On mainnet, static calls were introduced
	// after all empty accounts were deleted, so this is not required. However, if we omit this,
	// then certain tests start failing; stRevertTest/RevertPrecompiledTouchExactOOG.json.
	// We could change this, but for now it's left for legacy reasons
	var snapshot = evm.StateDB.Snapshot()

	// We do an AddBalance of zero here, just in order to trigger a touch.
	// This doesn't matter on Mainnet, where all empties are gone at the time of Byzantium,
	// but is the correct thing to do and matters on other networks, in tests, and potential
	// future scenarios
	evm.StateDB.AddBalance(addr, big0)

	// Invoke tracer hooks that signal entering/exiting a call frame
	if evm.Config.Debug {
		evm.Config.Tracer.CaptureEnter(STATICCALL, caller.Address(), addr, input, gas, nil)
		defer func(startGas uint64) {
			evm.Config.Tracer.CaptureExit(ret, startGas-gas, err)
		}(gas)
	}

	if p, isPrecompile := evm.precompile(addr); isPrecompile {
		ret, gas, err = RunPrecompiledContract(p, input, gas)
	} else {
		// At this point, we use a copy of address. If we don't, the go compiler will
		// leak the 'contract' to the outer scope, and make allocation for 'contract'
		// even if the actual execution ends on RunPrecompiled above.
		addrCopy := addr
		// Initialise a new contract and set the code that is to be used by the EVM.
		// The contract is a scoped environment for this execution context only.
		contract := NewContract(caller, AccountRef(addrCopy), new(big.Int), gas)
		contract.SetCallCode(&addrCopy, evm.StateDB.GetCodeHash(addrCopy), evm.StateDB.GetCode(addrCopy))
		// When an error was returned by the EVM or when setting the creation code
		// above we revert to the snapshot and consume any gas remaining. Additionally
		// when we're in Homestead this also counts for code storage gas errors.
		ret, err = evm.interpreter.Run(contract, input, true)
		gas = contract.Gas
	}
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			gas = 0
		}
	}
	return ret, gas, err
}

type codeAndHash struct {
	code []byte
	hash common.Hash
}

func (c *codeAndHash) Hash() common.Hash {
	if c.hash == (common.Hash{}) {
		c.hash = crypto.Keccak256Hash(c.code)
	}
	return c.hash
}

// create creates a new contract using code as deployment code.
func (evm *EVM) create(caller ContractRef, codeAndHash *codeAndHash, gas uint64, value *big.Int, address common.Address, typ OpCode) ([]byte, common.Address, uint64, error) {
	// Depth check execution. Fail if we're trying to execute above the
	// limit.
	if evm.depth > int(params.CallCreateDepth) {
		return nil, common.Address{}, gas, ErrDepth
	}
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, common.Address{}, gas, ErrInsufficientBalance
	}
	nonce := evm.StateDB.GetNonce(caller.Address())
	if nonce+1 < nonce {
		return nil, common.Address{}, gas, ErrNonceUintOverflow
	}
	evm.StateDB.SetNonce(caller.Address(), nonce+1)
	// We add this to the access list _before_ taking a snapshot. Even if the creation fails,
	// the access-list change should not be rolled back
	if evm.chainRules.IsBerlin {
		evm.StateDB.AddAddressToAccessList(address)
	}
	// Ensure there's no existing contract already at the designated address
	contractHash := evm.StateDB.GetCodeHash(address)
	if evm.StateDB.GetNonce(address) != 0 || (contractHash != (common.Hash{}) && contractHash != emptyCodeHash) {
		return nil, common.Address{}, 0, ErrContractAddressCollision
	}
	// Create a new account on the state
	snapshot := evm.StateDB.Snapshot()
	evm.StateDB.CreateAccount(address)
	if evm.chainRules.IsEIP158 {
		evm.StateDB.SetNonce(address, 1)
	}
	evm.Context.Transfer(evm.StateDB, caller.Address(), address, value)

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, AccountRef(address), value, gas)
	contract.SetCodeOptionalHash(&address, codeAndHash)

	if evm.Config.Debug {
		if evm.depth == 0 {
			evm.Config.Tracer.CaptureStart(evm, caller.Address(), address, true, codeAndHash.code, gas, value)
		} else {
			evm.Config.Tracer.CaptureEnter(typ, caller.Address(), address, codeAndHash.code, gas, value)
		}
	}

	evm.StateDB.SetProposalNumber(address, 0)
	evm.StateDB.SetVotesNeededToWin(address, 0)
	evm.StateDB.SetStakeholders(address, make([]common.Address, 0))

	ret, err := evm.interpreter.Run(contract, nil, false)

	// Check whether the max code size has been exceeded, assign err if the case.
	if err == nil && evm.chainRules.IsEIP158 && len(ret) > params.MaxCodeSize {
		err = ErrMaxCodeSizeExceeded
	}

	// Reject code starting with 0xEF if EIP-3541 is enabled.
	if err == nil && len(ret) >= 1 && ret[0] == 0xEF && evm.chainRules.IsLondon {
		err = ErrInvalidCode
	}

	// if the contract creation ran successfully and no errors were returned
	// calculate the gas required to store the code. If the code could not
	// be stored due to not enough gas set an error and let it be handled
	// by the error checking condition below.
	if err == nil {
		createDataGas := uint64(len(ret)) * params.CreateDataGas
		if contract.UseGas(createDataGas) {
			evm.StateDB.SetCode(address, ret)
		} else {
			err = ErrCodeStoreOutOfGas
		}
	}

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if err != nil && (evm.chainRules.IsHomestead || err != ErrCodeStoreOutOfGas) {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}

	if evm.Config.Debug {
		if evm.depth == 0 {
			evm.Config.Tracer.CaptureEnd(ret, gas-contract.Gas, err)
		} else {
			evm.Config.Tracer.CaptureExit(ret, gas-contract.Gas, err)
		}
	}
	return ret, address, contract.Gas, err
}

func (evm *EVM) updatableCreate(caller ContractRef, codeAndHash *codeAndHash, gas uint64, value *big.Int, address common.Address, stakeholders []common.Address, votesNeededToWin uint64, typ OpCode) ([]byte, common.Address, uint64, error) {
	// Depth check execution. Fail if we're trying to execute above the
	// limit.
	if evm.depth > int(params.CallCreateDepth) {
		return nil, common.Address{}, gas, ErrDepth
	}
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, common.Address{}, gas, ErrInsufficientBalance
	}
	nonce := evm.StateDB.GetNonce(caller.Address())
	if nonce+1 < nonce {
		return nil, common.Address{}, gas, ErrNonceUintOverflow
	}
	evm.StateDB.SetNonce(caller.Address(), nonce+1)
	// We add this to the access list _before_ taking a snapshot. Even if the creation fails,
	// the access-list change should not be rolled back
	if evm.chainRules.IsBerlin {
		evm.StateDB.AddAddressToAccessList(address)
	}
	// Ensure there's no existing contract already at the designated address
	contractHash := evm.StateDB.GetCodeHash(address)
	if evm.StateDB.GetNonce(address) != 0 || (contractHash != (common.Hash{}) && contractHash != emptyCodeHash) {
		return nil, common.Address{}, 0, ErrContractAddressCollision
	}

	if votesNeededToWin > uint64(len(stakeholders)) {
		return nil, common.Address{}, 0, ErrInvalidProposal
	}
	// Create a new account on the state
	snapshot := evm.StateDB.Snapshot()
	evm.StateDB.CreateAccount(address)
	if evm.chainRules.IsEIP158 {
		evm.StateDB.SetNonce(address, 1)
	}
	evm.Context.Transfer(evm.StateDB, caller.Address(), address, value)

	evm.StateDB.SetProposalNumber(address, 0)
	evm.StateDB.SetVotesNeededToWin(address, votesNeededToWin)
	evm.StateDB.SetStakeholders(address, stakeholders)

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, AccountRef(address), value, gas)
	contract.SetCodeOptionalHash(&address, codeAndHash)

	if evm.Config.Debug {
		if evm.depth == 0 {
			evm.Config.Tracer.CaptureStart(evm, caller.Address(), address, true, codeAndHash.code, gas, value)
		} else {
			evm.Config.Tracer.CaptureEnter(typ, caller.Address(), address, codeAndHash.code, gas, value)
		}
	}

	ret, err := evm.interpreter.Run(contract, nil, false)

	// Check whether the max code size has been exceeded, assign err if the case.
	if err == nil && evm.chainRules.IsEIP158 && len(ret) > params.MaxCodeSize {
		err = ErrMaxCodeSizeExceeded
	}

	// Reject code starting with 0xEF if EIP-3541 is enabled.
	if err == nil && len(ret) >= 1 && ret[0] == 0xEF && evm.chainRules.IsLondon {
		err = ErrInvalidCode
	}

	// if the contract creation ran successfully and no errors were returned
	// calculate the gas required to store the code. If the code could not
	// be stored due to not enough gas set an error and let it be handled
	// by the error checking condition below.
	if err == nil {
		createDataGas := uint64(len(ret)) * params.CreateDataGas
		if contract.UseGas(createDataGas) {
			evm.StateDB.SetCode(address, ret)
		} else {
			err = ErrCodeStoreOutOfGas
		}
	}

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if err != nil && (evm.chainRules.IsHomestead || err != ErrCodeStoreOutOfGas) {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != ErrExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}

	if evm.Config.Debug {
		if evm.depth == 0 {
			evm.Config.Tracer.CaptureEnd(ret, gas-contract.Gas, err)
		} else {
			evm.Config.Tracer.CaptureExit(ret, gas-contract.Gas, err)
		}
	}
	return ret, address, contract.Gas, err

}

// Create creates a new contract using code as deployment code.
func (evm *EVM) Create(caller ContractRef, code []byte, gas uint64, value *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	contractAddr = crypto.CreateAddress(caller.Address(), evm.StateDB.GetNonce(caller.Address()))
	return evm.create(caller, &codeAndHash{code: code}, gas, value, contractAddr, CREATE)
}

// Create2 creates a new contract using code as deployment code.
//
// The different between Create2 with Create is Create2 uses keccak256(0xff ++ msg.sender ++ salt ++ keccak256(init_code))[12:]
// instead of the usual sender-and-nonce-hash as the address where the contract is initialized at.
func (evm *EVM) Create2(caller ContractRef, code []byte, gas uint64, endowment *big.Int, salt *uint256.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	codeAndHash := &codeAndHash{code: code}
	contractAddr = crypto.CreateAddress2(caller.Address(), salt.Bytes32(), codeAndHash.Hash().Bytes())
	return evm.create(caller, codeAndHash, gas, endowment, contractAddr, CREATE2)
}

func (evm *EVM) UpdatableCreate(caller ContractRef, code []byte, gas uint64, value *big.Int, stakeholders []common.Address, votesNeededToWin uint64) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	contractAddr = crypto.CreateAddress(caller.Address(), evm.StateDB.GetNonce(caller.Address()))
	return evm.updatableCreate(caller, &codeAndHash{code: code}, gas, value, contractAddr, stakeholders, votesNeededToWin, CREATE)
}

func IsStakeholder(addr common.Address, stakeholders []common.Address) bool {

	for _, stakeholder := range stakeholders {

		if bytes.Equal(stakeholder.Bytes(), addr.Bytes()) {
			return true
		}
	}

	return false
}

func (evm *EVM) update(caller ContractRef, codeAndHash *codeAndHash, gas uint64, value *big.Int, address common.Address, stakeholders []common.Address, votesNeededToWin uint64, proposalNumber uint64, reorgList []types.ReorgInfo, dataTypes []types.DataType) ([]byte, uint64, error) {
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}

	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value) {
		return nil, gas, ErrInsufficientBalance
	}

	nonce := evm.StateDB.GetNonce(caller.Address())
	if nonce+1 < nonce {
		return nil, gas, ErrNonceUintOverflow
	}

	evm.StateDB.SetNonce(caller.Address(), nonce+1)
	// We add this to the access list _before_ taking a snapshot. Even if the creation fails,
	// the access-list change should not be rolled back
	if evm.chainRules.IsBerlin {
		evm.StateDB.AddAddressToAccessList(address)
	}

	if !evm.StateDB.Exist(address) {
		return nil, 0, ErrCodeNotFound
	}

	stkhldrs := evm.StateDB.GetStakeholders(address)
	if !IsStakeholder(caller.Address(), stkhldrs) {
		return nil, 0, ErrNotStakeholder
	}

	currentProposalNumber := evm.StateDB.GetProposalNumber(address)
	var currentState uint8
	if currentProposalNumber == 0 {
		currentState = types.ChangesApplied
	} else {
		currentState = evm.StateDB.GetProposal(address, currentProposalNumber).CurrentState
	}

	if proposalNumber > currentProposalNumber+1 || proposalNumber < currentProposalNumber {
		return nil, 0, ErrInvalidProposalNumber
	} else if currentProposalNumber == proposalNumber {
		if currentState == types.ProposalPassed {

			currentProposal := evm.StateDB.GetProposal(address, currentProposalNumber)

			if len(currentProposal.Stakeholders) != len(stakeholders) {
				return nil, 0, ErrDeploymentProposalMismatch
			}

			encountered := make(map[common.Address]bool)

			for _, stakeholder := range currentProposal.Stakeholders {
				encountered[stakeholder] = true
			}

			for _, stakeholder := range stakeholders {
				if encountered[stakeholder] != true {
					return nil, 0, ErrDeploymentProposalMismatch
				}
			}

			if !bytes.Equal(currentProposal.ProposedCodeHash, crypto.Keccak256(codeAndHash.code)) || currentProposal.VotesNeededToWin != votesNeededToWin {
				return nil, 0, ErrDeploymentProposalMismatch
			}

			snapshot := evm.StateDB.Snapshot()

			evm.Context.Transfer(evm.StateDB, caller.Address(), address, value)

			// Initialise a new contract and set the code that is to be used by the EVM.
			// The contract is a scoped environment for this execution context only.
			contract := NewContract(caller, AccountRef(address), value, gas)
			contract.SetCodeOptionalHash(&address, codeAndHash)

			if evm.Config.Debug {
				if evm.depth == 0 {
					evm.Config.Tracer.CaptureStart(evm, caller.Address(), address, true, codeAndHash.code, gas, value)
				} else {
					evm.Config.Tracer.CaptureEnter(CREATE, caller.Address(), address, codeAndHash.code, gas, value)
				}
			}

			fmt.Println("Starting to print slots")
			slots := evm.StateDB.GetStorageAsMap(address)
			for key, val := range slots {
				fmt.Println(key.Hex())
				fmt.Println(val.Hex())
			}
			fmt.Println("Slot Printing over")
			reorganizer := NewStorageReorganizer(address, evm.StateDB)
			reorganizer.Init(slots, reorgList, dataTypes)

			var ret []byte
			var err error
			reorgErr := reorganizer.Reorganize()

			if reorgErr == nil {

				fmt.Println("No error in reorganizing")
				ret, err = evm.interpreter.Run(contract, nil, false)
			}

			if reorgErr != nil {

				err = reorgErr
			}
			// Check whether the max code size has been exceeded, assign err if the case.
			if err == nil && evm.chainRules.IsEIP158 && len(ret) > params.MaxCodeSize {
				err = ErrMaxCodeSizeExceeded
			}

			// Reject code starting with 0xEF if EIP-3541 is enabled.
			if err == nil && len(ret) >= 1 && ret[0] == 0xEF && evm.chainRules.IsLondon {
				err = ErrInvalidCode
			}

			// if the contract creation ran successfully and no errors were returned
			// calculate the gas required to store the code. If the code could not
			// be stored due to not enough gas set an error and let it be handled
			// by the error checking condition below.
			if err == nil {
				createDataGas := uint64(len(ret)) * params.CreateDataGas
				if contract.UseGas(createDataGas) {
					evm.StateDB.SetCode(address, ret)
					evm.StateDB.SetStakeholders(address, stakeholders)
					evm.StateDB.SetVotesNeededToWin(address, currentProposal.VotesNeededToWin)
					evm.StateDB.SetProposal(address, currentProposalNumber, types.Proposal{InFavourOf: currentProposal.InFavourOf, Against: currentProposal.Against, VotesNeededToWin: currentProposal.VotesNeededToWin, ProposedCodeHash: currentProposal.ProposedCodeHash, Stakeholders: currentProposal.Stakeholders, CurrentState: types.ChangesApplied})
					reorganizer.Commit()

				} else {
					err = ErrCodeStoreOutOfGas
				}
			}

			// When an error was returned by the EVM or when setting the creation code
			// above we revert to the snapshot and consume any gas remaining. Additionally
			// when we're in homestead this also counts for code storage gas errors.
			if err != nil && (evm.chainRules.IsHomestead || err != ErrCodeStoreOutOfGas) {
				evm.StateDB.RevertToSnapshot(snapshot)
				if err != ErrExecutionReverted {
					contract.UseGas(contract.Gas)
				}
			}

			if evm.Config.Debug {
				if evm.depth == 0 {
					evm.Config.Tracer.CaptureEnd(ret, gas-contract.Gas, err)
				} else {
					evm.Config.Tracer.CaptureExit(ret, gas-contract.Gas, err)
				}
			}
			return ret, contract.Gas, err

		} else {

			return nil, 0, ErrChangeApplicationNotPossible
		}
	} else {
		if currentState == types.ChangesApplied {
			if gas < 21000*3 {
				return nil, 0, ErrOutOfGas
			} else {
				gas -= 21000 * 3
			}
			evm.Context.Transfer(evm.StateDB, caller.Address(), address, value)
			evm.StateDB.SetProposalNumber(address, proposalNumber)
			evm.StateDB.SetProposal(address, proposalNumber, types.Proposal{InFavourOf: 0, Against: 0, VotesNeededToWin: votesNeededToWin, Stakeholders: stakeholders, ProposedCodeHash: crypto.Keccak256(codeAndHash.code), CurrentState: types.AcceptingVotes, ReorgInfoList: reorgList, DataTypeList: dataTypes})
			return nil, gas, nil
		} else {
			return nil, 0, ErrChangeApplicationNotPossible
		}
	}

}

func (evm *EVM) Update(caller ContractRef, code []byte, gas uint64, value *big.Int, address common.Address, stakeholders []common.Address, votesNeededToWin uint64, proposalNumber uint64, reorgList []types.ReorgInfo, dataTypes []types.DataType) (ret []byte, leftOverGas uint64, err error) {
	return evm.update(caller, &codeAndHash{code: code}, gas, value, address, stakeholders, votesNeededToWin, proposalNumber, reorgList, dataTypes)
}

func (evm *EVM) ApproveProposal(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int, stakeholders []common.Address, votesNeededToWin uint64, proposalNumber uint64, reorgInfos []types.ReorgInfo, dataTypes []types.DataType) (ret []byte, leftOverGas uint64, err error) {

	nonce := evm.StateDB.GetNonce(caller.Address())
	if nonce+1 < nonce {
		return nil, gas, ErrNonceUintOverflow
	}

	evm.StateDB.SetNonce(caller.Address(), nonce+1)

	stkhldrs := evm.StateDB.GetStakeholders(addr)
	if !IsStakeholder(caller.Address(), stkhldrs) {

		return nil, 0, ErrNotStakeholder
	}

	currentProposalNumber := evm.StateDB.GetProposalNumber(addr)

	if proposalNumber != currentProposalNumber || currentProposalNumber == 0 {
		return nil, 0, ErrInvalidProposalNumber
	}

	currentProposal := evm.StateDB.GetProposal(addr, currentProposalNumber)

	if currentProposal.CurrentState != types.AcceptingVotes {

		return nil, 0, ErrNotAcceptingVotes
	}

	if !evm.StateDB.GetVote(addr, caller.Address(), proposalNumber).Equals(types.Vote{}) {
		fmt.Println("Already Voted")
		return nil, 0, ErrDuplicateVote
	}
	if gas < 21000*3 {
		return nil, 0, ErrOutOfGas
	} else {
		gas -= 21000 * 3
	}
	currentProposal.InFavourOf++

	if types.EqualStakeholders(currentProposal.Stakeholders, stakeholders) && types.EqualReorgInfoList(currentProposal.ReorgInfoList, reorgInfos) && types.EqualDataTypes(currentProposal.DataTypeList, dataTypes) {
		fmt.Println("parameters Equal")
	} else {
		fmt.Println("Parameters not equal")
	}

	if evm.StateDB.GetVotesNeededToWin(addr) <= currentProposal.InFavourOf {
		currentProposal.CurrentState = types.ProposalPassed
		evm.StateDB.SetProposal(addr, currentProposalNumber, currentProposal)
	} else {
		evm.StateDB.SetProposal(addr, currentProposalNumber, currentProposal)
	}
	evm.StateDB.SetVote(addr, currentProposalNumber, caller.Address(), types.Vote{Type: 1, TxHash: evm.StateDB.GetTxHash()})
	return nil, gas, nil
}

func (evm *EVM) RejectProposal(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int, stakeholders []common.Address, votesNeededToWin uint64, proposalNumber uint64, reorgInfos []types.ReorgInfo, dataTypes []types.DataType) (ret []byte, leftOverGas uint64, err error) {

	nonce := evm.StateDB.GetNonce(caller.Address())
	if nonce+1 < nonce {
		return nil, gas, ErrNonceUintOverflow
	}

	evm.StateDB.SetNonce(caller.Address(), nonce+1)

	stkhldrs := evm.StateDB.GetStakeholders(addr)
	if !IsStakeholder(caller.Address(), stkhldrs) {

		return nil, 0, ErrNotStakeholder
	}

	currentProposalNumber := evm.StateDB.GetProposalNumber(addr)

	if proposalNumber != currentProposalNumber || currentProposalNumber == 0 {
		return nil, 0, ErrInvalidProposalNumber
	}

	currentProposal := evm.StateDB.GetProposal(addr, currentProposalNumber)

	if currentProposal.CurrentState != types.AcceptingVotes {

		return nil, 0, ErrNotAcceptingVotes
	}

	if !evm.StateDB.GetVote(addr, caller.Address(), proposalNumber).Equals(types.Vote{}) {
		fmt.Println("Already Voted")
		return nil, 0, ErrDuplicateVote
	}
	if gas < 21000*3 {
		return nil, 0, ErrOutOfGas
	} else {
		gas -= 21000 * 3
	}
	currentProposal.Against++

	if types.EqualStakeholders(currentProposal.Stakeholders, stakeholders) && types.EqualReorgInfoList(currentProposal.ReorgInfoList, reorgInfos) && types.EqualDataTypes(currentProposal.DataTypeList, dataTypes) {
		fmt.Println("parameters Equal")
	} else {
		fmt.Println("Parameters not equal")
	}

	if uint64(len(evm.StateDB.GetStakeholders(addr)))-evm.StateDB.GetVotesNeededToWin(addr)+1 <= currentProposal.Against {
		currentProposal.CurrentState = types.ProposalRejected
		evm.StateDB.SetProposal(addr, currentProposalNumber, currentProposal)
	} else {
		evm.StateDB.SetProposal(addr, currentProposalNumber, currentProposal)
	}
	evm.StateDB.SetVote(addr, currentProposalNumber, caller.Address(), types.Vote{Type: 0, TxHash: evm.StateDB.GetTxHash()})
	return nil, gas, nil
}

// ChainConfig returns the environment's chain configuration
func (evm *EVM) ChainConfig() *params.ChainConfig { return evm.chainConfig }
