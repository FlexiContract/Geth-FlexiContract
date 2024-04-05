package vm

import (
	"errors"

	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

type StorageReorganizer struct {
	state           StateDB
	commitedStorage map[common.Hash]common.Hash
	modifiedStorage map[common.Hash]common.Hash
	reorgMessges    []types.ReorgInfo
	dataTypes       map[string]types.DataType
	addr            common.Address
}

func (s *StorageReorganizer) Init(currentState map[common.Hash]common.Hash, reorganizationMessages []types.ReorgInfo, dataTypes []types.DataType) {

	s.commitedStorage = currentState
	s.reorgMessges = reorganizationMessages

	for _, dataType := range dataTypes {

		s.dataTypes[dataType.Type] = dataType
	}
}

func (s *StorageReorganizer) GetCommitedState(key common.Hash) common.Hash {

	if _, ok := s.commitedStorage[key]; !ok {

		return common.Hash{}
	}

	return s.commitedStorage[key]

}

func (s *StorageReorganizer) GetModifiedState(key common.Hash) common.Hash {

	if _, ok := s.modifiedStorage[key]; !ok {

		return common.Hash{}
	}

	return s.modifiedStorage[key]

}

func (s *StorageReorganizer) SetModifiedState(key, val common.Hash) {

	s.modifiedStorage[key] = val
}

func (s *StorageReorganizer) IsNested(dataType string) (bool, error) {

	if dataType, found := s.dataTypes[dataType]; found {

		if dataType.Base == "" {

			return false, nil

		} else {

			return true, nil
		}

	} else {

		return false, errors.New("Type not found")
	}
}

func (s *StorageReorganizer) IsFlat(dataType string) (bool, error) {

	if dataType, found := s.dataTypes[dataType]; found {

		if dataType.Base == "" {

			return true, nil

		} else {

			return false, nil
		}

	} else {

		return false, errors.New("Type not found")
	}
}

func (s *StorageReorganizer) IsEncodingInplace(dataType string) (bool, error) {

	if data, found := s.dataTypes[dataType]; found {

		if data.Encoding == "inplace" {

			return true, nil

		} else {

			return false, nil
		}

	} else {

		return false, errors.New("Type not found")
	}
}

func (s *StorageReorganizer) IsEncodingDynamicArray(dataType string) (bool, error) {

	if data, found := s.dataTypes[dataType]; found {

		if data.Encoding == "dynamic_array" {

			return true, nil

		} else {

			return false, nil
		}

	} else {

		return false, errors.New("Type not found")
	}
}

func (s *StorageReorganizer) IsEncodingBytes(dataType string) (bool, error) {

	if data, found := s.dataTypes[dataType]; found {

		if data.Encoding == "bytes" {

			return true, nil

		} else {

			return false, nil
		}

	} else {

		return false, errors.New("Type not found")
	}
}

func (s *StorageReorganizer) GetNumberOfBytes(typeName string) (uint64, error) {

	if dataType, found := s.dataTypes[typeName]; found {

		return dataType.NumberOfBytes, nil

	} else {

		return 0, errors.New("Type not found")
	}
}

func (s *StorageReorganizer) Reorganize() error {

	for _, reorgMessage := range s.reorgMessges {

		if isInplace, err := s.IsEncodingInplace(reorgMessage.Type); err != nil {

			return err

		} else if isInplace {

			err := s.ReorganizeInplace(reorgMessage)

			if err != nil {

				return err
			}

		} else if isDynamicArray, err := s.IsEncodingDynamicArray(reorgMessage.Type); err != nil {

			return err

		} else if isDynamicArray {

			err := s.ReorganizeDynamicArray(reorgMessage)

			if err != nil {

				return err
			}

		} else if isBytes, err := s.IsEncodingBytes(reorgMessage.Type); err != nil {

			return err

		} else if isBytes {

			err := s.ReorganizeBytes(reorgMessage)

			if err != nil {

				return err
			}

		} else {
			fmt.Println("Throwing error in reorganize")
			return errors.New("Not implemented yet")
		}
	}

	return nil

}

func (s *StorageReorganizer) ExtractUntilInplace(typeName string) (string, string, bool, error) {

	curType := typeName

	for {

		if dataType, found := s.dataTypes[curType]; found {

			if dataType.Base == "" {

				return dataType.Type, dataType.Encoding, false, nil

			} else {

				if dataType.Encoding != "inplace" {

					return dataType.Type, dataType.Encoding, true, nil

				} else {

					curType = dataType.Base
				}
			}

		} else {

			return "", "", false, errors.New("Type not found")
		}
	}
}

func (s *StorageReorganizer) ReorganizeInplace(reorgMessage types.ReorgInfo) error {

	numberOfBytes, err := s.GetNumberOfBytes(reorgMessage.Type)

	if err != nil {

		return err
	}

	var prevOffset, newOffset uint64

	prevSlotNumber := reorgMessage.PrevSlot.Big()
	newSlotNumber := reorgMessage.NewSlot.Big()

	for prevOffset, newOffset = reorgMessage.PrevOffset, reorgMessage.NewOffset; prevOffset < numberOfBytes+reorgMessage.PrevOffset; prevOffset, newOffset = prevOffset+1, newOffset+1 {

		curOldSlotNumber := new(big.Int).Add(new(big.Int).SetUint64(prevOffset/32), prevSlotNumber)

		curNewSlotNumber := new(big.Int).Add(new(big.Int).SetUint64(newOffset/32), newSlotNumber)

		prevSlot := s.GetCommitedState(common.BytesToHash(curOldSlotNumber.Bytes()))
		newSlot := s.GetModifiedState(common.BytesToHash(curNewSlotNumber.Bytes()))

		newSlot[31-(newOffset%32)] = prevSlot[31-(prevOffset%32)]

		s.SetModifiedState(common.BytesToHash(curNewSlotNumber.Bytes()), newSlot)

	}

	typeName, encoding, found, err := s.ExtractUntilInplace(reorgMessage.Type)

	if err != nil {

		return err
	}

	if found == true {

		if encoding == "dynamic_array" {

			for i := 0; i < int(numberOfBytes/32); i++ {

				curOldSlotNumber := new(big.Int).Add(new(big.Int).SetInt64(int64(i)), prevSlotNumber)

				curNewSlotNumber := new(big.Int).Add(new(big.Int).SetInt64(int64(i)), newSlotNumber)

				err := s.ReorganizeDynamicArray(types.ReorgInfo{
					Type:       typeName,
					PrevSlot:   common.BytesToHash(curOldSlotNumber.Bytes()),
					NewSlot:    common.BytesToHash(curNewSlotNumber.Bytes()),
					PrevOffset: 0,
					NewOffset:  0,
				})

				if err != nil {

					return err
				}
			}

		} else if encoding == "bytes" {

			for i := 0; i < int(numberOfBytes/32); i++ {

				curOldSlotNumber := new(big.Int).Add(new(big.Int).SetInt64(int64(i)), prevSlotNumber)

				curNewSlotNumber := new(big.Int).Add(new(big.Int).SetInt64(int64(i)), newSlotNumber)

				err := s.ReorganizeBytes(types.ReorgInfo{
					Type:       typeName,
					PrevSlot:   common.BytesToHash(curOldSlotNumber.Bytes()),
					NewSlot:    common.BytesToHash(curNewSlotNumber.Bytes()),
					PrevOffset: 0,
					NewOffset:  0,
				})

				if err != nil {

					return err
				}
			}

		} else {
			fmt.Println("Throwing error in ReorgInplace")
			return errors.New("Not implemented yet")
		}

		return nil

	} else {

		return nil
	}
}

func (s *StorageReorganizer) ReorganizeDynamicArray(reorgMessage types.ReorgInfo) error {

	numberOfBytes, err := s.GetNumberOfBytes(reorgMessage.Type)

	if err != nil {

		return err
	}

	prevSlot := s.GetCommitedState(reorgMessage.PrevSlot)
	newSlot := s.GetModifiedState(reorgMessage.NewSlot)

	for i := 0; i < int(numberOfBytes); i++ {

		newSlot[i] = prevSlot[i]
	}

	s.SetModifiedState(reorgMessage.NewSlot, newSlot)

	prevDataSlot := common.BytesToHash(crypto.Keccak256(reorgMessage.PrevSlot[:]))
	newDataSlot := common.BytesToHash(crypto.Keccak256(reorgMessage.NewSlot[:]))

	dataType, _ := s.dataTypes[reorgMessage.Type]

	numberOfElements := prevSlot.Big()

	if numberOfElements.Cmp(big.NewInt(0)) == 0 {

		return nil
	}

	if isInplace, err := s.IsEncodingInplace(dataType.Base); err != nil {

		return err

	} else if isInplace {

		if isNested, err := s.IsNested(dataType.Base); err != nil {

			return err

		} else if isNested {

			sizeOfElement, err := s.GetNumberOfBytes(dataType.Base)

			if err != nil {

				return err
			}

			numberOfSlotsPerElement := new(big.Int).SetUint64(sizeOfElement / 32)

			for i := big.NewInt(0); i.Cmp(numberOfElements) < 0; i.Add(i, big.NewInt(1)) {

				err := s.ReorganizeInplace(types.ReorgInfo{
					PrevSlot:   common.BigToHash(new(big.Int).Add(prevDataSlot.Big(), new(big.Int).Mul(numberOfSlotsPerElement, i))),
					NewSlot:    common.BigToHash(new(big.Int).Add(newDataSlot.Big(), new(big.Int).Mul(numberOfSlotsPerElement, i))),
					PrevOffset: 0,
					NewOffset:  0,
					Type:       dataType.Base,
				})

				if err != nil {

					return err
				}
			}

		} else if isFlat, err := s.IsFlat(dataType.Base); err != nil {

			return err

		} else if isFlat {

			sizeOfElement, err := s.GetNumberOfBytes(dataType.Base)

			if err != nil {

				return err
			}

			numberOfElementsPerSlot := new(big.Int).SetUint64(32 / sizeOfElement)

			numberOfSlots := big.NewInt(0)
			remainder := big.NewInt(0)

			numberOfSlots.DivMod(numberOfElements, numberOfElementsPerSlot, remainder)

			if remainder.Cmp(big.NewInt(0)) > 0 {

				numberOfSlots.Add(numberOfSlots, big.NewInt(1))
			}

			for i := big.NewInt(0); i.Cmp(numberOfSlots) < 0; i.Add(i, big.NewInt(1)) {

				for j := uint64(0); j < 32/sizeOfElement; j++ {

					err := s.ReorganizeInplace(types.ReorgInfo{
						PrevSlot:   common.BigToHash(new(big.Int).Add(prevDataSlot.Big(), i)),
						NewSlot:    common.BigToHash(new(big.Int).Add(newDataSlot.Big(), i)),
						PrevOffset: j * sizeOfElement,
						NewOffset:  j * sizeOfElement,
						Type:       dataType.Base,
					})

					if err != nil {

						return err
					}
				}
			}

		} else {

			return errors.New("Not Implemented Yet....")
		}

	} else if isDynamicArray, err := s.IsEncodingDynamicArray(dataType.Base); err != nil {

		return err

	} else if isDynamicArray {

		for i := big.NewInt(0); i.Cmp(numberOfElements) < 0; i.Add(i, big.NewInt(1)) {

			err := s.ReorganizeInplace(types.ReorgInfo{
				PrevSlot:   common.BigToHash(new(big.Int).Add(prevDataSlot.Big(), i)),
				NewSlot:    common.BigToHash(new(big.Int).Add(newDataSlot.Big(), i)),
				PrevOffset: 0,
				NewOffset:  0,
				Type:       dataType.Base,
			})

			if err != nil {

				return err
			}
		}

	} else if isBytes, err := s.IsEncodingBytes(dataType.Base); err != nil {

		return err

	} else if isBytes {

		for i := big.NewInt(0); i.Cmp(numberOfElements) < 0; i.Add(i, big.NewInt(1)) {

			err := s.ReorganizeInplace(types.ReorgInfo{
				PrevSlot:   common.BigToHash(new(big.Int).Add(prevDataSlot.Big(), i)),
				NewSlot:    common.BigToHash(new(big.Int).Add(newDataSlot.Big(), i)),
				PrevOffset: 0,
				NewOffset:  0,
				Type:       dataType.Base,
			})

			if err != nil {

				return err
			}
		}

	} else {

		return errors.New("Not Implemented Yet....")
	}

	return nil

}

func (s *StorageReorganizer) ReorganizeBytes(reorgMessage types.ReorgInfo) error {

	numberOfBytes, err := s.GetNumberOfBytes(reorgMessage.Type)

	if err != nil {

		return err
	}

	prevSlot := s.GetCommitedState(reorgMessage.PrevSlot)
	newSlot := s.GetModifiedState(reorgMessage.NewSlot)

	for i := 0; i < int(numberOfBytes); i++ {

		newSlot[i] = prevSlot[i]
	}

	s.SetModifiedState(reorgMessage.NewSlot, newSlot)

	prevDataSlot := common.BytesToHash(crypto.Keccak256(reorgMessage.PrevSlot[:]))
	newDataSlot := common.BytesToHash(crypto.Keccak256(reorgMessage.NewSlot[:]))

	if (prevSlot[31] & 1) != 0 {

		numberOfElements := new(big.Int).Div(new(big.Int).Sub(prevSlot.Big(), big.NewInt(1)), big.NewInt(2))
		numberOfSlots := big.NewInt(0)
		remainder := big.NewInt(0)
		numberOfSlots.DivMod(numberOfElements, big.NewInt(32), remainder)

		if remainder.Cmp(big.NewInt(0)) > 0 {

			numberOfSlots.Add(numberOfSlots, big.NewInt(1))
		}

		for i := big.NewInt(0); i.Cmp(numberOfSlots) < 0; i.Add(i, big.NewInt(1)) {

			slotToBeCopiedFrom := common.BigToHash(new(big.Int).Add(prevDataSlot.Big(), i))
			slotToBeCopiedTo := common.BigToHash(new(big.Int).Add(newDataSlot.Big(), i))

			curPrevSlot := s.GetCommitedState(slotToBeCopiedFrom)
			curNewSlot := s.GetModifiedState(slotToBeCopiedTo)

			for j := 0; j < 32; j++ {

				curNewSlot[j] = curPrevSlot[j]
			}

			s.SetModifiedState(slotToBeCopiedTo, curNewSlot)

		}

	}

	return nil

}

func (s *StorageReorganizer) Commit() {

	fmt.Println(s.addr.Hex())

	keys := make([]common.Hash, 0)

	for key := range s.commitedStorage {
		keys = append(keys, key)
	}

	s.state.DeleteKeysFromStorage(s.addr, keys)

	for key, val := range s.modifiedStorage {

		fmt.Println(key.Hex())
		fmt.Println(val.Hex())

		if val != (common.Hash{}) {

			s.state.SetState(s.addr, key, val)
		}
	}
}

func NewStorageReorganizer(addr common.Address, state StateDB) *StorageReorganizer {
	return &StorageReorganizer{
		state:           state,
		commitedStorage: make(map[common.Hash]common.Hash),
		modifiedStorage: make(map[common.Hash]common.Hash),
		dataTypes:       make(map[string]types.DataType),
		addr:            addr,
	}
}
