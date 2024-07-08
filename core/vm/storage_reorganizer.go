package vm

import (
	"bytes"
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
	gas             uint64
}

func (s *StorageReorganizer) Init(currentState map[common.Hash]common.Hash, reorganizationMessages []types.ReorgInfo, dataTypes []types.DataType) error {

	s.commitedStorage = currentState
	s.reorgMessges = reorganizationMessages

	for _, dataType := range dataTypes {

		if s.gas < 10 {
			return errors.New("out of gas")
		}
		s.gas -= 10
		s.dataTypes[dataType.Type] = dataType
	}

	return nil
}

func (s *StorageReorganizer) GetCommitedState(key common.Hash) (common.Hash, error) {

	if s.gas < 5 {
		return common.Hash{}, errors.New("out of gas")
	}
	s.gas -= 5

	if _, ok := s.commitedStorage[key]; !ok {

		return common.Hash{}, nil
	}

	return s.commitedStorage[key], nil

}

func (s *StorageReorganizer) GetModifiedState(key common.Hash) (common.Hash, error) {

	if s.gas < 5 {
		return common.Hash{}, errors.New("out of gas")
	}
	s.gas -= 5

	if _, ok := s.modifiedStorage[key]; !ok {

		return common.Hash{}, nil
	}

	return s.modifiedStorage[key], nil

}

func (s *StorageReorganizer) SetModifiedState(key, val common.Hash) error {
	if s.gas < 5 {
		return errors.New("out of gas")
	}
	s.gas -= 5
	s.modifiedStorage[key] = val
	return nil
}

// function to check if data type is a struct
func (s *StorageReorganizer) IsStruct(dataType string) (bool, error) {

	if s.gas < 5 {
		return false, errors.New("out of gas")
	}
	s.gas -= 5

	if dataType, found := s.dataTypes[dataType]; found {

		if len(dataType.Members) == 0 {

			return false, nil

		} else {

			return true, nil
		}

	} else {

		return false, errors.New("Type not found")
	}
}

// function to check if a data type is nested. It is considered nested if there is a base or it has members(is a struct)
func (s *StorageReorganizer) IsNested(dataType string) (bool, error) {

	if s.gas < 5 {
		return false, errors.New("out of gas")
	}
	s.gas -= 5

	if dataType, found := s.dataTypes[dataType]; found {

		if dataType.Base == "" {

			if len(dataType.Members) == 0 {

				return false, nil
			} else {

				return true, nil
			}

		} else {

			return true, nil
		}

	} else {

		return false, errors.New("Type not found")
	}
}

// function to check if a data type is flat. It is considered flat
func (s *StorageReorganizer) IsFlat(dataType string) (bool, error) {

	if s.gas < 5 {
		return false, errors.New("out of gas")
	}
	s.gas -= 5

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

// function to check if the encoding of a data type is "inplace"
func (s *StorageReorganizer) IsEncodingInplace(dataType string) (bool, error) {

	if s.gas < 5 {
		return false, errors.New("out of gas")
	}
	s.gas -= 5

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

// function to check if the encoding of a data type is "dynamic_array"
func (s *StorageReorganizer) IsEncodingDynamicArray(dataType string) (bool, error) {

	if s.gas < 5 {
		return false, errors.New("out of gas")
	}
	s.gas -= 5

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

// function to check if the encoding of a data type is "bytes"
func (s *StorageReorganizer) IsEncodingBytes(dataType string) (bool, error) {

	if s.gas < 5 {
		return false, errors.New("out of gas")
	}
	s.gas -= 5

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

// function to get the size of a data type
func (s *StorageReorganizer) GetNumberOfBytes(typeName string) (uint64, uint64, error) {

	if s.gas < 5 {
		return 0, 0, errors.New("out of gas")
	}
	s.gas -= 5

	if dataType, found := s.dataTypes[typeName]; found {

		return dataType.PrevNumberOfBytes, dataType.NewNumberOfBytes, nil

	} else {

		return 0, 0, errors.New("Type not found")
	}
}

// change this
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

// The function iteratively searches through a type's hierarchy to retrieve its type, encoding, and whether it has a non-"inplace" encoding
func (s *StorageReorganizer) ExtractUntilInplace(typeName string) (string, string, bool, error) {

	curType := typeName

	for {
		if s.gas < 5 {
			return "", "", false, errors.New("out of gas")
		}
		s.gas -= 5
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

// checks if a data type contains struct inside it
func (s *StorageReorganizer) ContainsStruct(typeName string) (bool, string, error) {

	curType := typeName

	for {
		if s.gas < 5 {
			return false, "", errors.New("out of gas")
		}
		s.gas -= 5
		if dataType, found := s.dataTypes[curType]; found {

			if len(dataType.Members) != 0 {

				return true, curType, nil
			} else {

				if dataType.Base == "" {

					return false, "", nil
				} else {
					curType = dataType.Base
				}
			}
		} else {
			return false, "", errors.New("Type not found")
		}
	}
}

// Reorganizes data type with "inplace" encoding
func (s *StorageReorganizer) ReorganizeInplace(reorgMessage types.ReorgInfo) error {

	prevNumberOfBytes, _, err := s.GetNumberOfBytes(reorgMessage.Type)

	if err != nil {

		return err
	}

	prevSlotNumber := reorgMessage.PrevSlot.Big()
	newSlotNumber := reorgMessage.NewSlot.Big()

	typeName, encoding, found, err := s.ExtractUntilInplace(reorgMessage.Type)

	if err != nil {

		return err
	}

	structFound, structTypeName, err := s.ContainsStruct(reorgMessage.Type)

	if err != nil {

		return err
	}

	// if there is "dynamic_array" or "bytes" inside the data type then further processing is required
	if found {

		if encoding == "dynamic_array" {

			for i := 0; i < int(prevNumberOfBytes/32); i++ {

				if s.gas < 5 {
					return errors.New("out of gas")
				}
				s.gas -= 5

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

			for i := 0; i < int(prevNumberOfBytes/32); i++ {

				if s.gas < 5 {
					return errors.New("out of gas")
				}
				s.gas -= 5

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

			return errors.New("Not implemented yet")
		}

		return nil

	} else if structFound {
		// if there is a struct inside the inplace data type the members of the struct need to be processed
		prevStructSize, newStructSize, err := s.GetNumberOfBytes(structTypeName)
		if err != nil {
			return err
		}
		structDataType := s.dataTypes[structTypeName]

		curPrevSlot := reorgMessage.PrevSlot.Big()
		curNewSlot := reorgMessage.NewSlot.Big()

		// iterate based on the number of structs
		for i := 0; i < int(prevNumberOfBytes)/int(prevStructSize); i++ {
			if s.gas < 5 {
				return errors.New("out of gas")
			}
			s.gas -= 5
			//iterate over the members of the struct
			for _, member := range structDataType.Members {
				if s.gas < 5 {
					return errors.New("out of gas")
				}
				s.gas -= 5
				memberDataType, exists := s.dataTypes[member.Type]
				if !exists {

					return errors.New("Struct Member Not Found")
				}
				//process member according to data type
				if memberDataType.Encoding == "inplace" {
					err := s.ReorganizeInplace(types.ReorgInfo{
						PrevSlot:   common.BigToHash(new(big.Int).Add(curPrevSlot, member.PrevSlot.Big())),
						NewSlot:    common.BigToHash(new(big.Int).Add(curNewSlot, member.NewSlot.Big())),
						PrevOffset: member.PrevOffset,
						NewOffset:  member.NewOffset,
						Type:       memberDataType.Type,
					})

					if err != nil {

						return err
					}

				} else if memberDataType.Encoding == "dynamic_array" {

					err := s.ReorganizeDynamicArray(types.ReorgInfo{
						PrevSlot:   common.BigToHash(new(big.Int).Add(curPrevSlot, member.PrevSlot.Big())),
						NewSlot:    common.BigToHash(new(big.Int).Add(curNewSlot, member.NewSlot.Big())),
						PrevOffset: member.PrevOffset,
						NewOffset:  member.NewOffset,
						Type:       memberDataType.Type,
					})

					if err != nil {

						return err
					}

				} else if memberDataType.Encoding == "bytes" {

					err := s.ReorganizeBytes(types.ReorgInfo{
						PrevSlot:   common.BigToHash(new(big.Int).Add(curPrevSlot, member.PrevSlot.Big())),
						NewSlot:    common.BigToHash(new(big.Int).Add(curNewSlot, member.NewSlot.Big())),
						PrevOffset: member.PrevOffset,
						NewOffset:  member.NewOffset,
						Type:       memberDataType.Type,
					})

					if err != nil {

						return err
					}
				} else {

					return errors.New("Unknown Encoding")
				}
			}

			curPrevSlot = new(big.Int).Add(curPrevSlot, new(big.Int).SetUint64(prevStructSize/32))
			curNewSlot = new(big.Int).Add(curNewSlot, new(big.Int).SetUint64(newStructSize/32))
		}

		return nil

	} else {
		//if the data type does not contain struct or any other type that requires further processing then copy it from the prev slot to the new slot
		var prevOffset, newOffset uint64

		for prevOffset, newOffset = reorgMessage.PrevOffset, reorgMessage.NewOffset; prevOffset < prevNumberOfBytes+reorgMessage.PrevOffset; prevOffset, newOffset = prevOffset+1, newOffset+1 {
			if s.gas < 5 {
				return errors.New("out of gas")
			}
			s.gas -= 5
			curOldSlotNumber := new(big.Int).Add(new(big.Int).SetUint64(prevOffset/32), prevSlotNumber)

			curNewSlotNumber := new(big.Int).Add(new(big.Int).SetUint64(newOffset/32), newSlotNumber)

			prevSlot, err := s.GetCommitedState(common.BytesToHash(curOldSlotNumber.Bytes()))
			if err != nil {
				return err
			}
			newSlot, err := s.GetModifiedState(common.BytesToHash(curNewSlotNumber.Bytes()))
			if err != nil {
				return err
			}

			newSlot[31-(newOffset%32)] = prevSlot[31-(prevOffset%32)]

			s.SetModifiedState(common.BytesToHash(curNewSlotNumber.Bytes()), newSlot)

		}
		return nil
	}

}

func (s *StorageReorganizer) ReorganizeDynamicArray(reorgMessage types.ReorgInfo) error {

	prevNumberOfBytes, _, err := s.GetNumberOfBytes(reorgMessage.Type)

	if err != nil {

		return err
	}

	//copy the size of the dynamic array from the old slot to new slot
	prevSlot, err := s.GetCommitedState(reorgMessage.PrevSlot)
	if err != nil {
		return err
	}
	newSlot, err := s.GetModifiedState(reorgMessage.NewSlot)
	if err != nil {
		return err
	}

	for i := 0; i < int(prevNumberOfBytes); i++ {
		if s.gas < 3 {
			return errors.New("out of gas")
		}
		s.gas -= 3
		newSlot[i] = prevSlot[i]
	}

	s.SetModifiedState(reorgMessage.NewSlot, newSlot)
	if s.gas < 2*(30+(6*16)) {
		return errors.New("out of gas")
	}
	s.gas -= 2 * (30 + (6 * 16))
	//calculate the slot where data was stored previously and where data will be stored in the reorganized storage structure
	prevDataSlot := common.BytesToHash(crypto.Keccak256(reorgMessage.PrevSlot[:]))
	newDataSlot := common.BytesToHash(crypto.Keccak256(reorgMessage.NewSlot[:]))

	dataType := s.dataTypes[reorgMessage.Type]

	numberOfElements := prevSlot.Big()

	if numberOfElements.Cmp(big.NewInt(0)) == 0 {

		return nil
	}

	//process according to the encoding of the elements of the dynamic array
	if isInplace, err := s.IsEncodingInplace(dataType.Base); err != nil {

		return err

	} else if isInplace {
		// if it is "inplace" then check wether it is flat or nested
		if isNested, err := s.IsNested(dataType.Base); err != nil {

			return err

		} else if isNested {

			if s.gas < 5 {
				return errors.New("out of gas")
			}
			s.gas -= 5

			prevSizeOfElement, newSizeOfElement, err := s.GetNumberOfBytes(dataType.Base)

			if err != nil {

				return err
			}

			numberOfSlotsPerPrevElement := new(big.Int).SetUint64(prevSizeOfElement / 32)
			numberOfSlotsPerNewElement := new(big.Int).SetUint64(newSizeOfElement / 32)

			for i := big.NewInt(0); i.Cmp(numberOfElements) < 0; i.Add(i, big.NewInt(1)) {

				err := s.ReorganizeInplace(types.ReorgInfo{
					PrevSlot:   common.BigToHash(new(big.Int).Add(prevDataSlot.Big(), new(big.Int).Mul(numberOfSlotsPerPrevElement, i))),
					NewSlot:    common.BigToHash(new(big.Int).Add(newDataSlot.Big(), new(big.Int).Mul(numberOfSlotsPerNewElement, i))),
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

			if s.gas < 5 {
				return errors.New("out of gas")
			}
			s.gas -= 5

			sizeOfElement, _, err := s.GetNumberOfBytes(dataType.Base)

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

	numberOfBytes, _, err := s.GetNumberOfBytes(reorgMessage.Type)

	if err != nil {

		return err
	}

	prevSlot, err := s.GetCommitedState(reorgMessage.PrevSlot)
	if err != nil {
		return err
	}
	newSlot, err := s.GetModifiedState(reorgMessage.NewSlot)
	if err != nil {
		return err
	}

	//copy data from old slot to new slot
	for i := 0; i < int(numberOfBytes); i++ {
		if s.gas < 3 {
			return errors.New("out of gas")
		}
		s.gas -= 3
		newSlot[i] = prevSlot[i]
	}

	s.SetModifiedState(reorgMessage.NewSlot, newSlot)

	if s.gas < 2*(30+(6*16)) {
		return errors.New("out of gas")
	}
	s.gas -= 2 * (30 + (6 * 16))

	//calculate the old data slot and new data slot
	prevDataSlot := common.BytesToHash(crypto.Keccak256(reorgMessage.PrevSlot[:]))
	newDataSlot := common.BytesToHash(crypto.Keccak256(reorgMessage.NewSlot[:]))

	// if it is not a short byte do further processing
	if (prevSlot[31] & 1) != 0 {
		if s.gas < 8 {
			return errors.New("out of gas")
		}
		s.gas -= 8
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

			curPrevSlot, err := s.GetCommitedState(slotToBeCopiedFrom)
			if err != nil {
				return err
			}
			curNewSlot, err := s.GetModifiedState(slotToBeCopiedTo)
			if err != nil {
				return err
			}

			for j := 0; j < 32; j++ {
				if s.gas < 3 {
					return errors.New("out of gas")
				}
				s.gas -= 3
				curNewSlot[j] = curPrevSlot[j]
			}

			s.SetModifiedState(slotToBeCopiedTo, curNewSlot)

		}

	}

	return nil

}
func (s *StorageReorganizer) IsCommitPossible() error {

	if s.gas < uint64(5000*len(s.commitedStorage)) {

		return errors.New("out of gas")
	}
	s.gas -= 5000

	for _, val := range s.modifiedStorage {

		if bytes.Equal(val.Bytes(), common.Hash{}.Bytes()) {

			if s.gas < 5000 {

				return errors.New("out of gas")
			}
			s.gas -= 5000

		} else {

			if s.gas < 20000 {

				return errors.New("out of gas")
			}
			s.gas -= 20000
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

func NewStorageReorganizer(addr common.Address, state StateDB, gas uint64) *StorageReorganizer {
	return &StorageReorganizer{
		state:           state,
		commitedStorage: make(map[common.Hash]common.Hash),
		modifiedStorage: make(map[common.Hash]common.Hash),
		dataTypes:       make(map[string]types.DataType),
		addr:            addr,
		gas:             gas,
	}
}
