package binaryExpand

import (
	"debug/pe"
	"os"
	"encoding/binary"
	"log"
	"fmt"
	"errors"
	"io"
)

const (
	MAX_DIGITAL_SIGNATURE_SIZE       = 4294967295
	PE_ADDRESS_OFFSET                = 0x3c
	PE_ALIGN_ADDRESS_OFFSET          = 0x3c
	PE_SIGNATURE_SIZE_OFFSET_X64     = 0xAC
	PE_SIGNATURE_SIZE_OFFSET_X86     = 0x9c
	PE_SIGNATURE_ADDRESS_BASE_OFFSET = 0x78
	PE_SIGNATURE_ADDRESS_OFFSET_X64  = 0x30
	PE_SIGNATURE_ADDRESS_OFFSET_X86  = 0x20
)

func AllocateExtraSpaceTo(sourceFile, copyTo string, bytes []byte, isVerbose bool) (err error) {
	_, err = copyFile(sourceFile, copyTo)
	if err != nil {
		return
	}
	return AllocateExtraSpace(copyTo, bytes, isVerbose)
}

func AllocateExtraSpace(fileName string, bytes []byte, isVerbose bool) (err error) {
	peFile, err := getPeFileStructure(fileName)
	if err != nil {
		return
	}

	file, err := os.OpenFile(fileName, os.O_RDWR, 0)
	if err != nil {
		return
	}

	fileStats, err := file.Stat()
	if err != nil {
		return
	}

	defer file.Close()

	peSignatureOffset, peSignatureSizeOffset := determineSignatureOffsets(isFileX64Arch(peFile), isVerbose);

	peAddress, err := readData(file, int64(PE_ADDRESS_OFFSET))
	if err != nil {
		return
	}

	peDigintalSignatureSizeAddress := int64(peAddress + peSignatureSizeOffset)
	peDigitalSignatureSize, err := readData(file, peDigintalSignatureSizeAddress)
	if err != nil {
		return
	}
	verbose(fmt.Sprintf("INTERNAL_SECURITY_SIZE: %x", peDigitalSignatureSize), isVerbose)

	digitalSignatureAddressOffset := int64(peAddress + PE_SIGNATURE_ADDRESS_BASE_OFFSET + peSignatureOffset)
	digitalSignatureAddress, err := readData(file, digitalSignatureAddressOffset)
	if err != nil {
		return
	}
	verbose(fmt.Sprintf("SECURITY_RVA: %x", digitalSignatureAddress), isVerbose)

	digitalSignatureInlineSize, err := readData(file, int64(digitalSignatureAddress))
	if err != nil {
		return
	}
	verbose(fmt.Sprintf("SECURITY_SIZE: %x", digitalSignatureInlineSize), isVerbose)

	align, err := readData(file, int64(peAddress + PE_ALIGN_ADDRESS_OFFSET))
	verbose(fmt.Sprintf("AlIGN: %d", align), isVerbose)
	if err != nil {
		return
	}

	alignedBytes := alignSize(bytes, align)

	err = checkSignatureSizes(digitalSignatureInlineSize, peDigitalSignatureSize)
	if err != nil {
		return
	}

	newDigitalSignatureSize := digitalSignatureInlineSize + len(alignedBytes)
	verbose(fmt.Sprintf("New signature size is %d bytes", newDigitalSignatureSize), isVerbose)
	verbose(fmt.Sprintf("Allocated %d bytes at the end of file", len(alignedBytes)), isVerbose)

	err = writeData(file, int64(digitalSignatureAddress), newDigitalSignatureSize)
	if err != nil {
		return
	}

	err = writeData(file, int64(peDigintalSignatureSizeAddress), newDigitalSignatureSize)
	if err != nil {
		return
	}

	file.Seek(fileStats.Size(), 0)
	_, err = file.Write(alignedBytes)
	if err != nil {
		return
	}
	return nil
}

func checkSignatureSizes(digitalSignatureInlineSize, peDigitalSignatureSize int) (err error) {
	if digitalSignatureInlineSize == 0 || peDigitalSignatureSize == 0 {
		return errors.New("Digital signature not found")
	}
	if digitalSignatureInlineSize != peDigitalSignatureSize {
		return errors.New("PE header digital signature size and inline digital signature size not match!")
	}
	return
}

func determineSignatureOffsets(x64, isVerbose bool) (peSignatureOffset, peSignatureSizeOffset int) {
	if x64 {
		peSignatureOffset = PE_SIGNATURE_ADDRESS_OFFSET_X64
		peSignatureSizeOffset = PE_SIGNATURE_SIZE_OFFSET_X64

		verbose(fmt.Sprintf("x64 architecture"), isVerbose)
	}else {
		peSignatureOffset = PE_SIGNATURE_ADDRESS_OFFSET_X86
		peSignatureSizeOffset = PE_SIGNATURE_SIZE_OFFSET_X86

		verbose(fmt.Sprintf("x86 architecture"), isVerbose)
	}
	return;
}

func alignSize(bytes []byte, align int) []byte {
	byteLen := len(bytes)
	newLen := byteLen
	if byteLen%align != 0 {
		newLen = align*((byteLen/align) + 1)
	}
	if byteLen != newLen {
		leftSide := make([]byte, (newLen - byteLen))
		bytes = append(leftSide, bytes...)
	}
	return bytes
}


func getPeFileStructure(fileName string) (file *pe.File, err error) {
	file, err = pe.Open(fileName)
	if err != nil {
		return
	}
	defer file.Close()
	return
}

func isFileX64Arch(file *pe.File) bool {
	return file.Machine == pe.IMAGE_FILE_MACHINE_AMD64
}

func readData(file *os.File, offset int64) (data int, err error) {
	var buffer [4]byte
	_, err = file.ReadAt(buffer[0:], offset)
	data = int(binary.LittleEndian.Uint32(buffer[0:]))
	return
}

func writeData(file *os.File, offset int64, data int) (err error) {
	var buffer [4]byte
	binary.LittleEndian.PutUint32(buffer[0:], uint32(data))
	_, err = file.WriteAt(buffer[0:], offset)
	return
}

func copyFile(src, dst string) (int64, error) {
	sf, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer sf.Close()
	df, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer df.Close()
	return io.Copy(df, sf)
}

func verbose(message string, isVerbose bool) {
	if isVerbose {
		log.Println(message)
	}
}
