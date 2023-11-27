package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func readLittleEndianUint8(fileObj *os.File) (uint8, error) {
	buff := make([]byte, 1)
	_, err := io.ReadAtLeast(fileObj, buff, 1)
	return buff[0], err
}

func readLittleEndianUint16(fileObj *os.File) (uint16, error) {
	buff := make([]byte, 2)
	_, err := io.ReadAtLeast(fileObj, buff, 2)
	return binary.LittleEndian.Uint16(buff), err
}

func readLittleEndianUint32(fileObj *os.File) (uint32, error) {
	buff := make([]byte, 4)
	_, err := io.ReadAtLeast(fileObj, buff, 4)
	return binary.LittleEndian.Uint32(buff), err
}

func readLittleEndianUint64(fileObj *os.File) (uint64, error) {
	buff := make([]byte, 8)
	_, err := io.ReadAtLeast(fileObj, buff, 8)
	return binary.LittleEndian.Uint64(buff), err
}

func readString(fileObj *os.File, length int) (string, error) {
	buff := make([]byte, length)
	_, err := io.ReadAtLeast(fileObj, buff, length)
	return string(buff), err
}

func getMachineNameFromMachineValue(machineValue uint16) string {
	switch machineValue {
	case 0x184:
		return "Alpha AXP, 32-bit address space\n"
	case 0x284:
		return "Alpha 64, 64-bit address space\n"
	case 0x1d3:
		return "Matsushita AM33\n"
	case 0x8664:
		return "x64\n"
	case 0x1c0:
		return "ARM little endian\n"
	case 0xaa64:
		return "ARM64 little endian\n"
	case 0x1c4:
		return "ARM Thumb-2 little endian\n"
	case 0xebc:
		return "EFI byte code\n"
	case 0x14c:
		return "Intel 386 or later processors and compatible processors\n"
	case 0x200:
		return "Intel Itanium processor family\n"
	case 0x6232:
		return "LoongArch 32-bit processor family\n"
	case 0x6264:
		return "LoongArch 64-bit processor family\n"
	case 0x9041:
		return "Mitsubishi M32R little endian\n"
	case 0x266:
		return "MIPS16\n"
	case 0x366:
		return "MIPS with FPU\n"
	case 0x466:
		return "MIPS16 with FPU\n"
	case 0x1f0:
		return "Power PC little endian\n"
	case 0x1f1:
		return "Power PC with floating point support\n"
	case 0x166:
		return "MIPS little endian\n"
	case 0x5032:
		return "RISC-V 32-bit address space\n"
	case 0x5064:
		return "RISC-V 64-bit address space\n"
	case 0x5128:
		return "RISC-V 128-bit address space\n"
	case 0x1a2:
		return "Hitachi SH3"
	case 0x1a3:
		return "Hitachi SH3 DSP"
	case 0x1a6:
		return "Hitachi SH4"
	case 0x1a8:
		return "Hitachi SH5"
	case 0x1c2:
		return "Thumb"
	case 0x169:
		return "MIPS little-endian WCE v2"
	default:
		return "Unknown machine type"
	}
}

func parseCharacteristicsFlag(characteristicsFlag uint16) []string {
	var characteristics []string

	if characteristicsFlag&0x0001 == 0x0001 {
		characteristics = append(characteristics, "IMAGE_FILE_RELOCS_STRIPPED")
	}

	if characteristicsFlag&0x0002 == 0x0002 {
		characteristics = append(characteristics, "IMAGE_FILE_EXECUTABLE_IMAGE")
	}

	if characteristicsFlag&0x0004 == 0x0004 {
		characteristics = append(characteristics, "IMAGE_FILE_LINE_NUMS_STRIPPED")
	}

	if characteristicsFlag&0x0008 == 0x0008 {
		characteristics = append(characteristics, "IMAGE_FILE_LOCAL_SYMS_STRIPPED")
	}

	if characteristicsFlag&0x0010 == 0x0010 {
		characteristics = append(characteristics, "IMAGE_FILE_AGGRESSIVE_WS_TRIM")
	}

	if characteristicsFlag&0x0020 == 0x0020 {
		characteristics = append(characteristics, "IMAGE_FILE_LARGE_ADDRESS_AWARE")
	}

	if characteristicsFlag&0x0040 == 0x0040 {
		characteristics = append(characteristics, "RESERVED_FOR_FUTURE_USE")
	}

	if characteristicsFlag&0x0080 == 0x0080 {
		characteristics = append(characteristics, "IMAGE_FILE_BYTES_REVERSED_LO")
	}

	if characteristicsFlag&0x0100 == 0x0100 {
		characteristics = append(characteristics, "IMAGE_FILE_32BIT_MACHINE")
	}

	if characteristicsFlag&0x0200 == 0x0200 {
		characteristics = append(characteristics, "IMAGE_FILE_DEBUG_STRIPPED")
	}

	if characteristicsFlag&0x0400 == 0x0400 {
		characteristics = append(characteristics, "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP")
	}

	if characteristicsFlag&0x0800 == 0x0800 {
		characteristics = append(characteristics, "IMAGE_FILE_NET_RUN_FROM_SWAP")
	}

	if characteristicsFlag&0x1000 == 0x1000 {
		characteristics = append(characteristics, "IMAGE_FILE_SYSTEM")
	}

	if characteristicsFlag&0x2000 == 0x2000 {
		characteristics = append(characteristics, "IMAGE_FILE_DLL")
	}

	if characteristicsFlag&0x4000 == 0x4000 {
		characteristics = append(characteristics, "IMAGE_FILE_UP_SYSTEM_ONLY")
	}

	if characteristicsFlag&0x8000 == 0x8000 {
		characteristics = append(characteristics, "IMAGE_FILE_BYTES_REVERSED_HI")
	}

	return characteristics
}

func getSubsystemValue(value uint16) string {
	switch value {
	case 0:
		return "IMAGE_SUBSYSTEM_UNKNOWN"
	case 1:
		return "IMAGE_SUBSYSTEM_NATIVE"
	case 2:
		return "IMAGE_SUBSYSTEM_WINDOWS_GUI"
	case 3:
		return "IMAGE_SUBSYSTEM_WINDOWS_CUI"
	case 5:
		return "IMAGE_SUBSYSTEM_OS2_CUI"
	case 7:
		return "IMAGE_SUBSYSTEM_POSIX_CUI"
	case 8:
		return "IMAGE_SUBSYSTEM_NATIVE_WINDOWS"
	case 9:
		return "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI"
	case 10:
		return "IMAGE_SUBSYSTEM_EFI_APPLICATION"
	case 11:
		return "IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER"
	case 12:
		return "IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER"
	case 13:
		return "IMAGE_SUBSYSTEM_EFI_ROM"
	case 14:
		return "IMAGE_SUBSYSTEM_XBOX"
	case 16:
		return "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION"
	default:
		return "INVALID_SUBSYSTEM"
	}
}

func getDllCharacteristics(value uint16) []string {
	var dllCharacteristics []string

	if value&0x0020 == 0x0020 {
		dllCharacteristics = append(dllCharacteristics, "IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA")
	}
	if value&0x0040 == 0x0040 {
		dllCharacteristics = append(dllCharacteristics, "IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE")
	}
	if value&0x0080 == 0x0080 {
		dllCharacteristics = append(dllCharacteristics, "IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY")
	}
	if value&0x0100 == 0x0100 {
		dllCharacteristics = append(dllCharacteristics, "IMAGE_DLLCHARACTERISTICS_NX_COMPAT")
	}
	if value&0x0200 == 0x0200 {
		dllCharacteristics = append(dllCharacteristics, "IMAGE_DLLCHARACTERISTICS_NO_ISOLATION")
	}
	if value&0x0400 == 0x0400 {
		dllCharacteristics = append(dllCharacteristics, "IMAGE_DLLCHARACTERISTICS_NO_SEH")
	}
	if value&0x0800 == 0x0800 {
		dllCharacteristics = append(dllCharacteristics, "IMAGE_DLLCHARACTERISTICS_NO_BIND")
	}
	if value&0x1000 == 0x1000 {
		dllCharacteristics = append(dllCharacteristics, "IMAGE_DLLCHARACTERISTICS_APPCONTAINER")
	}
	if value&0x2000 == 0x2000 {
		dllCharacteristics = append(dllCharacteristics, "IMAGE_DLLCHARACTERISTICS_WDM_DRIVER")
	}
	if value&0x4000 == 0x4000 {
		dllCharacteristics = append(dllCharacteristics, "IMAGE_DLLCHARACTERISTICS_GUARD_CF")
	}
	if value&0x8000 == 0x8000 {
		dllCharacteristics = append(dllCharacteristics, "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE")
	}

	return dllCharacteristics
}

func getSectionCharacteristics(value uint32) []string {
	var sectionCharacteristics []string

	if value&0x00000008 == 0x00000008 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_TYPE_NO_PAD")
	}
	if value&0x00000020 == 0x00000020 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_CNT_CODE")
	}
	if value&0x00000040 == 0x00000040 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_CNT_INITIALIZED_DATA")
	}
	if value&0x00000080 == 0x00000080 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_CNT_UNINITIALIZED_DATA")
	}
	if value&0x00000100 == 0x00000100 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_LNK_OTHER")
	}
	if value&0x00000200 == 0x00000200 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_LNK_INFO")
	}
	if value&0x00000800 == 0x00000800 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_LNK_REMOVE")
	}
	if value&0x00001000 == 0x00001000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_LNK_COMDAT")
	}
	if value&0x00008000 == 0x00008000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_GPREL")
	}
	if value&0x00020000 == 0x00020000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_MEM_PURGEABLE | IMAGE_SCN_MEM_16BIT")
	}
	if value&0x00040000 == 0x00040000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_MEM_LOCKED")
	}
	if value&0x00080000 == 0x00080000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_MEM_PRELOAD")
	}
	if value&0x00100000 == 0x00100000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_ALIGN_1BYTES")
	}
	if value&0x00200000 == 0x00200000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_ALIGN_2BYTES")
	}
	if value&0x00300000 == 0x00300000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_ALIGN_4BYTES")
	}
	if value&0x00400000 == 0x00400000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_ALIGN_8BYTES")
	}
	if value&0x00500000 == 0x00500000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_ALIGN_16BYTES")
	}
	if value&0x00600000 == 0x00600000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_ALIGN_32BYTES")
	}
	if value&0x00700000 == 0x00700000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_ALIGN_64BYTES")
	}
	if value&0x00800000 == 0x00800000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_ALIGN_128BYTES")
	}
	if value&0x00900000 == 0x00900000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_ALIGN_256BYTES")
	}
	if value&0x00A00000 == 0x00A00000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_ALIGN_512BYTES")
	}
	if value&0x00B00000 == 0x00B00000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_ALIGN_1024BYTES")
	}
	if value&0x00C00000 == 0x00C00000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_ALIGN_2048BYTES")
	}
	if value&0x00D00000 == 0x00D00000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_ALIGN_4096BYTES")
	}
	if value&0x00E00000 == 0x00E00000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_ALIGN_8192BYTES")
	}
	if value&0x01000000 == 0x01000000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_LNK_NRELOC_OVFL")
	}
	if value&0x02000000 == 0x02000000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_MEM_DISCARDABLE")
	}
	if value&0x04000000 == 0x04000000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_MEM_NOT_CACHED")
	}
	if value&0x08000000 == 0x08000000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_MEM_NOT_PAGED")
	}
	if value&0x10000000 == 0x10000000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_MEM_SHARED")
	}
	if value&0x20000000 == 0x20000000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_MEM_EXECUTE")
	}
	if value&0x40000000 == 0x40000000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_MEM_READ")
	}
	if value&0x80000000 == 0x80000000 {
		sectionCharacteristics = append(sectionCharacteristics, "IMAGE_SCN_MEM_WRITE")
	}

	return sectionCharacteristics
}

func parsePortableExecutable(pePath string) {
	fileObj, err := os.Open(pePath)

	if os.IsNotExist(err) {
		fmt.Printf("%s does not exist.", pePath)
		return
	}

	check(err)
	defer fileObj.Close()

	mzSignatureBuff := make([]byte, 2)
	numBytesRead, err := io.ReadAtLeast(fileObj, mzSignatureBuff, 2)

	if numBytesRead != 2 {
		fmt.Println("Could not read the MZ signature.")
	}

	if !(mzSignatureBuff[0] == 0x4D && mzSignatureBuff[1] == 0x5A) {
		fmt.Println("The given file is not a Portable Executable file.")
	} else {
		fmt.Println("The given file has the MZ signature.")
	}

	// read e_lfanew
	_, err = fileObj.Seek(0x3C, 0)

	peOffset := make([]byte, 4)
	numBytesRead, err = io.ReadAtLeast(fileObj, peOffset, 4)

	peOffsetValue := int64(binary.LittleEndian.Uint32(peOffset))

	// seek to PE header location
	_, err = fileObj.Seek(peOffsetValue, 0)

	peSignatureBuff := make([]byte, 4)
	numBytesRead, err = io.ReadAtLeast(fileObj, peSignatureBuff, 4)

	if numBytesRead != 4 {
		fmt.Println("Could not read the PE signature.")
	}

	if !(peSignatureBuff[0] == 0x50 && peSignatureBuff[1] == 0x45 &&
		peSignatureBuff[2] == 0x0 && peSignatureBuff[3] == 0x0) {
		fmt.Println("The given file is not a Portable Executable file.")
	} else {
		fmt.Println("The given file has the Portable Executable signature.")
	}

	var peData PortableExecutableData
	var peHeaderData = getPeHeaderData(fileObj)

	peData.peHeader = peHeaderData

	fmt.Println("Obtained all information about the PE header.")
	fmt.Printf("The size of the optional header is %d", peHeaderData.sizeOfOptionalHeader)

	if peHeaderData.sizeOfOptionalHeader != 0 {
		fmt.Println("Proceeding with the read of the optional header..")
		peData.optionalHeader = getOptionalHeaderData(fileObj)
	} else {
		fmt.Println("Will not read the optional header as it does not exist.")
		peData.optionalHeader = OptionalHeader{}
	}

	var sections []Section

	for i := 0; i < int(peData.peHeader.numberOfSections); i++ {
		sections = append(sections, getSectionData(fileObj))
	}

	peData.sections = sections

	fmt.Println(peData)
}

func getSectionData(file *os.File) Section {
	var section Section
	name, err := readString(file, 8)
	check(err)
	section.name = name

	section.virtualSize, err = readLittleEndianUint32(file)
	check(err)
	section.virtualAddress, err = readLittleEndianUint32(file)
	check(err)

	section.sizeOfRawData, err = readLittleEndianUint32(file)
	check(err)
	section.pointerToRawData, err = readLittleEndianUint32(file)
	check(err)

	section.pointerToRelocations, err = readLittleEndianUint32(file)
	check(err)
	section.pointerToLineNumbers, err = readLittleEndianUint32(file)
	check(err)
	section.numberOfRelocations, err = readLittleEndianUint16(file)
	check(err)
	section.numberOfLineNumbers, err = readLittleEndianUint16(file)
	check(err)

	section.characteristics, err = readLittleEndianUint32(file)
	check(err)
	section.characteristicsData = getSectionCharacteristics(section.characteristics)

	return section
}

func getOptionalHeaderData(file *os.File) OptionalHeader {
	var optionalHeader OptionalHeader
	var peType string

	magicValue, err := readLittleEndianUint16(file)
	check(err)
	optionalHeader.magic = magicValue

	if magicValue == 0x10b {
		peType = "PE32"
	} else {
		peType = "PE32+"
	}

	fmt.Printf("PE is of type %s", peType)
	optionalHeader.magicStr = peType

	optionalHeader.majorLinkerVersion, err = readLittleEndianUint8(file)
	check(err)

	optionalHeader.minorLinkerVersion, err = readLittleEndianUint8(file)
	check(err)

	optionalHeader.sizeOfCode, err = readLittleEndianUint32(file)
	check(err)

	optionalHeader.sizeOfInitializedData, err = readLittleEndianUint32(file)
	check(err)

	optionalHeader.sizeOfUninitializedData, err = readLittleEndianUint32(file)
	check(err)

	optionalHeader.addressOfEntrypoint, err = readLittleEndianUint32(file)
	check(err)

	optionalHeader.baseOfCode, err = readLittleEndianUint32(file)
	check(err)

	if peType != "PE32+" {
		optionalHeader.baseOfData, err = readLittleEndianUint32(file)
	}

	optionalHeader.windowsSpecificFields = getWindowsSpecificFields(file, peType)
	optionalHeader.dataDirectories = getDataDirectoryData(file)

	return optionalHeader
}

func getWindowsSpecificFields(file *os.File, peType string) OptionalHeaderWindowsSpecificFields {
	var windowsSpecificFields OptionalHeaderWindowsSpecificFields
	if peType != "PE32+" {
		imageBase, err := readLittleEndianUint32(file)
		check(err)
		windowsSpecificFields.imageBase = uint64(imageBase)
	} else {
		imageBase, err := readLittleEndianUint64(file)
		check(err)
		windowsSpecificFields.imageBase = imageBase
	}

	sectionAlignment, err := readLittleEndianUint32(file)
	check(err)
	windowsSpecificFields.sectionAlignment = sectionAlignment

	windowsSpecificFields.fileAlignment, err = readLittleEndianUint32(file)
	check(err)

	windowsSpecificFields.majorOperatingSystemVersion, err = readLittleEndianUint16(file)
	check(err)
	windowsSpecificFields.minorOperatingSystemVersion, err = readLittleEndianUint16(file)
	check(err)

	windowsSpecificFields.majorImageVersion, err = readLittleEndianUint16(file)
	check(err)
	windowsSpecificFields.minorImageVersion, err = readLittleEndianUint16(file)
	check(err)

	windowsSpecificFields.majorSubsystemVersion, err = readLittleEndianUint16(file)
	check(err)
	windowsSpecificFields.minorSubsystemVersion, err = readLittleEndianUint16(file)
	check(err)

	windowsSpecificFields.win32VersionValue, err = readLittleEndianUint32(file)
	check(err)

	windowsSpecificFields.sizeOfImage, err = readLittleEndianUint32(file)
	check(err)

	windowsSpecificFields.sizeOfHeaders, err = readLittleEndianUint32(file)
	check(err)

	windowsSpecificFields.checkSum, err = readLittleEndianUint32(file)
	check(err)

	windowsSpecificFields.subsystem, err = readLittleEndianUint16(file)
	check(err)
	windowsSpecificFields.subsystemStr = getSubsystemValue(windowsSpecificFields.subsystem)

	windowsSpecificFields.dllCharacteristics, err = readLittleEndianUint16(file)
	check(err)
	windowsSpecificFields.dllCharacteristicsStr = getDllCharacteristics(windowsSpecificFields.dllCharacteristics)

	if peType != "PE32+" {
		sizeOfStackReserve, err := readLittleEndianUint32(file)
		check(err)
		windowsSpecificFields.sizeOfStackReserve = uint64(sizeOfStackReserve)
	} else {
		sizeOfStackReserve, err := readLittleEndianUint64(file)
		check(err)
		windowsSpecificFields.sizeOfStackReserve = sizeOfStackReserve
	}

	if peType != "PE32+" {
		sizeOfStackCommit, err := readLittleEndianUint32(file)
		check(err)
		windowsSpecificFields.sizeOfStackCommit = uint64(sizeOfStackCommit)
	} else {
		sizeOfStackCommit, err := readLittleEndianUint64(file)
		check(err)
		windowsSpecificFields.sizeOfStackCommit = sizeOfStackCommit
	}

	if peType != "PE32+" {
		sizeOfHeapReserve, err := readLittleEndianUint32(file)
		check(err)
		windowsSpecificFields.sizeOfHeapReserve = uint64(sizeOfHeapReserve)
	} else {
		sizeOfHeapReserve, err := readLittleEndianUint64(file)
		check(err)
		windowsSpecificFields.sizeOfHeapReserve = sizeOfHeapReserve
	}

	if peType != "PE32+" {
		sizeOfHeapCommit, err := readLittleEndianUint32(file)
		check(err)
		windowsSpecificFields.sizeOfHeapCommit = uint64(sizeOfHeapCommit)
	} else {
		sizeOfHeapCommit, err := readLittleEndianUint64(file)
		check(err)
		windowsSpecificFields.sizeOfHeapCommit = sizeOfHeapCommit
	}

	windowsSpecificFields.loaderFlags, err = readLittleEndianUint32(file)
	check(err)

	windowsSpecificFields.numberOfRvaAndSizes, err = readLittleEndianUint32(file)
	check(err)

	return windowsSpecificFields
}

func getDataDirectoryData(file *os.File) OptionalHeaderDataDirectories {
	var dataDirectoriesData OptionalHeaderDataDirectories

	exportTable, err := readLittleEndianUint64(file)
	check(err)
	dataDirectoriesData.exportTable = exportTable
	dataDirectoriesData.importTable, err = readLittleEndianUint64(file)
	check(err)

	dataDirectoriesData.resourceTable, err = readLittleEndianUint64(file)
	check(err)
	dataDirectoriesData.exceptionTable, err = readLittleEndianUint64(file)
	check(err)
	dataDirectoriesData.certificateTable, err = readLittleEndianUint64(file)
	check(err)
	dataDirectoriesData.baseRelocationTable, err = readLittleEndianUint64(file)
	check(err)

	dataDirectoriesData.debug, err = readLittleEndianUint64(file)
	check(err)

	dataDirectoriesData.architecture, err = readLittleEndianUint64(file)
	check(err)

	dataDirectoriesData.globalPtr, err = readLittleEndianUint64(file)
	check(err)

	dataDirectoriesData.tlsTable, err = readLittleEndianUint64(file)
	check(err)

	dataDirectoriesData.loadConfigTable, err = readLittleEndianUint64(file)
	check(err)

	dataDirectoriesData.boundImport, err = readLittleEndianUint64(file)
	check(err)

	dataDirectoriesData.importAddressTable, err = readLittleEndianUint64(file)
	check(err)

	dataDirectoriesData.delayImportDescriptor, err = readLittleEndianUint64(file)
	check(err)

	dataDirectoriesData.clrRuntimeHeader, err = readLittleEndianUint64(file)
	check(err)

	_, err = readLittleEndianUint64(file)

	return dataDirectoriesData
}

func getPeHeaderData(fileObj *os.File) PortableExecutableHeader {
	var peHeaderData PortableExecutableHeader

	// Read machine
	machineValue, err := readLittleEndianUint16(fileObj)
	check(err)
	peHeaderData.machine = getMachineNameFromMachineValue(machineValue)

	// Read numberOfSections
	peHeaderData.numberOfSections, err = readLittleEndianUint16(fileObj)
	check(err)

	// Read timeDateStamp
	peHeaderData.timeDateStamp, err = readLittleEndianUint32(fileObj)
	check(err)

	// Read pointerToSymbolTable
	peHeaderData.pointerToSystemTable, err = readLittleEndianUint32(fileObj)
	check(err)

	// Read numberOfSymbols
	peHeaderData.numberOfSymbols, err = readLittleEndianUint32(fileObj)
	check(err)

	// Read sizeOfOptionalHeader
	peHeaderData.sizeOfOptionalHeader, err = readLittleEndianUint16(fileObj)
	check(err)

	// Read characteristics
	characteristics, err := readLittleEndianUint16(fileObj)
	peHeaderData.characteristics = parseCharacteristicsFlag(characteristics)
	check(err)

	return peHeaderData
}

type PortableExecutableData struct {
	peHeader       PortableExecutableHeader
	optionalHeader OptionalHeader
	sections       []Section
}

type PortableExecutableHeader struct {
	machine              string
	numberOfSections     uint16
	timeDateStamp        uint32
	pointerToSystemTable uint32
	numberOfSymbols      uint32
	sizeOfOptionalHeader uint16
	characteristics      []string
}

type OptionalHeader struct {
	magic                   uint16
	magicStr                string
	majorLinkerVersion      uint8
	minorLinkerVersion      uint8
	sizeOfCode              uint32
	sizeOfInitializedData   uint32
	sizeOfUninitializedData uint32
	addressOfEntrypoint     uint32
	baseOfCode              uint32
	baseOfData              uint32
	windowsSpecificFields   OptionalHeaderWindowsSpecificFields
	dataDirectories         OptionalHeaderDataDirectories
}

type OptionalHeaderWindowsSpecificFields struct {
	imageBase                   uint64
	sectionAlignment            uint32
	fileAlignment               uint32
	majorOperatingSystemVersion uint16
	minorOperatingSystemVersion uint16
	majorImageVersion           uint16
	minorImageVersion           uint16
	majorSubsystemVersion       uint16
	minorSubsystemVersion       uint16
	win32VersionValue           uint32
	sizeOfImage                 uint32
	sizeOfHeaders               uint32
	checkSum                    uint32
	subsystem                   uint16
	subsystemStr                string
	dllCharacteristics          uint16
	dllCharacteristicsStr       []string
	sizeOfStackReserve          uint64
	sizeOfStackCommit           uint64
	sizeOfHeapReserve           uint64
	sizeOfHeapCommit            uint64
	loaderFlags                 uint32
	numberOfRvaAndSizes         uint32
}

type OptionalHeaderDataDirectories struct {
	exportTable           uint64
	importTable           uint64
	resourceTable         uint64
	exceptionTable        uint64
	certificateTable      uint64
	baseRelocationTable   uint64
	debug                 uint64
	architecture          uint64
	globalPtr             uint64
	tlsTable              uint64
	loadConfigTable       uint64
	boundImport           uint64
	importAddressTable    uint64
	delayImportDescriptor uint64
	clrRuntimeHeader      uint64
}

type Section struct {
	name                 string
	virtualSize          uint32
	virtualAddress       uint32
	sizeOfRawData        uint32
	pointerToRawData     uint32
	pointerToRelocations uint32
	pointerToLineNumbers uint32
	numberOfRelocations  uint16
	numberOfLineNumbers  uint16
	characteristics      uint32
	characteristicsData  []string
}

func main() {
	pePath := flag.String("path", "", "The path of the Portable Executable that will be analyzed.")
	flag.Parse()

	fmt.Println(*pePath)

	if *pePath == "" {
		fmt.Println("The path of the PE to be analyzed cannot be null.")
	} else {
		parsePortableExecutable(*pePath)
	}
}
