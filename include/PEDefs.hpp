#ifndef PEDEFS_HPP
#define PEDEFS_HPP

#include <cstdint>

// Cross-platform PE format definitions
// These are standard PE/COFF structures that work on any platform

#pragma pack(push, 1)

// DOS Header
struct IMAGE_DOS_HEADER {
    uint16_t e_magic;    // Magic number
    uint16_t e_cblp;     // Bytes on last page of file
    uint16_t e_cp;       // Pages in file
    uint16_t e_crlc;     // Relocations
    uint16_t e_cparhdr;  // Size of header in paragraphs
    uint16_t e_minalloc; // Minimum extra paragraphs needed
    uint16_t e_maxalloc; // Maximum extra paragraphs needed
    uint16_t e_ss;       // Initial (relative) SS value
    uint16_t e_sp;       // Initial SP value
    uint16_t e_csum;     // Checksum
    uint16_t e_ip;       // Initial IP value
    uint16_t e_cs;       // Initial (relative) CS value
    uint16_t e_lfarlc;   // File address of relocation table
    uint16_t e_ovno;     // Overlay number
    uint16_t e_res[4];   // Reserved words
    uint16_t e_oemid;    // OEM identifier (for e_oeminfo)
    uint16_t e_oeminfo;  // OEM information; e_oemid specific
    uint16_t e_res2[10]; // Reserved words
    int32_t  e_lfanew;   // File address of new exe header
};

// File header
struct IMAGE_FILE_HEADER {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

// Data directory
struct IMAGE_DATA_DIRECTORY {
    uint32_t VirtualAddress;
    uint32_t Size;
};

// Optional header 64
struct IMAGE_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
};

// NT headers 64
struct IMAGE_NT_HEADERS64 {
    uint32_t Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

// Section header
struct IMAGE_SECTION_HEADER {
    uint8_t  Name[8];
    union {
        uint32_t PhysicalAddress;
        uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

#pragma pack(pop)

// Constants
constexpr uint16_t IMAGE_DOS_SIGNATURE = 0x5A4D;     // MZ
constexpr uint32_t IMAGE_NT_SIGNATURE  = 0x00004550; // PE00
constexpr uint16_t IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x020B;

// Directory Entries
constexpr int IMAGE_DIRECTORY_ENTRY_EXPORT    = 0;
constexpr int IMAGE_DIRECTORY_ENTRY_IMPORT    = 1;
constexpr int IMAGE_DIRECTORY_ENTRY_RESOURCE  = 2;
constexpr int IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3;
constexpr int IMAGE_DIRECTORY_ENTRY_SECURITY  = 4;
constexpr int IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
constexpr int IMAGE_DIRECTORY_ENTRY_DEBUG     = 6;
constexpr int IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7;
constexpr int IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8;
constexpr int IMAGE_DIRECTORY_ENTRY_TLS       = 9;
constexpr int IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;
constexpr int IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11;
constexpr int IMAGE_DIRECTORY_ENTRY_IAT       = 12;
constexpr int IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13;
constexpr int IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14;

// Section characteristics
constexpr uint32_t IMAGE_SCN_CNT_CODE               = 0x00000020;
constexpr uint32_t IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040;
constexpr uint32_t IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
constexpr uint32_t IMAGE_SCN_MEM_EXECUTE            = 0x20000000;
constexpr uint32_t IMAGE_SCN_MEM_READ               = 0x40000000;
constexpr uint32_t IMAGE_SCN_MEM_WRITE              = 0x80000000;

// Helper macro
#define IMAGE_FIRST_SECTION(ntheader) ((IMAGE_SECTION_HEADER*)((uintptr_t)(ntheader) + \
    sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER) + \
    ((IMAGE_NT_HEADERS64*)(ntheader))->FileHeader.SizeOfOptionalHeader))

// Windows types for compatibility
typedef uint16_t WORD;
typedef uint32_t DWORD;
typedef uint64_t ULONGLONG;
typedef uint8_t BYTE;

#endif // PEDEFS_HPP
