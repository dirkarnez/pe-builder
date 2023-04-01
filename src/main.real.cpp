#include <iostream>
#include <map>
#include <numeric>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <vector>
#include <memory>
#include <algorithm>
#include <iterator>
#include <filesystem>
#include <string>
#include <stdint.h>
#include <math.h>
#include <regex>
#ifdef _MSC_VER

#include <stdlib.h>
#define bswap_32(x) _byteswap_ulong(x)
#define bswap_64(x) _byteswap_uint64(x)

#elif defined(__APPLE__)

// Mac OS X / Darwin features
#include <libkern/OSByteOrder.h>
#define bswap_32(x) OSSwapInt32(x)
#define bswap_64(x) OSSwapInt64(x)

#elif defined(__sun) || defined(sun)

#include <sys/byteorder.h>
#define bswap_32(x) BSWAP_32(x)
#define bswap_64(x) BSWAP_64(x)

#elif defined(__FreeBSD__)

#include <sys/endian.h>
#define bswap_32(x) bswap32(x)
#define bswap_64(x) bswap64(x)

#elif defined(__OpenBSD__)

#include <sys/types.h>
#define bswap_32(x) swap32(x)
#define bswap_64(x) swap64(x)

#elif defined(__NetBSD__)

#include <sys/types.h>
#include <machine/bswap.h>
#if defined(__BSWAP_RENAME) && !defined(__bswap_32)
#define bswap_32(x) bswap32(x)
#define bswap_64(x) bswap64(x)
#endif

#else

#include <byteswap.h>

#endif

using namespace std;

struct image_dos_header
{
	uint16_t e_signature;
	uint16_t e_cblp;
	uint16_t e_cp;
	uint16_t e_crlc;
	uint16_t e_cparhdr;
	uint16_t e_minalloc;
	uint16_t e_maxalloc;
	uint16_t e_ss;
	uint16_t e_sp;
	uint16_t e_csum;
	uint16_t e_ip;
	uint16_t e_cs;
	uint16_t e_lfarlc;
	uint16_t e_ovno;
	uint16_t e_res[4];
	uint16_t e_oemid;
	uint16_t e_oeminfo;
	uint16_t e_res2[10];
	int32_t e_lfanew;
};

struct image_file_header
{
	uint16_t Machine;
	uint16_t NumberOfSections;
	uint32_t TimeDateStamp;
	uint32_t PointerToSymbolTable;
	uint32_t NumberOfSymbols;
	uint16_t SizeOfOptionalHeader;
	uint16_t Characteristics;
};

struct image_data_directory
{
	uint32_t VirtualAddress;
	uint32_t Size;
};

struct image_optional_header32
{
	uint16_t Magic;
	uint8_t MajorLinkerVersion;
	uint8_t MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddressOfEntryPoint;
	uint32_t BaseOfCode;
	uint32_t BaseOfData;
	uint32_t ImageBase;
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
	uint32_t SizeOfStackReserve;
	uint32_t SizeOfStackCommit;
	uint32_t SizeOfHeapReserve;
	uint32_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumberOfRvaAndSizes;
	image_data_directory DataDirectory[16];
};

struct image_nt_headers32
{
	uint32_t Signature;
	image_file_header FileHeader;
	image_optional_header32 OptionalHeader;
};

struct image_optional_header32plus
{
	uint16_t Magic;
	uint8_t MajorLinkerVersion;
	uint8_t MinorLinkerVersion;
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
	image_data_directory DataDirectory[16];
};

struct image_nt_headers32plus
{
	uint32_t Signature;
	image_file_header FileHeader;
	image_optional_header32plus OptionalHeader;
};

struct image_section_header
{
	uint8_t Name[8]; // IMAGE_SIZEOF_SHORT_NAME
	union
	{
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

struct image_thunk_data64 {
    union {
        unsigned long long ForwarderString;  // PBYTE 
		unsigned long long Function;         // PDWORD
		unsigned long long Ordinal;
		unsigned long long AddressOfData;    // PIMAGE_IMPORT_BY_NAME
    } u1;
};


struct image_import_descriptor {
/*    union {
        unsigned long   Characteristics;            // 0 for terminating null import descriptor*/
        unsigned long   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    /*} DUMMYUNIONNAME;*/
    unsigned long   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    unsigned long   ForwarderChain;                 // -1 if no forwarders
    unsigned long   Name;
    unsigned long   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
};

enum class PEResult : uint32_t
{
	Success = 0,

	ErrorReadFileOpen = 1,
	ErrorReadFileAlloc = 2,
	ErrorReadFileData = 3,

	ErrorInvalidFileSignature = 10,
	ErrorInvalidFileTooManySections = 11,

	ErrorReadImportsTableOffset = 20,

	ErrorAddSectionMaxReached = 30,

	ErrorSaveFileCreate = 40

};

// Could be in theory 65535, on XP only 96 (see https://stackoverflow.com/questions/17466916/whats-the-maximum-number-of-sections-a-pe-can-have)
constexpr auto MAX_SECTIONS = 64;
constexpr auto IMPORT_SECTION_NAME = ".idata";
// constexpr auto RESERV_SECTION_NAME = "@.reserv";

constexpr auto TEXT_SECTION_NAME = "@.text";
constexpr auto DATA_SECTION_NAME = "@.data";

// struct PE_DOS_STUB
// {
//     uint8_t* RawData;
//     DWORD Size;
// };

struct PE_IMPORT_FUNCTION_ENTRY
{
	char *Name;
	int Id;
	PE_IMPORT_FUNCTION_ENTRY *Next;
};

struct PE_IMPORT_DLL_ENTRY
{
	char *Name;
	PE_IMPORT_FUNCTION_ENTRY *Functions;
	PE_IMPORT_DLL_ENTRY *Next;
};

struct PE_SECTION_ENTRY
{
	unsigned long Offset;
	int8_t *RawData;
	unsigned long Size;
};

struct DLL_IAT_ADDRESS
{
	std::string dll_name;
	std::map<std::string, unsigned long long> iat_map;
};

class EXE_STRING_TO_HEX_AND_ADDRESS
{
private:
	std::map<std::string, unsigned long long> string_to_file_offset;

public:
	std::vector<uint8_t> hex_for_data_section;
	void convert_and_store(const std::string &str)
	{
		// std::string a = "Console Message\r\n";
		std::vector<int> hex;
		std::transform(str.cbegin(), str.cend(), std::back_inserter(hex), [](char const &c)
					   { return static_cast<int>(c); });

		hex_for_data_section.insert(hex_for_data_section.end(), hex.begin(), hex.end());
		hex_for_data_section.push_back(0x0d); // \r
		hex_for_data_section.push_back(0x0a); // \n

		// std::for_each(hex_for_data_section.cbegin(), hex_for_data_section.cend(), [](const uint8_t &n)
		// 			{     std::cout << std::hex << static_cast<int>(n) << " " ; });
	}
};

class PEFile
{
public:
	PEFile();

private:
	void Initialize();

public:
	void New();
	PEResult SaveToFile(std::filesystem::path filePath);
	unsigned long GetFileAlignment();
	PE_SECTION_ENTRY GetSectionByIndex(int32_t index);
	int32_t AddSection(std::string_view name, unsigned long size, bool isExecutable);
	void AddImport(std::string_view dllName, char **functions, int functionCount);
	void Commit();

private:
	image_dos_header m_dosHeader;
	image_nt_headers32plus m_ntHeaders64;

	/***/

	image_section_header m_sectionTable[MAX_SECTIONS];
	// PE_SECTION_ENTRY m_reservedData;
	PE_SECTION_ENTRY m_sections[MAX_SECTIONS];
	PE_IMPORT_DLL_ENTRY m_additionalImports;

	DLL_IAT_ADDRESS dll_iat_address;

	int8_t *m_loadedPeFile;
	// PEResult ReadAll();
	// PEResult ReadHeaders();
	// void ReadSections();
	// PEResult ReadImports();

	void BuildImportTable();
	char *BuildAdditionalImports(unsigned long baseRVA);
	unsigned long CalculateAdditionalImportsSize(unsigned long &sizeDlls, unsigned long &sizeFunctions, unsigned long &sizeStrings);

	bool WritePadding(std::ofstream &file, long paddingSize);
	unsigned long AlignNumber(unsigned long number, unsigned long alignment);
	unsigned long RvaToOffset(unsigned long rva);
	unsigned long OffsetToRVA(unsigned long offset);

	// void ComputeReservedData();
	void ComputeHeaders();
	void ComputeSectionTable();
};

PE_SECTION_ENTRY PEFile::GetSectionByIndex(int32_t index)
{
	return m_sections[index];
}

PEFile::PEFile()
{
	Initialize();
}

void PEFile::Commit()
{
	// ComputeReservedData();
	ComputeHeaders();
	ComputeSectionTable();
}

void PEFile::Initialize()
{
	// if (m_loadedPeFile != nullptr)
	// {
	// 	VirtualFree(m_loadedPeFile, 0, MEM_RELEASE);
	// }

	// m_loadedPeFile = nullptr;
	memset(&m_additionalImports, 0, sizeof(PE_IMPORT_DLL_ENTRY));

	memset(m_sectionTable, 0, sizeof(m_sectionTable));
}

unsigned long PEFile::GetFileAlignment()
{
	return this->m_ntHeaders64.OptionalHeader.FileAlignment;
}

PEResult PEFile::SaveToFile(std::filesystem::path filePath)
{
	Commit();
	BuildImportTable();

	std::ofstream file(filePath, std::ios::binary | std::ios::ate);
	if (!file)
	{
		// std::cout << "!!!!e" << std::endl;
		return PEResult::ErrorSaveFileCreate;
	}

	file.write((char *)&this->m_dosHeader, sizeof(image_dos_header));

	std::vector<uint8_t> stub = {
		0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21, 0x54, 0x68,
		0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x67, 0x72, 0x61, 0x6d, 0x20, 0x63, 0x61, 0x6e, 0x6e, 0x6f,
		0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6e, 0x20, 0x69, 0x6e, 0x20, 0x44, 0x4f, 0x53, 0x20,
		0x6d, 0x6f, 0x64, 0x65, 0x2e, 0x0d, 0x0d, 0x0a, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	std::for_each(stub.begin(), stub.end(), [&file](uint8_t &n)
				  { file.write((char *)&n, 1); });

	file.write((char *)&m_ntHeaders64, sizeof(image_nt_headers32plus));
	file.write((char *)&m_sectionTable, m_ntHeaders64.FileHeader.NumberOfSections * sizeof(image_section_header));
	// file.write((char*)m_reservedData.RawData, m_reservedData.Size);

	// std::cout << "!!!!f" << std::endl;
	for (int i = 0; i < m_ntHeaders64.FileHeader.NumberOfSections; i++)
	{
		WritePadding(file, m_sectionTable[i].PointerToRawData - file.tellp());
		file.write((char *)m_sections[i].RawData, m_sections[i].Size);
	}

	// std::cout << "!!!!g" << std::endl;
	return PEResult::Success;
}

void PEFile::New()
{
	memset(&this->m_dosHeader, 0, sizeof(image_dos_header));
	this->m_dosHeader.e_signature = 0x5A4D;
	this->m_dosHeader.e_cblp = 0x0090;
	this->m_dosHeader.e_cp = 0x0003;
	this->m_dosHeader.e_crlc = 0x0000;
	this->m_dosHeader.e_cparhdr = 0x0004;
	this->m_dosHeader.e_minalloc = 0x0000;
	this->m_dosHeader.e_maxalloc = 0xFFFF;
	this->m_dosHeader.e_ss = 0x0000;

	this->m_dosHeader.e_sp = 0x00B8;
	this->m_dosHeader.e_csum = 0x0000;
	this->m_dosHeader.e_ip = 0x0000;
	this->m_dosHeader.e_cs = 0x0000;
	this->m_dosHeader.e_lfarlc = 0x0040;
	this->m_dosHeader.e_ovno = 0x0000;
	this->m_dosHeader.e_oemid = 0x0000;
	this->m_dosHeader.e_oeminfo = 0x0000;
	this->m_dosHeader.e_lfanew = 0x080; // The file offset of the PE header, relative to the beginning of the file.

	// std::cout << "e_lfanew = sizeof(IMAGE_DOS_HEADER)" << sizeof(IMAGE_DOS_HEADER) << std::endl;

	// std::cout << "PE -> DOS Header -> Created" << std::endl;

	memset(&this->m_ntHeaders64, 0, sizeof(image_nt_headers32plus));
	this->m_ntHeaders64.Signature = 0x00004550; //IMAGE_NT_SIGNATURE;
	this->m_ntHeaders64.FileHeader.Machine = 0x8664;// IMAGE_FILE_MACHINE_AMD64;

	this->m_ntHeaders64.FileHeader.TimeDateStamp = 0x00000000;													   // leave this
	this->m_ntHeaders64.FileHeader.PointerToSymbolTable = 0x0;													   // leave this
	this->m_ntHeaders64.FileHeader.NumberOfSymbols = 0x0;														   // leave this
	this->m_ntHeaders64.FileHeader.SizeOfOptionalHeader = sizeof(image_optional_header32plus);						   // leave this
	this->m_ntHeaders64.FileHeader.Characteristics = 0x0002 | 0x0020; //IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE; // declare this is a 64bit exe

	this->m_ntHeaders64.OptionalHeader.Magic = 0x20b; //IMAGE_NT_OPTIONAL_HDR64_MAGIC;

	// TODO
	// nt_h.OptionalHeader.SizeOfCode							= 0x00000200;  // dynamic
	this->m_ntHeaders64.OptionalHeader.SizeOfInitializedData = 0x00000400; // dynamic
	this->m_ntHeaders64.OptionalHeader.SizeOfUninitializedData = 0x0;	   // dynamic

	// TODO
	// this->m_ntHeaders64.OptionalHeader.BaseOfCode							= 0x1000;  // dynamic, normally same as AddressOfEntryPoint
	this->m_ntHeaders64.OptionalHeader.ImageBase = 0x400000;			  // leave it
	this->m_ntHeaders64.OptionalHeader.SectionAlignment = 0x1000;		  // dynamic
	this->m_ntHeaders64.OptionalHeader.FileAlignment = 0x200;			  // dynamic
	this->m_ntHeaders64.OptionalHeader.MajorOperatingSystemVersion = 0x5; // leave it
	this->m_ntHeaders64.OptionalHeader.MinorOperatingSystemVersion = 0x2; // leave it
	this->m_ntHeaders64.OptionalHeader.MajorImageVersion = 0;			  // leave it
	this->m_ntHeaders64.OptionalHeader.MinorImageVersion = 0;			  // leave it
	this->m_ntHeaders64.OptionalHeader.MajorSubsystemVersion = 0x5;		  // leave it
	this->m_ntHeaders64.OptionalHeader.MinorSubsystemVersion = 0x2;		  // leave it
	this->m_ntHeaders64.OptionalHeader.Win32VersionValue = 0;			  // leave it

	/*
	The combined size of the following items, rounded to a multiple of the value specified in the FileAlignment member.

		e_lfanew member of IMAGE_DOS_HEADER
		4 byte signature
		size of IMAGE_FILE_HEADER
		size of optional header
		size of all section headers
	*/

	/*
	The image file checksum. The following files are validated at load time: all drivers, any DLL loaded at boot time, and any DLL loaded into a critical system process.
	*/
	this->m_ntHeaders64.OptionalHeader.CheckSum = 0; // 0x0000FB72; // dynamic, Must Update
	this->m_ntHeaders64.OptionalHeader.Subsystem = 3; //IMAGE_SUBSYSTEM_WINDOWS_CUI;
	this->m_ntHeaders64.OptionalHeader.DllCharacteristics = 0x0000;							   // leave it
	this->m_ntHeaders64.OptionalHeader.SizeOfStackReserve = 0x0000000000100000;				   // leave it
	this->m_ntHeaders64.OptionalHeader.SizeOfStackCommit = 0x0000000000001000;				   // leave it
	this->m_ntHeaders64.OptionalHeader.SizeOfHeapReserve = 0x0000000000100000;				   // leave it
	this->m_ntHeaders64.OptionalHeader.SizeOfHeapCommit = 0x0000000000001000;				   // leave it
	this->m_ntHeaders64.OptionalHeader.LoaderFlags = 0x00000000;							   // leave it
	this->m_ntHeaders64.OptionalHeader.NumberOfRvaAndSizes = 16; //IMAGE_NUMBEROF_DIRECTORY_ENTRIES; // leave it

	// std::cout << "SectionAlignment" << this->m_ntHeaders64.OptionalHeader.SectionAlignment << std::endl;
	// std::cout << "PE -> PE Header -> Created" << std::endl;
}

void PEFile::AddImport(std::string_view dllName, char **functions, int functionCount)
{
	PE_IMPORT_DLL_ENTRY *importDll = &this->m_additionalImports;
	PE_IMPORT_FUNCTION_ENTRY *importFunction;

	if (m_additionalImports.Name != nullptr)
	{
		while (importDll->Next != nullptr)
		{
			importDll = importDll->Next;
		}
		importDll->Next = new PE_IMPORT_DLL_ENTRY();
		importDll = importDll->Next;
	}
	// Copy dll name and alloc it on the heap
	size_t sizeOfName = dllName.length() + 1;
	char *allocedName = new char[sizeOfName];
	strncpy(allocedName, std::string(dllName).c_str() , sizeOfName);
	
	//strcpy_s(allocedName, sizeOfName, dllName.data());
	
	// strcpy(allocedName, dllName.data());
	importDll->Name = allocedName;
	importDll->Functions = new PE_IMPORT_FUNCTION_ENTRY();
	importDll->Next = nullptr;

	importFunction = importDll->Functions;
	importFunction->Name = functions[0];
	for (int i = 1; i < functionCount; i++)
	{
		importFunction->Next = new PE_IMPORT_FUNCTION_ENTRY();
		importFunction = importFunction->Next;
		importFunction->Name = functions[i];
	}
	importFunction->Next = nullptr;
}

void PEFile::BuildImportTable()
{
	// std::cout << "!!!!qwrew" << std::endl;
	// Calculate new import size
	unsigned long sizeDlls = 0;
	unsigned long sizeFunctions = 0;
	unsigned long sizeStrings = 0;
	unsigned long newImportsSize = CalculateAdditionalImportsSize(sizeDlls, sizeFunctions, sizeStrings);

	// Calculate current import size
	// DWORD currentImportDllsSize = 0;
	// PE_IMPORT_DLL_ENTRY* importDll = &this->m_importTable;
	// while (importDll != nullptr)
	// {
	//     currentImportDllsSize += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	//     importDll = importDll->Next;
	// }

	// Overwrite import section
	int index = AddSection(IMPORT_SECTION_NAME, /*currentImportDllsSize +*/ newImportsSize, false);
	// std::cout << "!!!!index" << index << std::endl;

	// Copy old imports
	// DWORD oldImportTableRVA = m_ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	// DWORD oldImportTableOffset = RvaToOffset(oldImportTableRVA);
	// memcpy(m_sections[index].RawData, m_loadedPeFile + oldImportTableOffset, currentImportDllsSize);

	// Copy new imports into the import section

	// std::cout << "m_sectionTable[index].VirtualAddress" << m_sectionTable[index].VirtualAddress << std::endl;
	char *newImportsData = BuildAdditionalImports(m_sectionTable[index].VirtualAddress /* + currentImportDllsSize*/);
	memcpy(m_sections[index].RawData /* + currentImportDllsSize*/, newImportsData, newImportsSize);
	// std::cout << "m_sections[index].Size" << m_sections[index].Size << std::endl;

	m_ntHeaders64.OptionalHeader.DataDirectory[1/*IMAGE_DIRECTORY_ENTRY_IMPORT*/].VirtualAddress = m_sectionTable[index].VirtualAddress;
	m_ntHeaders64.OptionalHeader.DataDirectory[1/*IMAGE_DIRECTORY_ENTRY_IMPORT*/].Size = m_sectionTable[index].Misc.VirtualSize;
	m_ntHeaders64.OptionalHeader.DataDirectory[12 /*IMAGE_DIRECTORY_ENTRY_IAT*/].VirtualAddress = 0;
	m_ntHeaders64.OptionalHeader.DataDirectory[12 /*IMAGE_DIRECTORY_ENTRY_IAT*/].Size = 0;

	// std::cout << "!!!!iu" << std::endl;
}

char *PEFile::BuildAdditionalImports(unsigned long baseRVA)
{
	Commit();

	image_import_descriptor importDesc;
	image_thunk_data64 importThunk;
	PE_IMPORT_DLL_ENTRY *importDll;
	PE_IMPORT_FUNCTION_ENTRY *importFunction;

	unsigned long sizeDlls = 0;
	unsigned long sizeFunctions = 0;
	unsigned long sizeStrings = 0;
	unsigned long newImportsSize = CalculateAdditionalImportsSize(sizeDlls, sizeFunctions, sizeStrings);
	unsigned long offsetDlls = 0;
	unsigned long offsetFunctions = sizeDlls;
	unsigned long offsetStrings = sizeDlls + 2 * sizeFunctions;

	char *buffer = new char[newImportsSize];
	memset(buffer, 0, newImportsSize);

	importDll = &m_additionalImports;
	while (importDll != nullptr)
	{
		memset(&importDesc, 0, sizeof(image_import_descriptor));
		importDesc.OriginalFirstThunk = baseRVA + offsetFunctions;
		importDesc.FirstThunk = baseRVA + offsetFunctions + sizeFunctions;

		dll_iat_address.dll_name = string(importDll->Name);

		importDesc.Name = baseRVA + offsetStrings;
		memcpy(buffer + offsetStrings, importDll->Name, strlen(importDll->Name));
		offsetStrings += AlignNumber((unsigned long)strlen(importDll->Name) + 1, 2);

		memcpy(buffer + offsetDlls, &importDesc, sizeof(image_import_descriptor));
		offsetDlls += sizeof(image_import_descriptor);

		importFunction = importDll->Functions;
		for (int i = 0; importFunction != nullptr; i++)
		{
			const auto function_name = string(importFunction->Name);
			const auto iat_address = this->m_ntHeaders64.OptionalHeader.ImageBase + importDesc.FirstThunk + (i * sizeof(unsigned long long));
			dll_iat_address.iat_map[function_name] = iat_address;

			// std::cout << "dll_iat_address.dll_name: " << dll_iat_address.dll_name << "function_name: " << function_name <<  "iat_address in (hex): " << std::hex << iat_address << std::endl;

			memset(&importThunk, 0, sizeof(image_thunk_data64));
			if (importFunction->Id != 0)
			{
				importThunk.u1.Ordinal = importFunction->Id | 0x8000000000000000; //IMAGE_ORDINAL_FLAG64 //;
			}
			else
			{
				importThunk.u1.AddressOfData = baseRVA + offsetStrings;
				memcpy(buffer + offsetStrings + 2, importFunction->Name, strlen(importFunction->Name));
				offsetStrings += 2 + AlignNumber((unsigned long)strlen(importFunction->Name) + 1, 2);
			}

			memcpy(buffer + offsetFunctions, &importThunk, sizeof(image_thunk_data64));
			memcpy(buffer + offsetFunctions + sizeFunctions, &importThunk, sizeof(image_thunk_data64));
			offsetFunctions += sizeof(image_thunk_data64);

			importFunction = importFunction->Next;
		}
		offsetFunctions += sizeof(image_thunk_data64);

		importDll = importDll->Next;
	}

	return buffer;
}

unsigned long PEFile::CalculateAdditionalImportsSize(unsigned long &sizeDlls, unsigned long &sizeFunctions, unsigned long &sizeStrings)
{
	PE_IMPORT_DLL_ENTRY *importDll = &this->m_additionalImports;
	PE_IMPORT_FUNCTION_ENTRY *importFunction;

	// Calculate size
	while (importDll != nullptr)
	{
		sizeDlls += sizeof(image_import_descriptor);
		sizeStrings += AlignNumber((unsigned long)strlen(importDll->Name) + 1, 2);
		importFunction = importDll->Functions;
		while (importFunction != nullptr)
		{
			sizeFunctions += sizeof(image_thunk_data64);
			if (importFunction->Id == 0)
			{
				sizeStrings += 2 + AlignNumber((unsigned long)strlen(importFunction->Name) + 1, 2);
			}
			importFunction = importFunction->Next;
		}
		sizeFunctions += sizeof(image_thunk_data64);
		importDll = importDll->Next;
	}
	sizeDlls += sizeof(image_import_descriptor);

	return sizeDlls + 2 * sizeFunctions + sizeStrings;
}

bool PEFile::WritePadding(std::ofstream &file, long paddingSize)
{
	if (paddingSize <= 0)
		return false;

	char *padding = new char[paddingSize];
	memset(padding, 0, paddingSize);
	if (file.write(padding, paddingSize))
	{
		return false;
	}
	delete[] padding;

	return true;
}

unsigned long PEFile::AlignNumber(unsigned long number, unsigned long alignment)
{
	return (unsigned long)(ceil(number / (alignment + 0.0)) * alignment);
}

unsigned long PEFile::RvaToOffset(unsigned long rva)
{
	for (int i = 0; i < m_ntHeaders64.FileHeader.NumberOfSections; i++)
	{
		if (rva >= m_sectionTable[i].VirtualAddress && rva < m_sectionTable[i].VirtualAddress + m_sectionTable[i].Misc.VirtualSize)
		{
			return m_sectionTable[i].PointerToRawData + (rva - m_sectionTable[i].VirtualAddress);
		}
	}

	return 0;
}

int32_t PEFile::AddSection(std::string_view name, unsigned long size, bool isExecutable)
{
	// Return if max sections are reached
	if (m_ntHeaders64.FileHeader.NumberOfSections == MAX_SECTIONS)
	{
		return -1;
	}

	PE_SECTION_ENTRY &newSection = m_sections[m_ntHeaders64.FileHeader.NumberOfSections];
	image_section_header &newSectionHeader = m_sectionTable[m_ntHeaders64.FileHeader.NumberOfSections];
	image_section_header &lastSectionHeader = m_sectionTable[m_ntHeaders64.FileHeader.NumberOfSections - 1];

	unsigned long sectionSize = AlignNumber(size, m_ntHeaders64.OptionalHeader.FileAlignment);
	sectionSize = sectionSize > 0 ? sectionSize : m_ntHeaders64.OptionalHeader.FileAlignment;

	unsigned long virtualSize = AlignNumber(sectionSize, m_ntHeaders64.OptionalHeader.SectionAlignment);
	virtualSize = virtualSize > 0 ? virtualSize : m_ntHeaders64.OptionalHeader.SectionAlignment;

	unsigned long sectionOffset = AlignNumber(lastSectionHeader.PointerToRawData + lastSectionHeader.SizeOfRawData, m_ntHeaders64.OptionalHeader.FileAlignment);
	sectionOffset = sectionOffset > 0 ? sectionOffset : m_ntHeaders64.OptionalHeader.FileAlignment;

	unsigned long virtualOffset = AlignNumber(lastSectionHeader.VirtualAddress + lastSectionHeader.Misc.VirtualSize, m_ntHeaders64.OptionalHeader.SectionAlignment);
	virtualOffset = virtualOffset > 0 ? virtualOffset : m_ntHeaders64.OptionalHeader.SectionAlignment;

	memset(&newSectionHeader, 0, sizeof(image_section_header));
	memcpy(newSectionHeader.Name, name.data(), name.length() > 8 ? 8 : name.length());

	newSectionHeader.PointerToRawData = sectionOffset;
	newSectionHeader.VirtualAddress = virtualOffset;
	newSectionHeader.SizeOfRawData = sectionSize;
	newSectionHeader.Misc.VirtualSize = virtualSize;
	newSectionHeader.Characteristics = 0x40000000 | 0x80000000 | 0x00000040; //IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA;

	if (isExecutable)
	{
		newSectionHeader.Characteristics = 0x40000000 | 0x00000020 | 0x20000000; // IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;
		this->m_ntHeaders64.OptionalHeader.AddressOfEntryPoint = newSectionHeader.VirtualAddress;
		this->m_ntHeaders64.OptionalHeader.BaseOfCode = this->m_ntHeaders64.OptionalHeader.AddressOfEntryPoint;
		// std::cout << "!!!!isExecutable" << this->m_ntHeaders64.OptionalHeader.AddressOfEntryPoint << std::endl;
	}

	newSection.RawData = (int8_t *)malloc(sizeof(int8_t *) * sectionSize);
	memset(newSection.RawData, 0, sectionSize);
	// newSection.RawData = (int8_t *)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, sectionSize);
	newSection.Size = sectionSize;
	// free(newSection.RawData);

	m_ntHeaders64.FileHeader.NumberOfSections++;
	// if (m_reservedData.Size > 0)
	// {
	//     m_reservedData.Size -= sizeof(IMAGE_SECTION_HEADER);
	// }

	// Return the new section index
	return m_ntHeaders64.FileHeader.NumberOfSections - 1;
}

unsigned long PEFile::OffsetToRVA(unsigned long offset)
{
	for (int i = 0; i < m_ntHeaders64.FileHeader.NumberOfSections; i++)
	{
		if (offset >= m_sectionTable[i].PointerToRawData &&
			offset < m_sectionTable[i].PointerToRawData + m_sectionTable[i].SizeOfRawData)
		{
			return m_sectionTable[i].VirtualAddress + (offset - m_sectionTable[i].PointerToRawData);
		}
	}

	return 0;
}

// void PEFile::ComputeReservedData()
// {
// 	std::cout << "!!!!bv" << std::endl;
//     DWORD dirIndex = 0;
//     for (dirIndex = 0; dirIndex < m_ntHeaders64.OptionalHeader.NumberOfRvaAndSizes; dirIndex++)
//     {
//         if (m_ntHeaders64.OptionalHeader.DataDirectory[dirIndex].VirtualAddress > 0 &&
//             m_ntHeaders64.OptionalHeader.DataDirectory[dirIndex].VirtualAddress >= m_reservedData.Offset &&
//             m_ntHeaders64.OptionalHeader.DataDirectory[dirIndex].VirtualAddress < m_reservedData.Size)
//         {
//             break;
//         }
//     }

//     if (dirIndex == m_ntHeaders64.OptionalHeader.NumberOfRvaAndSizes)
//     {
//         return;
//     }

//     int sectionIndex = AddSection(RESERV_SECTION_NAME, m_reservedData.Size, false);
//     memcpy(m_sections[sectionIndex].RawData, m_reservedData.RawData, m_reservedData.Size);

//     for (dirIndex = 0; dirIndex < m_ntHeaders64.OptionalHeader.NumberOfRvaAndSizes; dirIndex++)
//     {
//         if (m_ntHeaders64.OptionalHeader.DataDirectory[dirIndex].VirtualAddress > 0 &&
//             m_ntHeaders64.OptionalHeader.DataDirectory[dirIndex].VirtualAddress >= m_reservedData.Offset &&
//             m_ntHeaders64.OptionalHeader.DataDirectory[dirIndex].VirtualAddress < m_reservedData.Size)
//         {
//             m_ntHeaders64.OptionalHeader.DataDirectory[dirIndex].VirtualAddress += m_sectionTable[sectionIndex].VirtualAddress - m_reservedData.Offset;
//         }
//     }

//     m_reservedData.Size = 0;
// 	std::cout << "!!!!bvc" << std::endl;
// }

void PEFile::ComputeHeaders()
{
	// std::cout << "!!!!uy" << std::endl;
	m_ntHeaders64.OptionalHeader.SizeOfHeaders = AlignNumber(m_dosHeader.e_lfanew + m_ntHeaders64.FileHeader.SizeOfOptionalHeader +
																 m_ntHeaders64.FileHeader.NumberOfSections * sizeof(image_section_header),
															 m_ntHeaders64.OptionalHeader.FileAlignment);

	unsigned long imageSize = m_ntHeaders64.OptionalHeader.SizeOfHeaders;
	for (int i = 0; i < m_ntHeaders64.FileHeader.NumberOfSections; i++)
	{
		imageSize += AlignNumber(m_sectionTable[i].Misc.VirtualSize, m_ntHeaders64.OptionalHeader.SectionAlignment);
	}
	m_ntHeaders64.OptionalHeader.SizeOfImage = AlignNumber(imageSize, m_ntHeaders64.OptionalHeader.SectionAlignment);

	m_ntHeaders64.OptionalHeader.DataDirectory[11 /*IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT*/].VirtualAddress = 0;
	m_ntHeaders64.OptionalHeader.DataDirectory[11 /*IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT*/].Size = 0;
	// std::cout << "!!!!vc" << std::endl;
}

void PEFile::ComputeSectionTable()
{
	// std::cout << "!!!!rr" << std::endl;
	unsigned long offset = m_ntHeaders64.OptionalHeader.SizeOfHeaders;
	for (int i = 0; i < m_ntHeaders64.FileHeader.NumberOfSections; i++)
	{
		m_sectionTable[i].Characteristics |= 0x80000000; //IMAGE_SCN_MEM_WRITE;
		offset = AlignNumber(offset, m_ntHeaders64.OptionalHeader.FileAlignment);
		m_sectionTable[i].PointerToRawData = offset;
		offset += m_sectionTable[i].SizeOfRawData;
	}
	// std::cout << "!!!!pp" << std::endl;
}

// template <typename Ptr>
// size_t StrCpyT(Ptr p, const std::string &s)
// {
// 	strncpy(reinterpret_cast<char *>(p), s.c_str(), s.length());
// 	return s.size();
// }

// PBYTE = unsigned char*
// DWORD = unsigned long

/*
Same as RVA, except that the base address of the image file is not subtracted.
The address is called a VA because Windows creates a distinct VA space for each process,
independent of physical memory. For almost all purposes,
a VA should be considered just an address.
A VA is not as predictable as an RVA because
the loader might not load the image at its preferred location.
*/
// #define ToVA(import_section_header_ptr, ptr) (DWORD(ptr) - DWORD(&dos_h) - import_section_header_ptr->PointerToRawData + import_section_header_ptr->VirtualAddress + nt_h.OptionalHeader.ImageBase)

// #define ToRVA(pSH, p) (DWORD((((ULONGLONG)(p)) - ((ULONGLONG)(&dos_h)) - pSH->PointerToRawData + pSH->VirtualAddress)))
// #define ToVA(pSH, p) (((ULONGLONG)(p)) - ((ULONGLONG)(&dos_h)) - pSH->PointerToRawData + pSH->VirtualAddress + nt_h.OptionalHeader.ImageBase)

// #define VU_ALIGN_UP(v, a) (((v) + ((a) - (1))) & ~((a) - (1)))

// void import_GetStdHandle() {
//  	// The DLL that the exe file imports functions from.
// 	const char* dll_name = "kernel32.dll";

// 	// The names of the functions that the exe file imports from the DLL.
// 	const char* function_names[] = {
// 		"GetStdHandle"
// 		// "GetLastError",
// 		// "GetCurrentProcessId",
// 		// "GetCurrentThreadId",
// 		// "GetTickCount",
// 		// "GetSystemTimeAsFileTime",
// 		// "GetCurrentProcess"
// 	};

// 	// Create the import table for the exe file.
// 	IMAGE_IMPORT_DESCRIPTOR import_table[2] = {};

// 	memset(&import_table[0], 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
// 	import_table[0].Name = (DWORD)(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER)); // The file offset of the DLL name in the exe file.
// 	// RVA of the IAT
// 	import_table[0].FirstThunk = (DWORD)(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) + sizeof(IMAGE_IMPORT_DESCRIPTOR)); // The file offset of the import lookup table.
// 	// RVA of the ILT (lookup)
// 	import_table[0].OriginalFirstThunk = (DWORD)(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) + sizeof(IMAGE_IMPORT_DESCRIPTOR)); // The file offset of the import lookup table.

// 	// Create the import lookup table for the exe file.
// 	std::vector<IMAGE_THUNK_DATA64> import_lookup_table;
// 	for (const char* function_name : function_names) {
// 		// Create an IMAGE_IMPORT_BY_NAME structure for the function.
// 		size_t function_name_length = strlen(function_name);
// 		std::vector<uint8_t> function_name_data(sizeof(IMAGE_IMPORT_BY_NAME) + function_name_length);
// 		PIMAGE_IMPORT_BY_NAME function_name_struct = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(function_name_data.data());
// 		function_name_struct->Hint = 0; // Not necessary // The hint, which is a 16-bit index into the export table of the DLL.
// 		memcpy(function_name_struct->Name, function_name, function_name_length + 1); // The name of the imported function

// 		IMAGE_THUNK_DATA64 thunk_data_64;
// 		memset(&thunk_data_64, 0, sizeof(thunk_data_64));
// 		thunk_data_64.u1.AddressOfData = (ULONGLONG)function_name_struct;  // RVA to an IMAGE_IMPORT_BY_NAME with the imported API name
// 	}

// 	memset(&import_table[1], 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
// }
string readFile(const string &fileName) {
	ifstream t(fileName);
	stringstream buffer;
	buffer << t.rdbuf();
	return buffer.str();
}

#include <climits>

template <typename T>
T swap_endian(T u)
{
	static_assert(CHAR_BIT == 8, "CHAR_BIT != 8");

	union
	{
		T u;
		unsigned char u8[sizeof(T)];
	} source, dest;

	source.u = u;

	for (size_t k = 0; k < sizeof(T); k++)
		dest.u8[k] = source.u8[sizeof(T) - k - 1];

	return dest.u;
}

std::vector<std::string> parseFile(const string &fileName)
{
	std::vector<std::string> cout_content_list;

	// const std::string text = "standard.output(\"1\");standard.output(\"2\");";
	const std::string text = readFile(fileName);

	const std::regex ws_re("\\s*;\\s*"); // whitespace

	const std::regex a = std::regex("println\\(\"([^\"]+)\"\\)"); // or std::regex("standard\\.output\\(\"([^\"]+)\"\\)");

	auto b = std::sregex_token_iterator(text.begin(), text.end(), ws_re, -1);
	const std::sregex_token_iterator end;
	std::smatch base_match;

	while (b != end)
	{
		const std::string statement = *b++;
		std::regex_match(statement, base_match, a);
		// std::cout << statement;

		if (base_match.size() == 2)
		{
			std::ssub_match base_sub_match = base_match[1];
			std::string base = base_sub_match.str();
			// std::cout << " has a base of " << base;
			cout_content_list.push_back(base);
		}
		// std::cout << std::endl;
	}
	return cout_content_list;
}

uint8_t getFirst(const unsigned long a)
{
	return (
			   a & (1 << 24) |
			   a & (1 << 25) |
			   a & (1 << 26) |
			   a & (1 << 27) |
			   a & (1 << 28) |
			   a & (1 << 29) |
			   a & (1 << 30) |
			   a & (1 << 31)) >>
		   24;
}

uint8_t getSecond(const unsigned long a)
{
	return (
			   a & (1 << 16) |
			   a & (1 << 17) |
			   a & (1 << 18) |
			   a & (1 << 19) |
			   a & (1 << 20) |
			   a & (1 << 21) |
			   a & (1 << 22) |
			   a & (1 << 23)) >>
		   16;
}

uint8_t getThird(const unsigned long a)
{
	return (
			   a & (1 << 8) |
			   a & (1 << 9) |
			   a & (1 << 10) |
			   a & (1 << 11) |
			   a & (1 << 12) |
			   a & (1 << 13) |
			   a & (1 << 14) |
			   a & (1 << 15)) >>
		   8;
}

uint8_t getForth(const unsigned long a)
{
	return (
			   a & (1 << 0) |
			   a & (1 << 1) |
			   a & (1 << 2) |
			   a & (1 << 3) |
			   a & (1 << 4) |
			   a & (1 << 5) |
			   a & (1 << 6) |
			   a & (1 << 7)) >>
		   0;
}

int main()
{
	std::vector<std::string> cout_content_list = parseFile("main.hahahaha");

	// std::cout << cout_content_list.size() << std::endl;

	EXE_STRING_TO_HEX_AND_ADDRESS exe_string_to_hex_and_address;

	// std::vector<uint8_t> code = {
	// 	0x48, 0x83, 0xEC, 0x08, 								//	sub rsp, 0x8	// Align the stack to a multiple of 16 bytes
	//
	// 	0x48, 0x83, 0xEC, 0x20,									//	sub rsp, 0x20	// 32 bytes of shadow space
	// 	0xB9, 0xF5, 0xFF, 0xFF, 0xFF,							//	mov ecx, -0xb
	// 	0x48, 0xC7, 0xC0, 0x48, 0x30, 0x40, 0x00, //403048		//	mov rax, 0x403048
	// 	0xFF, 0x10,												//	call [rax]
	// 	0x48, 0x89, 0x05, 0xFB, 0x0F, 0x00, 0x00,				//	mov [rip+0xffb], rax // need to change
	// 	0x48, 0x83, 0xC4, 0x20,									//	add rsp, 0x20
	// 	0x48, 0x83, 0xEC, 0x30,									//	sub rsp, 0x30 	// Shadow space + 5th parameter + align stack
	// 	0x48, 0x8B, 0x0D, 0xEC, 0x0F, 0x00, 0x00,				//	mov rcx, [rip+0xfec] // need to change
	//
	// 	0x48, 0x8D, 0x15, 0xCD, 0x0F, 0x00, 0x00,				//	lea rdx, [rip+0xfcd] //
	//*// 	0x41, 0xB8, 0x14, 0x00, 0x00, 0x00,						//	mov r8d, 0x14

	//*// 	0x4C, 0x8D, 0x0D, 0xE0, 0x0F, 0x00, 0x00,				//	lea r9, [rip+0xfe0]	// Number(0x402000 - 0x401033).toString(16)
	// 	0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,	//	mov qword [rsp+0x20], 0x0
	// 	0x48, 0xC7, 0xC0, 0x50, 0x30, 0x40, 0x00, //403050		//	mov rax, 0x403050
	// 	0xFF, 0x10,												//	call [rax]
	// 	0x48, 0x83, 0xC4, 0x30,									//	add rsp, 0x30
	//
	//
	//
	// 	0x31, 0xC9,												//	xor ecx, ecx
	// 	0x48, 0xC7, 0xC0, 0x58, 0x30, 0x40, 0x00,  //403058		//	mov rax, 0x403058
	// 	0xFF, 0x10												//	call [rax]
	// };

	std::vector<uint8_t> code = {
		0x48, 0x83, 0xEC, 0x08, //	sub rsp, 0x8	// Align the stack to a multiple of 16 bytes
	};
	/************************/

	const unsigned long long text_starting = 0x401000;
	const unsigned long long data_starting = 0x402000;

	uint8_t i = 0;
	std::for_each(cout_content_list.cbegin(), cout_content_list.cend(),
				  [&](const std::string &elem)
				  {
					  std::vector<uint8_t> elem_code_1 = {
						  0x48, 0x83, 0xEC, 0x20,					//	sub rsp, 0x20	// 32 bytes of shadow space
						  0xB9, 0xF5, 0xFF, 0xFF, 0xFF,				//	mov ecx, -0xb
						  0x48, 0xC7, 0xC0, 0x48, 0x30, 0x40, 0x00, // 403048		//	mov rax, 0x403048
						  0xFF, 0x10,								//	call [rax]
						  0x48, 0x89, 0x05, 0x00, 0x00, 0x00, 0x00	// 0xFB, 0x0F, 0x00, 0x00,				//	mov [rip+0xffb], rax // need to change
					  };
					  code.insert(code.end(), elem_code_1.begin(), elem_code_1.end());

					  const unsigned long long absolute_location_to_store_standard_handle = 0x402030;
					  unsigned long long relative_location_to_store_standard_handle = absolute_location_to_store_standard_handle - (text_starting + code.size());
					  // std::cout << std::hex << relative_location_to_store_standard_handle << std::endl;

					  code.at(code.size() - 4) = getFirst(bswap_32(relative_location_to_store_standard_handle));
					  code.at(code.size() - 3) = getSecond(bswap_32(relative_location_to_store_standard_handle));
					  code.at(code.size() - 2) = getThird(bswap_32(relative_location_to_store_standard_handle));
					  code.at(code.size() - 1) = getForth(bswap_32(relative_location_to_store_standard_handle));

					  std::vector<uint8_t> elem_code_2 = {
						  0x48, 0x83, 0xC4, 0x20,					//	add rsp, 0x20
						  0x48, 0x83, 0xEC, 0x30,					//	sub rsp, 0x30 	// Shadow space + 5th parameter + align stack
						  0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00, //	mov rcx, [rip+0xfec] // need to change
					  };
					  code.insert(code.end(), elem_code_2.begin(), elem_code_2.end());

					  relative_location_to_store_standard_handle = absolute_location_to_store_standard_handle - (text_starting + code.size());
					  // std::cout << std::hex << relative_location_to_store_standard_handle << std::endl;
					  code.at(code.size() - 4) = getFirst(bswap_32(relative_location_to_store_standard_handle));
					  code.at(code.size() - 3) = getSecond(bswap_32(relative_location_to_store_standard_handle));
					  code.at(code.size() - 2) = getThird(bswap_32(relative_location_to_store_standard_handle));
					  code.at(code.size() - 1) = getForth(bswap_32(relative_location_to_store_standard_handle));

					  std::vector<uint8_t> elem_code_3 = {
						  0x48, 0x8D, 0x15, 0x00, 0x00, 0x00, 0x00, //	lea rdx, [rip+0xfcd] //
					  };
					  code.insert(code.end(), elem_code_3.begin(), elem_code_3.end());

					  const unsigned long long offset = std::accumulate(cout_content_list.begin(), cout_content_list.begin() + i, 0, [](int previous, const std::string &current)
																		{   
			//return std::move(a) + '-' + std::to_string(b);
			return previous + current.length() + 2; });

					  unsigned long long relative_location_to_store_element = (data_starting + offset) - (text_starting + code.size());
					  // std::cout << std::hex << relative_location_to_store_element << std::endl;
					  code.at(code.size() - 4) = getFirst(bswap_32(relative_location_to_store_element));
					  code.at(code.size() - 3) = getSecond(bswap_32(relative_location_to_store_element));
					  code.at(code.size() - 2) = getThird(bswap_32(relative_location_to_store_element));
					  code.at(code.size() - 1) = getForth(bswap_32(relative_location_to_store_element));

					  std::vector<uint8_t> elem_code_4 = {
						  0x41, 0xB8, 0x00, 0x00, 0x00, 0x00, //	mov r8d, 0x14
					  };
					  code.insert(code.end(), elem_code_4.begin(), elem_code_4.end());

					  unsigned long long elem_length_with_newline = elem.length() + 2;
					  code.at(code.size() - 4) = getFirst(bswap_32(elem_length_with_newline));
					  code.at(code.size() - 3) = getSecond(bswap_32(elem_length_with_newline));
					  code.at(code.size() - 2) = getThird(bswap_32(elem_length_with_newline));
					  code.at(code.size() - 1) = getForth(bswap_32(elem_length_with_newline));

					  std::vector<uint8_t> elem_code_5 = {
						  0x4C, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, //	lea r9, [rip+0xfe0]	// Number(0x402000 - 0x401033).toString(16)
					  };

					  code.insert(code.end(), elem_code_5.begin(), elem_code_5.end());

					  const unsigned long long absolute_location_to_store_number_of_bytes_written = 0x402040;
					  unsigned long long relative_location_to_store_number_of_bytes_written = absolute_location_to_store_number_of_bytes_written - (text_starting + code.size());
					  // std::cout << std::hex << relative_location_to_store_number_of_bytes_written << std::endl;
					  code.at(code.size() - 4) = getFirst(bswap_32(relative_location_to_store_number_of_bytes_written));
					  code.at(code.size() - 3) = getSecond(bswap_32(relative_location_to_store_number_of_bytes_written));
					  code.at(code.size() - 2) = getThird(bswap_32(relative_location_to_store_number_of_bytes_written));
					  code.at(code.size() - 1) = getForth(bswap_32(relative_location_to_store_number_of_bytes_written));

					  std::vector<uint8_t> elem_code_6 = {
						  0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, //	mov qword [rsp+0x20], 0x0
						  0x48, 0xC7, 0xC0, 0x50, 0x30, 0x40, 0x00,				// 403050		//	mov rax, 0x403050
						  0xFF, 0x10,											//	call [rax]
						  0x48, 0x83, 0xC4, 0x30,								//	add rsp, 0x30
					  };
					  code.insert(code.end(), elem_code_6.begin(), elem_code_6.end());
					  i++;
				  });

	/************************/
	// exit
	std::vector<uint8_t> exit = {
		0x31, 0xC9,								  //	xor ecx, ecx
		0x48, 0xC7, 0xC0, 0x58, 0x30, 0x40, 0x00, // 403058		//	mov rax, 0x403058
		0xFF, 0x10								  //	call [rax]
	};
	code.insert(code.end(), exit.begin(), exit.end());

	std::for_each(cout_content_list.cbegin(), cout_content_list.cend(), [&exe_string_to_hex_and_address](const std::string &elem)
				  {
		//std::cout << elem << std::endl;
		exe_string_to_hex_and_address.convert_and_store(elem); });

	PEFile pe;
	pe.New();

	// Add the exported functions of your DLL
	const char *functions[] = {"GetStdHandle", "WriteFile", "ExitProcess"};

	// Add the import to the PE file
	pe.AddImport("kernel32.dll", (char **)functions, 3);
	// std::cout << "Added imports to PE file" << std::endl;

	int textSectionIndex = pe.AddSection(TEXT_SECTION_NAME, pe.GetFileAlignment(), true);
	// std::cout << "!!!!a" << std::endl;
	auto codeSection = pe.GetSectionByIndex(textSectionIndex);

	// std::cout << " sizeof(ULONGLONG)" << sizeof(ULONGLONG) << std::endl;

	// 0x48, 0x83, 0xC4, 0x48,					  // add rsp, 0x48; Stack unwind
	// 0x48, 0x31, 0xC9,						  // xor rcx, rcx; hWnd
	// 0x48, 0xC7, 0xC2, 0x10, 0x20, 0x40, 0x00, // mov rdx, Message(0x402010) (offset 10)
	// 0x49, 0xC7, 0xC0, 0x00, 0x20, 0x40, 0x00, // mov r8, Title(0x402000) (offset 17)
	// 0x4D, 0x31, 0xC9,						  // xor r9, r9; MB_OK
	// 0x48, 0xC7, 0xC0, 0x5C, 0x30, 0x40, 0x00, // mov rax, MessageBoxA address(0x40305c) (offset 27)
	// 0xFF, 0x10,								  // call[rax]; MessageBoxA(hWnd, Message, Title, MB_OK)
	// // 0x48, 0x31, 0xC9,				// xor rcx, rcx; exit value
	// // 0x48, 0xC7, 0xC0,       0x6C, 0x30, 0x40, 0x00,	// mov rax, ExitProcess address (0x40306c)
	// // 0xFF, 0x10,					// call[rax]; ExitProcess(0)
	// 0xC3 // ret; Never reached

	// Number(iat_address_in_hex - next code line address _in_hex).toString(16)

	memcpy(codeSection.RawData, code.data(), code.size());
	codeSection.Size = code.size();

	int dataSectionIndex = pe.AddSection(DATA_SECTION_NAME, pe.GetFileAlignment(), false);

	// std::vector<uint8_t> data = {
	// 	0x43, 0x6F, 0x6E, 0x73, 0x6F, 0x6C, 0x65, 0x20, 0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x36, 0x34,
	// 	0x0D, 0x0A //\r\n
	// };

	auto dataSection = pe.GetSectionByIndex(dataSectionIndex);
	memcpy(dataSection.RawData, exe_string_to_hex_and_address.hex_for_data_section.data(), exe_string_to_hex_and_address.hex_for_data_section.size());

	// std::cout << "!!!!b" << std::endl;

	pe.SaveToFile("main.exe");

	std::cout << "Compiled with 0 Errors." << std::endl;

	// // The Section Header(s) after the NT Header
	// // auto pSH = PIMAGE_SECTION_HEADER(ULONGLONG(&nt_h) + sizeof(IMAGE_NT_HEADERS64));

	// // // import kernel32
	// // // cout << (n + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR)<< endl;
	// // nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0x00000028;
	// // nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0x00003034;

	// // // pPE->Import.VirtualAddress = pSHImport->VirtualAddress;
	// // // pPE->Import.Size = sizeof(ImportDescriptor);

	// // // cout << n * sizeof(ULONGLONG)<< endl;
	// // nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0x00000020;
	// // nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0x00003000;

	// // https://github.com/TinyCC/tinycc/blob/d76e03232bb858387108c91e7bf58bd892563483/tccpe.c
	// // pe->imp_size = (ndlls + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
	// // pe->iat_size = (sym_cnt + ndlls) * sizeof(ADDR3264);

	// // dll_ptr = pe->thunk->data_offset;
	// // thk_ptr = dll_ptr + pe->imp_size;
	// // ent_ptr = thk_ptr + pe->iat_size;

	// // pe->imp_offs  [IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = pe->thunk->data_offset + rva_base;
	// // pe->iat_offs  [IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress= pe->thunk->data_offset + pe->imp_size + rva_base;

	// // IMAGE_IMPORT_DESCRIPTOR* importTable = (IMAGE_IMPORT_DESCRIPTOR*)
	// //         (nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress +
	// // 		nt_h.OptionalHeader.ImageBase);

	// // ULONGLONG;

	// // // import kernel32.dll
	// // IMAGE_IMPORT_DESCRIPTOR import_descripter;
	// // memset(&import_descripter, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	// // //import_descripter.OriginalFirstThunk = NULL; // Replace with rva to this->thunk_entry when outputting
	// // // import_descripter.TimeDateStamp = -1; // NO NEEDED
	// // // import_descripter.ForwarderChain = -1; // NO NEEDED
	// // // import_descripter.Name = NULL; // NO NEEDED
	// // import_descripter.FirstThunk = rva; // PE Loader with patchup address at rva to become the address of the import, awesome!

	// // IMAGE_THUNK_DATA64  _thunk_entry;
	// // _thunk_entry.u1.Ordinal = IMAGE_ORDINAL_FLAG64 | (ordinal & 0xffff);

	// // char* _library_name = new char[strlen("KERNEL32.dll")+1];
	// // strcpy(_library_name, "KERNEL32.dll");

	// // _thunk_entry.u1.AddressOfData = NULL; // Replace with rva to import_by_name

	// // IMAGE_IMPORT_BY_NAME* _import_by_name = (IMAGE_IMPORT_BY_NAME*) new char[strlen("GetStdHandle")+1+sizeof(WORD)];
	// // _import_by_name->Hint = 0; // Not necessary
	// // size_t _import_by_name_len = strlen("GetStdHandle")+1+sizeof(WORD);
	// // strcpy((char*)(&_import_by_name->Name), "GetStdHandle");

	// // // import_descripter.Name[0] = 'K';
	// // // import_descripter.Name[0] = 'K';

	// // // "KERNEL32.dll";
	// // IMAGE_THUNK_DATA64 importAddressTable = import_descripter.FirstThunk;

	// unsigned short section_index = 0;

	// IMAGE_SECTION_HEADER empty_section;
	// memset(&empty_section, 0, sizeof(IMAGE_SECTION_HEADER));
	// empty_section.PointerToRawData = 0x200;
	// empty_section.SizeOfRawData = nt_h.OptionalHeader.FileAlignment;
	// empty_section.Misc.VirtualSize = nt_h.OptionalHeader.SectionAlignment;

	// PIMAGE_SECTION_HEADER prev_section_ptr = &empty_section;
	// PIMAGE_SECTION_HEADER last_section_ptr = nullptr;

	// const auto my_to_rva = [&](PIMAGE_SECTION_HEADER import_section_ptr, DWORD target_address) -> int
	// {

	// 	// For instance, consider an EXE file loaded at address 0x400000,
	// 	// with its code section at address 0x401000. The RVA of the code section would be:
	// 	//  (target address) 0x401000 - (load address)0x400000  = (RVA)0x1000

	// 	return target_address - DWORD(&dos_h) - import_section_ptr->PointerToRawData + import_section_ptr->VirtualAddress;
	// 	/*
	// 		In an image file, this is the address of an item after it is loaded into memory,
	// 		with the base address of the image file subtracted from it.
	// 		The RVA of an item almost always differs from its position
	// 		within the file on disk (file pointer).
	// 		In an object file, an RVA is less meaningful because memory
	// 		locations are not assigned. In this case, an RVA would be
	// 		an address within a section (described later in this table),
	// 		to which a relocation is later applied during linking.
	// 		For simplicity, a compiler should just set the first RVA in each section to zero.
	// 	*/
	// 	// #define ToRVA(import_section_header_ptr, ptr) (\
	// 	// 	DWORD(ptr) - \
	// 	// 	DWORD(&dos_h) - \
	// 	// 	import_section_header_ptr->PointerToRawData + \
	// 	// 	import_section_header_ptr->VirtualAddress \
	// 	// )
	// };

	// // For this example,
	// // Default the raw/virtual offset is continuous file offset + raw size of previous section
	// // Default the raw/virtual size is equal to OptHeader.FileAlignment/OptHeader.SectionAlignment
	// const auto config_section_header = [&](IMAGE_SECTION_HEADER& section_header) -> void
	// {
	// 	section_header.PointerToRawData = prev_section_ptr->PointerToRawData + prev_section_ptr->SizeOfRawData;
	// 	section_header.SizeOfRawData = nt_h.OptionalHeader.FileAlignment;
	// 	section_header.VirtualAddress = prev_section_ptr->VirtualAddress + prev_section_ptr->Misc.VirtualSize;
	// 	section_header.Misc.VirtualSize = nt_h.OptionalHeader.SectionAlignment;

	// 	std::cout << "PE -> Section Header -> " << section_header.Name << " -> Created" << std::endl;

	// 	section_index++;

	// 	last_section_ptr = &section_header;
	// 	prev_section_ptr = &section_header;
	// };

	// IMAGE_SECTION_HEADER code_section;
	// memset(&code_section, 0, sizeof(IMAGE_SECTION_HEADER));
	// code_section.Name[0] = '.';
	// code_section.Name[1] = 't';
	// code_section.Name[2] = 'e';
	// code_section.Name[3] = 'x';
	// code_section.Name[4] = 't';
	// code_section.Name[5] = 0x0;
	// code_section.Characteristics =
	// IMAGE_SCN_MEM_EXECUTE |	// 0x20000000
	// IMAGE_SCN_MEM_READ	  |	// 0x40000000
	// IMAGE_SCN_CNT_CODE	  ; // 0x00000020
	// // ==========
	// // 0x60000020
	// // Add .code section

	// config_section_header(code_section);

	// //pSHData
	// IMAGE_SECTION_HEADER data_section;
	// memset(&data_section, 0, sizeof(IMAGE_SECTION_HEADER));
	// data_section.Name[0] = '.';
	// data_section.Name[1] = 'd';
	// data_section.Name[2] = 'a';
	// data_section.Name[3] = 't';
	// data_section.Name[4] = 'a';
	// data_section.Name[5] = 0x0;
	// data_section.Characteristics =
	// IMAGE_SCN_CNT_INITIALIZED_DATA | //0x00000040
	// IMAGE_SCN_MEM_READ | //0x40000000
	// IMAGE_SCN_MEM_WRITE; //0x80000000

	// config_section_header(data_section);

	// // pSHImport
	// IMAGE_SECTION_HEADER import_section;
	// memset(&import_section, 0, sizeof(IMAGE_SECTION_HEADER));
	// import_section.Name[0] = '.';
	// import_section.Name[1] = 'i';
	// import_section.Name[2] = 'd';
	// import_section.Name[3] = 'a';
	// import_section.Name[4] = 't';
	// import_section.Name[5] = 'a';
	// import_section.Name[6] = 0x0;
	// import_section.Characteristics =
	// IMAGE_SCN_MEM_WRITE	  |
	// IMAGE_SCN_MEM_READ	  |
	// IMAGE_SCN_CNT_INITIALIZED_DATA;

	// config_section_header(import_section);

	// // Fixup PE Header

	// nt_h.FileHeader.NumberOfSections = section_index;
	// std::cout << "NumberOfSections: " << nt_h.FileHeader.NumberOfSections << std::endl;

	// nt_h.OptionalHeader.AddressOfEntryPoint = code_section.VirtualAddress;
	// nt_h.OptionalHeader.BaseOfCode = code_section.VirtualAddress;
	// nt_h.OptionalHeader.SizeOfCode = code_section.Misc.VirtualSize;
	// nt_h.OptionalHeader.SizeOfImage = last_section_ptr->VirtualAddress + last_section_ptr->Misc.VirtualSize;
	// nt_h.OptionalHeader.SizeOfHeaders = VU_ALIGN_UP(DWORD(PBYTE(&import_section) - (PBYTE)&dos_h), nt_h.OptionalHeader.FileAlignment); // The offset after the last section is the end / combined-size of all headers.

	// std::cout << "PE -> PE Header -> Fixed" << std::endl;

	// nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = import_section.VirtualAddress;
	// nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = sizeof(import_section);

	// std::cout << "PE -> Import Directories -> Created" << std::endl;

	// typedef std::pair<unsigned short, std::string> ImportByName;
	// std::map<std::string, std::vector<ImportByName>> dll_map;
	// std::vector<ImportByName> dll_functions_imported_by_name;

	// dll_functions_imported_by_name.clear();
	// dll_functions_imported_by_name.push_back(ImportByName(0, "MessageBoxA"));
	// dll_map["user32.dll"] = dll_functions_imported_by_name;

	// //	auto pIDT = PIMAGE_IMPORT_DESCRIPTOR((&dos_h + pSHImport->PointerToRawData));

	// // Create IDT, IAT, ILT for each DLL
	// // - IDT -> Import Directory Table that Array<IMAGE_IMPORT_DESCRIPTOR>
	// // - IAT -> Import Address Table that Array<Thunk Data> IMAGE_THUNK_DATA64
	// // - ILT -> Import Lookup Table that Array<Hint, Function> IMAGE_THUNK_DATA64::Function

	// /* Write them all in .idata section
	//  * Array<IDT> | Array<IAT | DLL | ILT>
	//  * or
	//  * |--- Array for <IDT>
	//  * | IDT / Import Descriptor (s) / 20 bytes for each dll / padding 1 IDT = 20 bytes
	//  * |--- Array for <IAT, DLL, ILT>
	//  * |  | IAT / Thunk Table / 4 bytes for each function / padding 1 DWORD = 4 bytes
	//  * |  |---
	//  * |  | DLL / DLL Name / depends on dll name / any padding
	//  * |  |---
	//  * |  | ILT / Thunk Data / import by name (s) / depends on function hint/name / any padding
	//  * |  |---
	//  */

	// std::vector<PIMAGE_IMPORT_DESCRIPTOR> import_descripter_list;

	// // Total size of IDTs
	// // const unsigned long TotalSizeIDTs = (dll_map.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR); // +1 for an empty IDD
	// // auto pPtr = import_descripter_pointer + TotalSizeIDTs;

	// for (const std::pair<std::string, std::vector<ImportByName>> &dll_map_entry : dll_map)
	// {
	// 	std::string dll_name = dll_map_entry.first;
	// 	std::vector<ImportByName> dll_functions = dll_map_entry.second;

	// 	IMAGE_IMPORT_DESCRIPTOR import_descripter;
	// 	memset(&import_descripter, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));

	// 	PIMAGE_IMPORT_DESCRIPTOR import_descripter_pointer = &import_descripter;

	// 	// auto pIAT = PDWORD(pPtr);
	// 	// auto rvaIAT = ToRVA((&import_section), pIAT);

	// 	// const auto EachIATSize = (dll_map_entry.second.size() + 1) * sizeof(DWORD); // +1 DWORD for IAT padding
	// 	// pPtr += EachIATSize;

	// 	// // Write hint/name of import functions of each DLL

	// 	// StrCpyT(pPtr, dll_name.c_str());
	// 	// auto rvaName = ToRVA((&import_section), pPtr);

	// 	// pPtr += dll_name.size() + 1; // +1 for a null-char padding

	// 	std::vector<IMAGE_THUNK_DATA64> import_lookup_table;
	// 	std::vector<IMAGE_THUNK_DATA64> import_address_table;

	// 	for (const ImportByName &ibn : dll_functions) // image import by name (s)
	// 	{
	// 		unsigned short hint = ibn.first;
	// 		std::string function_name = ibn.second;

	// 		size_t function_name_length = strlen(function_name.c_str());

	// 		// *PWORD(pPtr) = hint;						  // Hint
	// 		// StrCpyT(pPtr + sizeof(WORD), name.c_str()); // Name

	// 		// *pIAT++ = ToRVA((&import_section), pPtr); // Update Thunk Data for each import function in IAT

	// 		// pPtr += sizeof(WORD) + name.size() + 2; // +2 for string terminating null-character & a null-char padding

	// 		IMAGE_IMPORT_BY_NAME import_by_name;
	// 		memset(&import_by_name, 0, sizeof(IMAGE_IMPORT_BY_NAME));
	// 		import_by_name.Hint = 0;

	// 		memcpy(import_by_name.Name, function_name.c_str(), function_name_length + 1); // The name of the imported function

	// 		IMAGE_THUNK_DATA64 thunk_data_64;
	// 		memset(&thunk_data_64, 0, sizeof(thunk_data_64));
	// 		thunk_data_64.u1.AddressOfData = (unsigned long long)&import_by_name;

	// 		/*
	// 		    importThunk.u1.AddressOfData = baseRVA + offsetStrings;
	//             memcpy(buffer + offsetStrings + 2, importFunction->Name, strlen(importFunction->Name));
	//             offsetStrings += 2 + AlignNumber((DWORD)strlen(importFunction->Name) + 1, 2);
	// 		*/
	// 		// import_descripter.FirstThunk = (DWORD)&thunk_data_64;
	// 		// import_descripter.OriginalFirstThunk = (DWORD)&thunk_data_64;

	// 		// Function store the runtime address
	// 		// thunk_data_64.u1.Function

	// 	}

	// 	// Update IDT for each DLL
	// 	auto ptr = (&import_section);
	// 	auto ptr2 = (dll_name.c_str());
	// 	import_descripter.ForwarderChain = -1;
	// 	//import_descripter.Name = ToRVA(ptr, ptr2); // get the rva of dll name
	// 	my_to_rva(&import_section, (DWORD)dll_name.c_str());
	// 	// import_descripter.FirstThunk = ;
	// 	// import_descripter.OriginalFirstThunk = rvaIAT; // get the rva of ImportByName

	// 	std::cout << "PE -> Import Directory -> " << dll_name << " -> Created" << std::endl;

	// 	import_descripter_list.push_back(&import_descripter);
	// }

	// //pIDT++; // Next an empty IDD to mark end of IDT array
	// IMAGE_IMPORT_DESCRIPTOR import_descripter;
	// memset(&import_descripter, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	// import_descripter_list.push_back(&import_descripter);

	// import_section.PointerToRawData = (DWORD)import_descripter_list.at(0);
	// //import_section.SizeOfRawData =

	// // BYTE code[] =
	// // {
	// // 	0x6A, 0x40,                         // push 40 uType = MB_ICONINFORMATION + MB_OK
	// // 	0x68, 0x00, 0x00, 0x00, 0x00,       // push ?  lpCaption = ? (offset 3)  // TODO: Fixup Later
	// // 	0x68, 0x00, 0x00, 0x00, 0x00,       // push ?  lpText = ?    (offset 8)  // TODO: Fixup Later
	// // 	0x6A, 0x00,                         // push 0  hWnd = NULL
	// // 	0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, // call MessageBoxA = ? (offset 16) // TODO: Fixup Later
	// // 	0xC3,                               // ret
	// // };

	// std::vector<uint8_t> code = {
	// 	0x48, 0x83, 0xC4, 0x48,					  // add rsp, 0x48; Stack unwind
	// 	0x48, 0x31, 0xC9,						  // xor rcx, rcx; hWnd
	// 	0x48, 0xC7, 0xC2, 0x10, 0x20, 0x40, 0x00, // mov rdx, Message(0x402010) (offset 10)
	// 	0x49, 0xC7, 0xC0, 0x00, 0x20, 0x40, 0x00, // mov r8, Title(0x402000) (offset 17)
	// 	0x4D, 0x31, 0xC9,						  // xor r9, r9; MB_OK
	// 	0x48, 0xC7, 0xC0, 0x5C, 0x30, 0x40, 0x00, // mov rax, MessageBoxA address(0x40305c) (offset 27)
	// 	0xFF, 0x10,								  // call[rax]; MessageBoxA(hWnd, Message, Title, MB_OK)
	// 	// 0x48, 0x31, 0xC9,				// xor rcx, rcx; exit value
	// 	// 0x48, 0xC7, 0xC0,       0x6C, 0x30, 0x40, 0x00,	// mov rax, ExitProcess address (0x40306c)
	// 	// 0xFF, 0x10,					// call[rax]; ExitProcess(0)
	// 	0xC3 // ret; Never reached
	// };

	// //   auto pData = (PBYTE)(&dos_h + pSHData->PointerToRawData);

	// //   auto len = StrCpyT(pData, "Howdy, Vic P.");
	// //   const auto vaCaption = ToVA(pSHData, pData);
	// //   pData += len + 1; // +1 for string terminating null-character

	// //   StrCpyT(pData, "This is an example that manually created a PE file format");
	// //   const auto vaText = ToVA(pSHData, pData);
	// //   pData += len + 1; // +1 for string terminating null-character

	// // IMAGE_IMPORT_DESCRIPTOR import_descripter_another;
	// // memset(&import_descripter_another, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	// // pIDT = &import_descripter_another;

	// //   // Correct API callee to imported functions that defined in the IAT
	// //   pIDT = ;

	// //   auto pIAT = PBYTE(PIMAGE_IMPORT_DESCRIPTOR(&dos_h + pSHImport->PointerToRawData)) + TotalSizeIDTs;
	// //   const auto vaMessageBoxA = ToVA(pSHImport, pIAT); // For this example, IAT contains only one this API, so treat IAT offset as its offset

	// std::cout << "PE -> Executable Codes -> Created" << std::endl;

	// // code[10]  = (uint8_t)vaText;
	// // code[17]  = (uint8_t)vaCaption;
	// // code[27] = (uint8_t)vaMessageBoxA;

	// // Create/Open PE File
	// fstream pe_writter;
	// pe_writter.open(output_pe_file, ios::binary | ios::out);

	// // Write DOS Header
	// pe_writter.write((char *)&dos_h, sizeof(dos_h));

	// // Write NT Header
	// pe_writter.write((char *)&nt_h, sizeof(nt_h));

	// // Write Headers of Sections
	// pe_writter.write((char *)&code_section, sizeof(code_section));
	// while (pe_writter.tellp() != code_section.PointerToRawData) pe_writter.put(0x0);

	// pe_writter.write((char *)&data_section, sizeof(data_section));
	// while (pe_writter.tellp() != data_section.PointerToRawData) pe_writter.put(0x0);

	// pe_writter.write((char *)&import_section, sizeof(import_section));
	// while (pe_writter.tellp() != import_section.PointerToRawData) pe_writter.put(0x0);

	// // Write Code Section

	// // std::vector<uint8_t> code = {
	// // 	0x48, 0x83, 0xC4, 0x48,				// add rsp, 0x48; Stack unwind
	// // 	0x48, 0x31, 0xC9,				// xor rcx, rcx; hWnd
	// // 	0x48, 0xC7, 0xC2, 0x10, 0x20, 0x40, 0x00,	// mov rdx, Message(0x402010)
	// // 	0x49, 0xC7, 0xC0, 0x00, 0x20, 0x40, 0x00,	// mov r8, Title(0x402000)
	// // 	0x4D, 0x31, 0xC9,				// xor r9, r9; MB_OK
	// // 	0x48, 0xC7, 0xC0, 0x5C, 0x30, 0x40, 0x00,	// mov rax, MessageBoxA address(0x40305c)
	// // 	0xFF, 0x10,					// call[rax]; MessageBoxA(hWnd, Message, Title, MB_OK)
	// // 	0x48, 0x31, 0xC9,				// xor rcx, rcx; exit value
	// // 	0x48, 0xC7, 0xC0, 0x6C, 0x30, 0x40, 0x00,	// mov rax, ExitProcess address (0x40306c)
	// // 	0xFF, 0x10,					// call[rax]; ExitProcess(0)
	// // 	0xC3						// ret; Never reached
	// // };

	// std::for_each(code.begin(), code.end(), [&pe_writter](uint8_t &n){ pe_writter.put(n); });
	// for (size_t i = 0; i < code_section.SizeOfRawData - code.size(); i++) pe_writter.put(0x0);

	// std::cout << "PE -> Executable Codes -> Fixed" << std::endl;

	// // /***********************************/

	// // // "Console Message 64\r\n"
	// std::vector<uint8_t> data = {
	// 	0x43, 0x6F, 0x6E, 0x73, 0x6F, 0x6C, 0x65, 0x20, 0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x36, 0x34, 0x0D, 0x0A
	// };

	// std::for_each(data.begin(), data.end(), [&pe_writter](uint8_t &n){ pe_writter.put(n); });
	// for (size_t i = 0; i < data_section.SizeOfRawData - data.size(); i++) pe_writter.put(0x0);

	// // // gibberish
	// // std::vector<uint8_t> imports = {
	// // 	0x8E, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9E, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// // 	0xAA, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// // 	0xFF, 0x25, 0xDA, 0xFF, 0xFF, 0xFF, 0xFF, 0x25, 0xDC, 0xFF, 0xFF, 0xFF, 0xFF, 0x25, 0xDE, 0xFF,
	// // 	0xFF, 0xFF, 0x00, 0x00, 0x60, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// // 	0x80, 0x30, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// // 	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// // 	0x8E, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9E, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// // 	0xAA, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// // 	0x4B, 0x45, 0x52, 0x4E, 0x45, 0x4C, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x00, 0xE1, 0x02,
	// // 	0x47, 0x65, 0x74, 0x53, 0x74, 0x64, 0x48, 0x61, 0x6E, 0x64, 0x6C, 0x65, 0x00, 0x00, 0x33, 0x06,
	// // 	0x57, 0x72, 0x69, 0x74, 0x65, 0x46, 0x69, 0x6C, 0x65, 0x00, 0x68, 0x01, 0x45, 0x78, 0x69, 0x74,
	// // 	0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73
	// // };

	// std::for_each(import_descripter_list.begin(), import_descripter_list.end(), [&pe_writter](PIMAGE_IMPORT_DESCRIPTOR &import_descripter_pointer){
	// 	pe_writter.write((char *)import_descripter_pointer, sizeof((*import_descripter_pointer)));
	// });

	// // std::for_each(imports.begin(), imports.end(), [&pe_writter](uint8_t &n){ pe_writter.put(n); });
	// // for (size_t i = 0; i < import_section.SizeOfRawData - imports.size(); i++) pe_writter.put(0x0);

	// Close PE File
	// pe_writter.close();

	cin.get();
	return EXIT_SUCCESS;
}
