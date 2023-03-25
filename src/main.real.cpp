#include <iostream>
#include <map>
#include <windows.h>
#include <winnt.h>
#include <iostream>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <vector>
#include <memory>
#include <algorithm>
#include <iterator>
#include <filesystem>

#include <Windows.h>
#include <winnt.h>
#include <stdint.h>
#include <math.h>
#include <fstream>
#include <iostream>

using namespace std;


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
    char* Name;
    int Id;
    PE_IMPORT_FUNCTION_ENTRY* Next;
};

struct PE_IMPORT_DLL_ENTRY
{
    char* Name;
    PE_IMPORT_FUNCTION_ENTRY* Functions;
    PE_IMPORT_DLL_ENTRY* Next;
};

struct PE_SECTION_ENTRY
{
    DWORD Offset;
    int8_t* RawData;
    DWORD Size;
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
    DWORD GetFileAlignment();
	PE_SECTION_ENTRY GetSectionByIndex(int32_t index);
    int32_t AddSection(std::string_view name, DWORD size, bool isExecutable);
    void AddImport(std::string_view dllName, char** functions, int functionCount);
    void Commit();

private:
    IMAGE_DOS_HEADER m_dosHeader;
    IMAGE_NT_HEADERS m_ntHeaders64;


    /***/


    
	
    IMAGE_SECTION_HEADER m_sectionTable[MAX_SECTIONS];
    // PE_SECTION_ENTRY m_reservedData;
    PE_SECTION_ENTRY m_sections[MAX_SECTIONS];
    PE_IMPORT_DLL_ENTRY m_additionalImports;

    int8_t* m_loadedPeFile;
    // PEResult ReadAll();
    // PEResult ReadHeaders();
    // void ReadSections();
    // PEResult ReadImports();


    void BuildImportTable();
    char* BuildAdditionalImports(DWORD baseRVA);
    DWORD CalculateAdditionalImportsSize(DWORD& sizeDlls, DWORD& sizeFunctions, DWORD& sizeStrings);

    bool WritePadding(std::ofstream& file, long paddingSize);
    DWORD AlignNumber(DWORD number, DWORD alignment);
    DWORD RvaToOffset(DWORD rva);
    DWORD OffsetToRVA(DWORD offset);

    // void ComputeReservedData();
    void ComputeHeaders();
    void ComputeSectionTable();
};

PE_SECTION_ENTRY PEFile::GetSectionByIndex(int32_t index) {
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
	if (m_loadedPeFile != nullptr)
    {
        VirtualFree(m_loadedPeFile, 0, MEM_RELEASE);
    }

    m_loadedPeFile = nullptr;
    memset(&m_additionalImports, 0, sizeof(PE_IMPORT_DLL_ENTRY));
	
	memset(m_sectionTable, 0, sizeof(m_sectionTable));
}

DWORD PEFile::GetFileAlignment() {
    return this->m_ntHeaders64.OptionalHeader.FileAlignment;
}

PEResult PEFile::SaveToFile(std::filesystem::path filePath)
{
    Commit();
    BuildImportTable();

    std::ofstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file)
    {
		std::cout << "!!!!e" << std::endl;
        return PEResult::ErrorSaveFileCreate;
    }

    file.write((char*)&this->m_dosHeader, sizeof(IMAGE_DOS_HEADER));
    //file.write((char*)&this->m_dosStub.RawData, m_dosStub.Size);

	std::vector<uint8_t> stub = {
	0x0e,
	0x1f,
	0xba,
	0x0e,
	0x00,
	0xb4,
	0x09,
	0xcd,
	0x21,
	0xb8,
	0x01,
	0x4c,
	0xcd,
	0x21,
	0x54,
	0x68,
	0x69,
	0x73,
	0x20,
	0x70,
	0x72,
	0x6f,
	0x67,
	0x72,
	0x61,
	0x6d,
	0x20,
	0x63,
	0x61,
	0x6e,
	0x6e,
	0x6f,
	0x74,
	0x20,
	0x62,
	0x65,
	0x20,
	0x72,
	0x75,
	0x6e,
	0x20,
	0x69,
	0x6e,
	0x20,
	0x44,
	0x4f,
	0x53,
	0x20,
	0x6d,
	0x6f,
	0x64,
	0x65,
	0x2e,
	0x0d,
	0x0d,
	0x0a,
	0x24,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00
	};
	
	std::for_each(stub.begin(), stub.end(), [&file](uint8_t &n){ file.write((char*)&n, 1); });
	
    //WritePadding(file, m_dosHeader.e_lfanew - sizeof(IMAGE_DOS_HEADER) - m_dosStub.Size);

    file.write((char*)&m_ntHeaders64, sizeof(IMAGE_NT_HEADERS));
    file.write((char*)&m_sectionTable, m_ntHeaders64.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    //file.write((char*)m_reservedData.RawData, m_reservedData.Size);

	std::cout << "!!!!f" << std::endl;
    for (int i = 0; i < m_ntHeaders64.FileHeader.NumberOfSections; i++)
    {
        WritePadding(file, m_sectionTable[i].PointerToRawData - file.tellp());
        file.write((char*)m_sections[i].RawData, m_sections[i].Size);
    }
	
	std::cout << "!!!!g" << std::endl;
    return PEResult::Success;
}

void PEFile::New() {
	memset(&this->m_dosHeader, 0, sizeof(IMAGE_DOS_HEADER));
	this->m_dosHeader.e_magic = IMAGE_DOS_SIGNATURE;
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
	this->m_dosHeader.e_lfanew = 0x080;// The file offset of the PE header, relative to the beginning of the file.

	std::cout << "e_lfanew = sizeof(IMAGE_DOS_HEADER)" << sizeof(IMAGE_DOS_HEADER) << std::endl;

	std::cout << "PE -> DOS Header -> Created" << std::endl;

	
	// memset(&this->m_dosStub.RawData, 0, stub.size());
    // memcpy(&this->m_dosStub.RawData, stub.data(), stub.size());
	// this->m_dosStub.Size = stub.size();

	memset(&this->m_ntHeaders64, 0, sizeof(IMAGE_NT_HEADERS64));
	this->m_ntHeaders64.Signature = IMAGE_NT_SIGNATURE;
	this->m_ntHeaders64.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
	
	this->m_ntHeaders64.FileHeader.TimeDateStamp = 0x00000000;												  // leave this
	this->m_ntHeaders64.FileHeader.PointerToSymbolTable = 0x0;												  // leave this
	this->m_ntHeaders64.FileHeader.NumberOfSymbols = 0x0;													  // leave this
	this->m_ntHeaders64.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);					  // leave this
	this->m_ntHeaders64.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE; // declare this is a 64bit exe

	this->m_ntHeaders64.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;

	// TODO
	// nt_h.OptionalHeader.SizeOfCode							= 0x00000200;  // dynamic
	this->m_ntHeaders64.OptionalHeader.SizeOfInitializedData = 0x00000400; // dynamic
	this->m_ntHeaders64.OptionalHeader.SizeOfUninitializedData = 0x0;		// dynamic

	// TODO
	//this->m_ntHeaders64.OptionalHeader.BaseOfCode							= 0x1000;  // dynamic, normally same as AddressOfEntryPoint
	this->m_ntHeaders64.OptionalHeader.ImageBase = 0x400000;			   // leave it
	this->m_ntHeaders64.OptionalHeader.SectionAlignment = 0x1000;		   // dynamic
	this->m_ntHeaders64.OptionalHeader.FileAlignment = 0x200;			   // dynamic
	this->m_ntHeaders64.OptionalHeader.MajorOperatingSystemVersion = 0x5; // leave it
	this->m_ntHeaders64.OptionalHeader.MinorOperatingSystemVersion = 0x2; // leave it
	this->m_ntHeaders64.OptionalHeader.MajorImageVersion = 0;			   // leave it
	this->m_ntHeaders64.OptionalHeader.MinorImageVersion = 0;			   // leave it
	this->m_ntHeaders64.OptionalHeader.MajorSubsystemVersion = 0x5;	   // leave it
	this->m_ntHeaders64.OptionalHeader.MinorSubsystemVersion = 0x2;	   // leave it
	this->m_ntHeaders64.OptionalHeader.Win32VersionValue = 0;			   // leave it

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
	this->m_ntHeaders64.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
	this->m_ntHeaders64.OptionalHeader.DllCharacteristics = 0x0000;							// leave it
	this->m_ntHeaders64.OptionalHeader.SizeOfStackReserve = 0x0000000000100000;				// leave it
	this->m_ntHeaders64.OptionalHeader.SizeOfStackCommit = 0x0000000000001000;					// leave it
	this->m_ntHeaders64.OptionalHeader.SizeOfHeapReserve = 0x0000000000100000;					// leave it
	this->m_ntHeaders64.OptionalHeader.SizeOfHeapCommit = 0x0000000000001000;					// leave it
	this->m_ntHeaders64.OptionalHeader.LoaderFlags = 0x00000000;								// leave it
	this->m_ntHeaders64.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES; // leave it

	std::cout << "SectionAlignment" << this->m_ntHeaders64.OptionalHeader.SectionAlignment << std::endl;
	std::cout << "PE -> PE Header -> Created" << std::endl;
}

void PEFile::AddImport(std::string_view dllName, char** functions, int functionCount)
{
    PE_IMPORT_DLL_ENTRY* importDll = &this->m_additionalImports;
    PE_IMPORT_FUNCTION_ENTRY* importFunction;

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
    char* allocedName = new char[sizeOfName];
    strcpy_s(allocedName, sizeOfName, dllName.data());
    //strcpy(allocedName, dllName.data());
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
	std::cout << "!!!!qwrew" << std::endl;
    // Calculate new import size
    DWORD sizeDlls = 0;
    DWORD sizeFunctions = 0;
    DWORD sizeStrings = 0;
    DWORD newImportsSize = CalculateAdditionalImportsSize(sizeDlls, sizeFunctions, sizeStrings);

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
	std::cout << "!!!!index" << index << std::endl;

    // Copy old imports
    // DWORD oldImportTableRVA = m_ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    // DWORD oldImportTableOffset = RvaToOffset(oldImportTableRVA);
    // memcpy(m_sections[index].RawData, m_loadedPeFile + oldImportTableOffset, currentImportDllsSize);

    // Copy new imports into the import section

	std::cout << "m_sectionTable[index].VirtualAddress" << m_sectionTable[index].VirtualAddress << std::endl;
    char* newImportsData = BuildAdditionalImports(m_sectionTable[index].VirtualAddress/* + currentImportDllsSize*/);
    memcpy(m_sections[index].RawData/* + currentImportDllsSize*/, newImportsData, newImportsSize);
	std::cout << "m_sections[index].Size" << m_sections[index].Size << std::endl;

    m_ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = m_sectionTable[index].VirtualAddress;
    m_ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = m_sectionTable[index].Misc.VirtualSize;
    m_ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
    m_ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
	
	std::cout << "!!!!iu" << std::endl;
}

char* PEFile::BuildAdditionalImports(DWORD baseRVA)
{
    Commit();

    IMAGE_IMPORT_DESCRIPTOR importDesc;
    IMAGE_THUNK_DATA64 importThunk;
    PE_IMPORT_DLL_ENTRY* importDll;
    PE_IMPORT_FUNCTION_ENTRY* importFunction;

    DWORD sizeDlls = 0;
    DWORD sizeFunctions = 0;
    DWORD sizeStrings = 0;
    DWORD newImportsSize = CalculateAdditionalImportsSize(sizeDlls, sizeFunctions, sizeStrings);
    DWORD offsetDlls = 0;
    DWORD offsetFunctions = sizeDlls;
    DWORD offsetStrings = sizeDlls + 2 * sizeFunctions;

    char* buffer = new char[newImportsSize];
    memset(buffer, 0, newImportsSize);

    importDll = &m_additionalImports;
    while (importDll != nullptr)
    {
        memset(&importDesc, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
        importDesc.OriginalFirstThunk = baseRVA + offsetFunctions;
        importDesc.FirstThunk = baseRVA + offsetFunctions + sizeFunctions;
		std::cout << "baseRVA: " << baseRVA << std::endl;
		std::cout << "importDesc.FirstThunk: " << importDesc.FirstThunk << std::endl;
        importDesc.Name = baseRVA + offsetStrings;
        memcpy(buffer + offsetStrings, importDll->Name, strlen(importDll->Name));
        offsetStrings += AlignNumber((DWORD)strlen(importDll->Name) + 1, 2);

        memcpy(buffer + offsetDlls, &importDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR));
        offsetDlls += sizeof(IMAGE_IMPORT_DESCRIPTOR);

        importFunction = importDll->Functions;
        while (importFunction != nullptr)
        {
            memset(&importThunk, 0, sizeof(IMAGE_THUNK_DATA64));
            if (importFunction->Id != 0)
            {
                importThunk.u1.Ordinal = importFunction->Id | IMAGE_ORDINAL_FLAG32;
            }
            else
            {
                std::cout << "u1.Function location is something like: " << baseRVA + offsetStrings << std::endl;

                importThunk.u1.AddressOfData = baseRVA + offsetStrings;
                memcpy(buffer + offsetStrings + 2, importFunction->Name, strlen(importFunction->Name));
                offsetStrings += 2 + AlignNumber((DWORD)strlen(importFunction->Name) + 1, 2);
            }

            memcpy(buffer + offsetFunctions, &importThunk, sizeof(IMAGE_THUNK_DATA64));
            memcpy(buffer + offsetFunctions + sizeFunctions, &importThunk, sizeof(IMAGE_THUNK_DATA64));
            offsetFunctions += sizeof(IMAGE_THUNK_DATA64);

            importFunction = importFunction->Next;
        }
        offsetFunctions += sizeof(IMAGE_THUNK_DATA64);

        importDll = importDll->Next;
    }

    return buffer;
}

DWORD PEFile::CalculateAdditionalImportsSize(DWORD& sizeDlls, DWORD& sizeFunctions, DWORD& sizeStrings)
{
    PE_IMPORT_DLL_ENTRY* importDll = &this->m_additionalImports;
    PE_IMPORT_FUNCTION_ENTRY* importFunction;

    // Calculate size
    while (importDll != nullptr)
    {
        sizeDlls += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        sizeStrings += AlignNumber((DWORD)strlen(importDll->Name) + 1, 2);
        importFunction = importDll->Functions;
        while (importFunction != nullptr)
        {
            sizeFunctions += sizeof(IMAGE_THUNK_DATA64);
            if (importFunction->Id == 0)
            {
                sizeStrings += 2 + AlignNumber((DWORD)strlen(importFunction->Name) + 1, 2);
            }
            importFunction = importFunction->Next;
        }
        sizeFunctions += sizeof(IMAGE_THUNK_DATA64);
        importDll = importDll->Next;
    }
    sizeDlls += sizeof(IMAGE_IMPORT_DESCRIPTOR);

    return sizeDlls + 2 * sizeFunctions + sizeStrings;
}

bool PEFile::WritePadding(std::ofstream& file, long paddingSize)
{
    if (paddingSize <= 0)
        return false;

    char* padding = new char[paddingSize];
    memset(padding, 0, paddingSize);
    if (file.write(padding, paddingSize))
    {
        return false;
    }
    delete padding;

    return true;
}

DWORD PEFile::AlignNumber(DWORD number, DWORD alignment)
{
    return (DWORD)(ceil(number / (alignment + 0.0)) * alignment);
}

DWORD PEFile::RvaToOffset(DWORD rva) {
    for (int i = 0; i < m_ntHeaders64.FileHeader.NumberOfSections; i++)
    {
        if (rva >= m_sectionTable[i].VirtualAddress && rva < m_sectionTable[i].VirtualAddress + m_sectionTable[i].Misc.VirtualSize)
        {
            return m_sectionTable[i].PointerToRawData + (rva - m_sectionTable[i].VirtualAddress);
        }
    }

    return 0;
}


int32_t PEFile::AddSection(std::string_view name, DWORD size, bool isExecutable)
{
    // Return if max sections are reached
    if (m_ntHeaders64.FileHeader.NumberOfSections == MAX_SECTIONS)
    {
        return -1;
    }

    PE_SECTION_ENTRY& newSection = m_sections[m_ntHeaders64.FileHeader.NumberOfSections];
    IMAGE_SECTION_HEADER& newSectionHeader = m_sectionTable[m_ntHeaders64.FileHeader.NumberOfSections];
    IMAGE_SECTION_HEADER& lastSectionHeader = m_sectionTable[m_ntHeaders64.FileHeader.NumberOfSections - 1];
	
    DWORD sectionSize = AlignNumber(size, m_ntHeaders64.OptionalHeader.FileAlignment);
	sectionSize = sectionSize > 0 ? sectionSize : m_ntHeaders64.OptionalHeader.FileAlignment;

    DWORD virtualSize = AlignNumber(sectionSize, m_ntHeaders64.OptionalHeader.SectionAlignment);
	virtualSize = virtualSize > 0 ? virtualSize : m_ntHeaders64.OptionalHeader.SectionAlignment;
	
    DWORD sectionOffset = AlignNumber(lastSectionHeader.PointerToRawData + lastSectionHeader.SizeOfRawData, m_ntHeaders64.OptionalHeader.FileAlignment);
	sectionOffset = sectionOffset > 0 ? sectionOffset : m_ntHeaders64.OptionalHeader.FileAlignment;

    DWORD virtualOffset = AlignNumber(lastSectionHeader.VirtualAddress + lastSectionHeader.Misc.VirtualSize, m_ntHeaders64.OptionalHeader.SectionAlignment);
	virtualOffset = virtualOffset > 0 ? virtualOffset : m_ntHeaders64.OptionalHeader.SectionAlignment;


    memset(&newSectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
    memcpy(newSectionHeader.Name, name.data(), name.length() > 8 ? 8 : name.length());

    newSectionHeader.PointerToRawData = sectionOffset;
    newSectionHeader.VirtualAddress = virtualOffset;
    newSectionHeader.SizeOfRawData = sectionSize;
    newSectionHeader.Misc.VirtualSize = virtualSize;
    newSectionHeader.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA;

    if (isExecutable)
    {
        newSectionHeader.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;
		this->m_ntHeaders64.OptionalHeader.AddressOfEntryPoint = newSectionHeader.VirtualAddress;
		this->m_ntHeaders64.OptionalHeader.BaseOfCode = this->m_ntHeaders64.OptionalHeader.AddressOfEntryPoint;
		std::cout << "!!!!isExecutable" << this->m_ntHeaders64.OptionalHeader.AddressOfEntryPoint << std::endl;
    }

    newSection.RawData = (int8_t*)GlobalAlloc(GMEM_FIXED | GMEM_ZEROINIT, sectionSize);
    newSection.Size = sectionSize;

    m_ntHeaders64.FileHeader.NumberOfSections++;
    // if (m_reservedData.Size > 0)
    // {
    //     m_reservedData.Size -= sizeof(IMAGE_SECTION_HEADER);
    // }

    // Return the new section index
    return m_ntHeaders64.FileHeader.NumberOfSections - 1;
}


DWORD PEFile::OffsetToRVA(DWORD offset)
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
	std::cout << "!!!!uy" << std::endl;
    m_ntHeaders64.OptionalHeader.SizeOfHeaders = AlignNumber(m_dosHeader.e_lfanew + m_ntHeaders64.FileHeader.SizeOfOptionalHeader +
        m_ntHeaders64.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), m_ntHeaders64.OptionalHeader.FileAlignment);

    DWORD imageSize = m_ntHeaders64.OptionalHeader.SizeOfHeaders;
    for (int i = 0; i < m_ntHeaders64.FileHeader.NumberOfSections; i++)
    {
        imageSize += AlignNumber(m_sectionTable[i].Misc.VirtualSize, m_ntHeaders64.OptionalHeader.SectionAlignment);
    }
    m_ntHeaders64.OptionalHeader.SizeOfImage = AlignNumber(imageSize, m_ntHeaders64.OptionalHeader.SectionAlignment);

    m_ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
    m_ntHeaders64.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
	std::cout << "!!!!vc" << std::endl;
}

void PEFile::ComputeSectionTable()
{
	std::cout << "!!!!rr" << std::endl;
    DWORD offset = m_ntHeaders64.OptionalHeader.SizeOfHeaders;
    for (int i = 0; i < m_ntHeaders64.FileHeader.NumberOfSections; i++)
    {
        m_sectionTable[i].Characteristics |= IMAGE_SCN_MEM_WRITE;
        offset = AlignNumber(offset, m_ntHeaders64.OptionalHeader.FileAlignment);
        m_sectionTable[i].PointerToRawData = offset;
        offset += m_sectionTable[i].SizeOfRawData;
    }
	std::cout << "!!!!pp" << std::endl;
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



int main()
{
	PEFile pe;
	pe.New();

	 // Add the exported functions of your DLL
    const char* functions[] = { "GetStdHandle", "WriteFile", "ExitProcess" };

    // Add the import to the PE file
    pe.AddImport("kernel32.dll", (char**)functions, 3);
    std::cout << "Added imports to PE file" << std::endl;

	int textSectionIndex = pe.AddSection(TEXT_SECTION_NAME, pe.GetFileAlignment(), true);
	std::cout << "!!!!a" << std::endl;
	auto codeSection = pe.GetSectionByIndex(textSectionIndex);
	
	std::cout << " sizeof(ULONGLONG)" <<  sizeof(ULONGLONG) << std::endl;

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

	std::vector<uint8_t> code = {
		0x48, 0x83, 0xEC, 0x08,
		0x48, 0x83, 0xEC, 0x20,
		0xB9, 0xF5, 0xFF, 0xFF, 0xFF,
		0xE8, 0x0E, 0x20, 0x0, 0x0,
		0x48, 0x89, 0x05, 0xFB, 0x0F, 0x0, 0x0,
		0x48, 0x83, 0xC4, 0x20,
		0x48, 0x83, 0xEC, 0x30,
		0x48, 0x8B, 0x0D, 0xEC, 0x0F, 0x0, 0x0,
		0x48, 0x8D, 0x15, 0xD1, 0x0F, 0x0, 0x0,
		0x41, 0xB8, 0x14, 0x0, 0x0, 0x0,
		0x4C, 0x8D, 0x0D, 0xE0, 0x0F, 0x0, 0x0,
		0x48, 0xC7, 0x44, 0x24, 0x20, 0x0, 0x0, 0x0, 0x0,
		0xE8, 0xDC, 0x1F, 0x0, 0x0,
		0x48, 0x83, 0xC4, 0x30,
		0x31, 0xC9,
		0xE8, 0xD7, 0x1F, 0x0, 0x0
	};

    memcpy(codeSection.RawData, code.data(), code.size());
	codeSection.Size = code.size();


	int dataSectionIndex = pe.AddSection(DATA_SECTION_NAME, pe.GetFileAlignment(), false);
	std::vector<uint8_t> data = {
		0x43, 0x6F, 0x6E, 0x73, 0x6F, 0x6C, 0x65, 0x20, 0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x36, 0x34, 0x0D, 0x0A
	};
	auto dataSection = pe.GetSectionByIndex(dataSectionIndex);
	memcpy(dataSection.RawData, data.data(), data.size());
	
	std::cout << "!!!!b" << std::endl;

	pe.SaveToFile("dev.exe");
	std::cout << "!!!!c" << std::endl;

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

	printf("[Information] PE File packed with 0 Errors.");
	cin.get();

	return EXIT_SUCCESS;
}