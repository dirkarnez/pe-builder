pe-builder
==========

### Truth
- (target address) 0x401000 - (load address)0x400000  = (RVA)0x1000
  - To convert an RVA to an actual address, simply reverse the process: add the RVA to the actual load address to find the actual memory address.
  - > For instance, consider an EXE file loaded at address 0x400000, with its code section at address 0x401000. The RVA of the code section would be:
- DataDirectory[dwEntry].VirtualAddress is rva
- DWORD = unsigned long

### Reference
- [base/pe_image.cc at d7453874fda54fe2701fea6b108abf9a29a9b990 · yue/base](https://github.com/yue/base/blob/d7453874fda54fe2701fea6b108abf9a29a9b990/win/pe_image.cc)
- [PE格式第三讲扩展,VA,RVA,FA(RAW),模块地址的概念 - iBinary - 博客园](https://www.cnblogs.com/ibinary/p/7653693.html)
- [Parsing PE File Headers with C++ - Red Teaming Experiments](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/pe-file-header-parser-in-c++)

### Notes
- `DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]` points (RVAToPtr) to a linked list of `IMAGE_IMPORT_DESCRIPTOR` (list-end should be a zero-filled `IMAGE_IMPORT_DESCRIPTOR`), each `IMAGE_IMPORT_DESCRIPTOR` is responsible for 1 externel `.dll`
- RVAToPtr(IMAGE_IMPORT_DESCRIPTOR->FirstThunk) ---> PIMAGE_THUNK_DATA64
- PIMAGE_THUNK_DATA64->u1.AddressOfData
- ```cpp
    std::vector<PEIMPORTFUNC> vecFunc { };
    std::string strDllName { };
    ```


- each `IMAGE_IMPORT_DESCRIPTOR` points to a linked list of `IMAGE_THUNK_DATA` (in my case it is "name-inported"), each `IMAGE_THUNK_DATA` is responsible for a external function

### Notes today
            pe_set_datadir(&pe_header, IMAGE_DIRECTORY_ENTRY_IMPORT,
                pe->imp_offs, pe->imp_size);
            pe_set_datadir(&pe_header, IMAGE_DIRECTORY_ENTRY_IAT,
                pe->iat_offs, pe->iat_size);

        pe->imp_size = (ndlls + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR); // 
    pe->iat_size = (sym_cnt + ndlls) * sizeof(ADDR3264);


    pe->thunk is a Section (i think it is .idata)

    GetDirEntryRVA = if (m_stFileInfo.fIsx64)
			return m_pNTHeader64->OptionalHeader.DataDirectory[dwEntry].VirtualAddress;

    GetDirEntrySize = 
		if (m_stFileInfo.fIsx64)
			return m_pNTHeader64->OptionalHeader.DataDirectory[dwEntry].Size;

### References
- !!!!!!!!!!!!!!!!!https://0xrick.github.io/win-internals/pe5/

### Import exported dll
- [[Help] (manual mapping)how to get ordinal function address?](https://www.unknowncheats.me/forum/programming-for-beginners/365094-manual-mapping-ordinal-function-address.html)

### Shorthand
```cpp
#include <fstream> 
#include <windows.h>
#include <winnt.h>
#include <iostream>

int main () {

  std::ofstream outfile;
  outfile.open ("test.txt");
    IMAGE_NT_HEADERS64 nt_h;
	memset(&nt_h, 0, sizeof(IMAGE_NT_HEADERS64));
  std::cout << sizeof(IMAGE_NT_HEADERS64) << std::endl; 
    std::cout << sizeof(nt_h) << std::endl; 
	outfile.write((char *)&nt_h, sizeof(nt_h));
  long pos = outfile.tellp();
  std::cout << pos;
  
  outfile.seekp (pos-7);
  outfile.write (" sam",4);


  outfile.close();

  return 0;
}
```


### Notes
```cpp
// Function store the runtime address
address_table[i].u1.Function = (DWORD) function_handle;

// the lookup table points to function names or ordinals => it is the IDT
IMAGE_THUNK_DATA* lookup_table = (IMAGE_THUNK_DATA*) (ImageBase + import_descriptors[i].OriginalFirstThunk);

// the address table is a copy of the lookup table at first
// but we put the addresses of the loaded function inside => that's the IAT
IMAGE_THUNK_DATA* address_table = (IMAGE_THUNK_DATA*) (ImageBase + import_descriptors[i].FirstThunk);


// Check the lookup table for the adresse of the function name to import
// AddressOfData stores IMAGE_IMPORT_BY_NAME
DWORD lookup_addr = lookup_table[i].u1.AddressOfData;

if((lookup_addr & IMAGE_ORDINAL_FLAG) == 0) { //if first bit is not 1
	// import by name : get the IMAGE_IMPORT_BY_NAME struct
	IMAGE_IMPORT_BY_NAME* image_import = (IMAGE_IMPORT_BY_NAME*) (ImageBase + lookup_addr);
	// this struct points to the ASCII function name
	char* funct_name = (char*) &(image_import->Name);
	// get that function address from it's module and name
	function_handle = (void*) GetProcAddress(import_module, funct_name);
} else {
	// import by ordinal, directly
	function_handle = (void*) GetProcAddress(import_module, (LPSTR) lookup_addr);
}
	
```
```cpp
	IMAGE_IMPORT_DESCRIPTOR import_table[2] = {};

	memset(&import_table[0], 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	import_table[0].Name = (DWORD)(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER)); // The file offset of the DLL name in the exe file.
	// RVA of the IAT
	import_table[0].FirstThunk = (DWORD)(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) + sizeof(IMAGE_IMPORT_DESCRIPTOR)); // The file offset of the import lookup table.
	// RVA of the ILT (lookup)
	import_table[0].OriginalFirstThunk = (DWORD)(sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64) + sizeof(IMAGE_SECTION_HEADER) + sizeof(IMAGE_IMPORT_DESCRIPTOR)); // The file offset of the import lookup table.

	// Create the import lookup table for the exe file.
	std::vector<IMAGE_THUNK_DATA64> import_lookup_table;
	for (const char* function_name : function_names) {
		// Create an IMAGE_IMPORT_BY_NAME structure for the function.
		size_t function_name_length = strlen(function_name);
		std::vector<uint8_t> function_name_data(sizeof(IMAGE_IMPORT_BY_NAME) + function_name_length);
		PIMAGE_IMPORT_BY_NAME function_name_struct = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(function_name_data.data());
		function_name_struct->Hint = 0; // Not necessary // The hint, which is a 16-bit index into the export table of the DLL.
		memcpy(function_name_struct->Name, function_name, function_name_length + 1); // The name of the imported function

		IMAGE_THUNK_DATA64 thunk_data_64;
		memset(&thunk_data_64, 0, sizeof(thunk_data_64));
		thunk_data_64.u1.AddressOfData = (ULONGLONG)function_name_struct;  // RVA to an IMAGE_IMPORT_BY_NAME with the imported API name
	}

	memset(&import_table[1], 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
```

### NOTES
- PointerToRawData is the value in hex editor
- VirtualAddress is defined address to be load into the memory
- VirtualSize is size before aligned
- SizeOfRawData is aligned size
- !!!!!!!!!!!!!!!!!!https://github.com/TheDusty01/PEImportTableModifier/blob/fd6568b686feb1b38ea0fe210e5e0dd32c988506/PEImportTableModifier/src/PEFile.cpp
- https://www.cnblogs.com/zpchcbd/p/14674298.html
- https://github.com/hasherezade/libpeconv/blob/master/libpeconv/src/pe_raw_to_virtual.cpp
- https://github.com/csw201710/demo/blob/6b064dc44922fafec42ad90b1a9bc7c5781870f2/window/pe/libpe/pe.c
- ```cpp
	namespace winmd::impl
	{
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
		int32_t  e_lfanew;
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

	    struct image_section_header {
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

	    struct image_cor20_header
	    {
		uint32_t cb;
		uint16_t MajorRuntimeVersion;
		uint16_t MinorRuntimeVersion;
		image_data_directory MetaData;
		uint32_t Flags;
		union
		{
		    uint32_t EntryPointToken;
		    uint32_t EntryPointRVA;
		} dummyunionname;
		image_data_directory Resources;
		image_data_directory StrongNameSignature;
		image_data_directory CodeManagerTable;
		image_data_directory VTableFixups;
		image_data_directory ExportAddressTableJumps;
		image_data_directory ManagedNativeHeader;
	    };
	}
  ```
