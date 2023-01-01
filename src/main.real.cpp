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

using namespace std;

template<typename Ptr>
size_t StrCpyT(Ptr p, const std::string& s)
{
  strncpy(reinterpret_cast<char*>(p), s.c_str(), s.length());
  return s.size();
}

#define ToRVA(pSH, p) (DWORD(p) - DWORD(pBase) - pSH->PointerToRawData + pSH->VirtualAddress)
#define ToVA(pSH, p) (DWORD(p) - DWORD(pBase) - pSH->PointerToRawData + pSH->VirtualAddress + pPE->ImageBase)
#define VU_ALIGN_UP(v, a) (((v) + ((a) - 1)) & ~((a) - 1))

void import_GetStdHandle() {
 	// The DLL that the exe file imports functions from.
	const char* dll_name = "kernel32.dll";

	// The names of the functions that the exe file imports from the DLL.
	const char* function_names[] = {
		"GetStdHandle"
		// "GetLastError",
		// "GetCurrentProcessId",
		// "GetCurrentThreadId",
		// "GetTickCount",
		// "GetSystemTimeAsFileTime",
		// "GetCurrentProcess"
	};

	// Create the import table for the exe file.
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
}

int main()
{
   // Dev : Hamid.Memar
	string output_pe_file	= "dev.exe";
	// Generating PE File, Initializing DOS + NT Headeres

	IMAGE_DOS_HEADER	dos_h;
    memset(&dos_h, 0, sizeof(IMAGE_DOS_HEADER));
	dos_h.e_magic		= IMAGE_DOS_SIGNATURE;
	dos_h.e_cblp		= 0x0090;
	dos_h.e_cp			= 0x0003;
	dos_h.e_crlc		= 0x0000;
	dos_h.e_cparhdr		= 0x0004;
	dos_h.e_minalloc	= 0x0000;
	dos_h.e_maxalloc    = 0xFFFF;
	dos_h.e_ss			= 0x0000;
	dos_h.e_sp			= 0x00B8;
	dos_h.e_csum		= 0x0000;
	dos_h.e_ip			= 0x0000;
	dos_h.e_cs			= 0x0000;
	dos_h.e_lfarlc		= 0x0040;
	dos_h.e_ovno		= 0x0000;
	dos_h.e_oemid		= 0x0000;
	dos_h.e_oeminfo		= 0x0000;
	dos_h.e_lfanew = sizeof(IMAGE_DOS_HEADER); // The file offset of the PE header, relative to the beginning of the file.

  	std::cout << "PE -> DOS Header -> Created" << std::endl;
	
	IMAGE_NT_HEADERS64 nt_h;
	memset(&nt_h, 0, sizeof(IMAGE_NT_HEADERS64));
	nt_h.Signature											= IMAGE_NT_SIGNATURE;
	nt_h.FileHeader.Machine									= IMAGE_FILE_MACHINE_AMD64;

	// TODO
	nt_h.FileHeader.NumberOfSections						= 3; // ".text", ".bss", ".data"
	nt_h.FileHeader.TimeDateStamp							= 0x00000000; // leave this
	nt_h.FileHeader.PointerToSymbolTable					= 0x0; // leave this
	nt_h.FileHeader.NumberOfSymbols							= 0x0; // leave this
	nt_h.FileHeader.SizeOfOptionalHeader					= sizeof(IMAGE_OPTIONAL_HEADER64); // leave this
	nt_h.FileHeader.Characteristics							= IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE; // declare this is a 64bit exe

	nt_h.OptionalHeader.Magic								= IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	// nt_h.OptionalHeader.MajorLinkerVersion					= 10; // leave this
	// nt_h.OptionalHeader.MinorLinkerVersion					= 0x05; // leave this
	nt_h.OptionalHeader.SizeOfCode							= 0x00000200;  // dynamic
	nt_h.OptionalHeader.SizeOfInitializedData				= 0x00000400; // dynamic
	nt_h.OptionalHeader.SizeOfUninitializedData				= 0x0; // dynamic
	nt_h.OptionalHeader.AddressOfEntryPoint					= 0x00001000; // dynamic
	nt_h.OptionalHeader.BaseOfCode							= 0x00001000;  // dynamic, normally same as AddressOfEntryPoint
	nt_h.OptionalHeader.ImageBase							= 0x0000000000400000; // leave it
	nt_h.OptionalHeader.SectionAlignment					= 0x00001000; // dynamic
	nt_h.OptionalHeader.FileAlignment						= 0x00000200; // dynamic
	nt_h.OptionalHeader.MajorOperatingSystemVersion			= 0x0005; // leave it
	nt_h.OptionalHeader.MinorOperatingSystemVersion			= 0x0002; // leave it
	nt_h.OptionalHeader.MajorImageVersion					= 0x0000;  // leave it
	nt_h.OptionalHeader.MinorImageVersion					= 0x0000; // leave it
	nt_h.OptionalHeader.MajorSubsystemVersion				= 0x0005;// leave it
	nt_h.OptionalHeader.MinorSubsystemVersion				= 0x0002;// leave it
	nt_h.OptionalHeader.Win32VersionValue					= 0x0;// leave it
	
	/*
	The size of the image, in bytes, including all headers. Must be a multiple of SectionAlignment.
	*/
	nt_h.OptionalHeader.SizeOfImage							= 0x00004000; // dynamic
	/*
	The combined size of the following items, rounded to a multiple of the value specified in the FileAlignment member.

		e_lfanew member of IMAGE_DOS_HEADER
		4 byte signature
		size of IMAGE_FILE_HEADER
		size of optional header
		size of all section headers
	*/
	nt_h.OptionalHeader.SizeOfHeaders						= 0x00000400;

	/*
	The image file checksum. The following files are validated at load time: all drivers, any DLL loaded at boot time, and any DLL loaded into a critical system process.
	*/
	nt_h.OptionalHeader.CheckSum							= 0; //0x0000FB72; // dynamic, Must Update
	nt_h.OptionalHeader.Subsystem							= IMAGE_SUBSYSTEM_WINDOWS_CUI;
	nt_h.OptionalHeader.DllCharacteristics					= 0x0000; // leave it
	nt_h.OptionalHeader.SizeOfStackReserve					= 0x0000000000100000;// leave it
	nt_h.OptionalHeader.SizeOfStackCommit					= 0x0000000000001000;// leave it
	nt_h.OptionalHeader.SizeOfHeapReserve					= 0x0000000000100000;// leave it
	nt_h.OptionalHeader.SizeOfHeapCommit					= 0x0000000000001000;// leave it
	nt_h.OptionalHeader.LoaderFlags							= 0x00000000;// leave it
	nt_h.OptionalHeader.NumberOfRvaAndSizes					= IMAGE_NUMBEROF_DIRECTORY_ENTRIES;// leave it
	
	std::cout << "PE -> PE Header -> Created" << std::endl;

	// import kernel32
	// cout << (n + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR)<< endl;
	nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0x00000028;
	nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0x00003034;

	// pPE->Import.VirtualAddress = pSHImport->VirtualAddress;
	// pPE->Import.Size = sizeof(ImportDescriptor);

	// cout << n * sizeof(ULONGLONG)<< endl;
	nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0x00000020;
	nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0x00003000;


	// https://github.com/TinyCC/tinycc/blob/d76e03232bb858387108c91e7bf58bd892563483/tccpe.c
    // pe->imp_size = (ndlls + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    // pe->iat_size = (sym_cnt + ndlls) * sizeof(ADDR3264);

    // dll_ptr = pe->thunk->data_offset;
    // thk_ptr = dll_ptr + pe->imp_size;
    // ent_ptr = thk_ptr + pe->iat_size;

    // pe->imp_offs  [IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = pe->thunk->data_offset + rva_base;
    // pe->iat_offs  [IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress= pe->thunk->data_offset + pe->imp_size + rva_base;
	

    // IMAGE_IMPORT_DESCRIPTOR* importTable = (IMAGE_IMPORT_DESCRIPTOR*)
    //         (nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + 
	// 		nt_h.OptionalHeader.ImageBase);

	// ULONGLONG;
	
	// // import kernel32.dll
	// IMAGE_IMPORT_DESCRIPTOR import_descripter;
	// memset(&import_descripter, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	// //import_descripter.OriginalFirstThunk = NULL; // Replace with rva to this->thunk_entry when outputting
	// // import_descripter.TimeDateStamp = -1; // NO NEEDED
	// // import_descripter.ForwarderChain = -1; // NO NEEDED
	// // import_descripter.Name = NULL; // NO NEEDED
	// import_descripter.FirstThunk = rva; // PE Loader with patchup address at rva to become the address of the import, awesome!

	// IMAGE_THUNK_DATA64  _thunk_entry;
	// _thunk_entry.u1.Ordinal = IMAGE_ORDINAL_FLAG64 | (ordinal & 0xffff);

	// char* _library_name = new char[strlen("KERNEL32.dll")+1];
	// strcpy(_library_name, "KERNEL32.dll");

	// _thunk_entry.u1.AddressOfData = NULL; // Replace with rva to import_by_name
	
	// IMAGE_IMPORT_BY_NAME* _import_by_name = (IMAGE_IMPORT_BY_NAME*) new char[strlen("GetStdHandle")+1+sizeof(WORD)];
	// _import_by_name->Hint = 0; // Not necessary
	// size_t _import_by_name_len = strlen("GetStdHandle")+1+sizeof(WORD);
	// strcpy((char*)(&_import_by_name->Name), "GetStdHandle");

	// // import_descripter.Name[0] = 'K';
	// // import_descripter.Name[0] = 'K';
	
	// // "KERNEL32.dll";
	// IMAGE_THUNK_DATA64 importAddressTable = import_descripter.FirstThunk;






	PIMAGE_SECTION_HEADER pSHLast = nullptr;

	// For this example,
	// Default the raw/virtual offset is continuous file offset + raw size of previous section
	// Default the raw/virtual size is equal to OptHeader.FileAlignment/OptHeader.SectionAlignment
	const auto AddSectionHeader = [&](const std::string& name, const DWORD characteristics) -> PIMAGE_SECTION_HEADER
	{
		PIMAGE_SECTION_HEADER result = nullptr;

		static IMAGE_SECTION_HEADER empty = { 0 };
		ZeroMemory(&empty, sizeof(empty));
		empty.PointerToRawData = PEBody;
		empty.SizeOfRawData = pPE->FileAlignment;
		empty.Misc.VirtualSize = pPE->SectionAlignment;

		const auto pPrevSection = iSH == 0 ? &empty : pSH - 1;
		
		StrCpyT(pSH->Name, name.c_str());
		pSH->PointerToRawData = pPrevSection->PointerToRawData + pPrevSection->SizeOfRawData;
		pSH->SizeOfRawData = pPE->FileAlignment;
		pSH->VirtualAddress = pPrevSection->VirtualAddress + pPrevSection->Misc.VirtualSize;
		pSH->Misc.VirtualSize = pPE->SectionAlignment;
		pSH->Characteristics = characteristics;

		result = pSH;

		std::cout << "PE -> Section Header -> " << name.c_str() << " -> Created" << std::endl;

		iSH++;
		pSH++;

		pSHLast = result;

		return result;
	};



























	// Initializing Section [ Code ]
	IMAGE_SECTION_HEADER	code_section;
	memset(&code_section, 0, sizeof(IMAGE_SECTION_HEADER));
	code_section.Name[0] = '.';
	code_section.Name[1] = 't';	
	code_section.Name[2] = 'e';
	code_section.Name[3] = 'x';
	code_section.Name[4] = 't';
	code_section.Name[5] = 0x0;
	code_section.Misc.VirtualSize					= 0x00000060;	// Virtual Size
	code_section.VirtualAddress						= 0x00001000;	// Virtual Address
	code_section.SizeOfRawData						= 0x00000200;	// Raw Size
	code_section.PointerToRawData					= 0x00000400;	// Raw Address
	code_section.PointerToRelocations				= 0x00000000;	// Reloc Address
	code_section.PointerToLinenumbers				= 0x00000000;	// Line Numbers
	code_section.NumberOfRelocations				= 0x00000000;	// Reloc Numbers
	code_section.NumberOfLinenumbers				= 0x00000000;	// Line Numbers Number
	code_section.Characteristics					= IMAGE_SCN_MEM_EXECUTE	  |	// 0x20000000
													  IMAGE_SCN_MEM_READ	  |	// 0x40000000
													  IMAGE_SCN_CNT_CODE	  ; // 0x00000020
																				// ==========
																				// 0x60000020

	IMAGE_SECTION_HEADER	data_section;
	memset(&data_section, 0, sizeof(IMAGE_SECTION_HEADER));
	data_section.Name[0] = '.';
	data_section.Name[1] = 'd';
	data_section.Name[2] = 'a';
	data_section.Name[3] = 't';
	data_section.Name[4] = 'a';
	data_section.Name[5] = 0x0;
	data_section.Misc.VirtualSize					= 0x00000024;	// Virtual Size
	data_section.VirtualAddress						= 0x00002000;	// Virtual Address
	data_section.SizeOfRawData						= 0x00000200;	// Raw Size
	data_section.PointerToRawData					= 0x00000600;	// Raw Address
	data_section.PointerToRelocations				= 0x00000000;	// Reloc Address
	data_section.PointerToLinenumbers				= 0x00000000;	// Line Numbers
	data_section.NumberOfRelocations				= 0x00000000;	// Reloc Numbers
	data_section.NumberOfLinenumbers				= 0x00000000;	// Line Numbers Number
	data_section.Characteristics					= IMAGE_SCN_CNT_INITIALIZED_DATA | //0x00000040
         											  	IMAGE_SCN_MEM_READ | //0x40000000
														IMAGE_SCN_MEM_WRITE; //0x80000000

	// ".idata"
	IMAGE_SECTION_HEADER	import_section;
	memset(&import_section, 0, sizeof(IMAGE_SECTION_HEADER));
	import_section.Name[0] = '.';
	import_section.Name[1] = 'i';
	import_section.Name[2] = 'd';
	import_section.Name[3] = 'a';
	import_section.Name[4] = 't';
	import_section.Name[5] = 'a';
	import_section.Name[6] = 0x0;

	import_section.Misc.VirtualSize					= 0x000000B8;	// Virtual Size
	import_section.VirtualAddress						= 0x00003000;	// Virtual Address****
	import_section.SizeOfRawData						= 0x00000200;	// Raw Size

	import_section.PointerToRawData					= 0x00000800;	// Raw Address
	import_section.PointerToRelocations				= 0x00000000;	// Reloc Address
	import_section.PointerToLinenumbers				= 0x00000000;	// Line Numbers
	import_section.NumberOfRelocations				= 0x00000000;	// Reloc Numbers
	import_section.NumberOfLinenumbers				= 0x00000000;	// Line Numbers Number
	import_section.Characteristics					= IMAGE_SCN_MEM_EXECUTE	  |	// 0x20000000
													  IMAGE_SCN_MEM_READ	  |	// 0x40000000
													  IMAGE_SCN_CNT_CODE	  ; // 0x00000020
																				// ==========
																				// 0x60000020




	// Create/Open PE File
	fstream pe_writter;
	pe_writter.open(output_pe_file, ios::binary | ios::out);

	// Write DOS Header
	pe_writter.write((char*)&dos_h, sizeof dos_h);

	// Write NT Header
	pe_writter.write((char*)&nt_h, sizeof nt_h);

	// Write Headers of Sections
	pe_writter.write((char*)&code_section, sizeof code_section);
	pe_writter.write((char*)&data_section, sizeof data_section);
	pe_writter.write((char*)&import_section, sizeof import_section);
	

	// Add Padding
	while (pe_writter.tellp() != code_section.PointerToRawData) pe_writter.put(0x0);

	// Write Code Section

    // std::vector<uint8_t> code = {
	// 	0x48, 0x83, 0xC4, 0x48,				// add rsp, 0x48; Stack unwind
	// 	0x48, 0x31, 0xC9,				// xor rcx, rcx; hWnd
	// 	0x48, 0xC7, 0xC2, 0x10, 0x20, 0x40, 0x00,	// mov rdx, Message(0x402010)
	// 	0x49, 0xC7, 0xC0, 0x00, 0x20, 0x40, 0x00,	// mov r8, Title(0x402000)
	// 	0x4D, 0x31, 0xC9,				// xor r9, r9; MB_OK
	// 	0x48, 0xC7, 0xC0, 0x5C, 0x30, 0x40, 0x00,	// mov rax, MessageBoxA address(0x40305c)
	// 	0xFF, 0x10,					// call[rax]; MessageBoxA(hWnd, Message, Title, MB_OK)
	// 	0x48, 0x31, 0xC9,				// xor rcx, rcx; exit value
	// 	0x48, 0xC7, 0xC0, 0x6C, 0x30, 0x40, 0x00,	// mov rax, ExitProcess address (0x40306c)
	// 	0xFF, 0x10,					// call[rax]; ExitProcess(0)
	// 	0xC3						// ret; Never reached
	// };

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
	std::for_each(code.begin(), code.end(), [&pe_writter](uint8_t &n){ pe_writter.put(n); });
	for (size_t i = 0; i < code_section.SizeOfRawData - code.size(); i++) pe_writter.put(0x0);



	/***********************************/

	// "Console Message 64\r\n"
	std::vector<uint8_t> data = {
		0x43, 0x6F, 0x6E, 0x73, 0x6F, 0x6C, 0x65, 0x20, 0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
		0x36, 0x34, 0x0D, 0x0A
	};

	std::for_each(data.begin(), data.end(), [&pe_writter](uint8_t &n){ pe_writter.put(n); });
	for (size_t i = 0; i < data_section.SizeOfRawData - data.size(); i++) pe_writter.put(0x0);


	// gibberish
	std::vector<uint8_t> imports = {
		0x8E, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9E, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xAA, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xFF, 0x25, 0xDA, 0xFF, 0xFF, 0xFF, 0xFF, 0x25, 0xDC, 0xFF, 0xFF, 0xFF, 0xFF, 0x25, 0xDE, 0xFF,
		0xFF, 0xFF, 0x00, 0x00, 0x60, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x80, 0x30, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x8E, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9E, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xAA, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x4B, 0x45, 0x52, 0x4E, 0x45, 0x4C, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x00, 0xE1, 0x02,
		0x47, 0x65, 0x74, 0x53, 0x74, 0x64, 0x48, 0x61, 0x6E, 0x64, 0x6C, 0x65, 0x00, 0x00, 0x33, 0x06,
		0x57, 0x72, 0x69, 0x74, 0x65, 0x46, 0x69, 0x6C, 0x65, 0x00, 0x68, 0x01, 0x45, 0x78, 0x69, 0x74,
		0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73
	};

	std::for_each(imports.begin(), imports.end(), [&pe_writter](uint8_t &n){ pe_writter.put(n); });
	for (size_t i = 0; i < import_section.SizeOfRawData - imports.size(); i++) pe_writter.put(0x0);



	// Close PE File
	pe_writter.close();

    cin.get();

	printf("[Information] PE File packed with 0 Errors.");
	return EXIT_SUCCESS;
}