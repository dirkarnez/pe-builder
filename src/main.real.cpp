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

// template <typename Ptr>
// size_t StrCpyT(Ptr p, const std::string &s)
// {
// 	strncpy(reinterpret_cast<char *>(p), s.c_str(), s.length());
// 	return s.size();
// }

// PBYTE = unsigned char*
// DWORD = unsigned long

/*
In an image file, this is the address of an item after it is loaded into memory, 
with the base address of the image file subtracted from it. 
The RVA of an item almost always differs from its position 
within the file on disk (file pointer).
In an object file, an RVA is less meaningful because memory 
locations are not assigned. In this case, an RVA would be 
an address within a section (described later in this table), 
to which a relocation is later applied during linking. 
For simplicity, a compiler should just set the first RVA in each section to zero.
*/
#define ToRVA(import_section_header_ptr, p) (DWORD(p) - DWORD(&dos_h) - import_section_header_ptr->PointerToRawData + import_section_header_ptr->VirtualAddress)

/*
Same as RVA, except that the base address of the image file is not subtracted.
The address is called a VA because Windows creates a distinct VA space for each process, 
independent of physical memory. For almost all purposes, 
a VA should be considered just an address. 
A VA is not as predictable as an RVA because 
the loader might not load the image at its preferred location.
*/
#define ToVA(import_section_header_ptr, p) (DWORD(p) - DWORD(&dos_h) - import_section_header_ptr->PointerToRawData + import_section_header_ptr->VirtualAddress + pPE->ImageBase)

// #define ToRVA(pSH, p) (DWORD((((ULONGLONG)(p)) - ((ULONGLONG)(&dos_h)) - pSH->PointerToRawData + pSH->VirtualAddress)))
// #define ToVA(pSH, p) (((ULONGLONG)(p)) - ((ULONGLONG)(&dos_h)) - pSH->PointerToRawData + pSH->VirtualAddress + nt_h.OptionalHeader.ImageBase)


#define VU_ALIGN_UP(v, a) (((v) + ((a) - (1))) & ~((a) - (1)))

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
	// Dev : Hamid.Memar
	string output_pe_file = "dev.exe";
	// Generating PE File, Initializing DOS + NT Headeres

	IMAGE_DOS_HEADER dos_h;
	memset(&dos_h, 0, sizeof(IMAGE_DOS_HEADER));
	dos_h.e_magic = IMAGE_DOS_SIGNATURE;
	dos_h.e_cblp = 0x0090;
	dos_h.e_cp = 0x0003;
	dos_h.e_crlc = 0x0000;
	dos_h.e_cparhdr = 0x0004;
	dos_h.e_minalloc = 0x0000;
	dos_h.e_maxalloc = 0xFFFF;
	dos_h.e_ss = 0x0000;
	dos_h.e_sp = 0x00B8;
	dos_h.e_csum = 0x0000;
	dos_h.e_ip = 0x0000;
	dos_h.e_cs = 0x0000;
	dos_h.e_lfarlc = 0x0040;
	dos_h.e_ovno = 0x0000;
	dos_h.e_oemid = 0x0000;
	dos_h.e_oeminfo = 0x0000;
	dos_h.e_lfanew = sizeof(IMAGE_DOS_HEADER); // The file offset of the PE header, relative to the beginning of the file.

	std::cout << "PE -> DOS Header -> Created" << std::endl;

	IMAGE_NT_HEADERS64 nt_h;
	memset(&nt_h, 0, sizeof(IMAGE_NT_HEADERS64));
	nt_h.Signature = IMAGE_NT_SIGNATURE;
	nt_h.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;

	// TODO
	// nt_h.FileHeader.NumberOfSections						= 3; // ".text", ".bss", ".data"
	nt_h.FileHeader.TimeDateStamp = 0x00000000;												  // leave this
	nt_h.FileHeader.PointerToSymbolTable = 0x0;												  // leave this
	nt_h.FileHeader.NumberOfSymbols = 0x0;													  // leave this
	nt_h.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);					  // leave this
	nt_h.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE; // declare this is a 64bit exe

	nt_h.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	// nt_h.OptionalHeader.MajorLinkerVersion					= 10; // leave this
	// nt_h.OptionalHeader.MinorLinkerVersion					= 0x05; // leave this

	// TODO
	// nt_h.OptionalHeader.SizeOfCode							= 0x00000200;  // dynamic
	nt_h.OptionalHeader.SizeOfInitializedData = 0x00000400; // dynamic
	nt_h.OptionalHeader.SizeOfUninitializedData = 0x0;		// dynamic

	// TODO
	// nt_h.OptionalHeader.AddressOfEntryPoint					= 0x00001000; // dynamic

	// TODO
	// nt_h.OptionalHeader.BaseOfCode							= 0x1000;  // dynamic, normally same as AddressOfEntryPoint
	nt_h.OptionalHeader.ImageBase = 0x400000;			   // leave it
	nt_h.OptionalHeader.SectionAlignment = 0x1000;		   // dynamic
	nt_h.OptionalHeader.FileAlignment = 0x200;			   // dynamic
	nt_h.OptionalHeader.MajorOperatingSystemVersion = 0x5; // leave it
	nt_h.OptionalHeader.MinorOperatingSystemVersion = 0x2; // leave it
	nt_h.OptionalHeader.MajorImageVersion = 0;			   // leave it
	nt_h.OptionalHeader.MinorImageVersion = 0;			   // leave it
	nt_h.OptionalHeader.MajorSubsystemVersion = 0x5;	   // leave it
	nt_h.OptionalHeader.MinorSubsystemVersion = 0x2;	   // leave it
	nt_h.OptionalHeader.Win32VersionValue = 0;			   // leave it

	/*
	The combined size of the following items, rounded to a multiple of the value specified in the FileAlignment member.

		e_lfanew member of IMAGE_DOS_HEADER
		4 byte signature
		size of IMAGE_FILE_HEADER
		size of optional header
		size of all section headers
	*/

	// TODO
	// nt_h.OptionalHeader.SizeOfImage							= 0x00000400;

	// TODO
	// nt_h.OptionalHeader.SizeOfHeaders						= 0x00000400;

	/*
	The image file checksum. The following files are validated at load time: all drivers, any DLL loaded at boot time, and any DLL loaded into a critical system process.
	*/
	nt_h.OptionalHeader.CheckSum = 0; // 0x0000FB72; // dynamic, Must Update
	nt_h.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
	nt_h.OptionalHeader.DllCharacteristics = 0x0000;							// leave it
	nt_h.OptionalHeader.SizeOfStackReserve = 0x0000000000100000;				// leave it
	nt_h.OptionalHeader.SizeOfStackCommit = 0x0000000000001000;					// leave it
	nt_h.OptionalHeader.SizeOfHeapReserve = 0x0000000000100000;					// leave it
	nt_h.OptionalHeader.SizeOfHeapCommit = 0x0000000000001000;					// leave it
	nt_h.OptionalHeader.LoaderFlags = 0x00000000;								// leave it
	nt_h.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES; // leave it

	std::cout << "PE -> PE Header -> Created" << std::endl;

	// The Section Header(s) after the NT Header
	// auto pSH = PIMAGE_SECTION_HEADER(ULONGLONG(&nt_h) + sizeof(IMAGE_NT_HEADERS64));

	// // import kernel32
	// // cout << (n + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR)<< endl;
	// nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0x00000028;
	// nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0x00003034;

	// // pPE->Import.VirtualAddress = pSHImport->VirtualAddress;
	// // pPE->Import.Size = sizeof(ImportDescriptor);

	// // cout << n * sizeof(ULONGLONG)<< endl;
	// nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0x00000020;
	// nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0x00003000;

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



	unsigned short section_index = 0;

	IMAGE_SECTION_HEADER empty_section;
	memset(&empty_section, 0, sizeof(IMAGE_SECTION_HEADER));
	empty_section.PointerToRawData = 0x200;
	empty_section.SizeOfRawData = nt_h.OptionalHeader.FileAlignment;
	empty_section.Misc.VirtualSize = nt_h.OptionalHeader.SectionAlignment;

	PIMAGE_SECTION_HEADER prev_section_ptr = &empty_section;
	PIMAGE_SECTION_HEADER last_section_ptr = nullptr;

	// For this example,
	// Default the raw/virtual offset is continuous file offset + raw size of previous section
	// Default the raw/virtual size is equal to OptHeader.FileAlignment/OptHeader.SectionAlignment
	const auto configSectionHeader = [&](IMAGE_SECTION_HEADER& section_header) -> void
	{
		section_header.PointerToRawData = prev_section_ptr->PointerToRawData + prev_section_ptr->SizeOfRawData;
		section_header.SizeOfRawData = nt_h.OptionalHeader.FileAlignment;
		section_header.VirtualAddress = prev_section_ptr->VirtualAddress + prev_section_ptr->Misc.VirtualSize;
		section_header.Misc.VirtualSize = nt_h.OptionalHeader.SectionAlignment;

		std::cout << "PE -> Section Header -> " << section_header.Name << " -> Created" << std::endl;

		section_index++;

		last_section_ptr = &section_header;
		prev_section_ptr = &section_header;
	};

	IMAGE_SECTION_HEADER code_section;
	memset(&code_section, 0, sizeof(IMAGE_SECTION_HEADER));
	code_section.Name[0] = '.';
	code_section.Name[1] = 't';
	code_section.Name[2] = 'e';
	code_section.Name[3] = 'x';
	code_section.Name[4] = 't';
	code_section.Name[5] = 0x0;
	code_section.Characteristics = 
	IMAGE_SCN_MEM_EXECUTE |	// 0x20000000
	IMAGE_SCN_MEM_READ	  |	// 0x40000000
	IMAGE_SCN_CNT_CODE	  ; // 0x00000020
	// ==========
	// 0x60000020
	// Add .code section

	configSectionHeader(code_section);

	//pSHData
	IMAGE_SECTION_HEADER data_section;
	memset(&data_section, 0, sizeof(IMAGE_SECTION_HEADER));
	data_section.Name[0] = '.';
	data_section.Name[1] = 'd';
	data_section.Name[2] = 'a';
	data_section.Name[3] = 't';
	data_section.Name[4] = 'a';
	data_section.Name[5] = 0x0;
	data_section.Characteristics = 
	IMAGE_SCN_CNT_INITIALIZED_DATA | //0x00000040
	IMAGE_SCN_MEM_READ | //0x40000000
	IMAGE_SCN_MEM_WRITE; //0x80000000
	
	configSectionHeader(data_section);

	// pSHImport
	IMAGE_SECTION_HEADER import_section;
	memset(&import_section, 0, sizeof(IMAGE_SECTION_HEADER));
	import_section.Name[0] = '.';
	import_section.Name[1] = 'i';
	import_section.Name[2] = 'd';
	import_section.Name[3] = 'a';
	import_section.Name[4] = 't';
	import_section.Name[5] = 'a';
	import_section.Name[6] = 0x0;
	import_section.Characteristics = 
	IMAGE_SCN_MEM_WRITE	  |
	IMAGE_SCN_MEM_READ	  |
	IMAGE_SCN_CNT_INITIALIZED_DATA;

	configSectionHeader(import_section);

	// Fixup PE Header

	nt_h.FileHeader.NumberOfSections = section_index;
	std::cout << "NumberOfSections: " << nt_h.FileHeader.NumberOfSections << std::endl;

	nt_h.OptionalHeader.AddressOfEntryPoint = code_section.VirtualAddress;
	nt_h.OptionalHeader.BaseOfCode = code_section.VirtualAddress;
	nt_h.OptionalHeader.SizeOfCode = code_section.Misc.VirtualSize;
	nt_h.OptionalHeader.SizeOfImage = last_section_ptr->VirtualAddress + last_section_ptr->Misc.VirtualSize;
	nt_h.OptionalHeader.SizeOfHeaders = VU_ALIGN_UP(DWORD(PBYTE(&import_section) - (PBYTE)&dos_h), nt_h.OptionalHeader.FileAlignment); // The offset after the last section is the end / combined-size of all headers.

	std::cout << "PE -> PE Header -> Fixed" << std::endl;

	nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = import_section.VirtualAddress;
	nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = sizeof(import_section);

	std::cout << "PE -> Import Directories -> Created" << std::endl;

	typedef unsigned short ushort;

	typedef std::pair<ushort, std::string> ImportByName;
	std::map<std::string, std::vector<ImportByName>> dll_map;
	std::vector<ImportByName> dll_functions_imported_by_name;

	dll_functions_imported_by_name.clear();
	dll_functions_imported_by_name.push_back(ImportByName(0, "MessageBoxA"));
	dll_map["user32.dll"] = dll_functions_imported_by_name;


	//	auto pIDT = PIMAGE_IMPORT_DESCRIPTOR((&dos_h + pSHImport->PointerToRawData));

	// Create IDT, IAT, ILT for each DLL
	// - IDT -> Import Directory Table that Array<IMAGE_IMPORT_DESCRIPTOR>
	// - IAT -> Import Address Table that Array<Thunk Data> IMAGE_THUNK_DATA64
	// - ILT -> Import Lookup Table that Array<Hint, Function> IMAGE_THUNK_DATA64::Function
	
	/* Write them all in .idata section
	 * Array<IDT> | Array<IAT | DLL | ILT>
	 * or
	 * |--- Array for <IDT>
	 * | IDT / Import Descriptor (s) / 20 bytes for each dll / padding 1 IDT = 20 bytes
	 * |--- Array for <IAT, DLL, ILT>
	 * |  | IAT / Thunk Table / 4 bytes for each function / padding 1 DWORD = 4 bytes
	 * |  |---
	 * |  | DLL / DLL Name / depends on dll name / any padding
	 * |  |---
	 * |  | ILT / Thunk Data / import by name (s) / depends on function hint/name / any padding
	 * |  |---
	 */
	
	std::vector<PIMAGE_IMPORT_DESCRIPTOR> import_descripter_list;

	// Total size of IDTs
	// const unsigned long TotalSizeIDTs = (dll_map.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR); // +1 for an empty IDD
	// auto pPtr = import_descripter_pointer + TotalSizeIDTs;

	for (const std::pair<std::string, std::vector<ImportByName>> &dll_map_entry : dll_map)
	{
		auto dll_name = dll_map_entry.first;
		auto dll_functions = dll_map_entry.second;

		IMAGE_IMPORT_DESCRIPTOR import_descripter;
		memset(&import_descripter, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));

		PIMAGE_IMPORT_DESCRIPTOR import_descripter_pointer = &import_descripter;


		auto pIAT = PDWORD(pPtr);
		auto rvaIAT = ToRVA((&import_section), pIAT);

		const auto EachIATSize = (dll_map_entry.second.size() + 1) * sizeof(DWORD); // +1 DWORD for IAT padding
		pPtr += EachIATSize;

		// Write hint/name of import functions of each DLL

		
		StrCpyT(pPtr, dll_name.c_str());
		auto rvaName = ToRVA((&import_section), pPtr);

		pPtr += dll_name.size() + 1; // +1 for a null-char padding

		for (const ImportByName &ibn : dll_functions) // image import by name (s)
		{
			unsigned short hint = ibn.first;
			std::string name = ibn.second;
			
			*PWORD(pPtr) = hint;						  // Hint
			StrCpyT(pPtr + sizeof(WORD), name.c_str()); // Name

			*pIAT++ = ToRVA((&import_section), pPtr); // Update Thunk Data for each import function in IAT

			pPtr += sizeof(WORD) + name.size() + 2; // +2 for string terminating null-character & a null-char padding
		}

		// Update IDT for each DLL

		import_descripter.Name = rvaName; // get the rva of dll name
		import_descripter.FirstThunk = rvaIAT;
		import_descripter.OriginalFirstThunk = rvaIAT; // get the rva of ImportByName

		std::cout << "PE -> Import Directory -> " << dll_name << " -> Created" << std::endl;

		import_descripter_list.push_back(&import_descripter);
	}

	//pIDT++; // Next an empty IDD to mark end of IDT array
	IMAGE_IMPORT_DESCRIPTOR import_descripter;
	memset(&import_descripter, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	import_descripter_list.push_back(&import_descripter);

	import_section.PointerToRawData = (DWORD)import_descripter_list.at(0);









	// BYTE code[] =
	// {
	// 	0x6A, 0x40,                         // push 40 uType = MB_ICONINFORMATION + MB_OK
	// 	0x68, 0x00, 0x00, 0x00, 0x00,       // push ?  lpCaption = ? (offset 3)  // TODO: Fixup Later
	// 	0x68, 0x00, 0x00, 0x00, 0x00,       // push ?  lpText = ?    (offset 8)  // TODO: Fixup Later
	// 	0x6A, 0x00,                         // push 0  hWnd = NULL
	// 	0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, // call MessageBoxA = ? (offset 16) // TODO: Fixup Later
	// 	0xC3,                               // ret
	// };

	std::vector<uint8_t> code = {
		0x48, 0x83, 0xC4, 0x48,					  // add rsp, 0x48; Stack unwind
		0x48, 0x31, 0xC9,						  // xor rcx, rcx; hWnd
		0x48, 0xC7, 0xC2, 0x10, 0x20, 0x40, 0x00, // mov rdx, Message(0x402010) (offset 10)
		0x49, 0xC7, 0xC0, 0x00, 0x20, 0x40, 0x00, // mov r8, Title(0x402000) (offset 17)
		0x4D, 0x31, 0xC9,						  // xor r9, r9; MB_OK
		0x48, 0xC7, 0xC0, 0x5C, 0x30, 0x40, 0x00, // mov rax, MessageBoxA address(0x40305c) (offset 27)
		0xFF, 0x10,								  // call[rax]; MessageBoxA(hWnd, Message, Title, MB_OK)
		// 0x48, 0x31, 0xC9,				// xor rcx, rcx; exit value
		// 0x48, 0xC7, 0xC0,       0x6C, 0x30, 0x40, 0x00,	// mov rax, ExitProcess address (0x40306c)
		// 0xFF, 0x10,					// call[rax]; ExitProcess(0)
		0xC3 // ret; Never reached
	};



	//   auto pData = (PBYTE)(&dos_h + pSHData->PointerToRawData);


	//   auto len = StrCpyT(pData, "Howdy, Vic P.");
	//   const auto vaCaption = ToVA(pSHData, pData);
	//   pData += len + 1; // +1 for string terminating null-character

	//   StrCpyT(pData, "This is an example that manually created a PE file format");
	//   const auto vaText = ToVA(pSHData, pData);
	//   pData += len + 1; // +1 for string terminating null-character

	// IMAGE_IMPORT_DESCRIPTOR import_descripter_another;
	// memset(&import_descripter_another, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	// pIDT = &import_descripter_another;

	//   // Correct API callee to imported functions that defined in the IAT
	//   pIDT = ;

	//   auto pIAT = PBYTE(PIMAGE_IMPORT_DESCRIPTOR(&dos_h + pSHImport->PointerToRawData)) + TotalSizeIDTs;
	//   const auto vaMessageBoxA = ToVA(pSHImport, pIAT); // For this example, IAT contains only one this API, so treat IAT offset as its offset

	std::cout << "PE -> Executable Codes -> Created" << std::endl;


	// code[10]  = (uint8_t)vaText;
	// code[17]  = (uint8_t)vaCaption;
	// code[27] = (uint8_t)vaMessageBoxA;

	//   *PDWORD(&code[10])  = vaText;
	//   *PDWORD(&code[17])  = vaCaption;
	//   *PDWORD(&code[27]) = vaMessageBoxA;




	// Create/Open PE File
	fstream pe_writter;
	pe_writter.open(output_pe_file, ios::binary | ios::out);

	// Write DOS Header
	pe_writter.write((char *)&dos_h, sizeof(dos_h));

	// Write NT Header
	pe_writter.write((char *)&nt_h, sizeof(nt_h));

	// Write Headers of Sections
	pe_writter.write((char *)&code_section, sizeof(code_section));
	pe_writter.write((char *)&data_section, sizeof(data_section));
	pe_writter.write((char *)&import_section, sizeof(import_section));

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

	// std::vector<uint8_t> code = {
	// 	0x48, 0x83, 0xEC, 0x08,
	// 	0x48, 0x83, 0xEC, 0x20,
	// 	0xB9, 0xF5, 0xFF, 0xFF, 0xFF,
	// 	0xE8, 0x0E, 0x20, 0x0, 0x0,
	// 	0x48, 0x89, 0x05, 0xFB, 0x0F, 0x0, 0x0,
	// 	0x48, 0x83, 0xC4, 0x20,
	// 	0x48, 0x83, 0xEC, 0x30,
	// 	0x48, 0x8B, 0x0D, 0xEC, 0x0F, 0x0, 0x0,
	// 	0x48, 0x8D, 0x15, 0xD1, 0x0F, 0x0, 0x0,
	// 	0x41, 0xB8, 0x14, 0x0, 0x0, 0x0,
	// 	0x4C, 0x8D, 0x0D, 0xE0, 0x0F, 0x0, 0x0,
	// 	0x48, 0xC7, 0x44, 0x24, 0x20, 0x0, 0x0, 0x0, 0x0,
	// 	0xE8, 0xDC, 0x1F, 0x0, 0x0,
	// 	0x48, 0x83, 0xC4, 0x30,
	// 	0x31, 0xC9,
	// 	0xE8, 0xD7, 0x1F, 0x0, 0x0
	// };

	std::for_each(code.begin(), code.end(), [&pe_writter](uint8_t &n){ pe_writter.put(n); });
	for (size_t i = 0; i < code_section.SizeOfRawData - code.size(); i++) pe_writter.put(0x0);

	std::cout << "PE -> Executable Codes -> Fixed" << std::endl;

	// /***********************************/

	// // "Console Message 64\r\n"
	std::vector<uint8_t> data = {
		0x43, 0x6F, 0x6E, 0x73, 0x6F, 0x6C, 0x65, 0x20, 0x4D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x36, 0x34, 0x0D, 0x0A
	};


	std::for_each(data.begin(), data.end(), [&pe_writter](uint8_t &n){ pe_writter.put(n); });
	for (size_t i = 0; i < data_section.SizeOfRawData - data.size(); i++) pe_writter.put(0x0);

	// // gibberish
	// std::vector<uint8_t> imports = {
	// 	0x8E, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9E, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// 	0xAA, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// 	0xFF, 0x25, 0xDA, 0xFF, 0xFF, 0xFF, 0xFF, 0x25, 0xDC, 0xFF, 0xFF, 0xFF, 0xFF, 0x25, 0xDE, 0xFF,
	// 	0xFF, 0xFF, 0x00, 0x00, 0x60, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// 	0x80, 0x30, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// 	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// 	0x8E, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9E, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// 	0xAA, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// 	0x4B, 0x45, 0x52, 0x4E, 0x45, 0x4C, 0x33, 0x32, 0x2E, 0x64, 0x6C, 0x6C, 0x00, 0x00, 0xE1, 0x02,
	// 	0x47, 0x65, 0x74, 0x53, 0x74, 0x64, 0x48, 0x61, 0x6E, 0x64, 0x6C, 0x65, 0x00, 0x00, 0x33, 0x06,
	// 	0x57, 0x72, 0x69, 0x74, 0x65, 0x46, 0x69, 0x6C, 0x65, 0x00, 0x68, 0x01, 0x45, 0x78, 0x69, 0x74,
	// 	0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73
	// };

	std::for_each(import_descripter_list.begin(), import_descripter_list.end(), [&pe_writter](PIMAGE_IMPORT_DESCRIPTOR &import_descripter_pointer){
		pe_writter.write((char *)import_descripter_pointer, sizeof((*import_descripter_pointer)));
	});

	// std::for_each(imports.begin(), imports.end(), [&pe_writter](uint8_t &n){ pe_writter.put(n); });
	// for (size_t i = 0; i < import_section.SizeOfRawData - imports.size(); i++) pe_writter.put(0x0);

	// Close PE File
	pe_writter.close();

	printf("[Information] PE File packed with 0 Errors.");
	cin.get();

	return EXIT_SUCCESS;
}