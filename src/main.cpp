#include <iostream>
#include <Windows.h>
#include <fstream>
#include <cstdio>
#include <cstring>
#include <vector>
#include <memory>
#include <algorithm>
#include <iterator>

using namespace std;

int main()
{
   // Dev : Hamid.Memar

	string output_pe_file	= "yoyoy.exe";
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
	dos_h.e_lfanew		= 0x0040;

	IMAGE_NT_HEADERS	nt_h;
	memset(&nt_h, 0, sizeof(IMAGE_NT_HEADERS));
	nt_h.Signature											= IMAGE_NT_SIGNATURE;
	nt_h.FileHeader.Machine									= IMAGE_FILE_MACHINE_AMD64;
	nt_h.FileHeader.NumberOfSections						= 2;
	nt_h.FileHeader.TimeDateStamp							= 0x00000000; // Must Update
	nt_h.FileHeader.PointerToSymbolTable					= 0x0;
	nt_h.FileHeader.NumberOfSymbols							= 0x0;
	nt_h.FileHeader.SizeOfOptionalHeader					= 0x00F0;
	nt_h.FileHeader.Characteristics							= 0x0022;
	nt_h.OptionalHeader.Magic								= IMAGE_NT_OPTIONAL_HDR64_MAGIC;
	nt_h.OptionalHeader.MajorLinkerVersion					= 10;
	nt_h.OptionalHeader.MinorLinkerVersion					= 0x05;
	nt_h.OptionalHeader.SizeOfCode							= 0x00000200;
	nt_h.OptionalHeader.SizeOfInitializedData				= 0x00000200;
	nt_h.OptionalHeader.SizeOfUninitializedData				= 0x0;
	nt_h.OptionalHeader.AddressOfEntryPoint					= 0x00001000; // Must Update
	nt_h.OptionalHeader.BaseOfCode							= 0x00001000;
	nt_h.OptionalHeader.ImageBase							= 0x0000000140000000;
	nt_h.OptionalHeader.SectionAlignment					= 0x00001000;
	nt_h.OptionalHeader.FileAlignment						= 0x00000200;
	nt_h.OptionalHeader.MajorOperatingSystemVersion			= 0x0;
	nt_h.OptionalHeader.MinorOperatingSystemVersion			= 0x0;
	nt_h.OptionalHeader.MajorImageVersion					= 0x0006;
	nt_h.OptionalHeader.MinorImageVersion					= 0x0000;
	nt_h.OptionalHeader.MajorSubsystemVersion				= 0x0006;
	nt_h.OptionalHeader.MinorSubsystemVersion				= 0x0000;
	nt_h.OptionalHeader.Win32VersionValue					= 0x0;
	nt_h.OptionalHeader.SizeOfImage							= 0x00003000; // Must Update
	nt_h.OptionalHeader.SizeOfHeaders						= 0x00000200;
	nt_h.OptionalHeader.CheckSum							= 0x0000F3A6; // Must Update
	nt_h.OptionalHeader.Subsystem							= IMAGE_SUBSYSTEM_WINDOWS_CUI;
	nt_h.OptionalHeader.DllCharacteristics					= 0x0120;
	nt_h.OptionalHeader.SizeOfStackReserve					= 0x0000000000100000;
	nt_h.OptionalHeader.SizeOfStackCommit					= 0x0000000000001000;
	nt_h.OptionalHeader.SizeOfHeapReserve					= 0x0000000000100000;
	nt_h.OptionalHeader.SizeOfHeapCommit					= 0x0000000000001000;
	nt_h.OptionalHeader.LoaderFlags							= 0x00000000;
	nt_h.OptionalHeader.NumberOfRvaAndSizes					= 0x00000010;

	// Initializing Section [ Code ]
	IMAGE_SECTION_HEADER	code_section;
	memset(&code_section, 0, sizeof(IMAGE_SECTION_HEADER));
	code_section.Name[0] = '[';
	code_section.Name[1] = ' ';
	code_section.Name[2] = 'H';
	code_section.Name[3] = '.';
	code_section.Name[4] = 'M';
	code_section.Name[5] = ' ';
	code_section.Name[6] = ']';
	code_section.Name[7] = 0x0;
	code_section.Misc.VirtualSize					= 0x00001000;	// Virtual Size
	code_section.VirtualAddress						= 0x00001000;	// Virtual Address
	code_section.SizeOfRawData						= 0x00000600;	// Raw Size
	code_section.PointerToRawData					= 0x00000200;	// Raw Address
	code_section.PointerToRelocations				= 0x00000000;	// Reloc Address
	code_section.PointerToLinenumbers				= 0x00000000;	// Line Numbers
	code_section.NumberOfRelocations				= 0x00000000;	// Reloc Numbers
	code_section.NumberOfLinenumbers				= 0x00000000;	// Line Numbers Number
	code_section.Characteristics					= IMAGE_SCN_MEM_EXECUTE	  |	
													  IMAGE_SCN_MEM_READ	  |
													  IMAGE_SCN_CNT_CODE	  ;

	// Initializing Section [ Data ]
	IMAGE_SECTION_HEADER	data_section;
	memset(&data_section, 0, sizeof(IMAGE_SECTION_HEADER));
	data_section.Name[0] = '[';
	data_section.Name[1] = ' ';
	data_section.Name[2] = 'H';
	data_section.Name[3] = '.';
	data_section.Name[4] = 'M';
	data_section.Name[5] = ' ';
	data_section.Name[6] = ']';
	data_section.Name[7] = 0x0;
	data_section.Misc.VirtualSize					= 0x00000200;	// Virtual Size
	data_section.VirtualAddress						= 0x00002000;	// Virtual Address
	data_section.SizeOfRawData						= 0x00000200;	// Raw Size
	data_section.PointerToRawData					= 0x00000800;	// Raw Address
	data_section.PointerToRelocations				= 0x00000000;	// Reloc Address
	data_section.PointerToLinenumbers				= 0x00000000;	// Line Numbers
	data_section.NumberOfRelocations				= 0x00000000;	// Reloc Numbers
	data_section.NumberOfLinenumbers				= 0x00000000;	// Line Numbers Number
	data_section.Characteristics					= IMAGE_SCN_CNT_INITIALIZED_DATA |
        											  IMAGE_SCN_MEM_READ;

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

	// Add Padding
	while (pe_writter.tellp() != code_section.PointerToRawData) pe_writter.put(0x0);

	// Write Code Section
	pe_writter.put(0xC3); // Empty PE Return Opcode

    std::vector<uint8_t> code = {
		0x48, 0x83, 0xC4, 0x48,				// add rsp, 0x48; Stack unwind
		0x48, 0x31, 0xC9,				// xor rcx, rcx; hWnd
		0x48, 0xC7, 0xC2, 0x10, 0x20, 0x40, 0x00,	// mov rdx, Message(0x402010)
		0x49, 0xC7, 0xC0, 0x00, 0x20, 0x40, 0x00,	// mov r8, Title(0x402000)
		0x4D, 0x31, 0xC9,				// xor r9, r9; MB_OK
		0x48, 0xC7, 0xC0, 0x5C, 0x30, 0x40, 0x00,	// mov rax, MessageBoxA address(0x40305c)
		0xFF, 0x10,					// call[rax]; MessageBoxA(hWnd, Message, Title, MB_OK)
		0x48, 0x31, 0xC9,				// xor rcx, rcx; exit value
		0x48, 0xC7, 0xC0, 0x6C, 0x30, 0x40, 0x00,	// mov rax, ExitProcess address (0x40306c)
		0xFF, 0x10,					// call[rax]; ExitProcess(0)
		0xC3						// ret; Never reached
	};

	for (size_t i = 0; i < code_section.SizeOfRawData - 1; i++) pe_writter.put(0x0);

	// Write Data Section
	for (size_t i = 0; i < data_section.SizeOfRawData; i++) pe_writter.put(0x0);

	// Close PE File
	pe_writter.close();

    cin.get();

	printf("[Information] PE File packed with 0 Errors.");
	return EXIT_SUCCESS;
}