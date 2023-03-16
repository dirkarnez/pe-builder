#include <windows.h>
#include <winnt.h>
#include <stdio.h>

// Function to write 64 bit PE file

void write64bitPEFile()
{
IMAGE_DOS_HEADER dosHeader;
IMAGE_NT_HEADERS64 ntHeader;
IMAGE_FILE_HEADER fileHeader;
IMAGE_OPTIONAL_HEADER64 optionalHeader;
IMAGE_SECTION_HEADER textSection;
IMAGE_SECTION_HEADER importSection;
IMAGE_IMPORT_DESCRIPTOR importDescriptor;
IMAGE_THUNK_DATA64 thunkData;

// Fill DOS Header
dosHeader.e_magic = 0x5A4D; // MZ
dosHeader.e_cblp = 0x90;
dosHeader.e_cp = 3;
dosHeader.e_cparhdr = 4;
dosHeader.e_maxalloc = 0xFFFF;
dosHeader.e_sp = 0xB8;
dosHeader.e_lfarlc = 0x40;
dosHeader.e_lfanew = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64);

// Fill NT Header
ntHeader.Signature = 0x00004550;
ntHeader.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
ntHeader.FileHeader.NumberOfSections = 2;
ntHeader.FileHeader.TimeDateStamp = 0;
ntHeader.FileHeader.PointerToSymbolTable = 0;
ntHeader.FileHeader.NumberOfSymbols = 0;
ntHeader.FileHeader.SizeOfOptionalHeader =
sizeof(IMAGE_OPTIONAL_HEADER64);
ntHeader.FileHeader.Characteristics =
IMAGE_FILE_EXECUTABLE_IMAGE |
IMAGE_FILE_LARGE_ADDRESS_AWARE;

// Fill Optional Header
optionalHeader.Magic = 0x20b;
optionalHeader.MajorLinkerVersion = 0;
optionalHeader.MinorLinkerVersion = 0;
optionalHeader.SizeOfCode = 0x1000;
optionalHeader.SizeOfInitializedData = 0;
optionalHeader.SizeOfUninitializedData = 0;
optionalHeader.AddressOfEntryPoint = 0x1000;
optionalHeader.BaseOfCode = 0x1000;
optionalHeader.ImageBase = 0x400000;
optionalHeader.SectionAlignment = 0x1000;
optionalHeader.FileAlignment = 0x200;
optionalHeader.MajorOperatingSystemVersion = 0;
optionalHeader.MinorOperatingSystemVersion = 0;
optionalHeader.MajorImageVersion = 0;
optionalHeader.MinorImageVersion = 0;
optionalHeader.MajorSubsystemVersion = 4;
optionalHeader.MinorSubsystemVersion = 0;
optionalHeader.Win32VersionValue = 0;
optionalHeader.SizeOfImage = 0x2000;
optionalHeader.SizeOfHeaders = 0x400;
optionalHeader.CheckSum = 0;
optionalHeader.Subsystem = 3;
optionalHeader.DllCharacteristics = 0;
optionalHeader.SizeOfStackReserve = 0x100000;
optionalHeader.SizeOfStackCommit = 0x1000;
optionalHeader.SizeOfHeapReserve = 0x100000;
optionalHeader.SizeOfHeapCommit = 0x1000;
optionalHeader.LoaderFlags = 0;
optionalHeader.NumberOfRvaAndSizes = 16;

// Fill Text Section
textSection.Name[0] = '.';
textSection.Name[1] = 't';
textSection.Name[2] = 'e';
textSection.Name[3] = 'x';
textSection.Name[4] = 't';
textSection.Name[5] = '\0';
textSection.Misc.VirtualSize = 0x1000;
textSection.VirtualAddress = 0x1000;
textSection.SizeOfRawData = 0x200;
textSection.PointerToRawData = 0x400;
textSection.PointerToRelocations = 0;
textSection.PointerToLinenumbers = 0;
textSection.NumberOfRelocations = 0;
textSection.NumberOfLinenumbers = 0;
textSection.Characteristics =
IMAGE_SCN_CNT_CODE |
IMAGE_SCN_MEM_EXECUTE |
IMAGE_SCN_MEM_READ;

// Fill Import Section
importSection.Name[0] = '.';
importSection.Name[1] = 'i';
importSection.Name[2] = 'd';
importSection.Name[3] = 'a';
importSection.Name[4] = 't';
importSection.Name[5] = 'a';
importSection.Name[6] = '\0';
importSection.Misc.VirtualSize = 0x1000;
importSection.VirtualAddress = 0x2000;
importSection.SizeOfRawData = 0x200;
importSection.PointerToRawData = 0x600;
importSection.PointerToRelocations = 0;
importSection.PointerToLinenumbers = 0;
importSection.NumberOfRelocations = 0;
importSection.NumberOfLinenumbers = 0;
importSection.Characteristics =
IMAGE_SCN_CNT_INITIALIZED_DATA |
IMAGE_SCN_MEM_READ;

// Fill Import Descriptor
importDescriptor.OriginalFirstThunk = 0x3000;
importDescriptor.TimeDateStamp = 0;
importDescriptor.ForwarderChain = 0;
importDescriptor.Name = 0x3000;
importDescriptor.FirstThunk = 0x3008;

// Fill Thunk Data
thunkData.u1.AddressOfData = 0x6000;

// File pointer
FILE* fp;

// Open file in write binary mode
fp = fopen("64bitPE.exe", "wb");

// Write DOS Header
fwrite(&dosHeader, sizeof(dosHeader), 1, fp);

// Write NT Header
fwrite(&ntHeader, sizeof(ntHeader), 1, fp);

// Write File Header
fwrite(&fileHeader, sizeof(fileHeader), 1, fp);

// Write Optional Header
fwrite(&optionalHeader,
sizeof(optionalHeader), 1, fp);

// Write Text Section
fwrite(&textSection, sizeof(textSection), 1, fp);

// Write Import Section
fwrite(&importSection, sizeof(importSection), 1, fp);

// Write Import Descriptor
fwrite(&importDescriptor,
sizeof(importDescriptor), 1, fp);

// Write Thunk Data
fwrite(&thunkData, sizeof(thunkData), 1, fp);

// Write Kernel32's GetStdHandle name
fwrite("GetStdHandle\0", 13, 1, fp);

// Close the file
fclose(fp);
}

// Driver Code
int main()
{
// Call function to write 64 bit PE file
write64bitPEFile();

return 0;
}