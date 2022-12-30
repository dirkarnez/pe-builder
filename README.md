pe-builder
==========

### Truth
- (target address) 0x401000 - (load address)0x400000  = (RVA)0x1000
  - To convert an RVA to an actual address, simply reverse the process: add the RVA to the actual load address to find the actual memory address.
- DataDirectory[dwEntry].VirtualAddress is rva

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