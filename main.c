#include <stdio.h>
#include <Windows.h>

void error(char* funcname) {
	printf("[-] %s error: %d\n",funcname,GetLastError());
	exit(1);
}


int main(int argc,char** argv){

	if (argc != 2) {
		printf("\n\t[-] Usage: %s file\n", argv[0]);
		return 1;
	}
	printf("\n\thttps://github.com/xHector1337\n");
	HANDLE file = CreateFileA(argv[1], GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (file == INVALID_HANDLE_VALUE) {
		error("CreateFileA");
	}
	DWORD PEsize = GetFileSize(file, 0);
	if (PEsize == 0) {
		error("GetFileSize");
	}
	PBYTE pPE = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, PEsize);
	if (pPE == 0) {
		error("HeapAlloc");
	}
	DWORD ReadBytes;
	if (!ReadFile(file, pPE, PEsize, &ReadBytes, 0) || ReadBytes != PEsize) {
		error("ReadFile");
	}
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pPE;
	PIMAGE_NT_HEADERS pImageNTHeaders = (PIMAGE_NT_HEADERS)(pPE + pImageDosHeader->e_lfanew);
	IMAGE_FILE_HEADER ImageFileHeader = pImageNTHeaders->FileHeader;
	IMAGE_OPTIONAL_HEADER ImageOptionalHeader = pImageNTHeaders->OptionalHeader;
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(pPE + ImageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PIMAGE_IMPORT_DESCRIPTOR pImageImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(pPE + ImageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)(((PBYTE)pImageNTHeaders) + sizeof(IMAGE_NT_HEADERS));

	printf("\n\t---------->[GENERAL INFO]<----------\t\n");

	printf("\n\t[+] File name: %s\n", argv[1]);
	printf("\n\t[+] File size: %d KBs\n", PEsize/1000);
	printf("\n\t[+] Magic Header: 0x%X\n", pImageDosHeader->e_magic);
	printf("\n\t[+] Architecture: ");
	if (ImageFileHeader.Machine == 0x014c) {
		printf("x86 (i386)\n");
	}
	else if (ImageFileHeader.Machine == 0x0200) {
		printf("Intel Itanium\n");
	}
	else if (ImageFileHeader.Machine == 0x8664) {
		printf("x64 (amd64)\n");
	}
	else {
		printf("Unknown architecture.\n");
	}

	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("\n\t[-] File is not an executable!\n");
		return 1;
	}
	printf("\n\t[+] File loaded at: 0x%p\n", pPE);
	printf("\n\t---------->[NT HEADER]<----------\t\n");

	
	if (pImageNTHeaders->Signature != IMAGE_NT_SIGNATURE) {
		printf("\n\t[-] Invalid NT Signature!\n\tExpected: 0x%x\n\tGot: 0x%x\n", IMAGE_NT_SIGNATURE,pImageNTHeaders->Signature);
		return 2;
	}
	printf("\n\t[+] NT Signature: 0x%x\n",pImageNTHeaders->Signature);
	
	printf("\n\t---------->[FILE HEADER]<----------\t\n");

	printf("\n\t[+] Executable characteristics:\n");
    if (ImageFileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED) {
        printf("\tRelocation information was stripped from the file.\n");
    }
    if (ImageFileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
        printf("\tFile is an executable.\n");
    }
    if (ImageFileHeader.Characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED) {
        printf("\tLine numbers were stripped from the file.\n");
    }
    if (ImageFileHeader.Characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED) {
        printf("\tSymbol table entries were stripped from the file.\n");
    }
    if (ImageFileHeader.Characteristics & IMAGE_FILE_AGGRESIVE_WS_TRIM) {
        printf("\tAggressively trim the working set.\n");
    }
    if (ImageFileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) {
        printf("\tThe application can handle addresses larger than 2 GB.\n");
    }
	if (ImageFileHeader.Characteristics & IMAGE_FILE_BYTES_REVERSED_LO) {
		printf("\tThe bytes of the word are reversed.\n");
	}
	if (ImageFileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) {
		printf("\tThe computer supports 32 bit words.\n");
	}
	if (ImageFileHeader.Characteristics & IMAGE_FILE_DEBUG_STRIPPED) {
		printf("\tDebugging information was removed and stored separately in another file.\n");
	}
	if (ImageFileHeader.Characteristics & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) {
		printf("\tIf the image is on removable media, copy it to and run it from the swap file.\n");
	}
	if (ImageFileHeader.Characteristics & IMAGE_FILE_NET_RUN_FROM_SWAP) {
		printf("\tIf the image is on the network, copy it to and run it from the swap file.\n");
	}
	if (ImageFileHeader.Characteristics & IMAGE_FILE_SYSTEM) {
			printf("\tIt is a system file.\n");
		}
	if (ImageFileHeader.Characteristics & IMAGE_FILE_DLL) {
		printf("\tIt is a DLL file.\n");
	}
	if (ImageFileHeader.Characteristics & IMAGE_FILE_UP_SYSTEM_ONLY) {
		printf("\tThe file should be run only on a uniprocessor computer.\n");
	}
	if (ImageFileHeader.Characteristics & IMAGE_FILE_BYTES_REVERSED_HI) {
		printf("\tThe bytes of the word are reversed.\n");
	}

	printf("\n\t[+]Time Data Stamp: %lu\n", ImageFileHeader.TimeDateStamp);
	printf("\n\t[+]Number of sections: %u\n", ImageFileHeader.NumberOfSections);
	printf("\n\t[+]Offset in the file to the symbol table (PointerToSymbolTable): 0x%x\n", ImageFileHeader.PointerToSymbolTable);
	printf("\n\t[+]Number of symbols in the symbol table: %lu\n",ImageFileHeader.NumberOfSymbols);
	
	printf("\n\t---------->[OPTIONAL HEADER]<----------\t\n");

	if (ImageOptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC || ImageOptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		printf("\n\t[+]The file is an executable.\n");
	}
	printf("\n\t[+] Linker version: %d.%d\n",ImageOptionalHeader.MajorLinkerVersion,ImageOptionalHeader.MinorLinkerVersion);
	printf("\n\t[+] Minimum OS version required to run the file: %d.%d\n",ImageOptionalHeader.MajorOperatingSystemVersion,ImageOptionalHeader.MinorOperatingSystemVersion);
	printf("\n\t[+] Version of the file: %d.%d\n", ImageOptionalHeader.MajorImageVersion, ImageOptionalHeader.MinorImageVersion);
	printf("\n\t[+] Size of the code section: %lu\n",ImageOptionalHeader.SizeOfCode);
	printf("\n\t[+] Size of the initialized data section: %lu\n", ImageOptionalHeader.SizeOfInitializedData);
	printf("\n\t[+] Size of uinitialized data section: %lu\n",ImageOptionalHeader.SizeOfUninitializedData);
	printf("\n\t[+] Preffered base address: 0x%p\n ",  (VOID*)ImageOptionalHeader.ImageBase);
	printf("\n\t[+] Base address of the code section: 0x%p | (RVA) 0x%x\n", (VOID*)(pPE + ImageOptionalHeader.BaseOfCode), ImageOptionalHeader.BaseOfCode);
	printf("\n\t[+] Address of the entry point: 0x%p | (RVA) 0x%x\n",(VOID*)(pPE + ImageOptionalHeader.AddressOfEntryPoint),ImageOptionalHeader.AddressOfEntryPoint);
	printf("\n\t[+] Size of the image: %lu KBs.\n",ImageOptionalHeader.SizeOfImage/1000);
	printf("\n\t[+] File checksum: 0x%x\n", ImageOptionalHeader.CheckSum);
	printf("\n\t[+] Subsytem required to run the file: ");
	if (ImageOptionalHeader.Subsystem == IMAGE_SUBSYSTEM_UNKNOWN) {
		printf("Unknown subsytem.\n");
	}
	if (ImageOptionalHeader.Subsystem == IMAGE_SUBSYSTEM_NATIVE){
		printf("No subystem required.\n");
	}
	if (ImageOptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI) {
		printf("Windows GUI subsytem.\n");
	}
	if (ImageOptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI) {
		printf("Windows CUI subsytem.\n");
	}
	if (ImageOptionalHeader.Subsystem == IMAGE_SUBSYSTEM_OS2_CUI) {
		printf("OS/2 CUI subsytem.\n");
	}
	if (ImageOptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CE_GUI) {
		printf("Windows CE subsystem.\n");
	}
	if (ImageOptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION) {
		printf("Image is a Windows boot aplication.\n");
	}
	if (ImageOptionalHeader.Subsystem == IMAGE_SUBSYSTEM_EFI_APPLICATION) {
		printf("Image is an EFI application.\n");
	}
	if (ImageOptionalHeader.Subsystem == IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER) {
		printf("Image is an EFI driver with boot services.\n");
	}
	if (ImageOptionalHeader.Subsystem == IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER) {
		printf("Image is an EFI driver with runtime services.\n");
	}
	if (ImageOptionalHeader.Subsystem == IMAGE_SUBSYSTEM_EFI_ROM) {
		printf("Image is an EFI ROM.\n");
	}
	if (ImageOptionalHeader.Subsystem == IMAGE_SUBSYSTEM_XBOX) {
		printf("Xbox system.\n");
	}

	printf("\n\t---------->[EXPORT TABLE]<----------\t\n");
	printf("\n\t[+] Address of the export table: 0x%p | (RVA) 0x%x\n", (VOID*)(pPE + ImageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress), ImageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	printf("\n\t[+] Size of the export table: %u\n", ImageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
	printf("\n\t[+] Number of exported functions: %u\n", pImageExportDirectory->NumberOfFunctions);
	printf("\n\t[+] Number of exported names: %u\n", pImageExportDirectory->NumberOfNames);

	printf("\n\t---------->[IMPORT TABLE]<----------\t\n");
	printf("\n\t[+] Address of the import table: 0x%p | (RVA) 0x%x\n",(VOID*)(pPE + ImageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),ImageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	printf("\n\t[+] Size of the import table: %u\n", ImageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
	
	printf("\n\t---------->[RESOURCE TABLE]<----------\t\n");
	printf("\n\t[+] Address of the resource table: 0x%p | (RVA) 0x%x\n", (VOID*)(pPE + ImageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress), ImageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
	printf("\n\t[+] Size of the resource table: %lu\n", ImageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);

	printf("\n\t---------->[EXCEPTION TABLE]<----------\t\n");
	printf("\n\t[+] Address of the exception table: 0x%p | (RVA) 0x%x\n", (VOID*)(pPE + ImageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress), ImageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
	printf("\n\t[+] Size of the exception table: %lu\n", ImageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);

	printf("\n\t---------->[PE SECTIONS]<----------\t\n");
	for (int i = 0;i < pImageNTHeaders->FileHeader.NumberOfSections;i++) {
		printf("\n%s\n", (CHAR*)pImageSectionHeader->Name);
		printf("\t[+] RVA: 0x%x\n", pImageSectionHeader->VirtualAddress);
		printf("\t[+] Address: 0x%p\n", (VOID*)(pPE + pImageSectionHeader->VirtualAddress));
		printf("\t[+] Size: %u\n", pImageSectionHeader->SizeOfRawData);
		printf("\t[+] Number of line numbers: %u\n", pImageSectionHeader->NumberOfLinenumbers);
		printf("\t[+] Number of relocations: %u\n", pImageSectionHeader->NumberOfRelocations);
		printf("\t[+] Permissions: ");
		if (pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_READ) {
			printf("\n\tThe section can be read.\n");
		}
		if (pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			printf("\tThe section can be executed.\n");
		}
		if (pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) {
			printf("\tThe section can be written.");
		}
		pImageSectionHeader = (PIMAGE_SECTION_HEADER)((PBYTE)pImageSectionHeader + (DWORD)sizeof(IMAGE_SECTION_HEADER));
	}
	return 0;
}
