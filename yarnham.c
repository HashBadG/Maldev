#include <stdio.h>
#include <io.h>
#include <string.h>
#include <windows.h>
#include <winnt.h>
#include <Imagehlp.h>
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "Imagehlp.lib")
/*
    IMPORTANT : 
        - https://learn.microsoft.com/en-us/archive/msdn-magazine/2002/february/inside-windows-win32-portable-executable-file-format-in-detail 
        - https://doxygen.reactos.org/
*/

void printDOSHeader(const char* filename)
{
    // Open the file
    HANDLE fileHandle = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        printf("Failed to open file\n");
        return;
    }
    // Get the file size
    DWORD fileSize = GetFileSize(fileHandle, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        printf("Failed to get file size\n");
        CloseHandle(fileHandle);
        return;
    }
    // Read the DOS header
    /*
    struct IMAGE_DOS_HEADER
    typedef struct _IMAGE_DOS_HEADER
    {
        WORD e_magic;
        WORD e_cblp;
        WORD e_cp;
        WORD e_crlc;
        WORD e_cparhdr;
        WORD e_minalloc;
        WORD e_maxalloc;
        WORD e_ss;
        WORD e_sp;
        WORD e_csum;
        WORD e_ip;
        WORD e_cs;
        WORD e_lfarlc;
        WORD e_ovno;
        WORD e_res[4];
        WORD e_oemid;
        WORD e_oeminfo;
        WORD e_res2[10];
        LONG e_lfanew;
    } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
    */
    IMAGE_DOS_HEADER dosHeader;
    DWORD bytesRead;
    if (!ReadFile(fileHandle, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead, NULL) || bytesRead != sizeof(IMAGE_DOS_HEADER)) {
        printf("Failed to read DOS header\n");
        CloseHandle(fileHandle);
        return;
    }
    printf("DOS Header:\n");
    printf("---------\n");
    // Print the DOS header fields
    printf("\te_magic: 0x%X\n", dosHeader.e_magic);
    printf("\te_cblp: 0x%X\n", dosHeader.e_cblp);
    printf("\te_cp: 0x%X\n", dosHeader.e_cp);
    printf("\te_crlc: 0x%X\n", dosHeader.e_crlc);
    printf("\te_cparhdr: 0x%X\n", dosHeader.e_cparhdr);
    printf("\te_minalloc: 0x%X\n", dosHeader.e_minalloc);
    printf("\te_maxalloc: 0x%X\n", dosHeader.e_maxalloc);
    printf("\te_ss: 0x%X\n", dosHeader.e_ss);
    printf("\te_sp: 0x%X\n", dosHeader.e_sp);
    printf("\te_csum: 0x%X\n", dosHeader.e_csum);
    printf("\te_ip: 0x%X\n", dosHeader.e_ip);
    printf("\te_cs: 0x%X\n", dosHeader.e_cs);
    printf("\te_lfarlc: 0x%X\n", dosHeader.e_lfarlc);
    printf("\te_ovno: 0x%X\n", dosHeader.e_ovno);
    printf("\te_res: ");
    for (int i = 0; i < 4; i++) {
        printf("0x%X ", dosHeader.e_res[i]);
    }
    printf("\n");
    printf("\te_oemid: 0x%X\n", dosHeader.e_oemid);
    printf("\te_oeminfo: 0x%X\n", dosHeader.e_oeminfo);
    printf("\te_res2: ");
    for (int i = 0; i < 10; i++) {
        printf("0x%X ", dosHeader.e_res2[i]);
    }
    printf("\n");
    printf("\te_lfanew: 0x%X\n", dosHeader.e_lfanew);
    // Close the file
    CloseHandle(fileHandle);
}

void printNTHeader(const char* filePath) {
    // Open the file for reading
    HANDLE fileHandle = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        // If the file cannot be opened, print an error message and return
        printf("Failed to open file: %s\n", filePath);
        return;
    }
    // Create a file mapping object
    HANDLE fileMapping = CreateFileMapping(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (fileMapping == NULL) {
        // If the file mapping object cannot be created, print an error message, close the file handle, and return
        printf("Failed to create file mapping: %s\n", filePath);
        CloseHandle(fileHandle);
        return;
    }
    // Map the file into memory
    LPVOID fileBaseAddress = MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0);
    if (fileBaseAddress == NULL) {
        // If the file cannot be mapped into memory, print an error message, close the file mapping and file handles, and return
        printf("Failed to map view of file: %s\n", filePath);
        CloseHandle(fileMapping);
        CloseHandle(fileHandle);
        return;
    }
    // Get the DOS header and NT headers from the file base address
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBaseAddress;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileBaseAddress + dosHeader->e_lfanew);
    // Print the NT Header section 
    printf("NT Header:\n");
    printf("---------\n\n");
    printf("PE Signature: 0x%X\n", ntHeaders->Signature);
    printf("\nFile Header:\n\n");
    printf("\tMachine: 0x%X\n", ntHeaders->FileHeader.Machine);
    printf("\tNumber of Sections: %d\n", ntHeaders->FileHeader.NumberOfSections);
    printf("\tSize of optionnal header: 0x%X\n", ntHeaders->FileHeader.SizeOfOptionalHeader);
    printf("\nOptional Header:\n\n");
    printf("\tMagic: 0x%X\n", ntHeaders->OptionalHeader.Magic);
    printf("\tSize of Code Section: 0x%X\n", ntHeaders->OptionalHeader.SizeOfCode);
    printf("\tSize of initialized data: 0x%X\n", ntHeaders->OptionalHeader.SizeOfInitializedData);
    printf("\tSize of uninitialized data: 0x%X\n", ntHeaders->OptionalHeader.SizeOfUninitializedData);
    printf("\tAddress of entry point: 0x%X\n", ntHeaders->OptionalHeader.AddressOfEntryPoint);
    printf("\tRVA of start of code section: 0x%X\n", ntHeaders->OptionalHeader.BaseOfCode);
    printf("\tDesired image base: 0x%IX\n", ntHeaders->OptionalHeader.ImageBase);
    printf("\tSection alignment: 0x%X\n", ntHeaders->OptionalHeader.SectionAlignment);
    printf("\tFile alignment: 0x%X\n", ntHeaders->OptionalHeader.FileAlignment);
    printf("\tSize of image: 0x%X\n", ntHeaders->OptionalHeader.SizeOfImage);
    printf("\tSize of headers: 0x%X\n", ntHeaders->OptionalHeader.SizeOfHeaders);
    printf("\nData Directories:\n\n");
    printf("\t* Export Directory:\n");
    printf("\t  RVA: 0x%X\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    printf("\t  Size : 0x%X\n\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
    printf("\t* Import Directory:\n");
    printf("\t  RVA: 0x%X\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    printf("\t  Size : 0x%X\n\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
    printf("\t* Resource Directory:\n");
    printf("\t  RVA: 0x%X\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
    printf("\t  Size : 0x%X\n\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].Size);
    printf("\t* Exception Directory:\n");
    printf("\t  RVA: 0x%X\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
    printf("\t  Size : 0x%X\n\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size);
    printf("\t* Security Directory:\n");
    printf("\t  RVA: 0x%X\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress);
    printf("\t  Size : 0x%X\n\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size);
    printf("\t* Basereloc Directory:\n");
    printf("\t  RVA: 0x%X\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    printf("\t  Size : 0x%X\n\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
    printf("\t* Basereloc Directory:\n");
    printf("\t  RVA: 0x%X\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    printf("\t  Size : 0x%X\n\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
    printf("\t* Debug Directory:\n");
    printf("\t  RVA: 0x%X\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
    printf("\t  Size : 0x%X\n\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size);
    printf("\t* Architecture Directory:\n");
    printf("\t  RVA: 0x%X\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress);
    printf("\t  Size : 0x%X\n\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size);
    printf("\t* GLOBALPTR Directory:\n");
    printf("\t  RVA: 0x%X\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress);
    printf("\t  Size : 0x%X\n\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size);
    printf("\t* TLS Directory:\n");
    printf("\t  RVA: 0x%X\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
    printf("\t  Size : 0x%X\n\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size);
    printf("\t* Load Config Directory:\n");
    printf("\t  RVA: 0x%X\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
    printf("\t  Size : 0x%X\n\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size);
    printf("\t* Bound Import Directory:\n");
    printf("\t  RVA: 0x%X\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress);
    printf("\t  Size : 0x%X\n\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size);
    printf("\t* IAT Directory:\n");
    printf("\t  RVA: 0x%X\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
    printf("\t  Size : 0x%X\n\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size);
    printf("\t* Delay Import Directory:\n");
    printf("\t  RVA: 0x%X\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
    printf("\t  Size : 0x%X\n\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size);
    printf("\t* COM Descriptor Directory:\n");
    printf("\t  RVA: 0x%X\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress);
    printf("\t  Size : 0x%X\n\n", ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size);    
    // Clean up: unmap the file, close the file mapping and file handles
    UnmapViewOfFile(fileBaseAddress);
    CloseHandle(fileMapping);
    CloseHandle(fileHandle);
}

void printOptionalHeader(const char* filePath) {
    // Open the file for reading
    HANDLE fileHandle = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) {
        // If the file cannot be opened, print an error message and return
        printf("Failed to open file: %s\n", filePath);
        return;
    }
    // Create a file mapping object
    HANDLE fileMapping = CreateFileMapping(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
    if (fileMapping == NULL) {
        // If the file mapping object cannot be created, print an error message, close the file handle, and return
        printf("Failed to create file mapping: %s\n", filePath);
        CloseHandle(fileHandle);
        return;
    }
    // Map the file into memory
    LPVOID fileBaseAddress = MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0);
    if (fileBaseAddress == NULL) {
        // If the file cannot be mapped into memory, print an error message, close the file mapping and file handles, and return
        printf("Failed to map view of file: %s\n", filePath);
        CloseHandle(fileMapping);
        CloseHandle(fileHandle);
        return;
    }
    // Get pointers to DOS and NT headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBaseAddress;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)fileBaseAddress + dosHeader->e_lfanew);
    // Get a pointer to the optional header
    /*	
    struct IMAGE_OPTIONAL_HEADER
    typedef struct _IMAGE_OPTIONAL_HEADER
    {       
        WORD Magic;
        UCHAR MajorLinkerVersion;
        UCHAR MinorLinkerVersion;
        ULONG SizeOfCode;
        ULONG SizeOfInitializedData;
        ULONG SizeOfUninitializedData;
        ULONG AddressOfEntryPoint;
        ULONG BaseOfCode;
        ULONG BaseOfData;
        ULONG ImageBase;
        ULONG SectionAlignment;
        ULONG FileAlignment;
        WORD MajorOperatingSystemVersion;
        WORD MinorOperatingSystemVersion;
        WORD MajorImageVersion;
        WORD MinorImageVersion;
        WORD MajorSubsystemVersion;
        WORD MinorSubsystemVersion;
        ULONG Win32VersionValue;
        ULONG SizeOfImage;
        ULONG SizeOfHeaders;
        ULONG CheckSum;
        WORD Subsystem;
        WORD DllCharacteristics;
        ULONG SizeOfStackReserve;
        ULONG SizeOfStackCommit;
        ULONG SizeOfHeapReserve;
        ULONG SizeOfHeapCommit;
        ULONG LoaderFlags;
        ULONG NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[16];
    } IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

    */
    PIMAGE_OPTIONAL_HEADER optionalHeader = &ntHeaders->OptionalHeader;
    // Print the optional header fields
    printf("\tMagic: 0x%X\n", optionalHeader->Magic);
    printf("\tAddress of Entry Point: 0x%X\n", optionalHeader->AddressOfEntryPoint);
    printf("\tImage Base: 0x%llX\n", optionalHeader->ImageBase);
    printf("\tSection Alignment: 0x%X\n", optionalHeader->SectionAlignment);
    // ... print other fields as needed
    // Close the file mapping and file handles
    UnmapViewOfFile(fileBaseAddress);
    CloseHandle(fileMapping);
    CloseHandle(fileHandle);
}

void printSectionHeader(const char* filePath) {
    // Open the file
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open file\n");
        return;
    }
    // Create a file mapping
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapping == NULL) {
        printf("Failed to create file mapping\n");
        CloseHandle(hFile);
        return;
    }
    // Map the file to memory
    LPVOID lpBaseAddress = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (lpBaseAddress == NULL) {
        printf("Failed to map view of file\n");
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }
    // Get the DOS header
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
    // Get the NT headers
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpBaseAddress + pDosHeader->e_lfanew);
    // Get the first section header
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    // Print section headers
    printf("Section Headers:\n");
    printf("---------\n");
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
        printf("\t* Section Name: %s\n", pSectionHeader[i].Name);
        printf("\t      Virtual Size: 0x%x\n", pSectionHeader[i].Misc.VirtualSize);
        printf("\t      Virtual Address: 0x%x\n", pSectionHeader[i].VirtualAddress);
        printf("\t      Size of Raw Data: 0x%x\n", pSectionHeader[i].SizeOfRawData);
        printf("\t      Pointer to Raw Data: 0x%x\n", pSectionHeader[i].PointerToRawData);
        printf("\t      Characteristics: 0x%x\n\n", pSectionHeader[i].Characteristics);
    }
    // Close the file mapping and file handles
    UnmapViewOfFile(lpBaseAddress);
    CloseHandle(hMapping);
    CloseHandle(hFile);
}

void printIAT(const char* filePath) {
    // Load the module
    HMODULE module = LoadLibraryExA(filePath, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (module == NULL) {
        printf("Failed to load the module\n");
        return;
    }
    // Get the DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
    // Get the NT headers
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)module + dosHeader->e_lfanew);
    // Get the import descriptor
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)module + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // Iterate over the import descriptors
    while (importDescriptor->Name != NULL) {
        // Get the module name
        const char* moduleName = (const char*)((DWORD_PTR)module + importDescriptor->Name);
        printf("Module Name: %s\n", moduleName);
        
        // Get the thunk data
        PIMAGE_THUNK_DATA thunkData = (PIMAGE_THUNK_DATA)((DWORD_PTR)module + importDescriptor->FirstThunk);
        // Iterate over the thunk data
        while (thunkData->u1.AddressOfData != NULL) {
            // Check if the import is by ordinal or by name
            if (thunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                printf("\tOrdinal: %I64u\n", IMAGE_ORDINAL(thunkData->u1.Ordinal));
            } else {
                // Get the import by name
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)module + thunkData->u1.AddressOfData);
                printf("\tImport Name: %s\n", importByName->Name);
                printf("\tMemory : %x ; Value : %x\n", thunkData, *thunkData);
            }
            thunkData++;
        }
        importDescriptor++;
    }

    // Free the module
    FreeLibrary(module);
}

void addSectionToPE(char* filePath, char* sectionName, char* codeBuffer, DWORD codeSize)
{
    HANDLE hFile, hMap;
    LPVOID pBase;
    PIMAGE_NT_HEADERS pNTHeader;
    PIMAGE_SECTION_HEADER pSectionHeader;
    DWORD dwFileSize, dwHeaderSum, dwCheckSum;
    DWORD dwAlignment = 0x200; // Section alignment value, adjust as needed

    // Open the PE file
    hFile = CreateFile(filePath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf_s("Failed to open file: %s\n", filePath);
        return;
    }

    // Create a file mapping
    hMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (hMap == NULL) {
        printf_s("Failed to create file mapping\n");
        CloseHandle(hFile);
        return;
    }

    // Map the PE file into memory
    pBase = MapViewOfFile(hMap, FILE_MAP_WRITE, 0, 0, 0);
    if (pBase == NULL) {
        printf_s("Failed to map view of file\n");
        CloseHandle(hMap);
        CloseHandle(hFile);
        return;
    }

    // Get the pointer to the PE headers
    pNTHeader = (PIMAGE_NT_HEADERS)((LPBYTE)pBase + ((PIMAGE_DOS_HEADER)pBase)->e_lfanew);

    // Calculate the new size of the image
    dwFileSize = GetFileSize(hFile, NULL);

    // Calculate the checksum
    dwHeaderSum = pNTHeader->OptionalHeader.CheckSum;
    pNTHeader->OptionalHeader.CheckSum = 0;
    dwCheckSum = MapFileAndCheckSumA(filePath, &dwHeaderSum, 1, dwFileSize - dwHeaderSum);

    // Find the last section header
    pSectionHeader = IMAGE_FIRST_SECTION(pNTHeader);
    for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++) {
        if (pSectionHeader->SizeOfRawData == 0) {
            break;
        }
        pSectionHeader++;
    }

    // Set the new section header properties
    lstrcpyA((char*)pSectionHeader->Name, sectionName);
    pSectionHeader->VirtualAddress = pNTHeader->OptionalHeader.SizeOfImage;
    pSectionHeader->Misc.VirtualSize = dwAlignment;
    pSectionHeader->SizeOfRawData = dwAlignment;
    pSectionHeader->PointerToRawData = dwFileSize;
    pSectionHeader->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE;

    // Update the PE headers
    pNTHeader->FileHeader.NumberOfSections++;
    pNTHeader->OptionalHeader.SizeOfHeaders += sizeof(IMAGE_SECTION_HEADER);

    // Copy the code buffer to the new section
    LPBYTE pCode = (LPBYTE)pBase + pSectionHeader->PointerToRawData;
    memcpy_s(pCode, codeSize, codeBuffer, codeSize);

    // Unmap the file and clean up
    UnmapViewOfFile(pBase);
    CloseHandle(hMap);
    CloseHandle(hFile);
}


void FindPEFiles(const char* directory) {
    struct _finddata_t file_info;
    intptr_t handle;

    // Open the directory
    char search_path[256];
    sprintf(search_path, "%s/*", directory);
    handle = _findfirst(search_path, &file_info);
    if (handle == -1) {
        perror("Unable to open directory");
        return;
    }

    // Iterate through files
    do {
        // Ignore '.' and '..' directories
        if (strcmp(file_info.name, ".") == 0 || strcmp(file_info.name, "..") == 0)
            continue;

        // Read the file signature
        char file_path[256];
        sprintf(file_path, "%s/%s", directory, file_info.name);
        FILE* file = fopen(file_path, "rb");
        if (file != NULL) {
            char signature[4];
            fread(signature, sizeof(char), 4, file);
            fclose(file);

            // Compare the signature with known executable signatures
            if (_strnicmp(signature, "MZ", 2) == 0 || _strnicmp(signature, "PE", 2) == 0) {
                // The file is an executable
                printf("Detected executable: %s\n\n", file_path);
                printf("\n%s - DOS Header\n\n", file_path);
                printDOSHeader(file_path);
                printf("\n%s - NT Header\n\n", file_path);
                printNTHeader(file_path);
                printf("\n%s - Section Header\n\n", file_path);
                printSectionHeader(file_path);
                printf("\n%s - Import Table\n\n", file_path);
                printIAT(file_path);
                // char* sectionName = ".infect";
                // char codeBuffer[] = "\x90\x90\x90"; // Example code buffer, adjust as needed
                // DWORD codeSize = sizeof(codeBuffer);

                // if (addSectionToPE(file_path, sectionName, codeBuffer, codeSize)) {
                //     printf("Section addition succeeded\n");
                // } else {
                //     printf("Section addition failed\n");
                // }
            }
        }

        // Recursively search subdirectories
        if (file_info.attrib & _A_SUBDIR) {
            char subdirectory[256];
            sprintf(subdirectory, "%s/%s", directory, file_info.name);
            FindPEFiles(subdirectory);
        }

    } while (_findnext(handle, &file_info) == 0);

    // Close the directory
    _findclose(handle);
}

int main() {
    FindPEFiles("Z:\\Maldev\\Executables");

    return 0;
}