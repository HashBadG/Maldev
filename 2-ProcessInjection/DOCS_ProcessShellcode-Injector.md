# Code Documentation

This documentation provides an overview of the usage of the Process Injection code. 

## Dependencies
The code includes several header files and relies on the following libraries:
- `stdio.h`
- `string.h`
- `windows.h`
- `tlhelp32.h`

## Structures
The code defines several structures used in the code:
- `UNICODE_STRING`: Represents a Unicode string.
- `OBJECT_ATTRIBUTES`: Represents object attributes.
- `CLIENT_ID`: Represents a client ID.

## Function Pointers
The code declares several function pointers:
- `pNtCreateSection`: Points to the `NtCreateSection` function.
- `pNtMapViewOfSection`: Points to the `NtMapViewOfSection` function.
- `pRtlCreateUserThread`: Points to the `RtlCreateUserThread` function.
- `pNtOpenProcess`: Points to the `NtOpenProcess` function.
- `pZwUnmapViewOfSection`: Points to the `ZwUnmapViewOfSection` function.

## Function: `findMyProc`
The `findMyProc` function searches for a process with a given name and returns its process ID (PID). It takes a `procname` parameter and returns an integer representing the PID of the process if found, or 0 if not found.

## Function: `main`
The `main` function is the entry point of the program. It performs the following steps:
1. Defines an array `my_payload` that contains a payload in the form of a hexadecimal string.
2. Initializes variables and handles.
3. Calls the `findMyProc` function to find the process ID of a process specified as a command-line argument.
4. Retrieves function addresses using `GetProcAddress` for various functions from the `ntdll.dll` library.
5. Calls `myNtCreateSection` to create a section object.
6. Calls `myNtMapViewOfSection` to map the section object into the current process.
7. Calls `myNtOpenProcess` to open a handle to the target process.
8. Checks if the process handle is valid and prints an error message if not.
9. Calls `myNtMapViewOfSection` again to map the section object into the target process.
10. Copies the payload to the mapped section.
11. Calls `myRtlCreateUserThread` to create a new thread in the target process.
12. Waits for the thread to complete.
13. Calls `myZwUnmapViewOfSection` to unmap the section from both the current process and the target process.
14. Closes the section handle.

## Usage
To use this code, you need to:
1. Include the necessary header files.
2. Compile the code using a C compiler.
3. Execute the compiled program, providing the name of the target process as a command-line argument.