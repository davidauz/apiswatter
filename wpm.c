#include <windows.h>
#include <stdbool.h>
#include "common.h"


LPVOID g_wpm_address;
char g_wpm_orig_bytes[50] = {0};

CHAR *get_wpm_orig_bytes()
{
	return g_wpm_orig_bytes;
}

set_wpm_orig_bytes
(	CHAR *orig_bytes
,	int n_size
)
{
	memcpy(g_wpm_orig_bytes, orig_bytes, n_size);
}

BOOL new_WriteProcessMemory
(	HANDLE hProcess
,	LPVOID lpBaseAddress
,	LPCVOID lpBuffer
,	SIZE_T nSize
,	SIZE_T *lpNumberOfBytesWritten
)
{
	file_log("%s:%d writing at `0x%.16llX` size is `%d`\n", __FILE__, __LINE__, lpBaseAddress, nSize);
	file_dump_hex(lpBuffer, nSize);

// restore the original function
	RestoreHook(g_wpm_orig_bytes);

// call the original function
	BOOL bRet = WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

// place the hook back again
	hook_on(g_wpm_orig_bytes);
}


BOOL WINAPI DllMain
(	HINSTANCE hinstDLL // handle to DLL module
,	DWORD fdwReason    // reason for calling function
,	LPVOID lpvReserved // reserved
)
{
// get the address of the function to hijack
	g_wpm_address = (LPVOID)GetProcAddress(GetModuleHandle("KERNELBASE"), "WriteProcessMemory");
//	MessageBox(NULL, get_log_file_path() , "INFO", MB_OK);
//	file_log("%s:%d KERNELBASE!WriteProcessMemory at `%.16llX`\n", __FILE__, __LINE__, g_wpm_address);
	if( DLL_PROCESS_ATTACH == fdwReason ) { 
// Initialize once for each new process.
// Return FALSE to fail DLL load.
		hook_on(g_wpm_orig_bytes);
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH
}

