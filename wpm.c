#include <windows.h>
#include <stdbool.h>
#include "common.h"

// code specific for WriteProcessMemory

LPVOID g_wpm_address;
LPVOID original_address=0;
char g_hooked_func_orig_bytes[50] = {0};

CHAR *get_wpm_buffer_for_orig_bytes()
{
	return g_hooked_func_orig_bytes;
}

void set_wpm_orig_bytes
(	CHAR *orig_bytes
,	int n_size
)
{
	memcpy(g_hooked_func_orig_bytes, orig_bytes, n_size);
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

	if(0==original_address)
		original_address=(LPVOID)GetProcAddress(GetModuleHandle("KERNELBASE"), "WriteProcessMemory");

// restore the original function
	RestoreHook(g_hooked_func_orig_bytes, original_address);

// call the original function
	BOOL bRet = WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

// place the hook back again
	hook_on
	(	g_hooked_func_orig_bytes
	,	original_address
	,	new_WriteProcessMemory
	);
}


