#include <windows.h>
#include <stdbool.h>
#include "common.h"


LPVOID g_wpm_address;
LPVOID original_address=0;
char g_wpm_orig_bytes[50] = {0};

CHAR *get_wpm_buffer_for_orig_bytes()
{
	return g_wpm_orig_bytes;
}

void set_wpm_orig_bytes
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
file_log("%s:%d A01\n", __FILE__, __LINE__);

	if(0==original_address)
		original_address=(LPVOID)GetProcAddress(GetModuleHandle("KERNELBASE"), "WriteProcessMemory");
file_log("%s:%d wpm original address=`%.16llX`\n", __FILE__, __LINE__, original_address);

// restore the original function
	RestoreHook(g_wpm_orig_bytes, g_wpm_address);
file_log("%s:%d A03\n", __FILE__, __LINE__);

// call the original function
	BOOL bRet = WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
file_log("%s:%d A04\n", __FILE__, __LINE__);

// place the hook back again
	hook_on
	(	g_wpm_orig_bytes
	,	original_address
	,	new_WriteProcessMemory
	);
file_log("%s:%d A05\n", __FILE__, __LINE__);
}


