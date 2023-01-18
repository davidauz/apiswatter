#include <windows.h>
#include <stdbool.h>
#include "common.h"

// code specific for WriteProcessMemory

LPVOID g_wpm_address;
LPVOID original_wpm_function_address=0xBADCAFFE;
char g_hooked_func_orig_bytes[50] = {0};

LPVOID get_wpm_pointer_to_original_address(){
	return &original_wpm_function_address;
}

CHAR *get_wpm_buffer_for_orig_bytes() {
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
	file_log("WriteProcessMemory writing `%d` bytes at `0x%.16llX`:\n", nSize, lpBaseAddress);
	file_dump_hex(lpBuffer, nSize);

// restore the original function
	RestoreHook(g_hooked_func_orig_bytes, original_wpm_function_address);

// call the original function
	BOOL bRet = WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

// place the hook back again
	hook_on
	(	g_hooked_func_orig_bytes
	,	original_wpm_function_address
	,	new_WriteProcessMemory
	,	get_wpm_pointer_to_original_address()
	);
}


