#include <windows.h>
#include <stdbool.h>
#include "common.h"

// code specific for GetProcAddress

LPVOID g_gpa_address;
LPVOID gpa_original_address=0;
char g_gpa_hooked_func_orig_bytes[50] = {0};

CHAR *get_gpa_buffer_for_orig_bytes()
{
	return g_gpa_hooked_func_orig_bytes;
}

void set_gpa_orig_bytes
(	CHAR *orig_bytes
,	int n_size
)
{
	memcpy(g_gpa_hooked_func_orig_bytes, orig_bytes, n_size);
}



FARPROC new_GetProcAddress
(	HMODULE hModule
,	LPCSTR  lpProcName
)
{
	file_log("%s:%d getting address of `%s`\n", __FILE__, __LINE__, lpProcName);

	if(0==gpa_original_address)
		gpa_original_address=(LPVOID)GetProcAddress(GetModuleHandle("KERNELBASE"), "GetProcAddress");

// restore the original function
	RestoreHook(g_gpa_hooked_func_orig_bytes, gpa_original_address);

// call the original function
	FARPROC return_value = GetProcAddress(hModule, lpProcName);

// place the hook back again
	hook_on
	(	g_gpa_hooked_func_orig_bytes
	,	gpa_original_address
	,	new_GetProcAddress
	);

	return return_value;
}


