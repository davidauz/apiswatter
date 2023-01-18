#include <windows.h>
#include <stdbool.h>
#include "common.h"

// code specific for GetProcAddress

LPVOID g_gpa_address;
LPVOID gpa_original_address=0xBADCAFFE;
char g_gpa_hooked_func_orig_bytes[50] = {0};


LPVOID get_gpa_pointer_to_original_address(){
file_log("%s:%d pointer to orig address=`0x%.16llX`, value=`0x%.16llX`\n", __FILE__, __LINE__, &gpa_original_address, gpa_original_address);
	return &gpa_original_address;
}

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
// restore the original function
file_log("%s:%d %s orig address=`0x%.16llX`\n", __FILE__, __LINE__, __PRETTY_FUNCTION__, gpa_original_address);
	RestoreHook(g_gpa_hooked_func_orig_bytes, gpa_original_address);

// call the original function
	FARPROC return_value = GetProcAddress(hModule, lpProcName);
	file_log("%s:%d address of `%s`=`0x%.16llX`\n", __FILE__, __LINE__, lpProcName, return_value);

// place the hook back again
	hook_on
	(	g_gpa_hooked_func_orig_bytes
	,	gpa_original_address
	,	new_GetProcAddress
	,	get_gpa_pointer_to_original_address()
	);

	return return_value;
}


