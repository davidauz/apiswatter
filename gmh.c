#include <windows.h>
#include <stdbool.h>
#include "common.h"

// code specific for GetModuleHandle

LPVOID g_gmh_address;
LPVOID original_gmh_function_address=(LPVOID)0xBADCAFFE;
char g_gmh_func_orig_bytes[50] = {0};

LPVOID get_gmh_pointer_to_original_address(){
	return &original_gmh_function_address;
}

CHAR *get_gmh_buffer_for_orig_bytes() {
	return g_gmh_func_orig_bytes;
}

void set_gmh_orig_bytes
(	CHAR *orig_bytes
,	int n_size
)
{
	memcpy(get_gmh_buffer_for_orig_bytes, orig_bytes, n_size);
}

HMODULE new_GetModuleHandle
(	LPCSTR lpModuleName
)
{
// restore the original function
	RestoreHook(get_gmh_buffer_for_orig_bytes(), original_gmh_function_address);

// call the original function
	HMODULE hRet = GetModuleHandle(lpModuleName);
	if(0==hRet)
		file_log("GetModuleHandle says `%s`: no such module \n", lpModuleName );
	else
		file_log("GetModuleHandle says `%s` sits at `0x%.16llX`\n", lpModuleName, hRet);

// place the hook back again
	hook_on
	(	get_gmh_buffer_for_orig_bytes()
	,	original_gmh_function_address
	,	new_GetModuleHandle
	,	get_gmh_pointer_to_original_address()
	);

	return hRet;
}


//HMODULE GetModuleHandle(
//	LPCSTR lpModuleName
//);

