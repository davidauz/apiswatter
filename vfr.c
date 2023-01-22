#include <windows.h>
#include <stdbool.h>
#include "common.h"

// specifics for VirtualFree

LPVOID g_vfr_address;
LPVOID vfr_original_address=(LPVOID)0xBADCAFFE;
char g_vfr_hooked_func_orig_bytes[50] = {0};

LPVOID get_vfr_pointer_to_original_address(){
	return &vfr_original_address;
}

CHAR *get_vfr_buffer_for_orig_bytes() {
	return g_vfr_hooked_func_orig_bytes;
}

void set_vfr_orig_bytes
(	CHAR *orig_bytes
,	int n_size
)
{
	memcpy(g_vfr_hooked_func_orig_bytes, orig_bytes, n_size);
}

BOOL new_VirtualFree
(	LPVOID lpAddress
,	SIZE_T dwSize
,	DWORD dwFreeType
)
{
	file_log("VirtuaFree `%d` bytes at `0x%.16llX`:\n", dwSize, lpAddress );
	file_dump_hex(lpAddress, dwSize);
// restore the original function
	RestoreHook(g_vfr_hooked_func_orig_bytes, vfr_original_address);

// call the original function
	BOOL return_value = VirtualFree
(	lpAddress
,	dwSize
,	dwFreeType
);
	if(FALSE==return_value)
		file_log("VirtualFree lpAddress=`0x%.16llX`, size=`%d` failed\n", lpAddress, dwSize );
	else
		file_log("VirtualFree lpAddress=`0x%.16llX`, size=`%d`\n", lpAddress, dwSize );

// place the hook back again
	hook_on
	(	g_vfr_hooked_func_orig_bytes
	,	vfr_original_address
	,	new_VirtualFree
	,	get_vfr_pointer_to_original_address()
	);

	return return_value;
}


