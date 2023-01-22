#include <windows.h>
#include <stdbool.h>
#include "common.h"

// specifics for CreateRemoteThread

LPVOID g_crt_address;
LPVOID crt_original_address=(LPVOID)0xBADCAFFE;
char g_crt_hooked_func_orig_bytes[50] = {0};

LPVOID get_crt_pointer_to_original_address(){
	return &crt_original_address;
}

CHAR *get_crt_buffer_for_orig_bytes() {
	return g_crt_hooked_func_orig_bytes;
}

void set_crt_orig_bytes
(	CHAR *orig_bytes
,	int n_size
)
{
	memcpy(g_crt_hooked_func_orig_bytes, orig_bytes, n_size);
}

HANDLE new_CreateRemoteThread
(	HANDLE                 hProcess
,	LPSECURITY_ATTRIBUTES  lpThreadAttributes
,	SIZE_T                 dwStackSize
,	LPTHREAD_START_ROUTINE lpStartAddress
,	LPVOID                 lpParameter
,	DWORD                  dwCreationFlags
,	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList
,	LPDWORD                lpThreadId
)
{
// restore the original function
	RestoreHook(g_crt_hooked_func_orig_bytes, crt_original_address);

// call the original function
	HANDLE return_value = CreateRemoteThreadEx
(	hProcess
,	lpThreadAttributes
,	dwStackSize
,	lpStartAddress
,	lpParameter
,	dwCreationFlags
,	lpAttributeList
,	lpThreadId
);
	if(0==return_value)
		file_log("CreateRemoteThread HANDLE=`0x%.16llX`, pid=`%d`, start address=`0x%.16llX` failed\n", hProcess, lpThreadId, lpStartAddress );
	else
		file_log("CreateRemoteThread HANDLE=`0x%.16llX`, pid=`%d`, start address=`0x%.16llX` success\n", hProcess, lpThreadId, lpStartAddress);

// place the hook back again
	hook_on
	(	g_crt_hooked_func_orig_bytes
	,	crt_original_address
	,	new_CreateRemoteThread
	,	get_crt_pointer_to_original_address()
	);

	return return_value;
}


