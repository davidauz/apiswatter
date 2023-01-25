#ifndef _DLL_COMMOON_H_
#define _DLL_COMMOON_H_

#include <windows.h>

#define NUM_BYTES 13 // to divert flow need 13 bytes

BOOL RestoreHook
(	CHAR *OrgBytes
,	CHAR *dest_address
);

void hook_on
(	char *buffer_for_original_opcodes
,	LPVOID pointer_to_target_function
,	LPVOID lp_to_new_function
,	unsigned long long * where_to_store_target_function_address
);

#endif
