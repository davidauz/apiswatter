#include <windows.h>
#include <stdbool.h>
#include "common.h"
#include "wpm.h"

#define NUM_BYTES 13

BOOL WINAPI DllMain
(	HINSTANCE hinstDLL // handle to DLL module
,	DWORD fdwReason    // reason for calling function
,	LPVOID lpvReserved // reserved
)
{
	if( DLL_PROCESS_ATTACH == fdwReason ) { 
// Initialize once for each new process.

		set_wpm_orig_bytes( 
			hook_on
			(	get_wpm_orig_bytes()
			,	(LPVOID)GetProcAddress(GetModuleHandle("KERNELBASE"), "WriteProcessMemory");
			,	new_WriteProcessMemory
			)
		);
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH
}

