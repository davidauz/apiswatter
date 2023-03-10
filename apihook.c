#include <windows.h>
#include <stdbool.h>
#include "common.h"
#include "wpm.h" // WriteProcessMemory
#include "gpa.h" // GetProcAddress
#include "gmh.h" // GetModuleHandle
#include "crt.h" // CreateRemoteThread
#include "vfr.h" // VirtualFree
#include "vpr.h" // VirtualProtect

#define NUM_BYTES 13

BOOL WINAPI DllMain
(	HINSTANCE hinstDLL // handle to DLL module
,	DWORD fdwReason    // reason for calling function
,	LPVOID lpvReserved // reserved
)
{
	set_log_fp("c:\\log.txt");
	if( DLL_PROCESS_ATTACH == fdwReason ) {
		hook_on
		(	get_wpm_buffer_for_orig_bytes()
		,	(LPVOID)GetProcAddress(GetModuleHandle("KERNELBASE"), "WriteProcessMemory")
		,	new_WriteProcessMemory
		,	get_wpm_pointer_to_original_address()
		);

		hook_on
		(	get_gmh_buffer_for_orig_bytes()
		,	(LPVOID)GetProcAddress(GetModuleHandle("KERNELBASE"), "GetModuleHandleA")
		,	new_GetModuleHandle
		,	get_gmh_pointer_to_original_address()
		);

		hook_on
		(	get_gpa_buffer_for_orig_bytes()
		,	(LPVOID)GetProcAddress(GetModuleHandle("KERNELBASE"), "GetProcAddressForCaller")
		,	new_GetProcAddress
		,	get_gpa_pointer_to_original_address()
		);

		hook_on
		(	get_crt_buffer_for_orig_bytes()
		,	(LPVOID)GetProcAddress(GetModuleHandle("KERNELBASE"), "CreateRemoteThreadEx")
		,	new_CreateRemoteThread
		,	get_crt_pointer_to_original_address()
		);

		special_hook_on_virtualprotect();
		set_vpr_trace_on_off(1);

//		hook_on
//		(	get_vfr_buffer_for_orig_bytes()
//		,	(LPVOID)GetProcAddress(GetModuleHandle("KERNELBASE"), "VirtualFree")
//		,	new_VirtualFree
//		,	get_vfr_pointer_to_original_address()
//		);

	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH
}

