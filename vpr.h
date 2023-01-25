#ifndef _VPR_H_
#define _VPR_H_

void special_hook_on_virtualprotect();
void set_vpr_trace_on_off(int);

BOOL new_VirtualProtect
(	LPVOID lpAddress
,	SIZE_T dwSize
,	DWORD  flNewProtect
,	PDWORD lpflOldProtect
);

#endif
