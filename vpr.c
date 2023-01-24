#include <windows.h>
#include <stdbool.h>
#include "common.h"
#include "vpr.h"

// specifics for VirtualProtect
//BOOL CAN_SAFELY_TRIGGER_HOOK;
LPVOID g_vpr_address;
LPVOID vpr_original_address=(LPVOID)0xBADC0DE;
char g_vpr_hooked_func_orig_bytes[50] = {0};
/*
KERNELBASE!VirtualProtect:
00007ffb`4d944c00 488bc4          mov     rax,rsp
00007ffb`4d944c03 48895818        mov     qword ptr [rax+18h],rbx
00007ffb`4d944c07 55              push    rbp
00007ffb`4d944c08 56              push    rsi
00007ffb`4d944c09 57              push    rdi
00007ffb`4d944c0a 4883ec30        sub     rsp,30h
00007ffb`4d944c0e 498bf1          mov     rsi,r9
00007ffb`4d944c11 4c8948d8        mov     qword ptr [rax-28h],r9
00007ffb`4d944c15 458bc8          mov     r9d,r8d
00007ffb`4d944c18 48895008        mov     qword ptr [rax+8],rdx
00007ffb`4d944c1c 418be8          mov     ebp,r8d
00007ffb`4d944c1f 48894810        mov     qword ptr [rax+10h],rcx

*/

BOOL special_RestoreHook
(	CHAR *OrgBytes
,	CHAR *dest_address
)
{
	memcpy(dest_address, OrgBytes, NUM_BYTES);

	return TRUE;
}


void special_hook_on_virtualprotect()
{
	BOOL b_is_first_time=FALSE;
	DWORD	oldProtect
	;
	CHAR new_opcodes[]  = "\x49\xbb\x88\x77\x66\x55\x44\x33\x22\x11" // 10 bytes
	"\x41\xff\xe3" // 3 bytes
	;
	if( 0xBADCODE == vpr_original_address)
		vpr_original_address= (LPVOID)GetProcAddress(GetModuleHandle("KERNELBASE"), "VirtualProtect");

// save the original opcodes for later restore
	if(0==*g_vpr_hooked_func_orig_bytes) 
	{
		b_is_first_time=TRUE;
		memcpy(g_vpr_hooked_func_orig_bytes, vpr_original_address, 20);
	}

	BYTE *p_where_to_write=(BYTE *)(new_opcodes) // points at first byte
	,	opcode
	;
	p_where_to_write++; // points at second byte
	p_where_to_write++; // points at third byte: the beninning of the far address to jump to
	unsigned long long address = (unsigned long long) new_VirtualProtect;
	for(int idx=0; idx<8; idx++) {
		opcode=address & 0xFF;
		*p_where_to_write++=opcode;
		address=address >> 8;
	}
	if(b_is_first_time) {
		VirtualProtect( vpr_original_address , NUM_BYTES, PAGE_EXECUTE_READWRITE, &oldProtect); // this is still safe
		b_is_first_time=FALSE;
	}
	memcpy( vpr_original_address , new_opcodes, NUM_BYTES);
}




BOOL new_VirtualProtect
(	LPVOID lpAddress
,	SIZE_T dwSize
,	DWORD  flNewProtect
,	PDWORD lpflOldProtect
)
{
	file_log("VirtualProtect `%d` bytes at `0x%.16llX`:\n", dwSize, lpAddress );
	special_RestoreHook(g_vpr_hooked_func_orig_bytes, vpr_original_address);

// call the original function
	BOOL return_value = VirtualProtect
(	lpAddress
,	dwSize
,	flNewProtect
,	lpflOldProtect
);
	file_log("VirtualProtect returns `%d`, content is:\n", return_value );
	file_dump_hex(lpAddress, dwSize);
	special_hook_on_virtualprotect();
	return return_value;
}

