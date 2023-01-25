#include "dll_common.h"
#include "vpr.h"



BOOL RestoreHook
(	CHAR *OrgBytes
,	CHAR *dest_address
)
{
	DWORD oldProtect;

	set_vpr_trace_on_off(0);
	VirtualProtect(dest_address, NUM_BYTES, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(dest_address, OrgBytes, NUM_BYTES);
	VirtualProtect(dest_address, NUM_BYTES, oldProtect, &oldProtect);
	set_vpr_trace_on_off(1);

	return TRUE;
}



void hook_on
(	char *buffer_for_original_opcodes
,	LPVOID pointer_to_target_function
,	LPVOID lp_to_new_function
,	unsigned long long * where_to_store_target_function_address
){
	DWORD	oldProtect
	;
	CHAR new_opcodes[]  = "\x49\xbb\x88\x77\x66\x55\x44\x33\x22\x11" // movabs $0x1122334455667788,%r11 (10 bytes)
	"\x41\xff\xe3" // jmp    *%r11 (3 bytes)
	;
	*where_to_store_target_function_address = (unsigned long long)pointer_to_target_function;

// save the original opcodes for later restore
	if(0==*buffer_for_original_opcodes)
		memcpy(buffer_for_original_opcodes, pointer_to_target_function, 20);

// the beginning of the function will be overwritten with this:
// 49bb1122334455667788	mov r11,8877665544332211h
// 41ffe3		jmp     r11
// where the address 8877665544332211 is going to be changed to the alternate function
	BYTE *p_where_to_write=(BYTE *)(new_opcodes) // points at first byte
	,	opcode
	;
	p_where_to_write++; // points at second byte
	p_where_to_write++; // points at third byte: the beninning of the far address to jump to
	unsigned long long address = (unsigned long long) lp_to_new_function;
	for(int idx=0; idx<8; idx++) {
		opcode=address & 0xFF;
		*p_where_to_write++=opcode;
		address=address >> 8;
	}
	VirtualProtect(pointer_to_target_function, NUM_BYTES, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(pointer_to_target_function, new_opcodes, NUM_BYTES);
	VirtualProtect(pointer_to_target_function, NUM_BYTES, oldProtect, &oldProtect);
//from this moment on, every call to the target function will be diverted to the new one
}


