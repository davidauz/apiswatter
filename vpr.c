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

//BOOL safe_vpr
//(	LPVOID lpAddress
//,	SIZE_T dwSize
//,	DWORD  flNewProtect
//,	PDWORD lpflOldProtect
//)
//{
///*
//00007ffc`25e94c00 48 8b c4          mov     rax,rsp (3 bytes)
//00007ffc`25e94c03 48 89 58 18        mov     qword ptr [rax+18h],rbx (4 bytes)
//00007ffc`25e94c07 55              push    rbp (1 byte)
//00007ffc`25e94c08 56              push    rsi (1 byte)
//00007ffc`25e94c09 57              push    rdi (1 byte)
//00007ffc`25e94c0a 48 83 ec 30        sub     rsp,30h (4 bytes, tot 14)
//00007ffc`25e94c0e 49 8b f1          mov     rsi,r9
//00007ffc`25e94c11 4c 89 48 d8        mov     qword ptr [rax-28h],r9
//00007ffc`25e94c15 458bc8          mov     r9d,r8d
//*/
//	unsigned long long address_to_jump_to = (unsigned long long)vpr_original_address+14;
//	__asm__( 
//		"mov	%%rsp,%%rax;"
//		"mov	%%rbx,0x18(%%rax);"
//		"push	%%rbp;"
//		"push	%%rsi;"
//		"push	%%rdi;"
//		"sub	$0x30,%%rsp;"
////		"mov    %%r9,%%rsi;"
////		"mov    %%r9,-0x28(%%rax);"
////		"mov    %%r8d,%%r9d;"
//		"mov	%0, %%r9;"
//		"call *%%r9;"
//		"ret;"
//		:	// output operands (none)
//		:	"m" (address_to_jump_to) // input operands: the "%0" parametere above
//		:	// list of clobbered registers (none)
//	);
//// N.B. at the beginning of the the function there is the boilerplate code
//// this means that the __asm__ code above sits at safe_vpr()+39
//}


BOOL special_RestoreHook
(	CHAR *OrgBytes
,	CHAR *dest_address
)
{
//	file_log("%s:%d special_RestoreHook copying orig bytes from `%.16llX` to original func address `0x%.16llX`:\n", __FILE__, __LINE__, OrgBytes, dest_address );
//	file_log("%s:%d orig bytes:\n", __FILE__, __LINE__, OrgBytes, dest_address );
//file_dump_hex(OrgBytes, 20);
//	file_log("%s:%d dest address:\n", __FILE__, __LINE__, OrgBytes, dest_address );
//file_dump_hex(dest_address, 20);
	memcpy(dest_address, OrgBytes, NUM_BYTES);
//	file_log("%s:%d memcpy done\n", __FILE__, __LINE__ );
//	file_log("%s:%d orig bytes:\n", __FILE__, __LINE__, OrgBytes, dest_address );
//file_dump_hex(OrgBytes, 20);
//	file_log("%s:%d dest address:\n", __FILE__, __LINE__, OrgBytes, dest_address );
//file_dump_hex(dest_address, 20);

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
//file_log("%s:%d\n", __FILE__, __LINE__);
	vpr_original_address= (LPVOID)GetProcAddress(GetModuleHandle("KERNELBASE"), "VirtualProtect");
//file_log("%s:%d target`%.16llX`\n", __FILE__, __LINE__, vpr_original_address);
//file_log("%s:%d VirtualProtect original opcodes\n", __FILE__, __LINE__);
//file_dump_hex(vpr_original_address, 20);

// save the original opcodes for later restore
	if(0==*g_vpr_hooked_func_orig_bytes) 
	{
		b_is_first_time=TRUE;
//		file_log("%s:%d storing orig bytes at `%.16llX`\n", __FILE__, __LINE__, g_vpr_hooked_func_orig_bytes);
		memcpy(g_vpr_hooked_func_orig_bytes, vpr_original_address, 20);
	}

//file_log("%s:%d hooked func orig bytes at `%.16llX`\n", __FILE__, __LINE__, g_vpr_hooked_func_orig_bytes);
//file_dump_hex(g_vpr_hooked_func_orig_bytes, 20);

// the beginning of the function will be overwritten with this:
// 49bb1122334455667788	mov r11,8877665544332211h
// 41ffe3		jmp     r11
// where the address 8877665544332211 is going to be changed to the alternate function
//file_log("%s:%d\n", __FILE__, __LINE__);
	BYTE *p_where_to_write=(BYTE *)(new_opcodes) // points at first byte
	,	opcode
	;
//file_log("%s:%d opcodes buffer at `%.16llX`\n", __FILE__, __LINE__, p_where_to_write);
	p_where_to_write++; // points at second byte
//file_log("%s:%d\n", __FILE__, __LINE__);
	p_where_to_write++; // points at third byte: the beninning of the far address to jump to
//file_log("%s:%d\n", __FILE__, __LINE__);
	unsigned long long address = (unsigned long long) new_VirtualProtect;
//file_log("%s:%d new_VirtualProtect at `%.16llX`\n", __FILE__, __LINE__, new_VirtualProtect);
	for(int idx=0; idx<8; idx++) {
		opcode=address & 0xFF;
//	file_log("%s:%d opcode`%2x`\n", __FILE__, __LINE__, opcode);
		*p_where_to_write++=opcode;
		address=address >> 8;
	}
//file_log("%s:%d\n", __FILE__, __LINE__);
	if(b_is_first_time) {
		VirtualProtect( vpr_original_address , NUM_BYTES, PAGE_EXECUTE_READWRITE, &oldProtect); // this is still safe
		b_is_first_time=FALSE;
	}
//file_log("%s:%d copying new opcodes to original function adress`%.16llX`:\n", __FILE__, __LINE__, vpr_original_address);
//file_dump_hex(new_opcodes, NUM_BYTES);
	memcpy( vpr_original_address , new_opcodes, NUM_BYTES);
//file_log("%s:%d\n", __FILE__, __LINE__);
//from this moment on, every call to the target function will be diverted to the new one
}




BOOL new_VirtualProtect
(	LPVOID lpAddress
,	SIZE_T dwSize
,	DWORD  flNewProtect
,	PDWORD lpflOldProtect
)
{
	file_log("VirtualProtect `%d` bytes at `0x%.16llX`:\n", dwSize, lpAddress );
//// restore the original function
	special_RestoreHook(g_vpr_hooked_func_orig_bytes, vpr_original_address);
//	file_log("%s:%d Calling orig func\n", __FILE__, __LINE__ );

// call the original function
	BOOL return_value = VirtualProtect
(	lpAddress
,	dwSize
,	flNewProtect
,	lpflOldProtect
);
	file_log("VirtualProtect returns `%d`, content is:\n", return_value );
	file_dump_hex(lpAddress, dwSize);
////	if(FALSE==return_value)
////		file_log("VirtualProtect lpAddress=`0x%.16llX`, size=`%d` failed\n", lpAddress, dwSize );
////	else
////		file_log("VirtualProtect lpAddress=`0x%.16llX`, size=`%d`\n", lpAddress, dwSize );
//
//// place the hook back again
	special_hook_on_virtualprotect();
//
	return return_value;
//return FALSE;
}





