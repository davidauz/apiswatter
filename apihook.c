#include <windows.h>
#include <stdbool.h>
#include "common.h"

#define NUM_BYTES 13

void hook_on(char *);

typedef WINBOOL (WINAPI * WriteProcessMemory_)
(	HANDLE hProcess
,	LPVOID lpBaseAddress
,	LPCVOID lpBuffer
,	SIZE_T nSize
,	SIZE_T *lpNumberOfBytesWritten
);

LPVOID g_lp_original_address_in_dll;
char g_original_opcodes[50] = {0};


BOOL RestoreHook(CHAR* OrgBytes)
{
	DWORD oldProtect;

	VirtualProtect(g_lp_original_address_in_dll, NUM_BYTES, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(g_lp_original_address_in_dll, OrgBytes, NUM_BYTES);
	VirtualProtect(g_lp_original_address_in_dll, NUM_BYTES, oldProtect, &oldProtect);

	return TRUE;
}

void file_dump_hex(const void* data, size_t size) {
	size_t i;
	for (i = 0; i < size; ++i)
		file_log("%02X ", ((unsigned char*)data)[i]);
	file_log("\n");
}



BOOL new_WriteProcessMemory
(	HANDLE hProcess
,	LPVOID lpBaseAddress
,	LPCVOID lpBuffer
,	SIZE_T nSize
,	SIZE_T *lpNumberOfBytesWritten
)
{
	file_log("%s:%d writing at `0x%.16llX` size is `%d`\n", __FILE__, __LINE__, lpBaseAddress, nSize);
	file_dump_hex(lpBuffer, nSize);

// restore the original function
	RestoreHook(g_original_opcodes);

// call the original function
	BOOL bRet = WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

// place the hook back again
	hook_on(g_original_opcodes);
}



void hook_on(char *lp_original_opcodes){
	DWORD	oldProtect
	;

// save the original opcodes for later restore
	if(0==*lp_original_opcodes) {
		file_log("%s:%d A01\n", __FILE__, __LINE__);
		memcpy(lp_original_opcodes, g_lp_original_address_in_dll, 20);
	}

// the beginning of the function will be overwritten with this:
// 49bb1122334455667788	mov r11,8877665544332211h
// 41ffe3		jmp     r11
// where the address 8877665544332211 is going to be changed to the alternate function provided in new_WriteProcessMemory
	char new_opcodes[]=
"\x49\xbb\x88\x77\x66\x55\x44\x33\x22\x11" // 10 bytes
"\x41\xff\xe3" // 3 bytes
;
	BYTE * p_where_to_write=(BYTE *)(new_opcodes) // points at first byte
	,	opcode
	;
	unsigned long long new_WriteProcessMemory_address = (unsigned long long)new_WriteProcessMemory;
	p_where_to_write++; // points at second byte
	p_where_to_write++; // points at third byte, the beninning of the far address to jump to
	for(int idx=0; idx<8; idx++) {
		opcode=new_WriteProcessMemory_address & 0xFF;
		*p_where_to_write++=opcode;
		new_WriteProcessMemory_address=new_WriteProcessMemory_address >> 8;
	}
	VirtualProtect(g_lp_original_address_in_dll, NUM_BYTES, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(g_lp_original_address_in_dll, new_opcodes, NUM_BYTES);
	VirtualProtect(g_lp_original_address_in_dll, NUM_BYTES, oldProtect, &oldProtect);
//from this moment on, every call to WriteProcessMemory will be diverted to new_WriteProcessMemory
}


BOOL WINAPI DllMain
(	HINSTANCE hinstDLL // handle to DLL module
,	DWORD fdwReason    // reason for calling function
,	LPVOID lpvReserved // reserved
)
{
// get the address of the function to hijack
	g_lp_original_address_in_dll = (LPVOID)GetProcAddress(GetModuleHandle("KERNELBASE"), "WriteProcessMemory");
//	MessageBox(NULL, get_log_file_path() , "INFO", MB_OK);
//	file_log("%s:%d KERNELBASE!WriteProcessMemory at `%.16llX`\n", __FILE__, __LINE__, g_lp_original_address_in_dll);
	if( DLL_PROCESS_ATTACH == fdwReason ) { 
// Initialize once for each new process.
// Return FALSE to fail DLL load.
		hook_on(g_original_opcodes);
	}
	return TRUE;  // Successful DLL_PROCESS_ATTACH
}

