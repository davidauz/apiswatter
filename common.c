#include <Windows.h>
#include <stdio.h>
#include <shlwapi.h>
#include "common.h"

__declspec(dllexport) char g_log_file_path[100]={0};

int file_log(char* format, ...){
	char buf[255]
	;
	DWORD	dwBytesWritten;
	va_list argptr;
	if(0==strlen(g_log_file_path))
		return 0;
	va_start(argptr, format);
	vsprintf(buf, format, argptr);
	va_end(argptr);
	HANDLE report_file_handle;
	report_file_handle = CreateFile
	(	g_log_file_path	// file to write to
	,	FILE_APPEND_DATA
	,	0		// do not share
	,	NULL		// default security
	,	OPEN_ALWAYS
	,	FILE_ATTRIBUTE_NORMAL// normal file
	,	NULL		// no attr. template
	);
	if(INVALID_HANDLE_VALUE==report_file_handle)
		return 255;
	WriteFile
	(	report_file_handle
	,	buf// data to write
	,	strlen(buf)	// number of bytes to write
	,	&dwBytesWritten	// number of bytes that were written
	,	NULL      // no overlapped structure
	);
	CloseHandle(report_file_handle);
	return 0;
}


void set_log_fp(char *fp){
	strcpy(g_log_file_path, fp);
}


int delete_log_file() {
	if( ! PathFileExistsA (g_log_file_path)) 
		return show_error_exit( "%s:%d warning: file `%s` not found\n", __FILE__, __LINE__, g_log_file_path);
	else if(0==DeleteFileA(g_log_file_path))
		return show_error_exit( "%s:%d Cannot delete file `%s`\n", __FILE__, __LINE__, g_log_file_path);
	return 0;
}


void printout(char* format, ...){
	va_list argptr;
	va_start(argptr, format);
	vfprintf(stderr, format, argptr);
	va_end(argptr);
}

int show_error_exit(char* format, ...){
	va_list argptr;
	va_start(argptr, format);
	vfprintf(stderr, format, argptr);
	va_end(argptr);

	LPSTR messageBuffer = 0;
	DWORD error = GetLastError();
	size_t size = FormatMessageA
	(	FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS
	,	NULL
	,	error
	,	MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT)
	,	(LPSTR)&messageBuffer
	,	0
	,	NULL
	);
	printf(messageBuffer);
	LocalFree(messageBuffer);
	return ERROR_VALUE;
}


char * get_log_file_path() {
	return g_log_file_path;
}

BOOL RestoreHook
(	CHAR *OrgBytes
,	CHAR *dest_address
)
{
	DWORD oldProtect;

	VirtualProtect(dest_address, NUM_BYTES, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(dest_address, OrgBytes, NUM_BYTES);
	VirtualProtect(dest_address, NUM_BYTES, oldProtect, &oldProtect);

	return TRUE;
}

void file_dump_hex(const void* data, size_t size) {
	size_t i;
	for (i = 0; i < size; ++i)
		file_log("%02X ", ((unsigned char*)data)[i]);
	file_log("\n");
}


void hook_on
(	char *buffer_for_original_opcodes
,	CHAR *orig_address
,	LPVOID lp_to_new_function
){
	DWORD	oldProtect
	;
	CHAR new_opcodes[]  = "\x49\xbb\x88\x77\x66\x55\x44\x33\x22\x11" // 10 bytes
	"\x41\xff\xe3" // 3 bytes
	;
file_log("%s:%d buffer`0x%.16llX`, address`0x%.16llX`\n", __FILE__, __LINE__, buffer_for_original_opcodes, orig_address);

// save the original opcodes for later restore
	if(0==*buffer_for_original_opcodes)
		memcpy(buffer_for_original_opcodes, orig_address, 20);

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
	VirtualProtect(orig_address, NUM_BYTES, PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(orig_address, new_opcodes, NUM_BYTES);
	VirtualProtect(orig_address, NUM_BYTES, oldProtect, &oldProtect);
file_log("%s:%d hook_on SUCCESS\n", __FILE__, __LINE__);
//from this moment on, every call to orig_address will be diverted to lp_to_new_function
}


