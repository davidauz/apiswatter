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
		show_error_exit( "%s:%d warning: file `%s` not found", __FILE__, __LINE__, g_log_file_path);
	else if(0==DeleteFileA(g_log_file_path))
		return show_error_exit( "%s:%d Cannot delete file `%s`", __FILE__, __LINE__, g_log_file_path);
	return 0;
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

