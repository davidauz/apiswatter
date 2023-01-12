#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "common.h"

#define OPTION_DELETE_LOG_FILE 0x01

char g_dll_file_name[MAX_PATH]
;

int perform_dll_injection
(	int target_pid
,	char *dll_name
) {
	char	dll_path[MAX_PATH]={0}
	;
	SIZE_T  NumberOfBytesWritten;
	BOOL	b_res;
	MODULEINFO	modinfo
	;

	file_log("%s:%d dll_name=`%s`\n", __FILE__, __LINE__, dll_name);
	if(0 == GetFullPathNameA
	(	dll_name // [in]  LPCSTR lpFileName,
	,	MAX_PATH // [in]  DWORD  nBufferLength,
	,	dll_path // [out] LPSTR  lpBuffer,
	,	NULL // [out] LPSTR  *lpFilePart
	))
		return file_log("%s:%d Error in GetFullPathNameA\n", __FILE__, __LINE__)?FALSE:FALSE;
	int	n_path_size=1+strlen(dll_path);
	file_log("%s:%d DLL full path is `%s`\n", __FILE__, __LINE__, dll_path);
	HANDLE hProcess = OpenProcess
	(	STANDARD_RIGHTS_REQUIRED | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE
	,	FALSE
	,	target_pid
	);
	if(NULL==hProcess)
		return file_log("%s:%d Error in OpenProcess\n", __FILE__, __LINE__)?FALSE:FALSE;
	LPVOID p_dll_file_path= VirtualAllocEx
	(	hProcess // [in]           HANDLE hProcess,
	,	NULL // [in, optional] LPVOID lpAddress,
	,	n_path_size // [in]           SIZE_T dwSize,
	,	MEM_COMMIT|MEM_RESERVE // [in]           DWORD  flAllocationType,
	,	PAGE_READWRITE // [in]           DWORD  flProtect
	);
	b_res = WriteProcessMemory
	(	hProcess //  [in]  HANDLE  hProcess
	,	p_dll_file_path // [in]  LPVOID  lpBaseAddress
	,	dll_path // [in]  LPCVOID lpBuffer
	,	n_path_size //[in]  SIZE_T  nSize
	,	&NumberOfBytesWritten // [out] SIZE_T *lpNumberOfBytesWritten
	);
	if(0==b_res) {
		CloseHandle(hProcess);
		return file_log("%s:%d Error writing memory\n", __FILE__, __LINE__)?FALSE:FALSE;
	}
	if(NumberOfBytesWritten != n_path_size) {
		CloseHandle(hProcess);
		return file_log("%s:%d Size mismatch reading memory\n", __FILE__, __LINE__)?FALSE:FALSE;
	}
	file_log("%s:%d: Creating thread\n", __FILE__, __LINE__);
	HANDLE dll_thread_handle = CreateRemoteThread
	(	 hProcess // [in]  HANDLE                 hProcess,
	,	 NULL // [in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	,	 (SIZE_T)NULL // [in]  SIZE_T                 dwStackSize,
	,	 (LPTHREAD_START_ROUTINE)LoadLibraryA// [in]  LPTHREAD_START_ROUTINE lpStartAddress,
	,	 p_dll_file_path // [in]  LPVOID                 lpParameter,
	,	 (DWORD)0 // [in]  DWORD                  dwCreationFlags,
	,	 NULL // [out] LPDWORD                lpThreadId
	);
	file_log("%s:%d: DLL thread handle=`%d`\n", __FILE__, __LINE__, dll_thread_handle);
	WaitForSingleObject(dll_thread_handle, INFINITE);

	CloseHandle(dll_thread_handle);
	b_res=VirtualFreeEx
	(	hProcess // [in] HANDLE hProcess,
	,	dll_path // [in] LPVOID lpAddress,
	,	n_path_size // [in] SIZE_T dwSize,
	,	MEM_RELEASE // [in] DWORD  dwFreeType
	);

	CloseHandle(hProcess);
	file_log("%s:%d: DLL injection successful\n", __FILE__, __LINE__);

	return 0;
}

int fix_parameter
(	HANDLE hProcess
,	unsigned long long offset
,	BYTE *module_base_address
){
	DWORD	oldProtect
	,	oldOldProtect
	;
	char	*file_path
	;
	int	file_path_length
	;
	BOOL	b_res
	;
	SIZE_T	NumberOfBytesWritten
	;

	file_path=get_log_file_path();
	file_path_length=1+strlen(file_path);
	module_base_address+=offset;
// instead of "passing" the parameter, carve it in the dll's live flesh
	VirtualProtect(module_base_address, file_path_length, PAGE_EXECUTE_READWRITE, &oldProtect);
	b_res = WriteProcessMemory
	(	hProcess //  [in]  HANDLE  hProcess
	,	module_base_address // [in]  LPVOID  lpBaseAddress
	,	file_path // [in]  LPCVOID lpBuffer
	,	file_path_length //[in]  SIZE_T  nSize
	,	&NumberOfBytesWritten // [out] SIZE_T *lpNumberOfBytesWritten
	);
	if(NumberOfBytesWritten!=file_path_length)
		file_log("%s:%d: `%d`!=`%d`\n" ,__FILE__, __LINE__ , NumberOfBytesWritten, file_path_length);
	VirtualProtect(module_base_address, file_path_length, oldProtect, &oldProtect);
}


int set_parameter
(	DWORD target_pid
,	char *target_filename
)
{
// first load the DLL in our process space
	HINSTANCE hDLL=LoadLibrary(target_filename);
// LoadLibrary kindly gave us the base address
	uintptr_t dll_base_address = (uintptr_t)hDLL;
// get the absolute address of the parameter
	BYTE *target_address_in_dll = (BYTE *)GetProcAddress(hDLL, "g_log_file_path");
	if (!target_address_in_dll) {
		FreeLibrary(hDLL);
		show_error_exit( "%s:%d error in GetProcAddress\n", __FILE__, __LINE__ );
		return 255;
	}
// don't need it anymore
	FreeLibrary(hDLL);
	unsigned long long target_address_offset=(unsigned long long)target_address_in_dll-dll_base_address;
// check the library that was loaded in the target PID
	HANDLE moduleSnapshotHandle_ = INVALID_HANDLE_VALUE;
	MODULEENTRY32 moduleEntry_;
	HANDLE hProcess = OpenProcess
	(	STANDARD_RIGHTS_REQUIRED | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE
	,	FALSE
	,	target_pid
	);
// standard procedure: take a snapshot of all the modules in the process
	moduleSnapshotHandle_ = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, target_pid );
	if( moduleSnapshotHandle_ == INVALID_HANDLE_VALUE )
		return show_error_exit( "%s:%d Module Snapshot error\n", __FILE__, __LINE__ ) ? 255:255;
	moduleEntry_.dwSize = sizeof( MODULEENTRY32 );
	if( !Module32First( moduleSnapshotHandle_, &moduleEntry_ ) ) {
		CloseHandle( moduleSnapshotHandle_ );    
		file_log("%s:%d Error in Module32First\n", __FILE__, __LINE__ );
		return 255;
	}
// walk the list and find the one
	do {
		if( strstr(moduleEntry_.szModule, target_filename) ) {
// found the base address of the injected dll
			fix_parameter( hProcess, target_address_offset, moduleEntry_.modBaseAddr );
			CloseHandle(hProcess);
			return 0;
		}
	} while( Module32Next( moduleSnapshotHandle_, &moduleEntry_ ) );

	CloseHandle(hProcess);

	file_log( "%s:%d DLL base address not found\n", __FILE__, __LINE__ );
	return 255;
}

int Usage(){
	return show_error_exit("%s:%d\nUsage\n\n"
"-h: this help\n"
"-p <pid>\n"
"-d <dll file name> (default %s)\n"
"-l <log file> (default %s)\n"
"-r delete log file contents at startup\n"
,	__FILE__
,	__LINE__
,	g_dll_file_name
,	get_log_file_path()
);
}

int main
(	int argc
,	char **argv
)
{
	int	pid
	,	i=1
	,	CL_OPTIONS=0
	;
	SYSTEMTIME time
	;

	set_log_fp("log.txt"); // default log file name
	strcpy(g_dll_file_name, "apihook.dll");

	if(2>argc)
		return Usage();

	while (i < argc ) {
		if(!strcmp("-h", argv[i]))
			return Usage();			
	else if(!strcmp("-d", argv[i])){
		if(argc<=(1+i))
			return show_error_exit("%s:%d Missing argument after option `%s`\n", __FILE__, __LINE__, argv[i]);
		i++;
		if(MAX_PATH < strlen(argv[i]))
			return show_error_exit("%s:%d DLL file name max length=`%d`\n", __FILE__, __LINE__, MAX_PATH);
		strcpy(g_dll_file_name, argv[i]);
		i++;
	} else if(!strcmp("-r", argv[i])){
		CL_OPTIONS |= OPTION_DELETE_LOG_FILE;
		i++;
	} else if(!strcmp("-l", argv[i])){
		if(argc<=(1+i))
			return show_error_exit("%s:%d Missing argument after option `%s`", __FILE__, __LINE__, argv[i]);
		i++;
		if(37<strlen(argv[i]))
			return show_error_exit("%s:%d log file max path length is 37 bytes\n", __FILE__, __LINE__);
		set_log_fp(argv[i]);
		i++;
	} else if(!strcmp("-p", argv[i])){
		if(argc<=(1+i))
			return show_error_exit("%s:%d Missing argument after option `%s`\n", __FILE__, __LINE__, argv[i]);
		i++;
		sscanf(argv[i], "%i", &pid);
		i++;
	} else
		return show_error_exit("%s:%d unknown option `%s`\n", __FILE__, __LINE__, argv[i]);

	}

	if(CL_OPTIONS & OPTION_DELETE_LOG_FILE)
		if(ERROR_VALUE==delete_log_file())
			return ERROR_VALUE;

	GetLocalTime(&time);
	file_log("%s:%d: system time is %d-%d-%d %d:%d:%d\n"
	,	__FILE__
	,	__LINE__
	,	time.wYear
	,	time.wMonth
	,	time.wDay
	,	time.wHour
	,	time.wMinute
	,	time.wSecond
	);
	file_log("%s:%d: target pid:`%d`, dll:`%s`\n", __FILE__, __LINE__, pid, g_dll_file_name);

	perform_dll_injection(pid, g_dll_file_name);

// now for the old problem of passing a parameter to an injected DLL
	if(0 != set_parameter(pid, g_dll_file_name))
		return show_error_exit( "%s:%d error in set_parameter\n", __FILE__, __LINE__ );

	return 0;
}

