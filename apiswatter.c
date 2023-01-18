#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "common.h"

#define OPTION_DELETE_LOG_FILE 0x01
#define OPTION_EXE_NAME 0x02
#define OPTION_PID 0x04

char g_dll_file_name[MAX_PATH]
;

unsigned long long find_target_dll_base_address
(	int target_pid
,	char *target_module_name
){
// find the library that was loaded in the target PID
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
		return show_error_exit( "%s:%d Module Snapshot error for PID `%d`\n", __FILE__, __LINE__, target_pid )?0:0;
	moduleEntry_.dwSize = sizeof( MODULEENTRY32 );
	if( !Module32First( moduleSnapshotHandle_, &moduleEntry_ ) ) {
		CloseHandle( moduleSnapshotHandle_ );
		show_error_exit("%s:%d Error in Module32First\n", __FILE__, __LINE__ );
		return 0;
	}
// walk the list and find our one
	do {
		if( strstr(moduleEntry_.szModule, target_module_name) ) {
// found the base address of the injected dll
			CloseHandle(hProcess);
			return (unsigned long long)moduleEntry_.modBaseAddr;
		}
	} while( Module32Next( moduleSnapshotHandle_, &moduleEntry_ ) );
	CloseHandle(hProcess);
	return show_error_exit( "%s:%d Cound not find target module `%s`\n", __FILE__, __LINE__, target_module_name)?0:0;
}

unsigned int find_parameter_offset( char * target_dll ){
// load the DLL in our process space
	HINSTANCE hDLL=LoadLibrary(target_dll); // not calling FreeLibrary afterwards because of weird error
	if(NULL==hDLL)
		return show_error_exit( "%s:%d error in LoadLibrary `%s`\n", __FILE__, __LINE__, target_dll )?0:0;
// LoadLibrary kindly gave us the DLL base address
	uintptr_t our_dll_base_address = (uintptr_t)hDLL;
// get the absolute address of the parameter
	BYTE *target_address_in_our_dll = (BYTE *)GetProcAddress(hDLL, "g_log_file_path");
	if (!target_address_in_our_dll) {
		FreeLibrary(hDLL);
		printout( "%s:%d error in GetProcAddress\n", __FILE__, __LINE__ );
		return 0;
	}
	unsigned long long target_address_offset=(unsigned long long)target_address_in_our_dll-our_dll_base_address;
	return target_address_offset;
}

int perform_dll_injection
(	int target_pid
,	char *dll_name
) {
	char	dll_file_full_path[MAX_PATH]={0}
	;
	SIZE_T  NumberOfBytesWritten;
	BOOL	b_res;
	MODULEINFO	modinfo
	;
	LPVOID dll_file_path_buffer=NULL
	;

	if(0 == GetFullPathNameA
	(	dll_name // [in]  LPCSTR lpFileName,
	,	MAX_PATH // [in]  DWORD  nBufferLength,
	,	dll_file_full_path // [out] LPSTR  lpBuffer,
	,	NULL // [out] LPSTR  *lpFilePart
	))
		return file_log("%s:%d Error in GetFullPathNameA\n", __FILE__, __LINE__)?FALSE:FALSE;
	int	n_path_size=1+strlen(dll_file_full_path);
	HANDLE hProcess = OpenProcess
	(	PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE
	,	FALSE
	,	target_pid
	);
	if(NULL==hProcess)
		return show_error_exit("%s:%d Error in OpenProcess\n", __FILE__, __LINE__)?FALSE:FALSE;

	dll_file_path_buffer= VirtualAllocEx
	(	hProcess // [in]           HANDLE hProcess,
	,	NULL // [in, optional] LPVOID lpAddress,
	,	n_path_size // [in]           SIZE_T dwSize,
	,	MEM_COMMIT|MEM_RESERVE // [in]           DWORD  flAllocationType,
	,	PAGE_READWRITE // [in]           DWORD  flProtect
	);
	if(NULL==dll_file_path_buffer)
		return show_error_exit("%s:%d Error in VirtualAllocEx\n", __FILE__, __LINE__)?FALSE:FALSE;
	b_res = WriteProcessMemory
	(	hProcess //  [in]  HANDLE  hProcess
	,	dll_file_path_buffer // [in]  LPVOID  lpBaseAddress
	,	dll_file_full_path // [in]  LPCVOID lpBuffer
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

	HANDLE dll_thread_handle = CreateRemoteThread
	(	 hProcess // [in]  HANDLE                 hProcess,
	,	 NULL // [in]  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
	,	 (SIZE_T)NULL // [in]  SIZE_T                 dwStackSize,
	,	 (LPTHREAD_START_ROUTINE)LoadLibraryA// [in]  LPTHREAD_START_ROUTINE lpStartAddress,
	,	 dll_file_path_buffer // [in]  LPVOID                 lpParameter,
	,	 (DWORD)0 // [in]  DWORD                  dwCreationFlags,
	,	 NULL // [out] LPDWORD                lpThreadId
	);

	WaitForSingleObject(dll_thread_handle, INFINITE);
	CloseHandle(dll_thread_handle);
	b_res=VirtualFreeEx
	(	hProcess // [in] HANDLE hProcess,
	,	dll_file_full_path // [in] LPVOID lpAddress,
	,	n_path_size // [in] SIZE_T dwSize,
	,	MEM_RELEASE // [in] DWORD  dwFreeType
	);

	CloseHandle(hProcess);

	return 0;
}

int fix_parameter
(	int target_pid
,	BYTE *target_address
,	char *log_file_path
){
	DWORD	oldProtect
	;
	int	file_path_length=1+strlen(log_file_path)
	;
	BOOL	b_res
	;
	SIZE_T	NumberOfBytesWritten
	;

	HANDLE hProcess = OpenProcess
	(	PROCESS_ALL_ACCESS
	,	FALSE
	,	target_pid
	);
	if(0==VirtualProtectEx
	(	hProcess
	,	target_address
	,	file_path_length
	,	PAGE_EXECUTE_READWRITE
	,	&oldProtect
	))
		return show_error_exit( "%s:%d error in VirtualProtect\n", __FILE__, __LINE__);
	b_res = WriteProcessMemory
	(	hProcess //  [in]  HANDLE  hProcess
	,	target_address // [in]  LPVOID  lpBaseAddress
	,	log_file_path // [in]  LPCVOID lpBuffer
	,	file_path_length //[in]  SIZE_T  nSize
	,	&NumberOfBytesWritten // [out] SIZE_T *lpNumberOfBytesWritten
	);
	if(NumberOfBytesWritten!=file_path_length)
		file_log("%s:%d: `%d`!=`%d`\n" ,__FILE__, __LINE__ , NumberOfBytesWritten, file_path_length);
	if(0==VirtualProtectEx
	(	hProcess
	,	target_address
	,	file_path_length
	,	oldProtect
	, &oldProtect))
		return show_error_exit( "%s:%d error in VirtualProtect\n", __FILE__, __LINE__);
	return 0;
}

int find_process_id(char *TARGET_EXE) {
	PROCESSENTRY32 pe32;
	HANDLE hProcess;
	HANDLE hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	int result_pid = 0;
	if( hProcessSnap == INVALID_HANDLE_VALUE )
		return show_error_exit("%s:%d Error in CreateToolhelp32Snapshot", __FILE__, __LINE__)?0:0;

	pe32.dwSize = sizeof( PROCESSENTRY32 );
	if( !Process32First( hProcessSnap, &pe32 ) ) {
		CloseHandle( hProcessSnap );
		show_error_exit("%s:%d Error in Process32First", __FILE__, __LINE__);
		return 0;
	}

	do{
		hProcess = OpenProcess( PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID );
		if(strstr(TARGET_EXE, pe32.szExeFile)) {
			result_pid= pe32.th32ProcessID;
			break;
		}
	} while( Process32Next( hProcessSnap, &pe32 ) );
	CloseHandle(hProcess);

	return result_pid;
}


int Usage(){
	return show_error_exit("%s:%d\nUsage\n\n"
"-h: this help\n"
"-p <target pid>\n"
"-e <target exe name>\n"
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
	char exe_name[MAX_PATH]
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
	} else if(!strcmp("-e", argv[i])){
		CL_OPTIONS |= OPTION_EXE_NAME;
		if(argc<=(1+i))
			return show_error_exit("%s:%d Missing argument after option `%s`", __FILE__, __LINE__, argv[i]);
		i++;
		strcpy(exe_name, argv[i]);
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
		CL_OPTIONS |= OPTION_PID;
		if(argc<=(1+i))
			return show_error_exit("%s:%d Missing argument after option `%s`\n", __FILE__, __LINE__, argv[i]);
		i++;
		sscanf(argv[i], "%i", &pid);
		i++;
	} else
		return show_error_exit("%s:%d unknown option `%s`\n", __FILE__, __LINE__, argv[i]);

	}

	if(CL_OPTIONS & OPTION_DELETE_LOG_FILE)
		delete_log_file();
	if(	CL_OPTIONS & OPTION_EXE_NAME
	&&	CL_OPTIONS & OPTION_PID
	)
		return show_error_exit("%s:%d cannot give both PID and EXE NAME\n", __FILE__, __LINE__);

	if(CL_OPTIONS & OPTION_EXE_NAME) {
		pid=find_process_id(exe_name);
		if(0==pid)
			return show_error_exit("%s:%d problem getting pid for `%s`\n", __FILE__, __LINE__, exe_name);
	}

	GetLocalTime(&time);
	file_log("System time is %d-%02d-%02d %02d:%02d:%02d\n"
	,	time.wYear
	,	time.wMonth
	,	time.wDay
	,	time.wHour
	,	time.wMinute
	,	time.wSecond
	);
	printout("Target pid:`%d`, dll:`%s`\n", pid, g_dll_file_name);

	perform_dll_injection(pid, g_dll_file_name);

	unsigned long parameter_offset=find_parameter_offset(g_dll_file_name);
	if(0==parameter_offset)
		return show_error_exit( "%s:%d error getting parameter offset\n", __FILE__, __LINE__ );

	unsigned long long target_dll_base_address= find_target_dll_base_address(pid, g_dll_file_name);

	if(0==target_dll_base_address)
		return show_error_exit( "%s:%d error getting target DLL base addr\n", __FILE__, __LINE__ );

// now for the old problem of passing a parameter to an injected DLL
	if(0 != fix_parameter(pid, (BYTE *)(target_dll_base_address+parameter_offset), get_log_file_path()))
		return show_error_exit( "%s:%d error in fix_parameter\n", __FILE__, __LINE__ );
	printout("%s:%d Success\n\n", __FILE__, __LINE__);

	return 0;
}

