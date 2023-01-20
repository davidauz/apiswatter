#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "common.h"

#define OPTION_DELETE_LOG_FILE 0x01
#define OPTION_START_EXE 0x02
#define OPTION_RUNNING_PID 0x04
#define OPTION_RUNNING_EXE 0x10
#define OPTION_LOG_FILE 0x20

#define CHECK_ARGUMENT \
if(argc<=(1+idx)) \
	return show_error_exit("Missing argument after option `%s`\n", argv[idx]);

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
	target_address=(BYTE *)0x00007FF8AE82D020;
	HANDLE hProcess = OpenProcess
	(	PROCESS_ALL_ACCESS
	,	FALSE
	,	target_pid
	);
	if(0==VirtualProtectEx // If the function fails, the return value is zero
	(	hProcess
	,	target_address
	,	file_path_length
	,	PAGE_READWRITE
	,	&oldProtect
	))
		return show_error_exit( "%s:%d error in VirtualProtect\n", __FILE__, __LINE__);

	if ( 0==WriteProcessMemory // carve parameter into DLL live flesh
	(	hProcess //  [in]  HANDLE  hProcess
	,	target_address // [in]  LPVOID  lpBaseAddress
	,	log_file_path // [in]  LPCVOID lpBuffer
	,	file_path_length //[in]  SIZE_T  nSize
	,	&NumberOfBytesWritten // [out] SIZE_T *lpNumberOfBytesWritten
	))
		return show_error_exit("%s:%d: Error in WriteProcessMemory\n" ,__FILE__, __LINE__ );
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
"-a <exe name>: name of running executable to attach to\n"
"-p <pid>: PID of running executable to attach to\n"
"-e <target exe path>: executable file to run\n"
"-d <dll file name>: DLL file to inject (default %s)\n"
"-f <log file>: log file name (default c:\\log.txt)\n"
"-r: delete log file contents at startup\n"
,	__FILE__
,	__LINE__
,	g_dll_file_name
);
}

int start_exe_in_suspended_mode
(	char *exe_path
,	PROCESS_INFORMATION *p_process_information
){
	STARTUPINFO	startupinfo = {0}
	;

	startupinfo.cb = sizeof(STARTUPINFO);
	if (!CreateProcess
	(	NULL
	,	exe_path
	,	NULL
	,	NULL
	,	FALSE
	,	CREATE_SUSPENDED
	,	NULL
	,	NULL
	,	&startupinfo
	,	p_process_information)
	)
		return show_error_exit("CreateProcess for `%s` failed", exe_path);
	return 0;
}

int main
(	int argc
,	char **argv
)
{
	int	pid
	,	idx=1
	,	CL_OPTIONS=0
	;
	SYSTEMTIME time
	;
	char	*process_name_or_path
	,	*log_file_path=NULL
	;
	PROCESS_INFORMATION	process_information = {0}
	;

	strcpy(g_dll_file_name, "apihook.dll");

	if(2>argc)
		return Usage();

	while (idx < argc ) {
		if(!strcmp("-h", argv[idx]))
			return Usage();			
		else if(!strcmp("-a", argv[idx])){
			CHECK_ARGUMENT
			CL_OPTIONS |= OPTION_RUNNING_EXE;
			process_name_or_path=argv[++idx];
			idx++;
		} else if(!strcmp("-p", argv[idx])){
			CHECK_ARGUMENT
			CL_OPTIONS |= OPTION_RUNNING_PID;
			sscanf(argv[++idx], "%i", &pid);
			idx++;
		} else if(!strcmp("-e", argv[idx])){
			CHECK_ARGUMENT
			CL_OPTIONS |= OPTION_START_EXE;
			if(MAX_PATH < strlen(argv[++idx]))
				return show_error_exit("Executable path max length=`%d`\n", MAX_PATH);
			process_name_or_path= argv[idx++];
		} else if(!strcmp("-d", argv[idx])){
			CHECK_ARGUMENT
			if(100 < strlen(argv[++idx]))
				return show_error_exit("DLL file name max length=`100`\n");
			strcpy(g_dll_file_name, argv[idx++]);
		} else if(!strcmp("-f", argv[idx])){
			CHECK_ARGUMENT
			CL_OPTIONS |= OPTION_LOG_FILE;
			if(MAX_PATH<strlen(argv[++idx]))
				return show_error_exit("Log file max path length is 37 bytes\n");
			log_file_path=argv[idx++];
		} else if(!strcmp("-r", argv[idx])){
			CL_OPTIONS |= OPTION_DELETE_LOG_FILE;
			idx++;
		} else
			return show_error_exit("%s:%d unknown option `%s`\n", __FILE__, __LINE__, argv[idx]);
	}

	if(	CL_OPTIONS & OPTION_LOG_FILE
	&&	CL_OPTIONS & OPTION_START_EXE
	)
		return show_error_exit("Conflicting options `-e` and `-f` (sorry)\n");

	if(	CL_OPTIONS & OPTION_RUNNING_PID
	&&	CL_OPTIONS & OPTION_START_EXE
	)
		return show_error_exit("Conflicting options `-p` and `-e`\n");

	if(	CL_OPTIONS & OPTION_RUNNING_EXE
	&&	CL_OPTIONS & OPTION_START_EXE
	)
		return show_error_exit("Conflicting options `-a` and `-e`\n");

	if(	CL_OPTIONS & OPTION_RUNNING_EXE
	&&	CL_OPTIONS & OPTION_RUNNING_PID
	)
		return show_error_exit("Conflicting options `-a` and `-p`\n");
		
	if(	NULL==log_file_path)
		log_file_path= "c:\\log.txt";

	if(	CL_OPTIONS & OPTION_DELETE_LOG_FILE
	)
		if(0==DeleteFileA(log_file_path))
			show_error_exit( "Cannot delete file `%s`\n", log_file_path);

	if(	CL_OPTIONS & OPTION_RUNNING_EXE
	) {
		pid=find_process_id(process_name_or_path);
		if(0==pid)
			return show_error_exit("Problem getting pid for `%s`\n", process_name_or_path);
		else
			printf("pid for `%s` is `%d`\n", process_name_or_path, pid);
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

	if( CL_OPTIONS & OPTION_START_EXE) {
		if(0!=start_exe_in_suspended_mode(process_name_or_path, &process_information))
			return show_error_exit( "Error in start_exe_in_suspended_mode\n" );
		pid=process_information.dwProcessId;
	}

	perform_dll_injection(pid, g_dll_file_name);

	if( CL_OPTIONS & OPTION_LOG_FILE ) {
// now for the old problem of passing a parameter to an injected DLL
		unsigned long parameter_offset=find_parameter_offset(g_dll_file_name);
		if(0==parameter_offset)
			return show_error_exit( "%s:%d error getting parameter offset\n", __FILE__, __LINE__ );

		unsigned long long target_dll_base_address= find_target_dll_base_address(pid, g_dll_file_name);

		if(0==target_dll_base_address)
			return show_error_exit( "%s:%d error getting target DLL base addr\n", __FILE__, __LINE__ );

		if(0 != fix_parameter(pid, (BYTE *)target_dll_base_address+parameter_offset, log_file_path))
			return show_error_exit( "%s:%d error in fix_parameter\n", __FILE__, __LINE__ );
	}

	if(0!=process_information.dwProcessId) {
		if (ResumeThread(process_information.hThread) == -1)
			return show_error_exit("ResumeThread failed\n");
		CloseHandle(process_information.hProcess);
	}

	printout("%s:%d Success\n\n", __FILE__, __LINE__);

	return 0;
}

