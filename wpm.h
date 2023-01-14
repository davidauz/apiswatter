#ifndef _WPM_H_
#define _WPM_H_

typedef WINBOOL (WINAPI * WriteProcessMemory_)
(	HANDLE hProcess
,	LPVOID lpBaseAddress
,	LPCVOID lpBuffer
,	SIZE_T nSize
,	SIZE_T *lpNumberOfBytesWritten
);

BOOL new_WriteProcessMemory
(	HANDLE hProcess
,	LPVOID lpBaseAddress
,	LPCVOID lpBuffer
,	SIZE_T nSize
,	SIZE_T *lpNumberOfBytesWritten
);

CHAR *get_wpm_orig_bytes();

set_wpm_orig_bytes(CHAR *);

#endif

