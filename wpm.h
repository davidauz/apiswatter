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

CHAR *get_wpm_buffer_for_orig_bytes();

LPVOID get_wpm_pointer_to_original_address();

void set_wpm_orig_bytes(CHAR *);

#endif

