#ifndef _GPA_H_
#define _GPA_H_

typedef FARPROC (WINAPI *GetProcAddress_)
(	HMODULE hModule
,	LPCSTR  lpProcName
);

FARPROC new_GetProcAddress
(	HMODULE hModule
,	LPCSTR  lpProcName
);

CHAR *get_gpa_buffer_for_orig_bytes();

LPVOID get_gpa_pointer_to_original_address();

void set_gpa_orig_bytes(CHAR *);

#endif

