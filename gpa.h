#ifndef _WPM_H_
#define _WPM_H_

typedef FARPROC (WINAPI *GetProcAddress_)
(	HMODULE hModule
,	LPCSTR  lpProcName
);


FARPROC new_GetProcAddress
(	HMODULE hModule
,	LPCSTR  lpProcName
);


CHAR *get_gpa_buffer_for_orig_bytes();

void set_gpa_orig_bytes(CHAR *);

#endif

