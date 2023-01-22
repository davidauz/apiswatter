#ifndef _CRT_H_
#define _CRT_H_

CHAR *get_crt_buffer_for_orig_bytes();

LPVOID get_crt_pointer_to_original_address();

void set_crt_orig_bytes(CHAR *);

HANDLE new_CreateRemoteThread
(	HANDLE                 hProcess
,	LPSECURITY_ATTRIBUTES  lpThreadAttributes
,	SIZE_T                 dwStackSize
,	LPTHREAD_START_ROUTINE lpStartAddress
,	LPVOID                 lpParameter
,	DWORD                  dwCreationFlags
,	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList
,	LPDWORD                lpThreadId
);

#endif
