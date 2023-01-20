#ifndef _GMH_H_
#define _GMH_H_

FARPROC new_GetModuleHandle
(	LPCSTR lpModuleName
);

CHAR *get_gmh_buffer_for_orig_bytes();

LPVOID get_gmh_pointer_to_original_address();

void set_gmh_orig_bytes(CHAR *);

#endif
