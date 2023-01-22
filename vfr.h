#ifndef _VFR_H_
#define _VFR_H_

CHAR *get_vfr_buffer_for_orig_bytes();

LPVOID get_vfr_pointer_to_original_address();

void set_vfr_orig_bytes(CHAR *);

BOOL new_VirtualFree
(	LPVOID lpAddress
,	SIZE_T dwSize
,	DWORD dwFreeType
);

#endif
