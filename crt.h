#ifndef _CRT_H_
#define _CRT_H_

CHAR *get_crt_buffer_for_orig_bytes();

LPVOID get_crt_pointer_to_original_address();

void set_crt_orig_bytes(CHAR *);

#endif
