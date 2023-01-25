#ifndef _COMMON_H_
#define _COMMON_H_

#define ERROR_VALUE	255

int file_log(char* format, ...);
void set_log_fp(char *);
int delete_log_file();
int show_error_exit(char* format, ...);
void printout(char* format, ...);
char *get_log_file_path();

void hook_on
(	CHAR *buffer_for_original_opcodes
,	LPVOID orig_address
,	LPVOID lp_to_new_function
,	unsigned long long * where_to_store_target_function_address
);

BOOL RestoreHook
(	CHAR *OrgBytes
,	CHAR *dest_address
);

void file_dump_hex(const void* data, size_t size);

#endif
