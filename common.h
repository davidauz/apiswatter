#ifndef _COMMON_H_
#define _COMMON_H_

#define ERROR_VALUE	255
#define NUM_BYTES 13 // to divert flow need 13 bytes


typedef struct new_opcodes_s{
	char *new_opcodes;
	int n_size;
};

int file_log(char* format, ...);
void set_log_fp(char *);
int delete_log_file();
int show_error_exit(char* format, ...);
char * get_log_file_path();


void hook_on
(	char *lp_original_opcodes
,	CHAR *orig_address
,	CHAR *new_opcodes
,	LPVOID lp_to_new_function
);

BOOL RestoreHook
(	CHAR *OrgBytes
,	CHAR *dest_address
);

void file_dump_hex(const void* data, size_t size);

#endif
