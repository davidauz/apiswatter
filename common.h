#ifndef _COMMON_H_
#define _COMMON_H_

#define ERROR_VALUE	255

int file_log(char* format, ...);
void set_log_fp(char *);
int delete_log_file();
int show_error_exit(char* format, ...);
char * get_log_file_path();

#endif
