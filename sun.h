#ifndef SUN_H

#define SUN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>    
#include <sys/socket.h>  

#define LENGTH_OF_LISTEN_QUEUE     20  
#define BUFFER_SIZE                1024  
#define FILE_NAME_MAX_SIZE         512  
#define LEN_OF_RETKEY 32
#define SIZE_OF_RETKEY LEN_OF_RETKEY
#define ITER 4096
#define SALT "NaCl"
#define CIPHER_ALGO GCRY_CIPHER_AES128
#define MAGIC_STRING "CNT5410"

extern char * please_input_password();
extern void error_catch(int);
extern int size_of_file(char *);
#endif
