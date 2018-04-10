#include "sun.h"

char* please_input_password(){
	char buffer[40];
	printf("Please input your password:");
	fgets(buffer,35,stdin);
	char * outbuffer=(char *)malloc(SIZE_OF_RETKEY);
	memset(outbuffer,0,SIZE_OF_RETKEY);
	

	gpg_error_t err = gcry_kdf_derive(buffer,strlen(buffer),
					GCRY_KDF_PBKDF2,GCRY_MD_SHA512,
					SALT,sizeof(SALT),ITER,
					LEN_OF_RETKEY,outbuffer);
	if (err) {
		fprintf(stderr,"Password error\n");
		fprintf(stderr,"error id = %d\n",err);
		exit(2);
	}
	return outbuffer;
}

void error_catch(int cipher_err){
	fprintf(stderr,"ERROR id=%d",cipher_err);
	exit(3);
}

int size_of_file(char *filename){
	struct stat file_stat;
	stat(filename,&file_stat);
	return file_stat.st_size;
}

