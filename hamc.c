#include <gcrypt.h> 
#include <stdio.h> 
#include <stdlib.h> 
// gcc test.c -lstdc++ -lgcrypt  -I/local/include -L/local/lib -o  testout

int main(int argc,char *argv[]){
	//suncrypt part
	FILE *fin = fopen(argv[1],"rb");
	gcry_error_t cipher_err;
	gcry_md_hd_t md_hd;

	int file_size = get_file_size(argv[1]);
	char *input_buf = (char*)malloc(file_size); 
	memset(input_buf, 0, file_size);
	cipher_err = gcry_md_open(&md_hd, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
	cipher_err = gcry_md_setkey(md_hd, key, gcry_md_get_algo_dlen(GCRY_CIPHER_AES128));

	fread(input_buf, 1, file_size, fin);
	gcry_md_write(md_hd, input_buf, file_size);
	
	char hash[] = gcry_md_read(md_hd, GCRY_MD_SHA512);
	gcry_md_close(md_hd);
	fclose(fin);

	printf("%s\n"，hash);
}