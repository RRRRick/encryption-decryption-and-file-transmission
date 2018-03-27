#include <gcrypt.h> 
#include <stdio.h> 
#include <stdlib.h> 
// gcc test.c -lstdc++ -lgcrypt  -I/local/include -L/local/lib -o  testout

int main(int argc, char **argv){
	FILE *fin = fopen(argv[1], 'rb');
	FILE *fout;

	fseek(fin, 0, SEEK_END);        
	int file_size = ftell(fin);
	fseek(fin, 0, SEEK_SET);

	char passphrase[20] = "hello";
	char salt[20] = "NaCl";
	char retkey[100] = {0};
	int retkey_bufferLen = 100;
	gpg_error_t cipher_err = gcry_kdf_derive(passphrase, strlen(passphrase), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, salt, sizeof(salt), 4096, retkey_bufferLen, retkey);

	printf("%s\n"，passphrase);
	//gcry_mac_hd_t = handle;

	size_t key_size = gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES128);
	size_t block_size = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES128);
	size_t block_required = file_size/block_size;

	if (file_size % block_size != 0){
		block_required++;
	}

	char *iv = malloc(block_size);
	memset(iv, 0, block_size);
	memcpy(iv, "abcdef", sizeof("abcdef"));
	gcry_cipher_hd_t cipher_hd;

	cipher_err = gcry_cipher_open(&cipher_hd, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_CBC_CTS);
	cipher_err  = gcry_cipher_setkey(cipher_hd, retkey, key_size);
	cipher_err = gcry_cipher_setiv(cipher_hd, iv, block_size);

	//char *input_buf = (char*)malloc(file_size);
	//char *cipher_buffer = malloc(block_size*block_required);
	//memset(cipher_buffer, 0, block_size*block_required);
	

	char *outfilename = malloc(5 + strlen(argv[1]));
	strcpy(outfilename,argv[1]);
	strcat(outfilename,".uf");

	fout = fopen(outfilename,"wb");

	char *input_buf = (char*)malloc(file_size);
	char *cipher_buffer = (char*)malloc(block_size*block_required);
	memset(cipher_buffer, 0, block_size*block_required);	

	fread(input_buf, 1, file_size,fin);
	memcpy(cipher_buffer,input_buf,block_required*block_size);
	cipher_err = gcry_cipher_encrypt(cipher_hd, cipher_buffer, block_required*block_size, NULL, 0);
	
	//HMAC
	cipher_err = gcry_md_open(&cipher_hd, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
	cipher_err = gcry_md_setkey(cipher_hd, retkey, gcry_md_get_algo_dlen(GCRY_CIPHER_AES128));
	gcry_md_write(cipher_hd, cipher_buffer, lock_required*block_size);
	char hmac[] = gcry_md_read(cipher_hd, GCRY_MD_SHA512);
	gcry_md_close(md_hd);

	fwrite(cipher_buffer, 1, block_required*block_size,fout);
	fwrite(hmac, 1, gcry_md_get_algo_dlen(GCRY_CIPHER_AES128),fout);

	gcry_cipher_close(cipher_hd);

	fclose(fin);
	fclose(fout);


	//cipher_err = gcry_md_setkey(md_hd, );

	return 0;
}