#include "sun.h"

int main(int argc,char *argv[])
{
	if (strcmp(argv[2], "-d") == 0){
	
	FILE *fin=fopen(argv[1],"r");
	FILE *fout;
	
	gcry_cipher_hd_t cipher_hd;
	gcry_error_t cipher_err;

	int file_size = size_of_file(argv[1]);
	char *input_buf= (char*)malloc(file_size); 
	memset(input_buf,0,file_size);
	// plain text buffer
	
	size_t key_size = gcry_cipher_get_algo_keylen(CIPHER_ALGO);
	size_t block_size = gcry_cipher_get_algo_blklen(CIPHER_ALGO);
	size_t block_required=file_size/block_size;
	if (file_size % block_size != 0){
		block_required++;
	}
	char *cipher_buffer=malloc(block_size*block_required);
	memset(cipher_buffer,0,block_size*block_required);
	
	char *iv=malloc(block_size);
	memset(iv,0,block_size);
	memcpy(iv,MAGIC_STRING,sizeof(MAGIC_STRING));
	
	char *key = please_input_password();
	printf("Key: ");
	for (int i = 0; i < gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES128); i++){
		printf("%X ", key[i]);	
	}
	printf("\n");
	//open cipher
	cipher_err=gcry_cipher_open(&cipher_hd,CIPHER_ALGO,
				GCRY_CIPHER_MODE_CBC,GCRY_CIPHER_CBC_CTS);
	if (cipher_err){
		error_catch(cipher_err);
	}

	//set key
	cipher_err=gcry_cipher_setkey(cipher_hd,key,key_size);
	if (cipher_err){
		error_catch(cipher_err);
	}

	//set iv
	cipher_err=gcry_cipher_setiv(cipher_hd, iv, block_size);
	if (cipher_err){
		error_catch(cipher_err);
	}

	char *outfilename=malloc(5+strlen(argv[1]));
	strcpy(outfilename,argv[1]);
	strcat(outfilename,".uf");

	fout = fopen(outfilename,"wb");

	fread(input_buf,1,file_size,fin);

	//padding
	char paddinginput[file_size];
	//int p = block_required*block_size - file_size;

	for (int i = 0; i < file_size; i++){
		paddinginput[i] = input_buf[i];
	}
	for (int j = file_size; j < block_required*block_size; j++){
		paddinginput[j] = 'p';
	}
	
	//encrypt
	memcpy(cipher_buffer,paddinginput,block_required*block_size);
	cipher_err=gcry_cipher_encrypt(cipher_hd,cipher_buffer,
					block_required*block_size,NULL,0);
	if (cipher_err){
		error_catch(cipher_err);
	}
	
	//Hash of encrypted file
	gcry_md_hd_t md_hd2;
	cipher_err = gcry_md_open(&md_hd2, GCRY_MD_SHA512, GCRY_MD_FLAG_SECURE);
	gcry_md_write(md_hd2, cipher_buffer, block_required*block_size);	
	
	unsigned char *hash = gcry_md_read(md_hd2, GCRY_MD_SHA512);
	gcry_md_close(md_hd2);

	//HMAC
	gcry_md_hd_t md_hd;
	cipher_err = gcry_md_open(&md_hd, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
	cipher_err = gcry_md_setkey(md_hd, key, gcry_md_get_algo_dlen(GCRY_CIPHER_AES128));
	gcry_md_write(md_hd, cipher_buffer, block_required*block_size);
	unsigned char *hmac = gcry_md_read(md_hd, GCRY_MD_SHA512);
	gcry_md_close(md_hd);

	printf("Hash of encrypted file || HMAC of encrypted file: \n");
	for (int i = 0; i < 64; i++){
		printf("%02X ", hash[i]);	
	}
	printf(" || ");
	for (int i = 0; i < 64; i++){
		printf("%02X ", hmac[i]);	
	}	
	printf("\n");
	
	fwrite(cipher_buffer,1,block_required*block_size,fout);
	fwrite(hmac, 1, gcry_md_get_algo_dlen(GCRY_MD_SHA512),fout);
	gcry_cipher_close(cipher_hd);
	fclose(fin);
	fclose(fout);
	 

	//socket
    struct sockaddr_in client_addr;  
    bzero(&client_addr, sizeof(client_addr));  
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = htons(INADDR_ANY);  
    client_addr.sin_port = htons(0);  
  
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);  
    if (client_socket < 0){  
        printf("Socket Creation Failed\n");  
        exit(1);  
    }  
  
    // blind socket and address   
    if (bind(client_socket, (struct sockaddr*)&client_addr, sizeof(client_addr))){  
        printf("Bind Port Failed\n");  
        exit(1);  
    }  
  
    // set server_addr  
    struct sockaddr_in  server_addr;  
    bzero(&server_addr, sizeof(server_addr));  
    server_addr.sin_family = AF_INET;  
  	
	
	char *ip = NULL;
	char *port = NULL;
	ip = strtok(argv[3], ":");
	port = strtok(NULL, ":");

    if (inet_aton(ip, &server_addr.sin_addr) == 0){  
        printf("IP Format Error\n");  
        exit(1);  
    }  
  	int crypt_port = atoi(port);
    server_addr.sin_port = htons(crypt_port);  
    socklen_t server_addr_length = sizeof(server_addr);  

    if (connect(client_socket, (struct sockaddr*)&server_addr, server_addr_length) < 0){  
        printf("Cannot Connect To %s\n", argv[1]);  
        exit(1);  
    }  
  
    char file_name[FILE_NAME_MAX_SIZE + 1];  
    bzero(file_name, sizeof(file_name));  
	strcpy(file_name,outfilename);  
  
    char buffer[BUFFER_SIZE]; 
        FILE *fp = fopen(file_name, "r");  
        if (fp == NULL) {  
            printf("File:\t%s  is Not Found\n", file_name);  
        }  
        else {  
            bzero(buffer, BUFFER_SIZE);  
            int file_block_length = 0;  
            while( (file_block_length = fread(buffer, sizeof(char), BUFFER_SIZE, fp)) > 0){    
                if (send(client_socket, buffer, file_block_length, 0) < 0){  
                    printf("File:\t%s Send Failed\n", file_name);  
                    break;  
                }  
                bzero(buffer, sizeof(buffer));  
            }    
            printf("File:\t%s Transmit Finished\n", file_name);  
        }  
   
    fclose(fp);  
    close(client_socket); 
	return 0;
	}
	else if(strcmp(argv[2], "-l") == 0){
	//local mode
	FILE *fin=fopen(argv[1],"r");
	FILE *fout;
		
	gcry_cipher_hd_t cipher_hd;
	gcry_error_t cipher_err;

	int file_size = size_of_file(argv[1]);
	char *input_buf = (char*)malloc(file_size); 
	memset(input_buf,0,file_size);

	//Hash of input file
	//user can untext to show the hash
	/*
	gcry_md_hd_t md_hd;
	cipher_err = gcry_md_open(&md_hd, GCRY_MD_SHA512, GCRY_MD_FLAG_SECURE);

	fread(input_buf, 1, file_size, fin);
	gcry_md_write(md_hd, input_buf, file_size);	
	
	unsigned char *hash = gcry_md_read(md_hd, GCRY_MD_SHA512);
	printf("Hash of input file: \n");
	for (int i = 0; i < 64; i++){
		printf("%02X ", hash[i]);	
	}
	printf("\n");
	gcry_md_close(md_hd);
	*/

	size_t key_size = gcry_cipher_get_algo_keylen(CIPHER_ALGO);
	size_t block_size = gcry_cipher_get_algo_blklen(CIPHER_ALGO);
	size_t block_required = file_size/block_size;
	if (file_size % block_size != 0){
		block_required++;
	}
	char *cipher_buffer = malloc(block_size*block_required);
	memset(cipher_buffer,0,block_size*block_required);
	
	char *iv = malloc(block_size);
	memset(iv,0,block_size);
	memcpy(iv,MAGIC_STRING,sizeof(MAGIC_STRING));
	
	char *key = please_input_password();
	printf("Key: ");
	for (int i = 0; i < gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES128); i++){
		printf("%X ", key[i]);	
	}
	printf("\n");
	//open cipher
	cipher_err = gcry_cipher_open(&cipher_hd,CIPHER_ALGO,
				GCRY_CIPHER_MODE_CBC,GCRY_CIPHER_CBC_CTS);
	if (cipher_err){
		error_catch(cipher_err);
	}

	//set key
	cipher_err=gcry_cipher_setkey(cipher_hd,key,key_size);
	if (cipher_err){
		error_catch(cipher_err);
	}

	//set iv
	cipher_err=gcry_cipher_setiv(cipher_hd, iv, block_size);
	if (cipher_err){
		error_catch(cipher_err);
	}

	char *outfilename=malloc(5+strlen(argv[1]));
	strcpy(outfilename,argv[1]);
	strcat(outfilename,".uf");

	fout = fopen(outfilename,"wb");

	fread(input_buf,1,file_size,fin);

	//padding
	char paddinginput[file_size];
	//int p = block_required*block_size - file_size;

	for (int i = 0; i < file_size; i++){
		paddinginput[i] = input_buf[i];
	}
	for (int j = file_size; j < block_required*block_size; j++){
		paddinginput[j] = 'p';
	}
	
	//encrypt
	memcpy(cipher_buffer,paddinginput,block_required*block_size);
	cipher_err=gcry_cipher_encrypt(cipher_hd,cipher_buffer,
					block_required*block_size,NULL,0);
	if (cipher_err){
		error_catch(cipher_err);
	}
	
	fwrite(cipher_buffer,1,block_required*block_size,fout);
	printf("Successfully encrypt ");
	printf("%s", argv[1]);
	printf(" to ");
	printf("%s\n", outfilename);
	gcry_cipher_close(cipher_hd);
	fclose(fin);
	fclose(fout);
	return 0;
	}
}	
