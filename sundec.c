#include "sun.h"

int main(int argc,char *argv[]){
	
	if (strcmp(argv[2], "-d") == 0){
	
	// set socket's address information
	char *port = argv[3];
	int dec_port = atoi(port);
    // set server_addr
    struct sockaddr_in   server_addr;  
    bzero(&server_addr, sizeof(server_addr));  
    server_addr.sin_family = AF_INET;  
    server_addr.sin_addr.s_addr = htons(INADDR_ANY);  
    server_addr.sin_port = htons(dec_port);  
  
    // create a stream socket   
    int server_socket = socket(PF_INET, SOCK_STREAM, 0);  
    if (server_socket < 0){  
        printf("Create Socket Failed!\n");  
        exit(1);  
    }  
  
    // blind socket and address  
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr))){  
        printf("Server Bind Port: %d Failed!\n", HELLO_WORLD_SERVER_PORT);  
        exit(1);  
    }  
  
    // server_socket for listening
    if (listen(server_socket, LENGTH_OF_LISTEN_QUEUE)){  
        printf("Server Listen Failed!\n");  
        exit(1);  
    }  
  	char *decfilename=malloc(5+strlen(argv[1]));
	strcpy(decfilename,argv[1]);
	strcat(decfilename,".uf");

    while(1){  
        struct sockaddr_in client_addr;  
        socklen_t          length = sizeof(client_addr);  
  
        int new_server_socket = accept(server_socket, (struct sockaddr*)&client_addr, &length);  
        if (new_server_socket < 0){  
            printf("Connection break, ready to decrypt\n");  
            break;  
        }  
  
        char buffer[BUFFER_SIZE];  
        bzero(buffer, sizeof(buffer));  	
		FILE *fp = fopen(decfilename, "wb");  

    	while(length = recv(new_server_socket, buffer, BUFFER_SIZE, 0)){  
        	if (length < 0){  
            	printf("Recieve Data From Clinet %s Failed!\n", argv[1]);  
            	break;  
        	}  
  
        	int write_length = fwrite(buffer, sizeof(char), length, fp);  
        	if (write_length < length){  
            	printf("File:\t%s Write Failed!\n", argv[1]);  
            	break;  
        	}  
        	bzero(buffer, BUFFER_SIZE);  
    	}  
  	
    printf("Recieve File:\t %s From Suncrypt\n", argv[1]);    
	fclose(fp);  
	close(new_server_socket);
	close(server_socket); 
    }  


	FILE *fin=fopen(decfilename,"rb");
	FILE *fout;
	
	gcry_cipher_hd_t cipher_hd;
	gcry_error_t cipher_err;
	

	int file_size = size_of_file(decfilename);
	char *input_buf = (char*)malloc(file_size); 
	memset(input_buf,0,file_size);
	// encry text buffer

	gcry_md_hd_t md_hd2;
	cipher_err = gcry_md_open(&md_hd2, GCRY_MD_SHA512, GCRY_MD_FLAG_SECURE);

	fread(input_buf, 1, file_size, fin);
	gcry_md_write(md_hd2, input_buf, file_size);	
	
	unsigned char *hash = gcry_md_read(md_hd2, GCRY_MD_SHA512);
	printf("Hash of inbound file: \n");
	for (int i = 0; i < 64; i++){
		printf("%02X ", hash[i]);	
	}
	printf("\n");
	gcry_md_close(md_hd2);

	size_t key_size = gcry_cipher_get_algo_keylen(CIPHER_ALGO);
	size_t block_size = gcry_cipher_get_algo_blklen(CIPHER_ALGO);
	char *decry_buf=malloc(file_size);

	char *iv=malloc(block_size);
	memset(iv,0,block_size);
	memcpy(iv,MAGIC_STRING,sizeof(MAGIC_STRING));

	char *key = please_input_password();
	printf("Key: ");
	for (int i = 0; i < gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES128); i++){
		printf("%X ", key[i]);	
	}
	printf("\n");
	int size = 0;
	int j = 0;
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
	
	char *name = decfilename;
        int namelength = strlen(name) - 3;
	char outfilename[namelength];
	strncpy(outfilename, name, strlen(name) - 3);
	fout = fopen(outfilename,"w");
	
	
	fread(decry_buf,1,file_size,fin);
	//check HMAC code
	char hmac[gcry_md_get_algo_dlen(GCRY_MD_SHA512)];
	char buf_to_decry[file_size - gcry_md_get_algo_dlen(GCRY_MD_SHA512)];
	memcpy(buf_to_decry, decry_buf, (file_size - gcry_md_get_algo_dlen(GCRY_MD_SHA512)));
	memcpy(hmac, decry_buf + (file_size - gcry_md_get_algo_dlen(GCRY_MD_SHA512) + 1), gcry_md_get_algo_dlen(GCRY_MD_SHA512));
	gcry_md_hd_t md_hd;

	cipher_err = gcry_md_open(&md_hd, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
	cipher_err = gcry_md_setkey(md_hd, key, gcry_md_get_algo_dlen(GCRY_CIPHER_AES128));
	gcry_md_write(md_hd, buf_to_decry, file_size- gcry_md_get_algo_dlen(GCRY_MD_SHA512));
	unsigned char *hash_new = gcry_md_read(md_hd, GCRY_MD_SHA512);
	gcry_md_close(md_hd);
	
	for (int i = 0; i < gcry_md_get_algo_dlen(GCRY_MD_SHA512); i++){
		if (hash_new[i] != hmac[i]){
			printf("HMAC check failed. Error in encrypt file.\n");  
        	exit(62);
		}
	}

	file_size = file_size - gcry_md_get_algo_dlen(GCRY_MD_SHA512);
	//decrypt	
	cipher_err=gcry_cipher_decrypt(cipher_hd,buf_to_decry,file_size,NULL,0);
	while (buf_to_decry[file_size-1]==0){
		file_size--;
	}
	if (cipher_err){
		error_catch(cipher_err);
	}
	
	//remove padding code
	char p = *(buf_to_decry+ (file_size - 1));
	int pd = 0;
	
	int i = file_size - 1;
	while (*(buf_to_decry+ i) == p){
		pd++;
		i--;
	}
	
	size = file_size - pd;
	char nopadding[size];
	
	while (j < size){
		nopadding[j] = *(buf_to_decry + j);
		j++;
	}
	
	fwrite(nopadding,1,size,fout);
	gcry_cipher_close(cipher_hd);
	fclose(fin);
	fclose(fout);
	printf("Successfully decrypted file\n");
	return 0;
	}
	else if(strcmp(argv[2], "-l") == 0){
	//local mode
	FILE *fin = fopen(argv[1],"rb");
	FILE *fout;
	
	gcry_cipher_hd_t cipher_hd;
	gcry_error_t cipher_err;


	int file_size = size_of_file(argv[1]);
	char *input_buf = (char*)malloc(file_size); 
	memset(input_buf,0,file_size);
	// encry text buffer
	
	size_t key_size = gcry_cipher_get_algo_keylen(CIPHER_ALGO);
	size_t block_size = gcry_cipher_get_algo_blklen(CIPHER_ALGO);
	char *decry_buf=malloc(file_size);

	char *iv = malloc(block_size);
	memset(iv,0,block_size);
	memcpy(iv,MAGIC_STRING,sizeof(MAGIC_STRING));

	char *key = please_input_password();
	printf("Key: ");
	for (int i = 0; i < gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES128); i++){
		printf("%X ", key[i]);	
	}
	printf("\n");
	
	int size = 0;
	int j = 0;
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
	
	char *name = argv[1];
        int namelength = strlen(name) - 3;
	char outfilename[namelength];
	strncpy(outfilename, name, strlen(name) - 3);
	fout = fopen(outfilename,"w");
	
	
	fread(decry_buf,1,file_size,fin);
	//decrypt	
	cipher_err=gcry_cipher_decrypt(cipher_hd,decry_buf,file_size,NULL,0);
	while (decry_buf[file_size-1]==0){
		file_size--;
	}
	if (cipher_err){
		error_catch(cipher_err);
	}
	
	//remove padding code
	char p = *(decry_buf+ (file_size - 1));
	int pd = 0;
	
	int i = file_size - 1;
	while (*(decry_buf+ i) == p){
		pd++;
		i--;
	}
	
	size = file_size - pd;
	char nopadding[size];
	
	while (j < size){
		nopadding[j] = *(decry_buf + j);
		j++;
	}
	
	fwrite(nopadding,1,size,fout);
	printf("Successfully decrypted file\n");
	gcry_cipher_close(cipher_hd);
	fclose(fin);
	fclose(fout);
	return 0;
	
	}
}
