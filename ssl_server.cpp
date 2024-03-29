//----------------------------------------------------------------------------
// File: ssl_server.cpp
// Description: Implementation of an SSL-secured server that performs
//              secure file transfer to a single client over a single
//              connection.
//----------------------------------------------------------------------------
#include <string>
#include <time.h>
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>

#include "utils.h"

//-----------------------------------------------------------------------------
// Function: main()
//-----------------------------------------------------------------------------
int main(int argc, char** argv)
{
    //-------------------------------------------------------------------------
    // initialize
	ERR_load_crypto_strings();
	SSL_load_error_strings();
    SSL_library_init();
    
    setbuf(stdout, NULL); // disables buffered output

	// Handle commandline arguments
	// Useage: client -server serveraddress -port portnumber filename
	if (argc < 2)
	{
		printf("Useage: server portnumber\n");
		exit(EXIT_FAILURE);
	}
	char* port = argv[1];

	printf("------------\n");
	printf("-- SERVER --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Allow for a client to establish an SSL connection
	printf("1. Allowing for client SSL connection...");
	/////////////////////////////////////////////////////////////////////////////
	// Setup DH object and generate Diffie-Helman Parameters
	DH* dh = DH_generate_parameters(128, 5, NULL, NULL);
	int dh_err;
	DH_check(dh, &dh_err);
	if (dh_err != 0)
	{
		printf("Error during Diffie-Helman parameter generation.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup server context
	SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_SINGLE_DH_USE);
	SSL_CTX_set_tmp_dh(ctx, dh);
	if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the BIO
	BIO* server = BIO_new(BIO_s_accept());
	BIO_set_accept_port(server, port);
	BIO_do_accept(server);

	// Setup the SSL
	SSL* ssl = SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	SSL_set_accept_state(ssl);
	SSL_set_bio(ssl, server, server);
	if (SSL_accept(ssl) <= 0)
	{
		printf("Error doing SSL_accept(ssl).\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	printf("DONE.\n");
	printf("    (Now listening on port: %s)\n", port);

    //-------------------------------------------------------------------------
	// 2. Receive a random number (the challenge) from the client
	printf("2. Waiting for client to connect and send challenge...");
    

  	//SSL_read
	

    	string challenge="";
	
	char buff[BUFFER_SIZE];
	int numBytes = SSL_read(ssl,buff,BUFFER_SIZE);    

	challenge = buff;

	printf("DONE.\n");
	printf("    (Challenge: \"%s\")\n", challenge.c_str());

    //-------------------------------------------------------------------------
	// 3. Generate the SHA1 hash of the challenge
	printf("3. Generating SHA1 hash...");
	/////////////////////////////////////////////////////////////////////////////
	//BIO_new(BIO_s_mem());
	char buffa[EVP_MAX_MD_SIZE];	
	BIO *hash_val;
	BIO *hash_bin = BIO_new(BIO_s_mem());
	
	//BIO_write
	int bwrite = BIO_write(hash_bin, buffa, numBytes);
	
	//BIO_new(BIO_f_md());
	hash_val = BIO_new(BIO_f_md());

	//BIO_set_md;
	BIO_set_md(hash_val, EVP_sha1());
	
	//BIO_push;
	BIO_push(hash_val, hash_bin);
	
	//BIO_gets;
    	int mdlen= BIO_gets(hash_val, buffa, EVP_MAX_MD_SIZE);
	string hash_string = buff2hex((const unsigned char*)buffa, mdlen);

	printf("SUCCESS.\n");
	printf("    (SHA1 hash: \"%s\" (%d bytes))\n", hash_string.c_str(), mdlen);

	BIO_free_all(hash_val);
    //-------------------------------------------------------------------------
	// 4. Sign the key using the RSA private key specified in the
	//     file "rsaprivatekey.pem"
	printf("4. Signing the key...");

	
	BIO * bio = BIO_new_file("rsaprivatekey.pem","r");
	 //PEM_read_bio_RSAPrivateKey
	RSA * rsa = PEM_read_bio_RSAPrivateKey(bio,NULL,NULL,NULL);
	
	unsigned char temp[128];	
	int rsa_size = RSA_size(rsa);
 	//RSA_private_encrypt	
	int signature_length = RSA_private_encrypt(rsa_size - 11, (const unsigned char*)buffa, temp, rsa, RSA_PKCS1_PADDING);
  
    char* signature=(char*)temp;

    printf("DONE.\n");
    printf("    (Signed key length: %d bytes)\n", signature_length);
    printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex((const unsigned char*)signature, signature_length).c_str(), signature_length);

    //-------------------------------------------------------------------------
	// 5. Send the signature to the client for authentication
	printf("5. Sending signature to client for authentication...");

	//BIO_flush
	BIO_flush(hash_bin);
	//SSL_write
	char signature_buffer[BUFFER_SIZE];
	memcpy(signature_buffer, signature, BUFFER_SIZE);
	SSL_write(ssl, signature_buffer, BUFFER_SIZE);

    printf("DONE.\n");
    
    //-------------------------------------------------------------------------
	// 6. Receive a filename request from the client
	printf("6. Receiving file request from client...");
	/////////////////////////////////////////////////////////////////////////////
    char file[BUFFER_SIZE];
    //SSL_read
    SSL_read(ssl,file,BUFFER_SIZE);
	
    printf("RECEIVED.\n");
    printf("    (File requested: \"%s\"\n", file);

    //-------------------------------------------------------------------------
	// 7. Send the requested file back to the client (if it exists)
	printf("7. Attempting to send requested file to client...");

	PAUSE(2);
	
    	//BIO_read(bfile, buffer, BUFFER_SIZE)) > 0)
	//SSL_write(ssl, buffer, bytesRead);

    	char buffer[BUFFER_SIZE];
	
        BIO_flush(server);
	int bytesRead = 0;
        
	//BIO_new_file
	BIO*bfile = BIO_new_file(file, "r"); 

	while(1)
	{
		bytesRead = BIO_read(bfile, buffer, BUFFER_SIZE); 
		char buffe[bytesRead];
		if(bytesRead < BUFFER_SIZE){
			for(int i = 0; i< bytesRead; i++){
				buffe[i] = buffer[i];
		 	 } 
		SSL_write(ssl, buffe, bytesRead);	
	break;
		}
		else{ 
		SSL_write(ssl, buffer, bytesRead); 
		}	
	}
    printf("SENT.\n");

    //-------------------------------------------------------------------------
	// 8. Close the connection
	printf("8. Closing connection...");
	/////////////////////////////////////////////////////////////////////////////
    //BIO_reset
    BIO_reset(server);
    //SSL_shutdown
    SSL_shutdown(ssl);
    //BIO_reset
    printf("DONE.\n");

    printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");
	
    //-------------------------------------------------------------------------
	// Freedom!
    
	BIO_free_all(server);
	return EXIT_SUCCESS;
}
