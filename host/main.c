/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)

int main(int argc, char* argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	// ceaser str	
	int len = 64;	
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	char encrypted_text[64] = {0,};
	char encrypted_key[64] = {0,};
	// rsa str
	char clear[RSA_MAX_PLAIN_LEN_1024];
	char ciph[RSA_CIPHER_LEN_1024];
	
	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/*
	 * Open a session to the "hello world" TA, the TA will print "hello
	 * world!" in the log when the session is created.
	 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	/*
	 * Execute a function in the TA by invoking it, in this case
	 * we're incrementing a number.
	 *
	 * The value of command ID part and how the parameters are
	 * interpreted is part of the interface provided by the TA.
	 */

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));

	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */

	
	// Ceaser
	if (!strcmp(argv[3], "Ceaser")) {

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);
	
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;
	op.params[1].value.a = 0;
	/*
	 * TEEencrypt is the actual function in the TA to be
	 * called.
	 */

	// encrypt :: TEEencrypt -e plain.txt
	if (!strcmp(argv[1], "-e")){
		printf("Encrypt\n");
		// encrypt file read	
		FILE *pf = fopen(argv[2], "r");
		if (pf == NULL){
			printf("not found %s file\n", argv[2]);
			return 0;		
		}
		fgets(plaintext, sizeof(plaintext), pf);
		fclose(pf);
		
		// memcopy
		memcpy(op.params[0].tmpref.buffer, plaintext, len); 
		
		// ta encrypt request
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
         res, err_origin);
				
		// print reply value
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		printf("Encrypted text : %s\n", ciphertext);
		printf("key : %d\n", op.params[1].value.a);
		
		// save encrypted file
		FILE *ef = fopen("encrypted_file.txt", "w+");
		fwrite(ciphertext, strlen(ciphertext), 1, ef);
		fprintf(ef, "%d", op.params[1].value.a);
		fclose(ef);
	}

	// decrypt :: TEEencrypt -d encrypted.txt
	else if (!strcmp(argv[1], "-d")){
		printf("decrypt\n");
		// decrypt file read
		FILE *ef = fopen(argv[2], "r");
		if (ef == NULL){
			printf("not found %s file\n", argv[2]);
			return 0;		
		}
		fgets(encrypted_text, sizeof(encrypted_text), ef);
		fgets(encrypted_key, sizeof(encrypted_key), ef);
		fclose(ef);
	
		// memcopy 
		memcpy(op.params[0].tmpref.buffer, encrypted_text, len);
		int encrypted_rand_key = atoi(encrypted_key);	
		op.params[1].value.a = encrypted_rand_key;			
		
		// ta decrypt request
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
         res, err_origin);
		
		// print reply value
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);
		printf("Decrypted text : %s\n", ciphertext);
		printf("Key : %d\n", op.params[1].value.a);

		// save decrypt file
		FILE *df = fopen("decrypted_file.txt", "w+");
		fwrite(ciphertext, strlen(ciphertext), 1, df);
		fprintf(df, "%d", op.params[1].value.a);
		fclose(df);
		
	 }
	}
	
	// RSA 
	else if (!strcmp(argv[3], "RSA")){
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 		TEEC_MEMREF_TEMP_OUTPUT,
					 		TEEC_NONE, TEEC_NONE);
	
		op.params[0].tmpref.buffer = clear;
		op.params[0].tmpref.size =  RSA_MAX_PLAIN_LEN_1024;
		op.params[1].tmpref.buffer = ciph;
		op.params[1].tmpref.size =  RSA_CIPHER_LEN_1024;
		
		if (!strcmp(argv[1], "-e")){		
		// read file
		FILE *pf = fopen(argv[2], "r");
		if (pf == NULL){
			printf("not found %s file\n", argv[2]);
			return 0;		
		}
		fgets(clear, sizeof(clear), pf);
		fclose(pf);

		// generate key
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSA_GENKEYS, &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_GENKEYS) failed %#x\n", res);
		
		// encrypt		
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSA_ENC,
				 &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_ENCRYPT) failed 0x%x origin 0x%x\n",	res, err_origin);
		
		// print rsa encrypted
		memcpy(ciph, op.params[1].tmpref.buffer, len);
		printf("RSA Encrypted : %s\n", ciph);

		// save rsa encrypted file
		FILE *ref = fopen("rsa_encrypted_file.txt", "w+");
		fwrite(ciph, strlen(ciph), 1, ref);
		fclose(ref);
		

		// decrypt		
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RSA_DEC,
				 &op, &err_origin);
		if (res != TEEC_SUCCESS)
			errx(1, "\nTEEC_InvokeCommand(TA_RSA_CMD_ENCRYPT) failed 0x%x origin 0x%x\n",	res, err_origin);
		
		// print rsa decrypted
		memcpy(clear, op.params[0].tmpref.buffer, len);
		printf("RSA Decrypted : %s\n", clear);

		// save rsa decrypted file
		FILE *rdf = fopen("rsa_decrypted_file.txt", "w+");
		fwrite(clear, strlen(clear), 1, rdf);
		fclose(rdf);
		}		

	}
	else {
		printf("No such option");
	}


	/*
	 * We're done with the TA, close the session and
	 * destroy the context.
	 *
	 * The TA will print "Goodbye!" in the log when the
	 * session is closed.
	 */

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
