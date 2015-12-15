#include "tee_client_api.h"
#include "autogen_shared_header.h"
#include <string.h>
#include <stdlib.h>
#include <openssl/rsa.h>

void InitializeTEEC();
void AllocateMemory(struct marshal_parameters* param_struct, uint8_t* buffer);
void ReleaseMemory();
void InitializeSharedMem(int size);
void InvokeCommand(int command, void* ret);
void end_3();
void add_parameter(struct marshal_parameters* marshal, uint8_t* param_data, uint16_t data_len, uint8_t* buffer);
void pack_parameters(struct marshal_parameters* marshal, uint8_t* buffer);
void write_parameter(uint8_t* dest, uint8_t* src, size_t num);
void unpack_parameters(struct marshal_parameters* marshal, uint8_t* buffer);
void chunk_parameter(uint8_t* param, int size);
void get_chunked_parameter(void* param_buf, int size);

void TEEC_AES_ecb_encrypt(const unsigned char *in, unsigned char *out, uint32_t* key, const int enc);
void TEEC_AES_ctr128_encrypt(const unsigned char *in, unsigned char *out, const unsigned long inlen,
                            uint32_t* key, unsigned char ctr[16], unsigned char ecount_buf[16], unsigned int *num);
unsigned char* TEEC_HMAC(int evp_md, uint32_t key, int key_len, const unsigned char *d,
                        int n, unsigned char *md, unsigned int *md_len);
int TEEC_RSA_private_encrypt(int flen, unsigned char *from, unsigned char *to, uint32_t rsa, int padding);
int TEEC_RSA_public_decrypt(int flen, unsigned char *from, unsigned char *to, uint32_t rsa, int padding);
int TEEC_RSA_public_encrypt(int flen, unsigned char *from, unsigned char *to, uint32_t rsa, int padding);
int TEEC_RSA_private_decrypt(int flen, unsigned char *from, unsigned char *to, uint32_t rsa, int padding);

uint32_t TEEC_create_bitkey(uint32_t keyType, uint32_t keyLen, int new, void* key);
uint32_t TEEC_import_RSA_key(uint32_t keyLen, RSA* rsa);
uint32_t TEEC_create_RSA_key(uint32_t keyLen, uint32_t pubexp);

extern TEEC_Context context;
extern TEEC_Session session;
extern TEEC_SharedMemory mem;
extern TEEC_Operation operation;
extern TEEC_Result result;

#define EXISTING    0
#define NEW         1
