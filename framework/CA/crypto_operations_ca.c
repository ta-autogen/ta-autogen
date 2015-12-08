#include "autogen_ca_header.h"
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

int TEEC_copy_param(char* param, int len, int ptr) {
    memmove(mem.buffer+ptr, param, len);
    return ptr+len;
}

uint32_t TEEC_import_RSA_key(uint32_t keyLen, RSA* rsa) {
    uint32_t keyID;
    int bsize_half = keyLen/16;
    int ptr = 0;
    
    unsigned char n[2*bsize_half], e[3], d[2*bsize_half], p[bsize_half], q[bsize_half], dmp1[bsize_half], dmq1[bsize_half], iqmp[bsize_half];
    
    BN_bn2bin(rsa->n, n);
    BN_bn2bin(rsa->e, e);
    BN_bn2bin(rsa->d, d);
    BN_bn2bin(rsa->p, p);
    BN_bn2bin(rsa->q, q);
    BN_bn2bin(rsa->dmp1, dmp1);
    BN_bn2bin(rsa->dmq1, dmq1);
    BN_bn2bin(rsa->iqmp, iqmp);
    
    InitializeSharedMem(9*bsize_half+7);
    operation.params[1].memref.parent = &mem;
    
    ptr = TEEC_copy_param((char*)&keyLen, 4, ptr);
    ptr = TEEC_copy_param(n, 2*bsize_half, ptr);
    ptr = TEEC_copy_param(e, 3, ptr);
    ptr = TEEC_copy_param(d, 2*bsize_half, ptr);
    ptr = TEEC_copy_param(p, bsize_half, ptr);
    ptr = TEEC_copy_param(q, bsize_half, ptr);
    ptr = TEEC_copy_param(dmp1, bsize_half, ptr);
    ptr = TEEC_copy_param(dmq1, bsize_half, ptr);
    ptr = TEEC_copy_param(iqmp, bsize_half, ptr);
    
    InvokeCommand(CMD_import_RSA_key, NULL);
	if (result != TEEC_SUCCESS) {
		printf("Invoking import RSA failed: 0x%x\n", result);
		end_3();
	}
    
    memmove(&keyID, mem.buffer, 4);
    ReleaseMemory();
    return keyID;
}

uint32_t TEEC_create_RSA_key(uint32_t keyLen, uint32_t pubexp) {
    uint32_t keyID;
    int ptr;
    InitializeSharedMem(8);
    operation.params[1].memref.parent = &mem;
    
    ptr = TEEC_copy_param((char*)&keyLen, 4, ptr);
    ptr = TEEC_copy_param((char*)&pubexp, 4, ptr);
    
    InvokeCommand(CMD_create_RSA_key, NULL);
	if (result != TEEC_SUCCESS) {
		printf("Invoking create RSA failed: 0x%x\n", result);
		end_3();
	}

    memmove(&keyID, mem.buffer, 4);
    ReleaseMemory();
    return keyID;
}

// This function both generates a new key and imports an existing bit key to TEE
uint32_t TEEC_create_bitkey(uint32_t keyType, uint32_t keyLen, int new, void* key) {
    uint32_t keyID;
    int memsize = 12+sizeof(int);
    
    if (new == 0) memsize += keyLen;
    
    InitializeSharedMem(memsize);
    operation.params[1].memref.parent = &mem;
    memmove(mem.buffer+4, &keyType, 4);
    memmove(mem.buffer+8, &keyLen, 4);
    memmove(mem.buffer+12, &new, sizeof(int));
    
    if (new == 0) memmove(mem.buffer+12+sizeof(int), key, (keyLen/8));
    
    InvokeCommand(CMD_create_bitkey, NULL);
	if (result != TEEC_SUCCESS) {
		printf("Invoking create bitkey failed: 0x%x\n", result);
		end_3();
	}
    
    memmove(&keyID, mem.buffer, 4);
    ReleaseMemory();
    return keyID;
}


void TEEC_AES_ecb_encrypt(const unsigned char *in, unsigned char *out,
                     uint32_t* key, const int enc) {
                         
    // Reserve a shared memory block for params
    InitializeSharedMem(132);
	operation.params[1].memref.parent = &mem;
    memmove(mem.buffer, in, 128);
    memmove(mem.buffer+128, key, 4);
    
    int command;
    if (enc) command = CMD_AES_ECB_encr;
    else command = CMD_AES_ECB_decr;
    
    InvokeCommand(command, NULL);
	if (result != TEEC_SUCCESS) {
		printf("Invoking AES ECB failed: 0x%x\n", result);
		end_3();
	}

    memmove(out, mem.buffer, 128);
    ReleaseMemory();

    return;
}

void TEEC_AES_ctr128_encrypt(const unsigned char *in, unsigned char *out,
	const unsigned long inlen, uint32_t* key, unsigned char ctr[16],
	unsigned char ecount_buf[16], unsigned int *num) {
        
    chunk_parameter((uint8_t*)in, inlen);
    
    InitializeSharedMem(20);
	operation.params[1].memref.parent = &mem;
    memmove(mem.buffer, ctr, 16);
    memmove(mem.buffer+16, key, 4);
        
    InvokeCommand(CMD_AES_CTR_encr, NULL);
	if (result != TEEC_SUCCESS) {
		printf("Invoking AES CTR failed: 0x%x\n", result);
		end_3();
	}
    
    get_chunked_parameter((uint8_t*)out, inlen);
    memset(ecount_buf, 0, 16);
    ReleaseMemory();

}

// pass CMD_HMAC_xxx in evp_md
unsigned char* TEEC_HMAC(int evp_md, uint32_t key,
               int key_len, const unsigned char *d, int n,
               unsigned char *md, unsigned int *md_len) {
    
    chunk_parameter((uint8_t*)d, n);
    InitializeSharedMem(4+*md_len);
	operation.params[1].memref.parent = &mem;
    memmove(mem.buffer, md, *md_len);
    memmove(mem.buffer+*md_len, &key, 4);
    
    InvokeCommand(evp_md, NULL);
	if (result != TEEC_SUCCESS) {
		printf("Invoking HMAC failed: 0x%x\n", result);
		end_3();
	}
    
    memmove(md, mem.buffer, *md_len);
    ReleaseMemory();
    return md;
}

int TEEC_RSA_private_encrypt(int flen, unsigned char *from,
    unsigned char *to, uint32_t rsa, int padding) {
    InitializeSharedMem(260);
    operation.params[1].memref.parent = &mem;
    memmove(mem.buffer, from, flen);
    memmove(mem.buffer+256, &rsa, 4);
    
    InvokeCommand(CMD_RSA_priv_encr, NULL);
    if (result != TEEC_SUCCESS) {
        printf("Invoking RSA priv encr failed: 0x%x\n", result);
        end_3();
    }
    int ret;
    memmove(to, mem.buffer, 256);
    memmove(&ret, mem.buffer+256, sizeof(int));
    ReleaseMemory();
    
    return ret;
}

int TEEC_RSA_public_decrypt(int flen, unsigned char *from, 
    unsigned char *to, uint32_t rsa, int padding) {
    InitializeSharedMem(292);
	operation.params[1].memref.parent = &mem;
    memmove(mem.buffer, from, 32);
    memmove(mem.buffer+32, to, 256);
    memmove(mem.buffer+32+256, &rsa, 4);
    
    InvokeCommand(CMD_RSA_pub_decr, NULL);
    if (result != TEEC_SUCCESS) {
        printf("Invoking RSA pub decr failed: 0x%x\n", result);
        end_3();
    }
    int ret;
    memmove(&ret, mem.buffer, sizeof(int));
    ReleaseMemory();
    
    return ret;
}

int TEEC_RSA_public_encrypt(int flen, unsigned char *from,
    unsigned char *to, uint32_t rsa, int padding) {
    
    if (flen > 190) {
        printf("RSA operation mode not supported: input length %d\n", flen);
        end_3();
    }
    
    InitializeSharedMem(260+sizeof(int));
    operation.params[1].memref.parent = &mem;
    memmove(mem.buffer, from, flen);
    memmove(mem.buffer+256, &rsa, 4);
    memmove(mem.buffer+260, &flen, sizeof(int));
    
    InvokeCommand(CMD_RSA_pub_encr, NULL);
    if (result != TEEC_SUCCESS) {
        printf("Invoking RSA pub encr failed: 0x%x\n", result);
        end_3();
    }
    int ret;
    memmove(to, mem.buffer, 256);
    memmove(&ret, mem.buffer+256, sizeof(int));
    ReleaseMemory();

    return ret;
}

int TEEC_RSA_private_decrypt(int flen, unsigned char *from,
     unsigned char *to, uint32_t rsa, int padding) {

    InitializeSharedMem(260);
    operation.params[1].memref.parent = &mem;
    memmove(mem.buffer, from, flen);
    memmove(mem.buffer+256, &rsa, 4);
    
    InvokeCommand(CMD_RSA_priv_decr, NULL);
    if (result != TEEC_SUCCESS) {
        printf("Invoking RSA priv decr failed: 0x%x\n", result);
        end_3();
    }
    
    int ret;
    memmove(to, mem.buffer, 256);
    memmove(&ret, mem.buffer+256, sizeof(int));
    ReleaseMemory();

    return ret;
}
