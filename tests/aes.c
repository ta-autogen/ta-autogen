#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <assert.h>

// Encrypting 16 byte long zero vector with 0 key in AES 128-bit ECB and CTR.

void print_function(unsigned char* buf, int len, int bin) {
    int i = 0;
    if (bin) while (i<len) { printf("%hhx", buf[i]); i++; }
    else while (i<len) { printf("%c", buf[i]); i++; }
    printf("\n");
}

int test_ecb(unsigned char key[16], unsigned char input[16], unsigned char output[16]) {
    AES_KEY aes_key;

    if (AES_set_encrypt_key(key, 128, &aes_key) != 0) return 1;
    
    AES_ecb_encrypt(input, output, &aes_key, 1);
    unsigned char res1[] = {0x66,0xe9,0x4b,0xd4,0xef,0x8a,0x2c,0x3b,0x88,0x4c,0xfa,0x59,0xca,0x34,0x2b,0x2e};
    assert(memcmp(res1,output,16)==0);
    printf("AES ECB encryption passed\n");
    
    if (AES_set_decrypt_key(key, 128, &aes_key) != 0) return 1;

    AES_ecb_encrypt(output, input, &aes_key, 0);
    
    unsigned char res2[16];
    memset(res2, 0, 16);
    assert(memcmp(res2,input,16)==0);
    printf("AES ECB decryption passed\n");
    return 0;
}

void init_ctr(unsigned int* num, unsigned char iv[8], unsigned char ivect[16], unsigned char ctr[16]) {
    *num = 0;
    memset(ivect, 0, 16);
    memset(ctr, 0, 16);
    memcpy(ivect, iv, 8);
}

int test_ctr(unsigned char key[16], unsigned char input[16], unsigned char output[16]) {
    AES_KEY aes_key;
    unsigned char iv[8], ivect[16], ctr[16];
    unsigned int num;
    memset(iv, 0, 8);
    
    init_ctr(&num, iv, ivect, ctr);
    
    if (AES_set_encrypt_key(key, 128, &aes_key) != 0) return 1;
    AES_ctr128_encrypt(input, output, 16, &aes_key, ivect, ctr, &num);
    unsigned char res1[] = {0x66,0xe9,0x4b,0xd4,0xef,0x8a,0x2c,0x3b,0x88,0x4c,0xfa,0x59,0xca,0x34,0x2b,0x2e};
    assert(memcmp(res1,output,16)==0);
    printf("AES CTR encryption passed\n");

    init_ctr(&num, iv, ivect, ctr);

    AES_ctr128_encrypt(output, input, 16, &aes_key, ivect, ctr, &num);
    unsigned char res2[16];
    memset(res2, 0, 16);
    assert(memcmp(res2,input,16)==0);
    printf("AES CTR decryption passed\n");
    
    return 0;
}

// AES support for 128 bit keys
int main() {
    int ret;
    unsigned char key[16], input[16], output[16];
    memset(key, 0, 16);
    memset(input, 0, 16);
    
    ret = test_ecb(key, input, output);
    ret = test_ctr(key, input, output);
       
    return ret;
}
