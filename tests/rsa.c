#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <assert.h>

int main() {
    unsigned char out[256], signature[256];
    
    unsigned char in[256] = "Some secret data to be encrypted\0";
    unsigned char hash[32] = "1234567890abcdef1234567890abcdef";
    
    unsigned char result[30];
    memcpy(result, in, 30);
    
    BIGNUM *bn;
    RSA* rsa_key;
    rsa_key = RSA_new();
    
    bn = BN_new();
    BN_set_word(bn, 65537);

    if (!RSA_generate_key_ex(rsa_key, 2048, bn, NULL)) return 1;
    BN_free(bn);
    
    int res1 = RSA_private_encrypt(32, hash, signature, rsa_key, 0);
    int res2 = RSA_public_decrypt(32, hash, signature, rsa_key, 0);
    printf("RSA Signature calculation and verification succeeded.\n");
    
    RSA_public_encrypt(33, in, out, rsa_key, 0);
    RSA_private_decrypt(256, out, in, rsa_key, 0);
    assert(memcmp(result, in, 30)==0);
    printf("RSA encrypt and decrypt succeeded.\n");
    
    return 0;
}
