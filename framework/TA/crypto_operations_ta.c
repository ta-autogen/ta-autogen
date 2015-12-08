#include "autogen_ta_header.h"

TEE_Result TA_EXPORT TEE_ASYMMETRIC(TEE_OperationHandle operation, void* inputBuf, uint32_t inBufLen,
                                    void* outputBuf, int* outBufLen);
TEE_Result TA_EXPORT TEE_SYMMETRIC(TEE_OperationHandle operation, void* inputBuf, uint32_t inBufLen,
                                    void* outputBuf, uint32_t outBufLen);
TEE_Result TA_EXPORT TEE_MAC(TEE_OperationHandle operation, uint8_t* inputBuf, uint32_t inBufLen,
                                uint8_t* outputBuf, uint32_t outBufLen);
void TEE_init_operation(TEE_OperationHandle* operation, uint32_t algorithm, uint32_t mode, TEE_ObjectHandle key, uint32_t keyLen);
uint32_t get_operation_mode(TEE_OperationHandle operation);
uint32_t get_operation_alg(TEE_OperationHandle operation);

static TEE_ObjectHandle key;

TEE_Result TA_EXPORT TEE_get_key_handle(uint32_t objectID, TEE_ObjectHandle* keyObject) {
    TEE_Result result;
    result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, (void*)&objectID, sizeof(uint32_t), TEE_DATA_FLAG_ACCESS_READ, keyObject);
    return result;
}

TEE_Result TA_EXPORT TEE_HMAC_SHA256(uint32_t keyID, uint8_t* inputBuf, uint32_t inBufLen, uint8_t* outputBuf) {
    TEE_Result result;
    if (TEE_get_key_handle(keyID, &key) != TEE_SUCCESS) return 1;
    TEE_OperationHandle operation;
    uint32_t outBufLen = 32;
    TEE_init_operation(&operation, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, key, 1024);
    result = TEE_MAC(operation, inputBuf, inBufLen, outputBuf, outBufLen);
    TEE_CloseObject(key);
    return result;
}

TEE_Result TA_EXPORT TEE_HMAC_SHA384(uint32_t keyID, uint8_t* inputBuf, uint32_t inBufLen, uint8_t* outputBuf) {
    TEE_Result result;
    if (TEE_get_key_handle(keyID, &key) != TEE_SUCCESS) return 1;
    TEE_OperationHandle operation;
    uint32_t outBufLen = 48;
    TEE_init_operation(&operation, TEE_ALG_HMAC_SHA384, TEE_MODE_MAC, key, 1024);
    result = TEE_MAC(operation, inputBuf, inBufLen, outputBuf, outBufLen);
    TEE_CloseObject(key);
    return result;
}

TEE_Result TA_EXPORT TEE_HMAC_SHA512(uint32_t keyID, uint8_t* inputBuf, uint32_t inBufLen, uint8_t* outputBuf) {
    TEE_Result result;
    if (TEE_get_key_handle(keyID, &key) != TEE_SUCCESS) return 1;
    TEE_OperationHandle operation;
    uint32_t outBufLen = 64;
    TEE_init_operation(&operation, TEE_ALG_HMAC_SHA512, TEE_MODE_MAC, key, 1024);
    result = TEE_MAC(operation, inputBuf, inBufLen, outputBuf, outBufLen);
    TEE_CloseObject(key);
    return result;
}

TEE_Result TA_EXPORT TEE_AES_CTR(uint32_t mode, uint32_t keyID, uint8_t* inputBuf, uint32_t inBufLen) {
    TEE_Result result;
    if (TEE_get_key_handle(keyID, &key) != TEE_SUCCESS) return 1;
    TEE_OperationHandle operation;
    TEE_init_operation(&operation, TEE_ALG_AES_CTR, mode, key, 128);
    
    int outBufLen;
    if (inBufLen%128) outBufLen = inBufLen + (128 - (inBufLen%128));
    else outBufLen = inBufLen;
    uint8_t outputBuf[outBufLen];
    
    result = TEE_SYMMETRIC(operation, inputBuf, inBufLen, outputBuf, outBufLen);
    TEE_CloseObject(key);
    return result;
}

TEE_Result TA_EXPORT TEE_AES_ECB(uint32_t mode, uint32_t keyID, uint8_t* inputBuf) {
    TEE_Result result;
    if (TEE_get_key_handle(keyID, &key) != TEE_SUCCESS) return 1;
    TEE_OperationHandle operation;
    TEE_init_operation(&operation, TEE_ALG_AES_ECB_NOPAD, mode, key, 128);
    
    int inBufLen = 128;
    uint8_t outputBuf[inBufLen];
    
    result = TEE_SYMMETRIC(operation, inputBuf, inBufLen, outputBuf, inBufLen);
    TEE_CloseObject(key);
    return result;
}

TEE_Result TA_EXPORT TEE_RSA_PSS(uint32_t mode, uint32_t keyID, uint8_t* inputBuf, uint32_t inBufLen,
                                uint8_t* outputBuf, int* outlen) {
    TEE_Result result;
    *outlen = 256;
    if (TEE_get_key_handle(keyID, &key) != TEE_SUCCESS) return 1;
    TEE_OperationHandle operation;
    TEE_init_operation(&operation, TEE_ALG_RSASSA_PKCS1_PSS_MGF1_SHA256, mode, key, 2048);
    result = TEE_ASYMMETRIC(operation, inputBuf, inBufLen, outputBuf, outlen);
    TEE_CloseObject(key);
    return result;
}

TEE_Result TA_EXPORT TEE_RSA_OAEP(uint32_t mode, uint32_t keyID, uint8_t* inputBuf, uint32_t inBufLen,
                                uint8_t* outputBuf, int* outlen) {
    TEE_Result result;
    *outlen = 256;
    if (TEE_get_key_handle(keyID, &key) != TEE_SUCCESS) return 1;
    TEE_OperationHandle operation;
    TEE_init_operation(&operation, TEE_ALG_RSAES_PKCS1_OAEP_MGF1_SHA256, mode, key, 2048);
    result = TEE_ASYMMETRIC(operation, inputBuf, inBufLen, outputBuf, outlen);
    TEE_CloseObject(key);
    return result;
}

void TEE_genKey(uint32_t keyType, uint32_t keyLen, TEE_ObjectHandle* keyObject,
                uint32_t objectID, uint32_t objectIDlen, uint32_t pubexp) {
    TEE_Result result;
    result = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, (void*)&objectID, objectIDlen, TEE_DATA_FLAG_ACCESS_READ, keyObject);
    if (result == TEE_SUCCESS) return;
    
    TEE_ObjectHandle tempObject;
    TEE_AllocateTransientObject(keyType, keyLen, &tempObject);
    
    if (keyType == TEE_TYPE_RSA_KEYPAIR) {
        // Convert public exponent to byte array
        uint8_t tempexp[4];
        int i = 0;
        while (i<4) { tempexp[i] = (pubexp>>(i*8)) & 0xFF; i++; }
        
        TEE_Attribute attr_list[1];
        attr_list[0].attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
        attr_list[0].content.ref.buffer = tempexp;
        attr_list[0].content.ref.length = 32;
        TEE_GenerateKey(tempObject, keyLen, attr_list, 0);
    }
    
    else {
        TEE_GenerateKey(tempObject, keyLen, NULL, 0);
    }
    // Populate given persistent object with generated key
    uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META;
    TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void*)&objectID, objectIDlen, flags, tempObject, NULL, 0, keyObject);
    TEE_FreeTransientObject(tempObject);
}

TEE_Result TA_EXPORT TEE_importBitkey(uint32_t keyType, uint32_t keyLen, uint32_t keyID, uint8_t* key, TEE_ObjectHandle* keyObject) {
    TEE_Result result;
    TEE_ObjectHandle tempObj;
    TEE_Attribute key_attr[1];
    
    uint32_t maxLen;
    if (keyLen < 256 && keyType != 0xA0000010) maxLen = 256;
    else maxLen = keyLen;
    
    key_attr[0].attributeID = TEE_ATTR_SECRET_VALUE;
    key_attr[0].content.ref.buffer = key;
    key_attr[0].content.ref.length = keyLen;

    result = TEE_AllocateTransientObject(keyType, maxLen, &tempObj);
    result = TEE_PopulateTransientObject(tempObj, key_attr, 1);
    
    uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META;
    TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void*)&keyID, sizeof(uint32_t), flags, tempObj, NULL, 0, keyObject);
    
    TEE_FreeTransientObject(tempObj);
    return result;
}

TEE_Result TA_EXPORT TEE_importRSAKey(uint32_t keyLen, uint32_t keyID, TEE_ObjectHandle* keyObject, uint8_t* mod, uint8_t* pub_exp,
                                        uint8_t* priv_exp, uint8_t* p1, uint8_t* p2, uint8_t* e1, uint8_t* e2, uint8_t* coeff) {
    TEE_Result result;
    TEE_ObjectHandle tempObj;
    TEE_Attribute key_attr[8];
    
    key_attr[0].attributeID = TEE_ATTR_RSA_MODULUS;
    key_attr[0].content.ref.buffer = mod;
    key_attr[0].content.ref.length = keyLen / 8;
    
    key_attr[1].attributeID = TEE_ATTR_RSA_PUBLIC_EXPONENT;
    key_attr[1].content.ref.buffer = pub_exp;
    key_attr[1].content.ref.length = 3;
    
    key_attr[2].attributeID = TEE_ATTR_RSA_PRIVATE_EXPONENT;
    key_attr[2].content.ref.buffer = priv_exp;
    key_attr[2].content.ref.length = keyLen / 8;
    
    key_attr[3].attributeID = TEE_ATTR_RSA_PRIME1;
    key_attr[3].content.ref.buffer = p1;
    key_attr[3].content.ref.length = keyLen / 16;
    
    key_attr[4].attributeID = TEE_ATTR_RSA_PRIME2;
    key_attr[4].content.ref.buffer = p2;
    key_attr[4].content.ref.length = keyLen / 16;
    
    key_attr[5].attributeID = TEE_ATTR_RSA_EXPONENT1;
    key_attr[5].content.ref.buffer = e1;
    key_attr[5].content.ref.length = keyLen / 16;
    
    key_attr[6].attributeID = TEE_ATTR_RSA_EXPONENT2;
    key_attr[6].content.ref.buffer = e2;
    key_attr[6].content.ref.length = keyLen / 16;
    
    key_attr[7].attributeID = TEE_ATTR_RSA_COEFFICIENT;
    key_attr[7].content.ref.buffer = coeff;
    key_attr[7].content.ref.length = keyLen / 16;
    
    result = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR, keyLen, &tempObj);
    result = TEE_PopulateTransientObject(tempObj, key_attr, 8);
    
    uint32_t flags = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META;
    TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, (void*)&keyID, sizeof(uint32_t), flags, tempObj, NULL, 0, keyObject);
    
    TEE_FreeTransientObject(tempObj);
    
    return result;
}



// NOTE: These functions are private (used only in this context)

TEE_Result TA_EXPORT TEE_MAC(TEE_OperationHandle operation, uint8_t* inputBuf, uint32_t inBufLen,
                                uint8_t* outputBuf, uint32_t outBufLen) {
    // No IV
    TEE_MACInit(operation, 0, 0);
    TEE_MACComputeFinal(operation, inputBuf, inBufLen, outputBuf, &outBufLen);
    TEE_FreeOperation(operation);
    return TEE_SUCCESS;
}

TEE_Result TA_EXPORT TEE_SYMMETRIC(TEE_OperationHandle operation, void* inputBuf, uint32_t inBufLen,
                                    void* outputBuf, uint32_t outBufLen) {
    
    uint32_t alg = get_operation_alg(operation);
    
    if (alg == TEE_ALG_AES_CTR) {
        uint8_t IV[256];
        TEE_MemFill(IV, 0, 64);
        TEE_CipherInit(operation, (void*)IV, 256);
    }
    
    else TEE_CipherInit(operation, 0, 0);
    
    TEE_CipherDoFinal(operation, inputBuf, inBufLen, outputBuf, &outBufLen);
    TEE_FreeOperation(operation);
    TEE_MemFill(inputBuf, 0, inBufLen);
    TEE_MemMove(inputBuf, outputBuf, outBufLen);
    return TEE_SUCCESS;
}

TEE_Result TA_EXPORT TEE_ASYMMETRIC(TEE_OperationHandle operation, void* inputBuf, uint32_t inBufLen,
                                    void* outputBuf, int* outBufLen) {
    uint32_t mode = get_operation_mode(operation);
    TEE_Result result;
    
    switch(mode) {
        case(TEE_MODE_ENCRYPT):
            result = TEE_AsymmetricEncrypt(operation, NULL, 0, inputBuf, inBufLen, outputBuf, (uint32_t*)outBufLen);
            break;
        case(TEE_MODE_DECRYPT):
            result = TEE_AsymmetricDecrypt(operation, NULL, 0, inputBuf, inBufLen, outputBuf, (uint32_t*)outBufLen);
            break;
        case(TEE_MODE_SIGN):
            result = TEE_AsymmetricSignDigest(operation, NULL, 0, inputBuf, inBufLen, outputBuf, (uint32_t*)outBufLen);
            break;
        case(TEE_MODE_VERIFY):
            result = TEE_AsymmetricVerifyDigest(operation, NULL, 0, inputBuf, inBufLen, outputBuf, *outBufLen);
            break;
    }
    TEE_FreeOperation(operation);
    
    return result;
}

void TEE_init_operation(TEE_OperationHandle* operation, uint32_t algorithm, uint32_t mode, TEE_ObjectHandle key, uint32_t keyLen) {
    TEE_AllocateOperation(operation, algorithm, mode, keyLen);
    TEE_SetOperationKey(*operation, key);
}

uint32_t get_operation_mode(TEE_OperationHandle operation) {
    TEE_OperationInfo info;
    TEE_GetOperationInfo(operation, &info);
    return info.mode;
}

uint32_t get_operation_alg(TEE_OperationHandle operation) {
    TEE_OperationInfo info;
    TEE_GetOperationInfo(operation, &info);
    return info.algorithm;
}
