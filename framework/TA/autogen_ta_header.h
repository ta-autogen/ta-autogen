#include "tee_internal_api.h"
#include "tee_ta_properties.h"
#include "tee_logging.h"
#include "autogen_shared_header.h"

extern uint32_t size;
extern void* chunked_buffer;
extern uint32_t ptr;

void TEE_write_parameter(uint8_t* dest, uint8_t* src, size_t num);
void TEE_pack_parameters(struct marshal_parameters* param_struct, void* shmem, uint8_t* buffer);
void TEE_unpack_parameters(struct marshal_parameters* param_struct, void* input, uint8_t* buffer);
void TEE_create_chunked(uint8_t* buffer);
void TEE_copy_chunked(uint8_t* buffer);
void TEE_reset_pointer();
void TEE_get_chunked(uint8_t* buffer);
void TEE_free_chunked();

TEE_Result TA_EXPORT TEE_HMAC_SHA256(uint32_t keyID, uint8_t* inputBuf, uint32_t inBufLen, uint8_t* outputBuf);
TEE_Result TA_EXPORT TEE_HMAC_SHA384(uint32_t keyID, uint8_t* inputBuf, uint32_t inBufLen, uint8_t* outputBuf);
TEE_Result TA_EXPORT TEE_HMAC_SHA512(uint32_t keyID, uint8_t* inputBuf, uint32_t inBufLen, uint8_t* outputBuf);
TEE_Result TA_EXPORT TEE_AES_CTR(uint32_t mode, uint32_t keyID, uint8_t* inputBuf, uint32_t inBufLen);
TEE_Result TA_EXPORT TEE_AES_ECB(uint32_t mode, uint32_t keyID, uint8_t* inputBuf);
TEE_Result TA_EXPORT TEE_RSA_PSS(uint32_t mode, uint32_t keyID, uint8_t* inputBuf, uint32_t inBufLen,
                                uint8_t* outputBuf, int* outlen);
TEE_Result TA_EXPORT TEE_RSA_OAEP(uint32_t mode, uint32_t keyID, uint8_t* inputBuf, uint32_t inBufLen,
                                uint8_t* outputBuf, int* outlen);

void TEE_genKey(uint32_t keyType, uint32_t keyLen, TEE_ObjectHandle* keyObject,
                uint32_t objectID, uint32_t objectIDlen, uint32_t pubexp);
TEE_Result TA_EXPORT TEE_importRSAKey(uint32_t keyLen, uint32_t keyID, TEE_ObjectHandle* keyObject, uint8_t* mod, uint8_t* pub_exp,
						uint8_t* priv_exp, uint8_t* p1, uint8_t* p2, uint8_t* e1, uint8_t* e2, uint8_t* coeff);
TEE_Result TA_EXPORT TEE_importBitkey(uint32_t keyType, uint32_t keyLen, uint32_t keyID, uint8_t* key, TEE_ObjectHandle* keyObject);
