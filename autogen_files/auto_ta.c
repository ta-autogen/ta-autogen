

SET_TA_PROPERTIES(ID, 512, 255, 1, 1, 1)

uint32_t chunk_buff_size;
void* chunked_buffer;
uint32_t ptr=0;

TEE_Result TA_EXPORT TA_CreateEntryPoint(void) {
	OT_LOG(LOG_INFO, "Entry point created");
	return TEE_SUCCESS;
}

void TA_EXPORT TA_DestroyEntryPoint(void) {
	OT_LOG(LOG_INFO, "Entry point destroyed");
}

TEE_Result TA_EXPORT TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[4], void **sessionContext) {
	paramTypes = paramTypes;
	sessionContext = sessionContext;
	params[4] = params[4];

	return TEE_SUCCESS;
}

void TA_EXPORT TA_CloseSessionEntryPoint(void *sessionContext) {
	OT_LOG(LOG_INFO, "Session entry point closed");
	sessionContext = sessionContext;
}

TEE_Result TA_EXPORT TA_InvokeCommandEntryPoint(void *sessionContext, uint32_t commandID, uint32_t paramTypes, TEE_Param params[4]) {
	sessionContext = sessionContext;
	TEE_Result res = TEE_SUCCESS;
    uint32_t keyID;


	switch (commandID) {
        struct marshal_parameters marshal = {.offset = 0, .b_size = BUF_MAX_SIZE, .list_len = 0};
        uint8_t shared_buffer[BUF_MAX_SIZE];
        TEE_MemFill(shared_buffer, 0, BUF_MAX_SIZE);
        
		case CMD_create_chunked:
            TEE_create_chunked(params[1].memref.buffer);
            break;
        
        case CMD_copy_chunked:
            TEE_copy_chunked(params[1].memref.buffer);
            break;
        
        case CMD_reset_pointer:
            TEE_reset_pointer();
            break;
        
        case CMD_get_chunked:
            TEE_get_chunked(params[1].memref.buffer);
            break;
        
        case CMD_free_chunked:
            TEE_free_chunked();
            break;
        
        case CMD_AES_ECB_encr: {
            uint8_t databuf[128];
            TEE_MemMove(databuf, params[1].memref.buffer, 128);
            TEE_MemMove(&keyID, params[1].memref.buffer+128, 4);
            res = TEE_AES_ECB(TEE_MODE_ENCRYPT, keyID, databuf);
            TEE_MemMove(params[1].memref.buffer, databuf, 128);
            break;
        }
        
        case CMD_AES_ECB_decr: {
            uint8_t databuf[128];
            TEE_MemMove(databuf, params[1].memref.buffer, 128);
            TEE_MemMove(&keyID, params[1].memref.buffer+128, 4);
            res = TEE_AES_ECB(TEE_MODE_DECRYPT, keyID, databuf);
            TEE_MemMove(params[1].memref.buffer, databuf, 128);
            break;
        }
        
        case CMD_AES_CTR_encr: {
            TEE_MemMove(&keyID, params[1].memref.buffer+16, 4);
            res = TEE_AES_CTR(TEE_MODE_ENCRYPT, keyID, chunked_buffer, chunk_buff_size);
            break;
        }
        
        case CMD_AES_CTR_decr: {
            TEE_MemMove(&keyID, params[1].memref.buffer+16, 4);
            res = TEE_AES_CTR(TEE_MODE_DECRYPT, keyID, chunked_buffer, chunk_buff_size);
            break;
        }
        
        case CMD_HMAC_SHA256: {
            TEE_MemMove(&keyID, params[1].memref.buffer+32, 4);
            uint8_t hash[32];
            res = TEE_HMAC_SHA256(keyID, chunked_buffer, chunk_buff_size, hash);
            TEE_MemMove(params[1].memref.buffer, hash, 32);
            break;
        }
        
        case CMD_HMAC_SHA384: {
            TEE_MemMove(&keyID, params[1].memref.buffer+48, 4);
            uint8_t hash[48];
            res = TEE_HMAC_SHA384(keyID, chunked_buffer, chunk_buff_size, hash);
            TEE_MemMove(params[1].memref.buffer, hash, 48);
            break;
        }
        
        case CMD_HMAC_SHA512: {
            TEE_MemMove(&keyID, params[1].memref.buffer+64, 4);
            uint8_t hash[64];
            res = TEE_HMAC_SHA512(keyID, chunked_buffer, chunk_buff_size, hash);
            TEE_MemMove(params[1].memref.buffer, hash, 64);
            break;
        }
        
        case CMD_RSA_priv_encr: {
            uint8_t hash[32], signature[256];
            int outsize;
            TEE_MemMove(hash, params[1].memref.buffer, 32);
            TEE_MemMove(&keyID, params[1].memref.buffer+256, 4);
            res = TEE_RSA_PSS(TEE_MODE_SIGN, keyID, hash, 32, signature, &outsize);
            TEE_MemMove(params[1].memref.buffer, signature, 256);
            TEE_MemMove(params[1].memref.buffer+256, &outsize, sizeof(int));
            break;
        }
        
        case CMD_RSA_priv_decr: {
            uint8_t cipher[256], secret[256];
            int outsize;
            TEE_MemMove(cipher, params[1].memref.buffer, 256);
            TEE_MemMove(&keyID, params[1].memref.buffer+256, 4);
            res = TEE_RSA_OAEP(TEE_MODE_DECRYPT, keyID, cipher, 256, secret, &outsize);
            TEE_MemMove(params[1].memref.buffer, secret, 256);
            TEE_MemMove(params[1].memref.buffer+256, &outsize, sizeof(int));
            break;
        }
        
        case CMD_RSA_pub_encr: {
            int secret_size, outsize;
            TEE_MemMove(&secret_size, params[1].memref.buffer+260, sizeof(int));
            uint8_t secret[secret_size], cipher[256];
            TEE_MemMove(secret, params[1].memref.buffer, secret_size);
            TEE_MemMove(&keyID, params[1].memref.buffer+256, 4);
            res = TEE_RSA_OAEP(TEE_MODE_ENCRYPT, keyID, secret, secret_size, cipher, &outsize);
            TEE_MemMove(params[1].memref.buffer, cipher, 256);
            TEE_MemMove(params[1].memref.buffer+256, &outsize, sizeof(int));
            break;
        }
        
        case CMD_RSA_pub_decr: {
            uint8_t hash[32], signature[256];
            int outsize;
            TEE_MemMove(hash, params[1].memref.buffer, 32);
            TEE_MemMove(signature, params[1].memref.buffer+32, 256);
            TEE_MemMove(&keyID, params[1].memref.buffer+32+256, 4);
            res = TEE_RSA_PSS(TEE_MODE_VERIFY, keyID, hash, 32, signature, &outsize);
            TEE_MemMove(params[1].memref.buffer, &outsize, sizeof(int));
            break;
        }
        
        case CMD_create_bitkey: {
            uint32_t keyType, keyLen;
            int new;
            TEE_MemMove(&keyType, params[1].memref.buffer+4, 4);
            TEE_MemMove(&keyLen, params[1].memref.buffer+8, 4);
            TEE_MemMove(&new, params[1].memref.buffer+12, sizeof(int));
            
            uint8_t key[keyLen];
            TEE_GenerateRandom(&keyID, 4);
            TEE_ObjectHandle keyObject;
            
            if (new == 0) {
                TEE_MemMove(key, params[1].memref.buffer+12+sizeof(int), (keyLen/8));
                TEE_importBitkey(keyType, keyLen, keyID, key, &keyObject);
            }
            
            else {
                TEE_genKey(keyType, keyLen, &keyObject, keyID, sizeof(uint32_t), 0);
            }
            
            TEE_CloseObject(keyObject);
            TEE_MemMove(params[1].memref.buffer, &keyID, 4);
            break;
        }
        
        case CMD_create_RSA_key: {
            uint32_t keyLen, pubexp;
            TEE_ObjectHandle keyObject;
            TEE_MemMove(&keyLen, params[1].memref.buffer, 4);
            TEE_MemMove(&pubexp, params[1].memref.buffer+4, 4);
            TEE_GenerateRandom(&keyID, 4);
            TEE_genKey(TEE_TYPE_RSA_KEYPAIR, keyLen, &keyObject, keyID, 4, pubexp);
            TEE_CloseObject(keyObject);
            TEE_MemMove(params[1].memref.buffer, &keyID, 4);
            break;
        }
        
        case CMD_import_RSA_key: {
            uint32_t keyLen;
            TEE_MemMove(&keyLen, params[1].memref.buffer, 4);
            int h = keyLen/16;
            uint8_t mod[h*2], pub_exp[3], priv_exp[h*2], p1[h], p2[h], e1[h], e2[h], coeff[h];
            TEE_ObjectHandle keyObject;
            
            TEE_MemMove(mod, params[1].memref.buffer+4, h*2);
            TEE_MemMove(pub_exp, params[1].memref.buffer+4+h*2, 3);
            TEE_MemMove(priv_exp, params[1].memref.buffer+7+h*2, h*2);
            TEE_MemMove(p1, params[1].memref.buffer+7+h*4, h);
            TEE_MemMove(p2, params[1].memref.buffer+7+h*5, h);
            TEE_MemMove(e1, params[1].memref.buffer+7+h*6, h);
            TEE_MemMove(e2, params[1].memref.buffer+7+h*7, h);
            TEE_MemMove(coeff, params[1].memref.buffer+7+h*8, h);
            
            TEE_GenerateRandom(&keyID, 4);
            
            res = TEE_importRSAKey(keyLen, keyID, &keyObject, mod, pub_exp, priv_exp, p1, p2, e1, e2, coeff);
            
            TEE_CloseObject(keyObject);
            TEE_MemMove(params[1].memref.buffer, &keyID, 4);
            
            break;
        }
        
        default:
			OT_LOG(LOG_ERR, "Unknow command");
			TEE_Free(&sessionContext);
			break;
	}
	return res;
}
