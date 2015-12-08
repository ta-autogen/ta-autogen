struct parameter {
	uint16_t len;
	uint16_t value;
};

struct marshal_parameters {
	uint16_t b_size;
	uint16_t offset;
	uint8_t list_len;
	struct parameter* param_list;
};

#define CMD_create_chunked  1
#define CMD_copy_chunked    2
#define CMD_reset_pointer   3
#define CMD_get_chunked     4
#define CMD_free_chunked    5
#define CMD_AES_ECB_encr    6
#define CMD_AES_ECB_decr    7
#define CMD_AES_CTR_encr    8
#define CMD_AES_CTR_decr    9
#define CMD_HMAC_SHA256     10
#define CMD_HMAC_SHA384     11
#define CMD_HMAC_SHA512     12
#define CMD_RSA_priv_encr   13
#define CMD_RSA_priv_decr   14
#define CMD_RSA_pub_encr    15
#define CMD_RSA_pub_decr    16
#define CMD_import_RSA_key  97
#define CMD_create_RSA_key  98
#define CMD_create_bitkey   99
