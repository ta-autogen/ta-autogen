#include "autogen_ta_header.h"

extern uint32_t chunk_buff_size;
extern void* chunked_buffer;
extern uint32_t ptr;
            
void TEE_get_chunked(uint8_t* buffer) {
    int buffsize;
    if ((ptr+SHMEM_MAX_SIZE) > chunk_buff_size) buffsize = chunk_buff_size - ptr;
    else buffsize = SHMEM_MAX_SIZE;
    TEE_MemMove(buffer, chunked_buffer+ptr, SHMEM_MAX_SIZE);
}

void TEE_reset_pointer() {
    ptr = 0;
}

void TEE_copy_chunked(uint8_t* buffer) {
    int buffsize;
    if ((ptr+SHMEM_MAX_SIZE) > chunk_buff_size) buffsize = chunk_buff_size - ptr;
    else buffsize = SHMEM_MAX_SIZE;
    TEE_MemMove(chunked_buffer+ptr, buffer, buffsize);
}

void TEE_create_chunked(uint8_t* buffer) {
    if (chunk_buff_size < TAMEM_MAX_SIZE) {
        TEE_MemMove(&chunk_buff_size, buffer, sizeof(int));
        chunked_buffer = TEE_Malloc(chunk_buff_size, 0);
    }
}

void TEE_free_chunked() {
    TEE_Free(chunked_buffer);
    ptr = 0;
    chunk_buff_size = 0;
}

void TEE_write_parameter(uint8_t* dest, uint8_t* src, size_t num) {
    TEE_MemMove(dest, src, num);
}

void TEE_pack_parameters(struct marshal_parameters* param_struct, void* shmem, uint8_t* buffer) {
    TEE_MemFill(shmem, 0, SHMEM_MAX_SIZE);
    
    int marshalsize = sizeof(struct marshal_parameters);
    int paramdef = (param_struct->list_len)*sizeof(struct parameter);
    
    TEE_MemMove(shmem, param_struct, marshalsize);
    TEE_MemMove(shmem+marshalsize, param_struct->param_list, paramdef);
    TEE_MemMove(shmem+marshalsize+paramdef, buffer, BUF_MAX_SIZE);
    
    TEE_MemFill(buffer, 0, BUF_MAX_SIZE);
    free(param_struct->param_list);
    param_struct->offset = 0;
    param_struct->list_len = 0;
}

void TEE_unpack_parameters(struct marshal_parameters* param_struct, void* input, uint8_t* buffer) {
    int marshal_size = sizeof(struct marshal_parameters);
    TEE_MemMove(param_struct, input, marshal_size);
    param_struct->offset = marshal_size;
    
    int i=0;
    int size = sizeof(struct parameter);
    int len = param_struct->list_len;
        
    struct parameter* param = (struct parameter*) TEE_Malloc(len*size, 0);
    param_struct->param_list = param;
    while (i<len) {
        TEE_MemMove(param+i, input+(param_struct->offset), size);
        i++;
        param_struct->offset += size;
    }
    TEE_MemMove(buffer, input+(param_struct->offset), BUF_MAX_SIZE);
}
