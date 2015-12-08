#include "autogen_ca_header.h"

void add_parameter(struct marshal_parameters* param_struct, uint8_t* param_data, uint16_t data_len, uint8_t* buffer) {
    int index = param_struct->list_len;
    struct parameter* ptr = realloc(param_struct->param_list, sizeof(struct parameter)*(index+1));
    memset(ptr+index, 0, sizeof(struct parameter));
    
    ptr[index] = (struct parameter){.len=data_len, .value=param_struct->offset};
    memmove(buffer+ptr[index].value, param_data, data_len);
    
    param_struct->offset += data_len;
    param_struct->param_list = ptr;
    (param_struct->list_len)++;
    
}

void pack_parameters(struct marshal_parameters* param_struct, uint8_t* buffer) {
    memset(mem.buffer, 0, SHMEM_MAX_SIZE);
    
    int marshalsize = sizeof(struct marshal_parameters);
    int paramdef = (param_struct->list_len)*sizeof(struct parameter);
    
    memmove(mem.buffer, param_struct, marshalsize);
    memmove(mem.buffer+marshalsize, param_struct->param_list, paramdef);
    memmove(mem.buffer+marshalsize+paramdef, buffer, BUF_MAX_SIZE);
    
    memset(buffer, 0, BUF_MAX_SIZE);
    free(param_struct->param_list);
    param_struct->offset = 0;
    param_struct->list_len = 0;
}

void write_parameter(uint8_t* dest, uint8_t* src, size_t num) {
    memmove(dest, src, num);
}

void unpack_parameters(struct marshal_parameters* param_struct, uint8_t* buffer) {
    int marshal_size = sizeof(struct marshal_parameters);
    memmove(param_struct, mem.buffer, marshal_size);
    param_struct->offset = marshal_size;
    
    int i=0;
    int size = sizeof(struct parameter);
    int len = param_struct->list_len;
        
    struct parameter* param = (struct parameter*) calloc(len, size);
    param_struct->param_list = param;
    while (i<len) {
        memmove(param+i, mem.buffer+(param_struct->offset), size);
        i++;
        param_struct->offset += size;
    }
    memmove(buffer, mem.buffer+(param_struct->offset), BUF_MAX_SIZE);
}


void chunk_parameter(uint8_t* param, int size) {
    // 1. Pass size of the parameter to TA
	InitializeSharedMem(sizeof(int));
    memmove(mem.buffer, &size, sizeof(int));
	operation.params[1].memref.parent = &mem;
    InvokeCommand(CMD_create_chunked, NULL);
    ReleaseMemory();
    
    int ptr = 0;
    int chunksize;
    // 2. Pass the parameter as chunks
    while (ptr < size) {
        if ((ptr+SHMEM_MAX_SIZE) > size) {
            chunksize = size - ptr;
        }
        else {
            chunksize = SHMEM_MAX_SIZE;
        }
        InitializeSharedMem(chunksize);
        memmove(mem.buffer, param+ptr, chunksize);
        operation.params[1].memref.parent = &mem;
        InvokeCommand(CMD_copy_chunked, NULL);
        ptr += chunksize;
        ReleaseMemory();
    }
}

void get_chunked_parameter(void* param_buf, int size) {
    
    int ptr = 0;
    int chunksize;
    
    InitializeSharedMem(1);
    InvokeCommand(CMD_reset_pointer, NULL);
    ReleaseMemory();
    
    while (ptr < size) {
        if ((ptr+SHMEM_MAX_SIZE) > size) {
            chunksize = size - ptr;
        }
        else {
            chunksize = SHMEM_MAX_SIZE;
        }
        InitializeSharedMem(chunksize);
        operation.params[1].memref.parent = &mem;
        InvokeCommand(CMD_get_chunked, NULL);
        memmove(param_buf+ptr, mem.buffer, chunksize);
        ptr += chunksize;
        ReleaseMemory();
    }
    
    InitializeSharedMem(1);
    InvokeCommand(CMD_free_chunked, NULL);
    ReleaseMemory();
}
