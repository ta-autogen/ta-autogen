#include "autogen_ca_header.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const TEEC_UUID uuid = ID;

TEEC_Context context;
TEEC_Session session;
TEEC_SharedMemory mem;
TEEC_Operation operation;
TEEC_Result result;


void end_1() {
    exit(result);
}

void end_2() {
	TEEC_ReleaseSharedMemory(&mem);
	TEEC_FinalizeContext(&context);
    end_1();
}

void end_3() {
    TEEC_CloseSession(&session);
    end_2();
}

void InvokeCommand(int command, void* ret) {	
    result = TEEC_InvokeCommand(&session, command, &operation, ret);
    if (result != TEE_SUCCESS) {
        printf("Invoking command %d failed\n", command);
        end_3();
    }
    return;
}

void InitializeSharedMem(int size) {
	operation.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE);
	mem.size = size;
	mem.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	result = TEEC_AllocateSharedMemory(&context, &mem);
	if (result != TEE_SUCCESS) {
		printf("Registering shared memory failed\n");
		end_2();
	}
}

void AllocateMemory(struct marshal_parameters* param_struct, uint8_t* buffer) {
    InitializeSharedMem(SHMEM_MAX_SIZE);
    pack_parameters(param_struct, buffer);
	operation.params[1].memref.parent = &mem;
}

void ReleaseMemory() {
    TEEC_ReleaseSharedMemory(&mem);
}

void InitializeTEEC() {
	memset((void*)&operation, 0, sizeof(operation));
	result = TEEC_InitializeContext(NULL, &context);
	if (result != TEEC_SUCCESS) {
		printf("Initialisation failed: 0x%x\n", result);
		end_1();
	}

	result = TEEC_OpenSession(&context, &session, &uuid, TEEC_LOGIN_PUBLIC, NULL, &operation, NULL);
	if (result != TEEC_SUCCESS) {
		printf("Opening session failed: 0x%x\n", result);
		end_2();
	}
}
