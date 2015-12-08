#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#pragma secure global secret
static long secret = 13;

#pragma secure function tc_process_string
int tc_process_string(long buffer_size, char* buffer) {
    #pragma shared var buffer
     int i, ret;

     for(i = 0; i < buffer_size; i++) {
         char c = buffer[i];
         if(c >= 'a' && c <= 'm') c += secret;
         else if(c >= 'A' && c <= 'M') c += secret;
         else if(c >= 'n' && c <= 'z') c -= secret;
         else if(c >= 'N' && c <= 'Z') c -= secret;
         buffer[i] = c;
     }
     
     ret = 0;
     return ret;
}

int main() {
    long s = 12;
    char buffer[12] = "testing....\0";
    char res[12] = "grfgvat....\0";
    tc_process_string(s, buffer);
    assert(memcmp(buffer, res, 12)==0);
    printf("ROT13 calculation succeeded\n");
    return 0;
}
