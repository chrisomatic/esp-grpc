#pragma once

#define TESTPB_PATH "/TestService"

#define TESTPB_CREATE "Create"
#define TESTPB_GET "Get"

typedef struct
{
    char id[64];
    int32_t x;
    int32_t y;
} Message;

int testpb_message_create(Message* cbs, uint8_t* buf, int buf_len);
int testpb_message_get(char* id, uint8_t* buf, int buf_len);
