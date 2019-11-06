//
// Created by Nguyễn Đức Quang on 11/5/19.
//
#include "principal.h"
#include "trusted.h"
#include "string.h"
#include "stdlib.h"
#include "utility.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#define MESSAGE "Hi, my name is Alice!"
#define ALICE "alice"
#define BOB "bob"
#define TRUSTED "sam"


int main() {
    char * message = MESSAGE;
    char *principal1 = "alice";
    char *principal2 = "bob";
    generated_trusted_key(ALICE, TRUSTED);
    generated_trusted_key(BOB, TRUSTED);

    // session key request
    unsigned char * session_message = NULL;
    session_key_request((unsigned char *)principal1, (unsigned char *)principal2, &session_message);
    // trusted provide encrypted session information:
    unsigned char * encrypted_session_message_AS = NULL;
    unsigned char * encrypted_session_message_BS = NULL;
    provide_session_key(session_message, &encrypted_session_message_AS, &encrypted_session_message_BS);

    // Alice verify encrypted_message_AS and get Kab
    unsigned char * Kab = NULL;
    int result = verify_session_key_message(encrypted_session_message_AS, encrypted_session_message_BS, principal1, principal2, &Kab);

    // Alice use Kab to encrypted her message
    unsigned char * encrypted_message_M = NULL;
    encrypt_and_send_message(Kab, (unsigned char *)MESSAGE, &encrypted_message_M);

    // Bob decrypt the message:
    unsigned char * decrypted_message_M = NULL;
    receive_and_decrypt_message(encrypted_session_message_BS, encrypted_message_M, &decrypted_message_M);

    printf("%s\n", decrypted_message_M);

    free(session_message);
    free(encrypted_session_message_AS);
    free(encrypted_session_message_BS);
    free(Kab);
    free(encrypted_message_M);
    free(decrypted_message_M);
    return SUCCESSFUL;
}
