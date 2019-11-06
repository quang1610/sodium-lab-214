//
// Created by Nguyễn Đức Quang on 11/5/19.
//
#include "trusted.h"
#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <lzma.h>
#include "utility.h"

/*
 * complete session_message and then encrypted it with Kas and Kbs. Stored encrypted session messages in:
 *  encrypted_session_message_AS
 *  encrypted_session_message_BS
 *
 *  the session_message has format:
 *  |padding|%|principal 1|%|principal2|%|time_stamp|%|KeyAB|
 *
 *  the encrypted_session_message has format:
 *  |encrypted session message||nonce|
 */
void provide_session_key(unsigned char *session_message, unsigned char **encrypted_session_message_AS,
                         unsigned char **encrypted_session_message_BS) {

    unsigned long size_session_message_init = strlen((char*) session_message);
    // create KeyAB & append that to session_message
    unsigned char Kab[crypto_secretbox_KEYBYTES];
    crypto_secretbox_keygen(Kab);
    memcpy(session_message + size_session_message_init, Kab, KEY_SIZE);
    session_message[SESSION_MESSAGE_LEN] = '\0'; // terminate
    // session_message_length = length of the session_message

    // parse principal names from session_message
    unsigned char buffer[SESSION_MESSAGE_LEN];
    memcpy(buffer, session_message, SESSION_MESSAGE_LEN * sizeof(unsigned char));
    // read the padding
    strtok((char *) buffer, SESSION_MESSAGE_DELIMITER);
    // read the name of the principals
    char *principal1 = strtok(NULL, SESSION_MESSAGE_DELIMITER);
    char *principal2 = strtok(NULL, SESSION_MESSAGE_DELIMITER);

    // get Kas and Kbs
    unsigned char *Kas = NULL;
    read_key_from_file(principal1, TRUSTED_THIRD_PARTY, &Kas);
    unsigned char *Kbs = NULL;
    read_key_from_file(principal2, TRUSTED_THIRD_PARTY, &Kbs);

    // encrypted_message into 2 version: one using Kas and one using Kbs
    unsigned char *temp_encrypted_session_message_AS = (unsigned char *)malloc((crypto_secretbox_MACBYTES + SESSION_MESSAGE_LEN + crypto_secretbox_NONCEBYTES) * sizeof(unsigned char));
    unsigned char *temp_encrypted_session_message_BS = (unsigned char *)malloc((crypto_secretbox_MACBYTES + SESSION_MESSAGE_LEN + crypto_secretbox_NONCEBYTES) * sizeof(unsigned char));
    // encrypt session_message with Kas & append the nonce to the end of encrypted message:
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
    crypto_secretbox_easy(temp_encrypted_session_message_AS, session_message, SESSION_MESSAGE_LEN * sizeof(unsigned char), nonce, Kas); // with Kas
    memcpy(temp_encrypted_session_message_AS + SESSION_MESSAGE_LEN + crypto_secretbox_MACBYTES, nonce, crypto_secretbox_NONCEBYTES *
            sizeof(unsigned char));

    // encrypt session_message with Kbs & append the nonce to the end of encrypted message:
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
    crypto_secretbox_easy(temp_encrypted_session_message_BS, session_message, SESSION_MESSAGE_LEN * sizeof(unsigned char), nonce, Kbs); // with Kbs
    memcpy(temp_encrypted_session_message_BS + SESSION_MESSAGE_LEN + crypto_secretbox_MACBYTES, nonce, crypto_secretbox_NONCEBYTES * sizeof(unsigned char));

    // put encrypted messages to appropriate address
    if(*encrypted_session_message_AS != NULL) free(*encrypted_session_message_AS);
    if(*encrypted_session_message_BS != NULL) free(*encrypted_session_message_BS);
    *encrypted_session_message_AS = temp_encrypted_session_message_AS;
    *encrypted_session_message_BS = temp_encrypted_session_message_BS;

    free(Kas);
    free(Kbs);
}

