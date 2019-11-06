//
// Created by Nguyễn Đức Quang on 11/4/19.
//
#include "principal.h"
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <lzma.h>
#include "utility.h"

/*
 * Message's length will be fixed = MESSAGE_LENGTH
 * The format of message will be:
 * |0 padding|%|principal 1|%|principal2|%|time_stamp|%|KeyAb or Kab|
 *
 * Notice that time_stamp has format YYYYMMDDHHMinMinSS
 * 
 * KeyAB hasn't been written down yet in this function
 */
void session_key_request(unsigned char *principal1, unsigned char *principal2, unsigned char ** session_message) {
    char *time_stamp = NULL;
    generate_timestamp(&time_stamp);
    unsigned char * temp_session_message = (unsigned char *) malloc(SESSION_MESSAGE_LEN + 1);
    strcat((char *) temp_session_message, SESSION_MESSAGE_DELIMITER);
    strcat((char *) temp_session_message, (char *) principal1);
    strcat((char *) temp_session_message, SESSION_MESSAGE_DELIMITER);
    strcat((char *) temp_session_message, (char *) principal2);
    strcat((char *) temp_session_message, SESSION_MESSAGE_DELIMITER);
    strcat((char *) temp_session_message, time_stamp);
    strcat((char *) temp_session_message, SESSION_MESSAGE_DELIMITER);

    padding_session_message((char **)&temp_session_message);
    // update session_message
    if(*session_message != NULL) free(*session_message);
    *session_message = temp_session_message;

    // free resource
    free(time_stamp);
}

/*
 * notice the final format of encrypted session message is:
 * |encrypted_session_message||nonce|
 *
 * verify session message by decrypt the message and check it
 */
int verify_session_key_message(unsigned char *encrypted_session_message_AS, unsigned char *encrypted_session_message_BS, char *principal1,
                               char *principal2, unsigned char **Kab) {
    unsigned char nonce_A[crypto_secretbox_NONCEBYTES];
    memcpy(nonce_A, encrypted_session_message_AS + crypto_secretbox_MACBYTES + SESSION_MESSAGE_LEN, crypto_secretbox_NONCEBYTES * sizeof(unsigned char));
    unsigned char nonce_B[crypto_secretbox_NONCEBYTES];
    memcpy(nonce_B, encrypted_session_message_BS + crypto_secretbox_MACBYTES + SESSION_MESSAGE_LEN, crypto_secretbox_NONCEBYTES * sizeof(unsigned char));

    // Get Key Kas, Kbs
    unsigned char *Kas = NULL;
    read_key_from_file(principal1, TRUSTED_THIRD_PARTY, &Kas);
    unsigned char *Kbs = NULL;
    read_key_from_file(principal2, TRUSTED_THIRD_PARTY, &Kbs);

    // check NULL

    // attempt to decrypt:
    unsigned char * decrypted_session_message_AS = (unsigned char *) malloc(
            (SESSION_MESSAGE_LEN + 1) * sizeof(unsigned char));
    unsigned char * decrypted_session_message_BS = (unsigned char *) malloc(
            (SESSION_MESSAGE_LEN + 1) * sizeof(unsigned char));
    // decrypt session message with Kas
    int decrypt_result_AS = crypto_secretbox_open_easy(decrypted_session_message_AS, encrypted_session_message_AS,
                                                       (crypto_secretbox_MACBYTES + SESSION_MESSAGE_LEN) * sizeof(unsigned char), nonce_A, Kas);
    decrypted_session_message_AS[SESSION_MESSAGE_LEN] = '\0'; // terminate the message

    // decrypt session message with Kbs
    int decrypt_result_BS = crypto_secretbox_open_easy(decrypted_session_message_BS, encrypted_session_message_BS,
                                                       (crypto_secretbox_MACBYTES + SESSION_MESSAGE_LEN) * sizeof(unsigned char), nonce_B, Kbs);
    decrypted_session_message_BS[SESSION_MESSAGE_LEN] = '\0'; // terminate the message
    if (decrypt_result_AS != 0 || decrypt_result_BS != 0 ||
        strcmp((char *)decrypted_session_message_AS, (char *) decrypted_session_message_BS) != 0) {
        exit(FAIL_DECRYPT);
    }

    // recover information in decrypted_message_BS
    verify_decrypted_session_message((char *) decrypted_session_message_AS, principal1, principal2, Kab);
    verify_decrypted_session_message((char *) decrypted_session_message_BS, principal1, principal2, Kab);

    free(decrypted_session_message_AS);
    free(decrypted_session_message_BS);

    return SUCCESSFUL;
}

/*
 * encrypted message has format:
 *
 * |nonce||8 bytes to store the length of the message||encrypted message|
 *
 */
void encrypt_and_send_message(unsigned char *Kab, unsigned char *message, unsigned char **encrypted_message) {
    unsigned long message_length = strlen((char *) message);
    // prepare the pointer for the encrypted message
    if(*encrypted_message != NULL) free(*encrypted_message);
    *encrypted_message = (unsigned char *)malloc((crypto_secretbox_NONCEBYTES + MESSAGE_BYTES + crypto_secretbox_MACBYTES + message_length) * sizeof(unsigned char));

    // create the nonce and put the nonce at the beginning of the encrypted_message without encrypt it.
    // notice that for session_message (aka key_request_message) we put nonce at the end.
    // Here, since the length of message is arbitrary, we put the nonce at the beginning of encrypted message.
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
    memcpy(*encrypted_message, nonce, crypto_secretbox_NONCEBYTES * sizeof(unsigned char));

    // write the length of the message encrypted message
    memcpy((*encrypted_message) + crypto_secretbox_NONCEBYTES, &message_length, MESSAGE_BYTES * sizeof(unsigned char));

    // encrypt the message and store it to encrypted_message
    crypto_secretbox_easy((*encrypted_message) + crypto_secretbox_NONCEBYTES + MESSAGE_BYTES, message, strlen((char*) message) * sizeof(unsigned char), nonce, Kab);
}

/*
 * notice that the encrypted message has format:
 * |nonce||8 bytes to store the length of the message||encrypted message|
 *
 * encrypted_session_message_BS has format:
 * |encrypted session message||nonce|
 *
 * decrypted_session_message_BS has form:
 * |padding|%|principal1|%|principal2|%|time_stamp|%|KeyAB|
 */
int receive_and_decrypt_message(unsigned char *encrypted_session_message_BS, unsigned char *encrypt_message,
                                unsigned char **decrypted_message) {
    // decrypted cipher_text and verify and obtain Kab
    // get Kbs
    unsigned char *Kbs = NULL;
    read_key_from_file(RECEIVER, TRUSTED_THIRD_PARTY, &Kbs);

    // decrypt encrypted_session_message_BS
    // get the nonce
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    memcpy(nonce, encrypted_session_message_BS + crypto_secretbox_MACBYTES + SESSION_MESSAGE_LEN, crypto_secretbox_NONCEBYTES * sizeof(unsigned char));
    // decrypt the session message
    unsigned char *decrypted_session_message_BS = (unsigned char *)malloc(
            (SESSION_MESSAGE_LEN + 1) * sizeof(unsigned char));
    int decrypt_result_BS = crypto_secretbox_open_easy(decrypted_session_message_BS, encrypted_session_message_BS,
            (SESSION_MESSAGE_LEN + crypto_secretbox_MACBYTES) * sizeof(unsigned char), nonce, Kbs);
    decrypted_session_message_BS[SESSION_MESSAGE_LEN] = '\0';

    // verify decrypted cipher text BS & obtain Kab
    if (decrypt_result_BS != 0) {
        exit(FAIL_DECRYPT);
    }

    // get rid of padding && read principals' names
    char buffer[SESSION_MESSAGE_LEN + 1];
    memcpy(buffer, (char *) decrypted_session_message_BS, SESSION_MESSAGE_LEN);
    char * token = strtok(buffer, SESSION_MESSAGE_DELIMITER);
    // read principals' names
    char *principal1 = strtok(NULL, SESSION_MESSAGE_DELIMITER);
    char *principal2 = strtok(NULL, SESSION_MESSAGE_DELIMITER);

    // verify decrypted session_message and obtain Kab
    unsigned char * Kab = NULL;
    verify_decrypted_session_message((char *) decrypted_session_message_BS, principal1, principal2, &Kab);

    // Attempt to decrypt M using Kab:
    // get the nonce
    memcpy(nonce, encrypt_message, crypto_secretbox_NONCEBYTES * sizeof(unsigned char));
    // get the message length
    long int * mess_length = malloc(MESSAGE_BYTES * sizeof(unsigned char));
    memcpy(mess_length, encrypt_message + crypto_secretbox_NONCEBYTES, MESSAGE_BYTES * sizeof(unsigned char));

    // prepare to copy decrypted message to *decrypted_message
    if (*decrypted_message != NULL) free(*decrypted_message);
    *decrypted_message = (unsigned char *)malloc(((*mess_length) + 1) * sizeof(unsigned char));

    // decrypt
    int decrypted_result_M = crypto_secretbox_open_easy(*decrypted_message, encrypt_message + crypto_secretbox_NONCEBYTES + MESSAGE_BYTES,
            (crypto_secretbox_MACBYTES + (*mess_length)) * sizeof(unsigned char), nonce, Kab);
    if(*decrypted_message == NULL || decrypted_result_M != 0) {
        printf("%d\n", decrypted_result_M);
        exit(FAIL_DECRYPT);
    }


    // free resource
    free(Kbs);
    free(Kab);
    free(decrypted_session_message_BS);
    free(mess_length);
    return 0;
}