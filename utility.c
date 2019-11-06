//
// Created by Nguyễn Đức Quang on 11/5/19.
//
#include <sodium.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <lzma.h>
#include "utility.h"

/*
 * This function take name of person1 and person2 and out put a path in format:
 * "./<person1>/<person2>.key"
 */
void generate_path(char *person1, char *person2, char ** path) {
    char *buffer = (char *) malloc(sizeof(unsigned char) * (strlen(person1) + strlen(person2) + strlen(".//.key") + 2));
    strcat(buffer, "./");
    strcat(buffer, person1);
    strcat(buffer, "/");
    strcat(buffer, person2);
    strcat(buffer, ".key");

    // update path pointer
    if(*path != NULL) free(*path);
    *path = buffer;
}

/*
 * cite: https://www.tutorialspoint.com/c_standard_library/c_function_strftime.htm
 *
 * create a string temp_time_stamp in format : YYYYMMDDHHMinMinSS.
 * the set *time_stamp = temp_time_stamp
 */
void generate_timestamp(char ** time_stamp) {
    // init char *
    time_t current_time = time(NULL);

    // SIZE & allocation
    char * temp_time_stamp = (char *) malloc(sizeof(char) * (SIZE_TIME_STAMP + 1));

    // write the readable time stamp in to temp_time_stamp
    // This function read current time, write it into time_stamp using readable
    // format of the timestamp is "YYYYMMDDHHMinMinSS"
    // for example we have "19991016063025" = "Oct/16/1999 06:30:25"
    strftime(temp_time_stamp, SIZE_TIME_STAMP, "%Y%m%d%H%M%S", localtime(&current_time));
    temp_time_stamp[SIZE_TIME_STAMP] = '\0'; // terminate string

    // update time_stamp pointer
    if(*time_stamp != NULL) free(*time_stamp);
    *time_stamp = temp_time_stamp;
}

/*
 * function read the key in path ./<person1>/<person2>.key then write the result to *key
 */
void read_key_from_file(char *person1, char *person2, unsigned char ** key) {
    FILE *file;
    unsigned char * temp_key = malloc(KEY_SIZE);
    // generate file path, store in path
    char * path = NULL;
    generate_path(person1, person2, &path);

    // read key to temp_key
    file = fopen(path, "rb");
    if(file == NULL) printf("%s\n", path);
    fread(temp_key, KEY_SIZE, 1, file);
    // free resource
    fclose(file);
    free(path);
    // update key
    if(*key != NULL) free(*key);
    *key = temp_key;
}

/*
 * this function convert string str to long tin
 */
long int convert_string_to_int(char *str) {
    return strtol(str, NULL, 10);
}

/*
 *  this function take a decrypted message, name of 2 principals and pointer to key AB Kab.
 *  it will validate the decrypted message by gradually parsing different elements of the message including:
 *      - principal1's name, principal2's name, time_stamp (readable time stamp and number of time), Key ab
 *      - it will store Key ab into Kab
 *  if nothing is wrong, the function will return 0.
 */
int verify_decrypted_message(char *decrypted_message, char *principal1, char *principal2, unsigned char ** Kab) {
    // check if decrypted_message is NULL
    if (decrypted_message == NULL) {
        exit(FAIL_DECRYPT);
    }

    // recover information in decrypted_message
    unsigned char buffer[SESSION_MESSAGE_LEN + 1];
    memcpy(buffer, decrypted_message, (SESSION_MESSAGE_LEN + 1) * sizeof(unsigned char));
    buffer[SESSION_MESSAGE_LEN] ='\0';

    // parse the padding
    char *token = strtok((char *)buffer, SESSION_MESSAGE_DELIMITER);
    // parse name of principal 1 & validate
    token = strtok(NULL, SESSION_MESSAGE_DELIMITER);
    if (token == NULL) {
        exit(FAIL_RECOVER_MESSAGE_COMPONENT);
    }
    if (strcmp(token, principal1) != 0) {
        exit(MISMATCH_NAME);
    }

    // parse name of principal 2 & validate
    token = strtok(NULL, SESSION_MESSAGE_DELIMITER);
    if (token == NULL) {
        exit(FAIL_RECOVER_MESSAGE_COMPONENT);
    }
    if (strcmp(token, principal2) != 0) {
        exit(MISMATCH_NAME);
    }

    // parse time_stamp
    token = strtok(NULL, SESSION_MESSAGE_DELIMITER); // token = time_stamp
    if(strlen(token) == 0) {
        exit(TIME_STAMP_INVALID);
    }
    // validate time_stamp
    unsigned long request_time = (unsigned long) convert_string_to_int(token);
    // generate current_time_stamp
    char * current_time_stamp = NULL;
    generate_timestamp(&current_time_stamp);
    unsigned long current_time = (unsigned long) convert_string_to_int(current_time_stamp);

    if (current_time < request_time || (current_time - request_time) >= ONE_DAY) {
        exit(TIME_STAMP_INVALID);
    }
    // read KeyAB by reading the last 32 bytes of decrypted message.
    if(*Kab != NULL) free(*Kab);
    *Kab = malloc(KEY_SIZE);
    memcpy(*Kab, buffer + (SESSION_MESSAGE_LEN - KEY_SIZE), KEY_SIZE);

    // return 0 if nothing is wrong
    return  SUCCESSFUL;
}

void generated_trusted_key(char * principal, char * trusted_third_party) {
    unsigned char key[crypto_secretbox_KEYBYTES];
    crypto_secretbox_keygen(key);

    FILE * principal_file;
    FILE * trusted_file;

    char * principal_key_path = NULL;
    generate_path(trusted_third_party, principal, &principal_key_path);
    char * trusted_key_path = NULL;
    generate_path(principal, trusted_third_party, &trusted_key_path);

    principal_file = fopen(principal_key_path, "wb");
    fwrite(key, KEY_SIZE, 1, principal_file);
    trusted_file = fopen(trusted_key_path, "wb");
    fwrite(key, KEY_SIZE, 1, trusted_file);

    fclose(principal_file);
    fclose(trusted_file);
    free(principal_key_path);
    free(trusted_key_path);
}

void padding_message(char ** message) {
    unsigned long mess_length = strlen(*message);
    assert(mess_length < SESSION_MESSAGE_LEN);

    int padding_length = SESSION_MESSAGE_LEN - mess_length - KEY_SIZE;
    char * padded_message = (char *) malloc(SESSION_MESSAGE_LEN + 1);
    memset(padded_message, '0', padding_length * sizeof(unsigned char));
    memcpy(padded_message + padding_length, *message, mess_length * sizeof(unsigned char));
    padded_message[padding_length + mess_length] = '\0'; // null terminate current message.

    if (*message != NULL) free(*message);
    *message = padded_message;
}