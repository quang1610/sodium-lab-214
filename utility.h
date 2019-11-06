//
// Created by Nguyễn Đức Quang on 11/5/19.
//

#ifndef CSC214_UTILITY_H
#define CSC214_UTILITY_H

#define SUCCESSFUL 0
#define SIZE_TIME_STAMP 14
#define NUM_DIGIT_OF_TIME 50
#define SESSION_MESSAGE_DELIMITER "%"
#define TRUSTED_THIRD_PARTY "sam"
#define RECEIVER "bob"
#define NULL_ENCRYPT_MESSAGE_ERROR 2
#define FAIL_DECRYPT 3
#define FAIL_RECOVER_MESSAGE_COMPONENT 4
#define MISMATCH_NAME 5
#define TIME_STAMP_INVALID 6
#define ONE_DAY 00000001000000
#define KEY_SIZE crypto_secretbox_KEYBYTES * sizeof(unsigned char)
#define SESSION_MESSAGE_LEN 500 // without null terminate
#define MESSAGE_BYTES 8

// Support method
/*
 * generated_name_key_file creates the key file's name based on input name.
 * for example input "sam" will return string "sam.key"
 */
//**********************************************************************************************************************
// HELPER FUNCTIONS
void generate_path(char *person1, char *person2, char ** path);
void generate_timestamp(char ** time_stamp);
void read_key_from_file(char *person1, char *person2, unsigned char ** key); // read key store in file ./person1/person2.key
long int convert_string_to_int(char *str);
int verify_decrypted_message(char *decrypted_message, char *principal1, char *principal2, unsigned char ** Kab);
void generated_trusted_key(char * principal, char * trusted_third_party);
void padding_message(char ** message);
#endif //CSC214_UTILITY_H
