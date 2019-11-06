//
// Created by Nguyễn Đức Quang on 11/4/19.
//

#ifndef CSC214_PRINCIPAL_H
#define CSC214_PRINCIPAL_H

void session_key_request(unsigned char *principal1, unsigned char *principal2, unsigned char ** session_message);
int verify_session_key_message(unsigned char * encrypted_message_AS, unsigned char *encrypted_message_BS, char *principal1, char *principal2, unsigned char **Kab);
void encrypt_and_send_message(unsigned char *Kab, unsigned char *message, unsigned char **encrypted_message);
int receive_and_decrypt_message(unsigned char *cipher_text_BS, unsigned char *encrypted_message,
                                unsigned char **decrypted_message);
#endif //CSC214_PRINCIPAL_H
