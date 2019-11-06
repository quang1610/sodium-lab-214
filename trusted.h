//
// Created by Nguyễn Đức Quang on 11/5/19.
//

#ifndef CSC214_TRUSTED_H
#define CSC214_TRUSTED_H

void provide_session_key(unsigned char *session_message, unsigned char **encrypted_message_AS,
                         unsigned char **encrypted_message_BS);
#endif //CSC214_TRUSTED_H
