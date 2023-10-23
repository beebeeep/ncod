#ifndef MISC_H
#define MISC_H

#include <stdio.h>

#define ERROR(...) (fprintf(stderr, __VA_ARGS__))
#define PW_LEN 33

int derive_key(unsigned char *key, unsigned char *nonce, unsigned char *pw_salt, FILE *container, int confirm_pw);

#endif