#ifndef NCOD_H
#define NCOD_H

#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define STORAGE_LEN 1000
#define STORAGE_BYTES (sizeof(secretRecord) * STORAGE_LEN)
#define CIPHER_BYTES (STORAGE_BYTES + crypto_secretbox_MACBYTES)
#define ID_LEN 32
#define USER_LEN 64
#define SECRET_LEN 512

typedef struct {
    time_t last_updated;
    char id[ID_LEN];
    char user[USER_LEN];
    char secret[SECRET_LEN];
} secretRecord;

int store_secret(char *filename);
int get_secret(char *filename);
int init_storage(char *filename);
void dump(unsigned char *d, size_t l);
void usage();

#endif