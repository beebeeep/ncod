#include <stdio.h>
#include <sodium.h>

int main(int argc, char *argv[]) {
    if (sodium_init() < 0) {
        fprintf(stderr, "failed to initialize libsodium\n");
        return -1;
    }

    printf("ncod\n");
}
