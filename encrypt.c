#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

void pad_key(unsigned char* key, size_t len) {
    const size_t key_len = 8;
    const unsigned char pad_char = 0;
    if (len < key_len) {
        memset(key + len, pad_char, key_len - len);
    }
}

int main() {

    // Chiave binaria a 64 bit
        unsigned char binary_key[8] = {
        0b00000000, 0b00000000, 0b00000000, 0b01000000,
        0b00100000, 0b01000000, 0b00110100, 0b00001011
    };



    const char* plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";

    // Inizializzazione DES
    DES_cblock des_key;
    DES_key_schedule key_schedule;
    memcpy(des_key, binary_key, 8);
    DES_set_key(&des_key, &key_schedule);

    // Cifratura
    const size_t plaintext_len = strlen(plaintext);
    unsigned char* ciphertext = (unsigned char*)malloc(plaintext_len + 8);
    size_t ciphertext_len = 0;
    DES_cblock input_block, output_block;
    for (int i = 0; i < plaintext_len; i += 8) {
        memset(input_block, 0, 8);
        memcpy(input_block, plaintext + i, plaintext_len - i < 8 ? plaintext_len - i : 8);
        DES_ecb_encrypt(&input_block, &output_block, &key_schedule, DES_ENCRYPT);
        memcpy(ciphertext + ciphertext_len, output_block, 8);
        ciphertext_len += 8;
    }

    // Stampa testo cifrato
    printf("Testo cifrato: ");
    for (int i = 0; i < ciphertext_len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Liberazione memoria allocata
    free(ciphertext);

    return 0;
}
