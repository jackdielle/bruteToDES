#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

int main() {

    // Chiave binaria a 64 bit
        unsigned char binary_key[8] = {
        0b00000000, 0b00000000, 0b00000000, 0b01000000,
        0b00100000, 0b01000000, 0b00110100, 0b00001011
    };

    const char* plaintext = ""; //inserire qui il testo da cifrare

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
