#include <stdio.h>
#include <string.h>
#include <stdlib.h> 
#include <openssl/des.h>
#include <stdbool.h>
#include <time.h>


void binaryStringToBytes(const char* binaryStr, unsigned char* bytes) {
    int len = strlen(binaryStr);
    for (int i = 0; i < len / 8; i++) {
        char byteStr[9];
        strncpy(byteStr, binaryStr + i * 8, 8);
        byteStr[8] = '\0';
        bytes[i] = strtol(byteStr, NULL, 2);
    }
}

const char* ullToBinaryString(unsigned long long num) {
    static char binaryStr[65];
    binaryStr[64] = '\0'; // Null-terminator alla fine

    for (int i = 63; i >= 0; i--) {
        binaryStr[i] = (num & 1) ? '1' : '0';
        num >>= 1;
    }

    return binaryStr;
}

int main() {
    int combinations = 0; // Variabile per conteggiare le combinazioni
    const char* ciphertext_hex = ""; //da inserire qui il testo esadecimale da decifrare
    const size_t ciphertext_len = strlen(ciphertext_hex) / 2;
    unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
    for (int i = 0; i < ciphertext_len; i++) {
        sscanf(ciphertext_hex + 2 * i, "%02hhx", &ciphertext[i]);
    }
    const char* plaintext = ""; // da inserire qui il testo decifrato con il quale comparare i tentativi
    
    bool found = false;
    for (int i = 0; i < 128 && !found; i++) {
        int number1 = i;

        for (int j = 0; j < 128 && !found; j++) {
            int number2 = j;

            for (int k = 0; k < 128 && !found; k++) {
                int number3 = k;

                for (int m = 0; m < 128 && !found; m++) {
                    int number4 = m;

                    for (int n = 0; n < 128 && !found; n++) {
                        int number5 = n;

                        for (int p = 0; p < 128 && !found; p++) {
                            int number6 = p;

                            for (int q = 0; q < 128 && !found; q++) {
                                int number7 = q;

                                for (int r = 0; r < 128 && !found; r++) {
                                    int number8 = r;

                                    int number1_with_parity = (number1 << 1) | 0;
                                    int number2_with_parity = (number2 << 1) | 0;
                                    int number3_with_parity = (number3 << 1) | 0;
                                    int number4_with_parity = (number4 << 1) | 0; 
                                    int number5_with_parity = (number5 << 1) | 0; 
                                    int number6_with_parity = (number6 << 1) | 0; 
                                    int number7_with_parity = (number7 << 1) | 0; 
                                    int number8_with_parity = (number8 << 1) | 0;


                                    unsigned long long concatenated_number = 
                                        ((unsigned long long)number1_with_parity << 56) |
                                        ((unsigned long long)number2_with_parity << 48) |
                                        ((unsigned long long)number3_with_parity << 40) |
                                        ((unsigned long long)number4_with_parity << 32) |
                                        ((unsigned long long)number5_with_parity << 24) |
                                        ((unsigned long long)number6_with_parity << 16) |
                                        ((unsigned long long)number7_with_parity << 8)  |
                                        (unsigned long long)number8_with_parity;

                                    // Chiave binaria in formato stringa
                                    const char* binary_key_str = ullToBinaryString(concatenated_number);

                                    unsigned char binary_key[8];
                                    binaryStringToBytes(binary_key_str, binary_key);

                                    // Inizializzazione DES
                                    DES_cblock des_key;
                                    DES_key_schedule key_schedule;
                                    memcpy(des_key, binary_key, 8);
                                    DES_set_key(&des_key, &key_schedule);

                                    // Decifratura
                                    const size_t encrypted_len = strlen(ciphertext_hex);
                                    unsigned char* decrypted_text = (unsigned char*)malloc(encrypted_len / 2);
                                    size_t decrypted_len = 0;
                                    DES_cblock input_block, output_block;
                                    for (int i = 0; i < encrypted_len; i += 16) {
                                        memset(input_block, 0, 8);
                                        for (int j = 0; j < 16; j += 2) {
                                            unsigned int hex_byte;
                                            sscanf(ciphertext_hex + i + j, "%2X", &hex_byte);
                                            input_block[j / 2] = (unsigned char)hex_byte;
                                        }
                                        DES_ecb_encrypt(&input_block, &output_block, &key_schedule, DES_DECRYPT);
                                        memcpy(decrypted_text + decrypted_len, output_block, 8);
                                        decrypted_len += 8;
                                    }                                    

                                    // Confronta il testo decifrato con il testo in chiaro
                                    if (memcmp(decrypted_text, plaintext, ciphertext_len) == 0) {
                                        for (int b = 63; b >= 0; b--) {
                                        printf("%llu", (concatenated_number >> b) & 1);
                                        }
                                        printf("\n");
                                        time_t current_time;
                                        time(&current_time);
                                        printf("Testo decifrato: %.*s\n", (int)decrypted_len, decrypted_text);
                                        // Stampare l'ora corrente
                                        printf("Ora corrente: %s", ctime(&current_time));
                                        found = true;
                                        printf("TESTO DECIFRATO CORRETTAMENTE.\n");
                                    } else {
                                        //printf("Testo decifrato non combacia con il testo in chiaro.\n");
                                        for (int b = 63; b >= 0; b--) {
                                        printf("%llu", (concatenated_number >> b) & 1);
                                        }
                                        printf("\n");
                                    }


                                    combinations++; // Incrementa il contatore delle combinazioni
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    printf("Numero totale di combinazioni generate: %d\n", combinations);
    free(ciphertext);

    return 0;
}
