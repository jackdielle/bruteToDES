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



// Funzione per stampare un numero in binario su 8 bit
void print_binary(int num) {
    for (int i = 7; i >= 0; i--) {
        printf("%d", (num >> i) & 1);
    }
}

const char* ullToBinaryString(unsigned long long num) {
    static char binaryStr[65]; // 64 bit + null-terminator
    binaryStr[64] = '\0'; // Null-terminator alla fine

    for (int i = 63; i >= 0; i--) {
        binaryStr[i] = (num & 1) ? '1' : '0';
        num >>= 1;
    }

    return binaryStr;
}

int main() {
    int combinations = 0; // Variabile per conteggiare le combinazioni
    const char* ciphertext_hex = "561098a306ce67a82c7b6d4677312ca76fababe37d6eea4b92e0e7ed4db1d9af32ab720627197eff5ee8a666adb184e405575180260bf0d4fc1a4f2214d75c598f460fba81dc72d4e3c963977813d61b4cccc901b2f5fb99dedd56afc621b5d65b94b2e7898ddec9b353c34acbc563e89513e1ca4e113a34a255a4ec188e37190d116997df9f64c3119e16fbed024c52c280c59e3b701f23b2a26b344217a174dc74784c600bf3846c372ad45ea1a4e7cd4be8f1742265023978b1af424e13e837d258dff94a48f563dc2ec9749edc26ac4706bb5b9cc859cea438c1b239e5b3bfc51b8e3a1c601c57c9a048253170ce887076c6eb7c684f330d1423da22fbcdb4786baeb4bc1b17aa0ff1ac34d8a7dd0917267f20c6b8cf8bb8448e262f55b1ff84dc4c7a8619b0ecaf6de1ee7b43e24d934c6c1cb68da8717584c85459dced31fa0a86153ae29ccd39830ea07703cc1f80cdf163ca267e12013bb865ce11c1ebd60dd64f9fa0674e58b90f3a00eeabf889c209f72477c8f75acf3cc000e3f21329231f94b769eb6dcd4b4ae0e857f6ded49d394a95043656befde68e24d47fb68c0593af82100aade9a6a55c45975a37e6fc0b57a4e1c6ef3e2fcca7b5ec37afbb732d8ffe66e9771748d868abb9eb62018078f8874a5a98d1a4586d71957d9cd999ce933df54f3d48b568d8842e1d4d219c5574d6a305851b9de2ccc1ca48a437b39c33b9a9abba4f7a0222787d1ee947073d3bc4d2c1402a59e3142b9c4794fe2e86010a0040378abda969a90b03bc8962ef2df35f32a6ef6f30320a80bc";
    const size_t ciphertext_len = strlen(ciphertext_hex) / 2;
    unsigned char* ciphertext = (unsigned char*)malloc(ciphertext_len);
    for (int i = 0; i < ciphertext_len; i++) {
        sscanf(ciphertext_hex + 2 * i, "%02hhx", &ciphertext[i]);
    }
    const char* plaintext = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";

    printf("Tutte le possibili combinazioni di 64 bit in binario con parità:\n");
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

                                    // Converti la chiave binaria da stringa a array di bytes
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

                                    // Stampa testo decifrato
                                    

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
