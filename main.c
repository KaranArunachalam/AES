#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "aes.h"

// Pad input to AES block size (16 bytes) using PKCS#7 padding
void pad_input(uint8_t *input, size_t *length) {
    uint8_t pad_value = AES_BLOCKLEN - (*length % AES_BLOCKLEN);
    memset(input + *length, pad_value, pad_value);
    *length += pad_value;
}

// Remove PKCS#7 padding after decryption
void unpad_input(uint8_t *input, size_t *length) {
    uint8_t pad_value = input[*length - 1];
    if(pad_value <= AES_BLOCKLEN) {
        *length -= pad_value;
        input[*length] = '\0';
    }
}

int main() {
    uint8_t key[16] = "abcdefghijklmnop";  // 128-bit key
    uint8_t input[256] = {0};              // User input buffer

    // Get user input
    printf("Enter text to encrypt (max 240 chars):\n");
    fgets((char *)input, sizeof(input), stdin);
    input[strcspn((char *)input, "\n")] = '\0'; // Remove newline

    size_t input_len = strlen((char *)input);
    size_t padded_len = input_len;

    // Pad the input
    pad_input(input, &padded_len);

    // Initialize AES context
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);

    // Encrypt each block
    for(size_t i = 0; i < padded_len; i += AES_BLOCKLEN) {
        AES_ECB_encrypt(&ctx, input + i);
    }

    printf("\nEncrypted (hex): ");
    for(size_t i = 0; i < padded_len; i++) {
        printf("%02x", input[i]);
    }

    // Decrypt each block
    AES_init_ctx(&ctx, key);  // Reset context
    for(size_t i = 0; i < padded_len; i += AES_BLOCKLEN) {
        AES_ECB_decrypt(&ctx, input + i);
    }

    // Remove padding
    unpad_input(input, &padded_len);

    printf("\nDecrypted: %s\n", input);
    return 0;
}
