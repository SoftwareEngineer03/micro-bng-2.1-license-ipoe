#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "base32.h"

// base32.h
typedef struct {
    uint8_t *data;
    size_t pos;
    size_t len;
} buffer_t;

// Base32 alphabet (standard RFC 4648)
static const char base32_alphabet[32] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
static const uint8_t base32_decode_map[256] = {
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,26,27,28,29,30,31,255,255,255,255,255,255,255,255,255,
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    16,17,18,19,20,21,22,23,24,25,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255
};

// base32.c
static bool is_base32(char c) {
    return base32_decode_map[(uint8_t)c] != 255;
}

size_t base32_encoded_size(size_t len, bool padding) {
    size_t size = (len * 8 + 4) / 5;
    return padding ? size + (8 - (size % 8)) % 8 : size;
}

size_t base32_encode(const uint8_t *input, size_t len, char *output, bool padding) {
    size_t count = 0;
    int buffer = 0, bits = 0;
    
    for(size_t i = 0; i < len; i++) {
        buffer = (buffer << 8) | input[i];
        bits += 8;
        
        while(bits >= 5) {
            output[count++] = base32_alphabet[(buffer >> (bits - 5)) & 0x1F];
            bits -= 5;
        }
    }
    
    if(bits > 0) {
        output[count++] = base32_alphabet[(buffer << (5 - bits)) & 0x1F];
    }
    
    if(padding) {
        while(count % 8 != 0) {
            output[count++] = '=';
        }
    }
    
    return count;
}

size_t base32_decoded_size(const char *input, size_t len) {
    size_t padding = 0;
    if(len >= 1 && input[len-1] == '=') padding++;
    if(len >= 2 && input[len-2] == '=') padding++;
    if(len >= 3 && input[len-3] == '=') padding++;
    if(len >= 4 && input[len-4] == '=') padding++;
    return (len * 5 - padding * 5) / 8;
}

size_t base32_decode(const char *input, size_t len, uint8_t *output) {
    size_t count = 0;
    int buffer = 0, bits = 0;
    
    for(size_t i = 0; i < len; i++) {
        if(input[i] == '=') break;
        if(!is_base32(input[i])) return (size_t)-1;
        
        buffer = (buffer << 5) | base32_decode_map[(uint8_t)input[i]];
        bits += 5;
        
        if(bits >= 8) {
            output[count++] = (buffer >> (bits - 8)) & 0xFF;
            bits -= 8;
        }
    }
    
    return count;
}

// Example usage
/*int main(int argc, char **argv) {

    if(argc < 2) {
	    printf("Usage: %s <data>\n", argv[0]);
	    return 0;
    }

    const char *text = argv[1];
    size_t text_len = strlen(text);
    
    // Encode
    size_t enc_size = base32_encoded_size(text_len, true);
    char *encoded = malloc(enc_size + 1);
    base32_encode((uint8_t*)text, text_len, encoded, true);
    encoded[enc_size] = '\0';
    printf("Encoded: %s\n", encoded);

    // Decode
    size_t dec_size = base32_decoded_size(encoded, enc_size);
    uint8_t *decoded = malloc(dec_size + 1);
    size_t result = base32_decode(encoded, enc_size, decoded);
    
    if(result == (size_t)-1) {
        printf("Decoding error!\n");
    } else {
        decoded[result] = '\0';
        printf("Decoded: %s\n", decoded);
    }
    
    free(encoded);
    free(decoded);
    return 0;
}*/
