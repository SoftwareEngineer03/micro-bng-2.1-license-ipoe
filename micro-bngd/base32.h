#include <stdbool.h>
#include <stdint.h>
size_t base32_encoded_size(size_t len, bool padding);
size_t base32_encode(const uint8_t *input, size_t len, char *output, bool padding);
size_t base32_decoded_size(const char *input, size_t len);
size_t base32_decode(const char *input, size_t len, uint8_t *output);
