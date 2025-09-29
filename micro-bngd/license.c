#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <time.h>
#include "license.h"
#include "base32.h"

#define AES_KEY_SIZE 32   // 256-bit key
#define AES_BLOCK_SIZE 16 // 128-bit block
#define INPUT_SIZE 16     // 128-bit input string

#define MAX_LINE_LENGTH 256

#define LICENSE_KEY_STRING "license_key="

// Alphanumeric characters (A-Z, 1-9) - Excludes '0' for better readability
static const char CHAR_TABLE[36] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789";

static void handle_errors() {
    ERR_print_errors_fp(stderr);
    exit(1);
}

static void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for(size_t i=0; i<len; i++) printf("%02x", data[i]);
    printf("\n");
}

static void remove_hyphens(char *str) {
    int i, j = 0;
    for (i = 0; str[i] != '\0'; i++) {
        if (str[i] != '-') {
            str[j++] = str[i];  // Copy non-hyphen characters
        }
    }
    str[j] = '\0';  // Null-terminate the cleaned string
}

// Execute a shell command and return output (stripped of newline)
char* get_dmi_string(const char* cmd) {
    FILE* pipe = popen(cmd, "r");
    if (!pipe) return NULL;

    char buffer[128];
    if (fgets(buffer, sizeof(buffer), pipe) == NULL) {
        pclose(pipe);
        return NULL;
    }
    pclose(pipe);

    // Remove trailing newline
    buffer[strcspn(buffer, "\n")] = '\0';
    return strdup(buffer);
}

// Generate a 16-char alphanumeric ID from combined input strings
static void generate_alnum_id(const char* uuid, const char* serial, const char* product, char* output) {
    char combined[256];
    snprintf(combined, sizeof(combined), "%s%s%s", uuid, serial, product);

    // Compute SHA-256 hash
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)combined, strlen(combined), sha256_hash);

    // Use first 16 bytes of the hash to generate 16 alphanumeric chars
    for (int i = 0; i < 16; i++) {
        output[i] = CHAR_TABLE[sha256_hash[i] % 36];
    }
    output[16] = '\0';
}

// Format as XXXX-XXXX-XXXX-XXXX
static void format_id(char* id) {
    char formatted[20];
    snprintf(formatted, sizeof(formatted),
             "%.4s-%.4s-%.4s-%.4s", id, id + 4, id + 8, id + 12);
    strcpy(id, formatted);
}

// Function to get the timestamp for (2025-01-01 + N days)
time_t get_future_timestamp(int days_to_add) {
    struct tm future_date = {0};
    future_date.tm_year = 2025 - 1900;  // Year 2025
    future_date.tm_mon = 0;             // January (0-based)
    future_date.tm_mday = 1 + days_to_add; // Add N days to Jan 1
    future_date.tm_hour = 0;            // Midnight
    future_date.tm_isdst = -1;          // Auto-adjust for DST

    // Normalize the date (handles month/year overflow)
    return mktime(&future_date);
}

int get_remaining(int days_to_add) {
    time_t future_timestamp = get_future_timestamp(days_to_add);

    if (future_timestamp == -1) {
        perror("Failed to calculate future timestamp");
        return 0;
    }

    // Get current timestamp
    time_t now = time(NULL);
    if (now == -1) {
        perror("Failed to get current time");
        return 0;
    }

    // Calculate difference in days
    double diff_seconds = difftime(future_timestamp, now);
    int days_remaining = (int)(diff_seconds / (60 * 60 * 24));

    printf("Timestamp for 2025-01-01 + %d days: %ld\n", days_to_add, future_timestamp);
    printf("Current timestamp: %ld\n", now);
    printf("Days remaining: %d\n\n", days_remaining);

    return days_remaining;
}

int get_data_from_license(char *unique_id, char *license, CompactData *data)
{
	unsigned char iv[AES_BLOCK_SIZE] = {
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f
    };
	size_t enc_size;

	unsigned char deviceinfo[32];
	unsigned char decrypted[INPUT_SIZE];  // Decrypted output
	int len;
    int ret = 0;

    memset(data, 0, sizeof(CompactData));
	memset(deviceinfo, 0, sizeof(deviceinfo));
	strcpy(deviceinfo, unique_id);
	
	remove_hyphens(license);
	enc_size = strlen(license);
	
	printf("### deviceinfo: %s\n", deviceinfo);
	printf("### key: %s\n", license);
	
	// Decode
    size_t dec_size = base32_decoded_size(license, enc_size);
    uint8_t *decoded = malloc(dec_size + 1);
    size_t result = base32_decode(license, enc_size, decoded);
    
    if(result == (size_t)-1) {
        printf("Decoding error!\n");
        return -1;
    } else {
        print_hex("### Decoded Base32:", decoded, dec_size);
    }
    

    // --- DECRYPTION ---
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handle_errors();
    
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (unsigned char*)deviceinfo, iv))
        handle_errors();
    
    // Disable padding for decryption
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    if (1 != EVP_DecryptUpdate(ctx, decrypted, &len, decoded, dec_size))
        handle_errors();
    int decrypted_len = len;

    // No EVP_DecryptFinal needed (no padding)

    print_hex("### Decrypted (16-byte)", decrypted, decrypted_len);
    
    memcpy(data, decrypted+8, 8);
    
    printf("### %d %d %d\n", data->session_count, data->bandwidth, data->expiry);
    
    char inputstr[256] = {0};
	unsigned char out1[8], out3[8];
	snprintf(inputstr, sizeof(inputstr), "%s%s%x%x%x", "MICRO-BNG2.0", unique_id, data->session_count, data->bandwidth, data->expiry);
	// Compute SHA-256 hash
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)inputstr, strlen(inputstr), sha256_hash);

    for(int i=0; i<8; i++) {
    	out1[i] = sha256_hash[i] ^ sha256_hash[i+8];
    }
    
    memcpy(out3, decrypted, 8);
    for (int i=0; i<8; i++) {
        if (out3[i] != out1[i]) {
            printf("AUTH_INVALID\n");
            ret = -1;
            memset(data, 0, sizeof(CompactData));
            break;
        }
    }
    
    EVP_CIPHER_CTX_free(ctx);

    free(decoded);

    return ret;
}

int get_data_from_authfile(char *unique_id, CompactData *data)
{
    FILE *file;
    char line[MAX_LINE_LENGTH];

    memset(data, 0, sizeof(CompactData));

    // Open the file in read mode
    file = fopen("/etc/micro-bng/micro-bng.lic", "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    char *license = NULL;

    // Read the first line
    while (fgets(line, sizeof(line), file) != NULL) {
        // Remove the newline character if present
        size_t len = strlen(line);
        if (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[len - 1] = '\0'; // Replace with null terminator
        }
        
        // Print the line
        printf("Read line: %s\n", line);

        if( !strncmp(line, LICENSE_KEY_STRING, strlen(LICENSE_KEY_STRING)) ) {
            license = line;
            license += strlen(LICENSE_KEY_STRING);
            break;
        }
    }

    // Close the file
    fclose(file);

    if(!license)
        return;
    
    return get_data_from_license(unique_id, license, data);

}

void get_unique_id(char *unique_id)
{
    // Step 1: Get original strings
    char* uuid    = get_dmi_string("sudo dmidecode --string system-uuid");
    char* serial  = get_dmi_string("sudo dmidecode --string system-serial-number");
    char* product = get_dmi_string("sudo dmidecode -s system-product-name");

    if (!uuid || !serial || !product) {
        printf("Error: Failed to fetch system info.\n");
        free(uuid); free(serial); free(product);
        return;
    }

    printf("Original UUID:     %s\n", uuid);
    printf("Original Serial:   %s\n", serial);
    printf("Original Product:  %s\n", product);

    // Step 2: Generate UniqueID (XXXX-XXXX-XXXX-XXXX)
    //char unique_id[17]; // 16 chars + null terminator
    generate_alnum_id(uuid, serial, product, unique_id);
    format_id(unique_id); // Add dashes

    printf("\nGenerated UniqueID: %s\n", unique_id);

    free(uuid); free(serial); free(product);

}

