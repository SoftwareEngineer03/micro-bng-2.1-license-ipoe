typedef struct {
    uint64_t session_count : 24;  // 24 bits (0-23)
    uint64_t bandwidth     : 20;  // 20 bits (24-43)
    uint64_t expiry        : 20;  // 20 bits (44-63)
} CompactData;

int get_remaining(int days_to_add);
int get_data_from_license(char *unique_id, char *license, CompactData *data);
void get_unique_id(char *unique_id);
int get_data_from_authfile(char *unique_id, CompactData *data);
char* get_dmi_string(const char* cmd);
time_t get_future_timestamp(int days_to_add);

