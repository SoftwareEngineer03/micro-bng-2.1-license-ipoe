#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <features.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/if.h>
#include <stdbool.h>
#include <ctype.h>

#include "triton.h"
#include "log.h"
#include "events.h"
#include "ap_session.h"
#include "ipdb.h"
#include "backup.h"
#include "iputils.h"
#include "spinlock.h"
#include "mempool.h"
#include "config.h"
#include "memdebug.h"

#include "vppapi.h"
#include "license.h"
#include "cli.h"

#define SID_SOURCE_SEQ 0
#define SID_SOURCE_URANDOM 1

#define MAX_LINE_LENGTH 256
#define MAX_VALUE_LENGTH 160

#define LICENSE_FILE_NAME "/etc/micro-bng/micro-bng.lic"
#define TEMP_FILE "/etc/micro-bng/temp_license.lic"

typedef struct {
    char license_key[MAX_VALUE_LENGTH];
    char contact_name[MAX_VALUE_LENGTH];
    char contact_phone[MAX_VALUE_LENGTH];
    char contact_email[MAX_VALUE_LENGTH];
    char contact_organization[MAX_VALUE_LENGTH];
} LicenseData;

static int conf_sid_ucase;
static int conf_single_session = -1;
static int conf_single_session_ignore_case;
static int conf_sid_source;
static int conf_seq_save_timeout = 10;
static int conf_session_timeout;
static const char *conf_seq_file;
int __export conf_max_sessions = 0;
int __export conf_max_starting;

pthread_rwlock_t __export ses_lock = PTHREAD_RWLOCK_INITIALIZER;
__export LIST_HEAD(ses_list);

int __export sock_fd;
int __export sock6_fd;
int __export urandom_fd;
int __export ap_shutdown;
int __export test_parameter = 0;

#if __WORDSIZE == 32
static spinlock_t seq_lock;
#endif
static long long unsigned seq;
static struct timespec seq_ts;

static char *product_uuid, *product_serial, *product_name;
static char microbng_uuid[256];

struct ap_session_stat __export ap_session_stat;

static void (*shutdown_cb)(void);

static void generate_sessionid(struct ap_session *ses);
static void save_seq(void);

void __export ap_session_init(struct ap_session *ses)
{
	memset(ses, 0, sizeof(*ses));
	INIT_LIST_HEAD(&ses->pd_list);
	ses->ifindex = -1;
	ses->unit_idx = -1;
	ses->net = net;
	ses->vpp_pppoe_sw_if_index = ~0;
	ses->download_ipv6_classify_table_index = ~0;
	ses->vpp_policer_id_up = ~0;
	ses->vpp_policer_id_down = ~0;
	ses->clientip = 0;
	ses->microbng_bandwidth_max_up = 0;
	ses->microbng_bandwidth_max_down = 0;
	ses->microbng_bandwidth_min_up = 20000;
	ses->microbng_bandwidth_min_down = 20000;
  ses->ppp_info.disc_sock = -1;
  ses->is_ipoe = 0;
	
}

void __export ap_session_set_ifindex(struct ap_session *ses)
{
	//struct rtnl_link_stats64 stats;

  ses->acct_rx_packets_i = 0;
  ses->acct_tx_packets_i = 0;
  ses->acct_rx_bytes_i = 0;
  ses->acct_tx_bytes_i = 0;
  ses->acct_rx_bytes = 0;
  ses->acct_tx_bytes = 0;

	/*if (iplink_get_stats(ses->ifindex, &stats))
		log_ppp_warn("failed to get interface statistics\n");
	else {
		ses->acct_rx_packets_i = stats.rx_packets;
		ses->acct_tx_packets_i = stats.tx_packets;
		ses->acct_rx_bytes_i = stats.rx_bytes;
		ses->acct_tx_bytes_i = stats.tx_bytes;
		ses->acct_rx_bytes = 0;
		ses->acct_tx_bytes = 0;
	}*/
}

int __export ap_session_starting(struct ap_session *ses)
{
	if (ap_shutdown)
		return -1;

	if (ses->ifindex == -1 && ses->ifname[0])
		ses->ifindex = net->get_ifindex(ses->ifname);

	if (ses->ifindex != -1)
		ap_session_set_ifindex(ses);

	if (ses->state != AP_STATE_RESTORE) {
		ses->start_time = _time();
		ses->idle_time = ses->start_time;
		generate_sessionid(ses);

		ses->state = AP_STATE_STARTING;
	}

	__sync_add_and_fetch(&ap_session_stat.starting, 1);

	pthread_rwlock_wrlock(&ses_lock);
	list_add_tail(&ses->entry, &ses_list);
	pthread_rwlock_unlock(&ses_lock);

	triton_event_fire(EV_SES_STARTING, ses);

	return 0;
}

static void ap_session_timer(struct triton_timer_t *t)
{
	struct timespec ts;
	struct ap_session *ses = container_of(t, typeof(*ses), timer);

	if (ap_session_read_stats(ses, NULL))
		ap_session_terminate(ses, TERM_NAS_ERROR, 0);

	clock_gettime(CLOCK_MONOTONIC, &ts);

	if (ses->idle_timeout && ts.tv_sec - ses->idle_time >= ses->idle_timeout) {
		log_ppp_msg("idle timeout\n");
		ap_session_terminate(ses, TERM_SESSION_TIMEOUT, 0);
	} else if (ses->session_timeout) {
		if (ts.tv_sec - ses->start_time >= ses->session_timeout) {
			log_ppp_msg("session timeout\n");
			ap_session_terminate(ses, TERM_SESSION_TIMEOUT, 0);
		}
	}
}

void __export ap_session_activate(struct ap_session *ses)
{
	if (ap_shutdown)
		return;

	ap_session_ifup(ses);

	if (ses->stop_time)
		return;

	ses->state = AP_STATE_ACTIVE;

	__sync_sub_and_fetch(&ap_session_stat.starting, 1);
	__sync_sub_and_fetch(&ap_session_stat.incoming, 1);
	__sync_add_and_fetch(&ap_session_stat.active, 1);

	if (!ses->session_timeout && conf_session_timeout)
		ses->session_timeout = conf_session_timeout;

	if (ses->idle_timeout) {
		ses->timer.expire = ap_session_timer;
		ses->timer.period = 60000;
		triton_timer_add(ses->ctrl->ctx, &ses->timer, 0);
	} else if (ses->session_timeout) {
		ses->timer.expire = ap_session_timer;
		ses->timer.expire_tv.tv_sec = ses->session_timeout;
		triton_timer_add(ses->ctrl->ctx, &ses->timer, 0);
	}

	triton_context_set_priority(ses->ctrl->ctx, 2);

#ifdef USE_BACKUP
	if (!ses->backup)
		backup_save_session(ses);
#endif
}

void __export ap_session_finished(struct ap_session *ses)
{
	ses->terminated = 1;

	if (!ses->down) {
		ap_session_ifdown(ses);
		ap_session_read_stats(ses, NULL);

		triton_event_fire(EV_SES_FINISHING, ses);
	}

	triton_event_fire(EV_SES_PRE_FINISHED, ses);

	pthread_rwlock_wrlock(&ses_lock);
	list_del(&ses->entry);
	pthread_rwlock_unlock(&ses_lock);

	switch (ses->state) {
		case AP_STATE_ACTIVE:
			__sync_sub_and_fetch(&ap_session_stat.active, 1);
			break;
		case AP_STATE_RESTORE:
		case AP_STATE_STARTING:
          __sync_sub_and_fetch(&ap_session_stat.starting, 1);
      __sync_sub_and_fetch(&ap_session_stat.incoming, 1);
    			break;
		case AP_STATE_FINISHING:
			__sync_sub_and_fetch(&ap_session_stat.finishing, 1);
			break;
	}

	if (ses->ipv4 && ses->ipv4->owner) {
		ipdb_put_ipv4(ses, ses->ipv4);
		ses->ipv4 = NULL;
	}

	if (ses->ipv6 && ses->ipv6->owner) {
		ipdb_put_ipv6(ses, ses->ipv6);
		ses->ipv6 = NULL;
	}

	triton_event_fire(EV_SES_FINISHED, ses);
	ses->ctrl->finished(ses);

	if (ses->wakeup)
		triton_context_wakeup(ses->wakeup);

	if (ses->username) {
		_free(ses->username);
		ses->username = NULL;
	}

	if (ses->ipv4_pool_name) {
		_free(ses->ipv4_pool_name);
		ses->ipv4_pool_name = NULL;
	}

	if (ses->ipv6_pool_name) {
		_free(ses->ipv6_pool_name);
		ses->ipv6_pool_name = NULL;
	}

	if (ses->dpv6_pool_name) {
		_free(ses->dpv6_pool_name);
		ses->dpv6_pool_name = NULL;
	}

	if (ses->ifname_rename) {
		_free(ses->ifname_rename);
		ses->ifname_rename = NULL;
	}

#ifdef HAVE_VRF
	if (ses->vrf_name)
		ap_session_vrf(ses, NULL, 0);
#endif

	if (ses->net)
		ses->net->release(ses->net);

	if (ses->timer.tpd)
		triton_timer_del(&ses->timer);

#ifdef USE_BACKUP
	if (ses->backup)
		ses->backup->storage->free(ses->backup);
#endif

	if (ap_shutdown && !ap_session_stat.starting && !ap_session_stat.active && !ap_session_stat.finishing) {
		if (shutdown_cb)
			shutdown_cb();
		else
			kill(getpid(), SIGTERM);
	}
}

void __export ap_session_terminate(struct ap_session *ses, int cause, int hard)
{
	if (ses->terminated)
		return;

	triton_context_set_priority(ses->ctrl->ctx, 3);

	if (!ses->stop_time)
		ses->stop_time = _time();

	if (!ses->terminate_cause)
		ses->terminate_cause = cause;

	if (ses->timer.tpd)
		triton_timer_del(&ses->timer);

	if (ses->terminating) {
		if (hard)
			ses->ctrl->terminate(ses, hard);
		else if (ses->state == AP_STATE_FINISHING)
			ses->ctrl->terminate(ses, 1);
		return;
	}

	if (ses->state == AP_STATE_ACTIVE)
		__sync_sub_and_fetch(&ap_session_stat.active, 1);
	else {
      __sync_sub_and_fetch(&ap_session_stat.starting, 1);
    __sync_sub_and_fetch(&ap_session_stat.incoming, 1);
  }
	__sync_add_and_fetch(&ap_session_stat.finishing, 1);
	ses->terminating = 1;
	ses->state = AP_STATE_FINISHING;

	log_ppp_debug("terminate\n");

	if (ses->ctrl->terminate(ses, hard)) {
		ap_session_ifdown(ses);
		ap_session_read_stats(ses, NULL);

		triton_event_fire(EV_SES_FINISHING, ses);

		ses->down = 1;
	}
}

static void __terminate_soft_reboot(struct ap_session *ses)
{
	ap_session_terminate(ses, TERM_NAS_REBOOT, 0);
}

int ap_shutdown_soft(void (*cb)(void), int term)
{
	struct ap_session *ses;

	ap_shutdown = 1;
	shutdown_cb = cb;

	pthread_rwlock_rdlock(&ses_lock);

	if (!ap_session_stat.starting && !ap_session_stat.active && !ap_session_stat.finishing) {
		pthread_rwlock_unlock(&ses_lock);
		if (shutdown_cb)
			shutdown_cb();
		else
			kill(getpid(), SIGTERM);
		return 1;
	} else if (term) {
		list_for_each_entry(ses, &ses_list, entry)
			triton_context_call(ses->ctrl->ctx, (triton_event_func)__terminate_soft_reboot, ses);
	}

	pthread_rwlock_unlock(&ses_lock);

	return 0;
}

static void generate_sessionid(struct ap_session *ses)
{
	if (conf_sid_source == SID_SOURCE_SEQ) {
		unsigned long long sid;
		struct timespec ts;

#if __WORDSIZE == 32
		spin_lock(&seq_lock);
		sid = ++seq;
		spin_unlock(&seq_lock);
#else
		sid = __sync_add_and_fetch(&seq, 1);
#endif

		clock_gettime(CLOCK_MONOTONIC, &ts);
		if (ts.tv_sec - seq_ts.tv_sec > conf_seq_save_timeout)
			save_seq();

		if (conf_sid_ucase)
			sprintf(ses->sessionid, "%016llX", sid);
		else
			sprintf(ses->sessionid, "%016llx", sid);
	} else {
		uint8_t sid[AP_SESSIONID_LEN/2];
		int i;
		read(urandom_fd, sid, AP_SESSIONID_LEN/2);
		for (i = 0; i < AP_SESSIONID_LEN/2; i++) {
			if (conf_sid_ucase)
				sprintf(ses->sessionid + i*2, "%02X", sid[i]);
			else
				sprintf(ses->sessionid + i*2, "%02x", sid[i]);
		}
	}
}

int __export ap_session_read_stats(struct ap_session *ses, struct rtnl_link_stats64 *stats)
{
	struct rtnl_link_stats64 lstats;

	//if (ses->ifindex == -1)
	//	return -1;

	if (!stats)
		stats = &lstats;

	/*if (iplink_get_stats(ses->ifindex, stats)) {
		log_ppp_warn("failed to get interface statistics\n");
		return -1;
	}*/

  pppoe_session_accounting_t accounting;
	vpp_api_pppoe_session_accounting(ses->ppp_info.addr, ses->ipv4? ses->ipv4->peer_addr:0, &accounting, ses->is_ipoe);

	stats->rx_packets = accounting.acct_input_packets + accounting.acct_input_packets_ipv6;
	stats->tx_packets = accounting.acct_output_packets + accounting.acct_output_packets_ipv6;
	stats->rx_bytes = accounting.acct_input_octets + accounting.acct_input_octets_ipv6;
	stats->tx_bytes = accounting.acct_output_octets + accounting.acct_output_octets_ipv6;

	if (stats->rx_bytes != ses->acct_rx_bytes)
		ses->idle_time = _time();

	ses->acct_rx_packets = stats->rx_packets;
	ses->acct_tx_packets = stats->tx_packets;
	ses->acct_rx_bytes = stats->rx_bytes;
	ses->acct_tx_bytes = stats->tx_bytes;

	return 0;
}

static void __terminate_sec(struct ap_session *ses)
{
	ap_session_terminate(ses, TERM_NAS_REQUEST, 0);
}

int __export ap_session_set_username(struct ap_session *s, char *username)
{
	struct ap_session *ses;
	int wait = 0;

	pthread_rwlock_wrlock(&ses_lock);
	if (conf_single_session >= 0) {
		list_for_each_entry(ses, &ses_list, entry) {
			if (ses->username && ses->terminate_cause != TERM_AUTH_ERROR && !(conf_single_session_ignore_case == 1 ? strcasecmp(ses->username, username) : strcmp(ses->username, username))) {
				if (conf_single_session == 0) {
					pthread_rwlock_unlock(&ses_lock);
					log_ppp_info1("%s: second session denied\n", username);
					_free(username);
					return -1;
				} else {
					if (!ses->wakeup) {
						ses->wakeup = s->ctrl->ctx;
						wait = 1;
					}
					ap_session_ifdown(ses);
					triton_context_call(ses->ctrl->ctx, (triton_event_func)__terminate_sec, ses);
					continue;
				}
			}
		}
	}
	s->username = username;
	pthread_rwlock_unlock(&ses_lock);

	if (wait)
		triton_context_schedule();

	return 0;
}

int __export ap_check_username(const char *username)
{
	struct ap_session *ses;
	int r = 0;

	if (conf_single_session)
		return 0;

	pthread_rwlock_rdlock(&ses_lock);
	list_for_each_entry(ses, &ses_list, entry) {
		if (ses->username && !(conf_single_session_ignore_case == 1 ? strcasecmp(ses->username, username) : strcmp(ses->username, username))) {
			r = 1;
			break;
		}
	}
	pthread_rwlock_unlock(&ses_lock);

	return r;
}

static void save_seq(void)
{
	FILE *f;
	char path[PATH_MAX];
	const char *ptr;

	if (conf_sid_source != SID_SOURCE_SEQ)
		return;

	for (ptr = conf_seq_file + 1; *ptr; ptr++) {
		if (*ptr == '/') {
			memcpy(path, conf_seq_file, ptr - conf_seq_file);
			path[ptr - conf_seq_file] = 0;
			mkdir(path, 0755);
		}
	}

	f = fopen(conf_seq_file, "w");
	if (f) {
		fprintf(f, "%llu", seq);
		fclose(f);
	}
}

static void update_license_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "update license <license-key,[contact-name,contact-phone,contact-email,contact-organization]> - updates license information\r\n"
                "\tex:\r\n"
                "\t\tupdate license K7FQG-BALTZ-ISHNL-YS47E-STATL-A\r\n"
                "\t\tupdate license K7FQG-BALTZ-ISHNL-YS47E-STATL-A,ankur,+91-99994-49349,ankurdelhi1987@gmail.com,netgroot\r\n");
}

static void show_license_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "show license - shows license information\r\n");
}

int parse_parameters(const char* input, char** fields, size_t field_count, size_t max_len) {
    const char* start = input;
    int current_field = 0;
    
    while (*input && current_field < field_count) {
        if (*input == ',') {
            size_t len = input - start;
            if (len >= max_len) return false;
            
            strncpy(fields[current_field], start, len);
            fields[current_field][len] = '\0';
            current_field++;
            start = input + 1;
        }
        input++;
    }
    
    // Handle last field
    if (current_field < field_count) {
        size_t len = input - start;
        if (len >= max_len) return false;
        strncpy(fields[current_field], start, len);
        fields[current_field][len] = '\0';
        current_field++;
    }
    
    return current_field;
}

void trim_whitespace(char* str) {
    char* end;
    
    // Trim leading space
    while(isspace((unsigned char)*str)) str++;
    
    if(*str == 0) return;
    
    // Trim trailing space
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    
    // Write new null terminator
    *(end+1) = 0;
}

bool parse_license_file(const char* filename, LicenseData* data) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("Error opening file");
        return false;
    }

    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file)) {
        // Remove newline character
        line[strcspn(line, "\n")] = '\0';

        char* delimiter = strchr(line, '=');
        if (!delimiter) continue;

        *delimiter = '\0';
        char* key = line;
        char* value = delimiter + 1;

        // Trim whitespace from key and value
        trim_whitespace(key);
        trim_whitespace(value);

        // Assign values to struct fields
        if (strcmp(key, "license_key") == 0) {
            strncpy(data->license_key, value, MAX_VALUE_LENGTH);
        } else if (strcmp(key, "contact_name") == 0) {
            strncpy(data->contact_name, value, MAX_VALUE_LENGTH);
        } else if (strcmp(key, "contact_phone") == 0) {
            strncpy(data->contact_phone, value, MAX_VALUE_LENGTH);
        } else if (strcmp(key, "contact_email") == 0) {
            strncpy(data->contact_email, value, MAX_VALUE_LENGTH);
        } else if (strcmp(key, "contact_organization") == 0) {
            strncpy(data->contact_organization, value, MAX_VALUE_LENGTH);
        }
    }

    fclose(file);
    return true;
}

bool is_comment_line(const char* line) {
    while(isspace((unsigned char)*line)) line++;
    return *line == '#' || *line == ';';
}

bool is_blank_line(const char* line) {
    while(*line) {
        if(!isspace((unsigned char)*line))
            return false;
        line++;
    }
    return true;
}

static int update_license_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt < 3)
		return CLI_CMD_SYNTAX;

    char license[MAX_VALUE_LENGTH] = "", name[MAX_VALUE_LENGTH] = "", phone[MAX_VALUE_LENGTH] = "", email[MAX_VALUE_LENGTH] = "", org[MAX_VALUE_LENGTH] = "";
    char* fields[] = {license, name, phone, email, org};

    parse_parameters(f[2], fields, 5, MAX_VALUE_LENGTH);
    printf("License: %s\n", license);
    printf("Name: %s\n", name);
    printf("Phone: %s\n", phone);
    printf("Email: %s\n", email);
    printf("Organization: %s\n", org);

    LicenseData licensedata;
    memset(&licensedata, 0, sizeof(licensedata));
    if (!parse_license_file(LICENSE_FILE_NAME, &licensedata)) {
        fprintf(stderr, "Failed to parse license file\n");
        return 1;
    }

    if(strlen(license)) strncpy(licensedata.license_key, license, MAX_VALUE_LENGTH);
    if(strlen(name)) strncpy(licensedata.contact_name, name, MAX_VALUE_LENGTH);
    if(strlen(phone)) strncpy(licensedata.contact_phone, phone, MAX_VALUE_LENGTH);
    if(strlen(email)) strncpy(licensedata.contact_email, email, MAX_VALUE_LENGTH);
    if(strlen(org)) strncpy(licensedata.contact_organization, org, MAX_VALUE_LENGTH);

    FILE* original = fopen(LICENSE_FILE_NAME, "r");
    if (!original) {
        perror("Error opening original file");
        return false;
    }

    FILE* temp = fopen(TEMP_FILE, "w");
    if (!temp) {
        perror("Error creating temp file");
        fclose(original);
        return false;
    }

    char line[MAX_LINE_LENGTH];
    bool fields_updated[5] = {false}; // Track which fields we've written
    
    while (fgets(line, sizeof(line), original)) {
        // Copy comments and blank lines as-is
        if(is_comment_line(line) || is_blank_line(line)) {
            fputs(line, temp);
            continue;
        }

        char* delimiter = strchr(line, '=');
        if (!delimiter) {
            fputs(line, temp); // Copy malformed lines as-is
            continue;
        }

        *delimiter = '\0';
        char* key = line;
        char* value = delimiter + 1;

        trim_whitespace(key);
        
        // Handle fields we want to update
        if (strcmp(key, "license_key") == 0) {
            fprintf(temp, "license_key=%s\n", licensedata.license_key);
            fields_updated[0] = true;
        } else if (strcmp(key, "contact_name") == 0) {
            fprintf(temp, "contact_name=%s\n", licensedata.contact_name);
            fields_updated[1] = true;
        } else if (strcmp(key, "contact_phone") == 0) {
            fprintf(temp, "contact_phone=%s\n", licensedata.contact_phone);
            fields_updated[2] = true;
        } else if (strcmp(key, "contact_email") == 0) {
            fprintf(temp, "contact_email=%s\n", licensedata.contact_email);
            fields_updated[3] = true;
        } else if (strcmp(key, "contact_organization") == 0) {
            fprintf(temp, "contact_organization=%s\n", licensedata.contact_organization);
            fields_updated[4] = true;
        } else {
            // Copy other key-value pairs unchanged
            *delimiter = '='; // Restore the delimiter
            fputs(line, temp);
        }
    }

    // Add any missing fields at the end
    if (!fields_updated[0]) fprintf(temp, "license_key=%s\n", licensedata.license_key);
    if (!fields_updated[1]) fprintf(temp, "contact_name=%s\n", licensedata.contact_name);
    if (!fields_updated[2]) fprintf(temp, "contact_phone=%s\n", licensedata.contact_phone);
    if (!fields_updated[3]) fprintf(temp, "contact_email=%s\n", licensedata.contact_email);
    if (!fields_updated[4]) fprintf(temp, "contact_organization=%s\n", licensedata.contact_organization);

    fclose(original);
    fclose(temp);

    // Replace original file with temp file
    remove(LICENSE_FILE_NAME);
    rename(TEMP_FILE, LICENSE_FILE_NAME);

    CompactData lic_data;
    memset(&lic_data, 0, sizeof(CompactData));
    int ret = get_data_from_authfile(microbng_uuid, &lic_data);
    if(ret) {
        log_warn("license key is invalid.\n");
        conf_max_sessions = 0;
        test_parameter  = 0;
    } else {
        if(get_remaining(lic_data.expiry) <= 0) {
            log_warn("license is expired.\n");
            conf_max_sessions = 0;
            test_parameter  = 0;
        } else {
            conf_max_sessions = lic_data.session_count;
            test_parameter  = lic_data.session_count;
        }
    }

    return CLI_CMD_OK;
}

static int show_license_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt < 2)
		return CLI_CMD_SYNTAX;

    CompactData lic_data;

    memset(&lic_data, 0, sizeof(CompactData));

    int ret = get_data_from_authfile(microbng_uuid, &lic_data);
    if(ret) {
        log_warn("license key is invalid.\n");
        cli_sendv(cli, "license key is invalid.\r\n\r\n");
    } else {
        if(get_remaining(lic_data.expiry) <= 0) {
            log_warn("license is expired.\n");
            cli_sendv(cli, "license is expired.\r\n\r\n");
        }
    }
    
    time_t future_timestamp = get_future_timestamp(lic_data.expiry);
    struct tm *timeinfo = localtime(&future_timestamp);
    if (timeinfo == NULL) {
        return CLI_CMD_INVAL;
    }
    char date_string[50];
    strftime(date_string, sizeof(date_string), "%Y-%m-%d", timeinfo);

    cli_sendv(cli, "microbng_uuid=%s\r\n", microbng_uuid);
    cli_sendv(cli, "max_sessions=%u\r\n", lic_data.session_count);
    cli_sendv(cli, "limit_bandwidth=%u Gbps\r\n", lic_data.bandwidth);
    cli_sendv(cli, "expiration_date=%s\r\n", date_string);
    cli_sendv(cli, "product_uuid=%s\r\n", product_uuid);
    cli_sendv(cli, "product_serial=%s\r\n", product_serial);
    cli_sendv(cli, "product_name=%s\r\n", product_name);

    FILE *file;
    char content[9000];

    // Open the file in read mode
    file = fopen(LICENSE_FILE_NAME, "r");
    if (file == NULL) {
        perror("Error opening file");
        return CLI_CMD_INVAL;
    }

    size_t bytes_read = fread(content, 1, sizeof(content), file);
    if(bytes_read > 0){
        content[bytes_read] = '\0';  // Null-terminate the string
        cli_sendv(cli, "%s\r\n", content);
    }

    fclose(file);

    return CLI_CMD_OK;
}

static void load_config(void)
{
	const char *opt;

	opt = conf_get_opt("common", "sid-case");
	if (opt) {
		if (!strcmp(opt, "upper"))
			conf_sid_ucase = 1;
		else if (strcmp(opt, "lower"))
			log_emerg("sid-case: invalid format\n");
	}

	opt = conf_get_opt("common", "single-session");
	if (opt) {
		if (!strcmp(opt, "deny"))
			conf_single_session = 0;
		else if (!strcmp(opt, "replace"))
			conf_single_session = 1;
	} else
		conf_single_session = -1;

	opt = conf_get_opt("common", "single-session-ignore-case");
	if (opt)
		conf_single_session_ignore_case = atoi(opt);
	else
		conf_single_session_ignore_case = 0;

	opt = conf_get_opt("common", "sid-source");
	if (opt) {
		if (strcmp(opt, "seq") == 0)
			conf_sid_source = SID_SOURCE_SEQ;
		else if (strcmp(opt, "urandom") == 0)
			conf_sid_source = SID_SOURCE_URANDOM;
		else
			log_error("unknown sid-source\n");
	} else
		conf_sid_source = SID_SOURCE_SEQ;

	conf_seq_file = conf_get_opt("common", "seq-file");
	if (!conf_seq_file)
		conf_seq_file = "/var/lib/micro-bng/seq";


	opt = conf_get_opt("common", "max-starting");
	if (opt)
		conf_max_starting = atoi(opt);
	else
		conf_max_starting = 0;

	opt = conf_get_opt("common", "session-timeout");
	if (opt)
		conf_session_timeout = atoi(opt);
	else
		conf_session_timeout = 0;
}

static void * license_thread(void *data)
{
    int ret;
    while(1) {
        CompactData lic_data;
        memset(&lic_data, 0, sizeof(CompactData));
        ret = get_data_from_authfile(microbng_uuid, &lic_data);
        if(ret) {
            log_warn("license key is invalid.\n");
            conf_max_sessions = 0;
            test_parameter  = 0;
        } else {
            if(get_remaining(lic_data.expiry) <= 0) {
                log_warn("license is expired.\n");
                conf_max_sessions = 0;
                test_parameter  = 0;
            } else {
                conf_max_sessions = lic_data.session_count;
                test_parameter  = lic_data.session_count;
            }
        }

        sleep(3600*24);
    }
    return NULL;
}

static void init(void)
{
	FILE *f;

#if __WORDSIZE == 32
	spinlock_init(&seq_lock);
#endif

	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_fd < 0) {
		perror("socket");
		_exit(EXIT_FAILURE);
	}

	fcntl(sock_fd, F_SETFD, fcntl(sock_fd, F_GETFD) | FD_CLOEXEC);

	sock6_fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock6_fd < 0)
		log_warn("ppp: kernel doesn't support ipv6\n");
	else
		fcntl(sock6_fd, F_SETFD, fcntl(sock6_fd, F_GETFD) | FD_CLOEXEC);

	urandom_fd = open("/dev/urandom", O_RDONLY);
	if (urandom_fd < 0) {
		log_emerg("failed to open /dev/urandom: %s\n", strerror(errno));
		return;
	}

	fcntl(urandom_fd, F_SETFD, fcntl(urandom_fd, F_GETFD) | FD_CLOEXEC);

    get_unique_id(microbng_uuid);
    product_uuid    = get_dmi_string("sudo dmidecode --string system-uuid");
    product_serial  = get_dmi_string("sudo dmidecode --string system-serial-number");
    product_name    = get_dmi_string("sudo dmidecode -s system-product-name");

	load_config();

    pthread_t lic_thr;
	pthread_create(&lic_thr, NULL, license_thread, NULL);

	f = fopen(conf_seq_file, "r");
	if (f) {
		fscanf(f, "%llu", &seq);
		seq += 1000;
		fclose(f);
	} else
		read(urandom_fd, &seq, sizeof(seq));

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);

    cli_register_simple_cmd2(show_license_exec, show_license_help, 2, "show", "license");
    cli_register_simple_cmd2(update_license_exec, update_license_help, 2, "update", "license");

	atexit(save_seq);
}

DEFINE_INIT(2, init);

