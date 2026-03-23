#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <aio.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <regex.h>
#include <ctype.h>

#include "log.h"
#include "events.h"
#include "ppp.h"
#include "spinlock.h"
#include "mempool.h"

#include "memdebug.h"

#define LOG_BUF_SIZE 16*1024

#define RED_COLOR     "\033[1;31m"
#define GREEN_COLOR   "\033[1;32m"
#define YELLOW_COLOR  "\033[1;33m"
#define BLUE_COLOR  	"\033[1;34m"
#define NORMAL_COLOR  "\033[0;39m"

#define MAX_LINE_LEN 256
#define MAX_RULES 10000
#define MAX_PATH_LEN 1024
#define MAX_PATTERN_LEN 128

typedef enum {
    RULE_EXACT,
    RULE_WILDCARD,
    RULE_REGEX
} rule_type_t;

typedef struct {
    char pattern[MAX_PATTERN_LEN];
    rule_type_t type;
    regex_t regex;
    char log_pattern[MAX_PATH_LEN];
    int specificity;
} log_rule_t;

typedef struct {
    char log_dir[MAX_PATH_LEN];
    char interface_log_dir[MAX_PATH_LEN];
    char user_log_dir[MAX_PATH_LEN];
    log_rule_t interface_rules[MAX_RULES];
    int interface_rule_count;
    log_rule_t user_rules[MAX_RULES];
    int user_rule_count;
} log_config_t;

struct log_file_t {
	struct list_head entry;
	struct list_head msgs;
	spinlock_t lock;
	unsigned int need_free:1;
	unsigned int queued:1;
	struct log_file_pd_t *lpd;

	int fd;
	int new_fd;
};

struct log_file_pd_t {
	struct ap_private pd;
	struct log_file_t lf;
	unsigned long tmp;
};

struct fail_log_pd_t {
	struct ap_private pd;
	struct list_head msgs;
};

static log_config_t log_rules_config;

static int conf_color;
static int conf_per_session;
static char *conf_per_user_dir;
static char *conf_per_session_dir;
static int conf_copy;
static int conf_fail_log;
static pthread_t log_thr;

static const char* level_name[]={"  msg", "error", " warn", " info", " info", "debug"};
static const char* level_color[]={NORMAL_COLOR, RED_COLOR, YELLOW_COLOR, GREEN_COLOR, GREEN_COLOR, BLUE_COLOR};

static void *pd_key_log_rule;
static void *pd_key1;
static void *pd_key2;
static void *pd_key3;

static struct log_file_t *log_file;
static struct log_file_t *fail_log_file;

static mempool_t lpd_pool;
static mempool_t fpd_pool;

static LIST_HEAD(lf_queue);
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static unsigned long temp_seq;

struct interface_log_entry_t {
    struct list_head entry;
    char interface_name[64];
    struct log_file_t *log_file;
    time_t last_used;
    char log_path[MAX_PATH_LEN];
};

static LIST_HEAD(interface_log_list);
static spinlock_t interface_list_lock;

#define MAX_OPEN_INTERFACE_FILES 100

static void trim_whitespace(char *str);
static rule_type_t detect_rule_type(const char *pattern);
static int calculate_specificity(const char *pattern, rule_type_t type);
static int compile_regex(log_rule_t *rule);
static void free_regex(log_rule_t *rule);
static int match_pattern_simple(const char *pattern, const char *str);
static void load_log_rules_config(void);
static int match_pattern(const log_rule_t *rule, const char *input);
const log_rule_t* find_best_rule(const log_rule_t *rules, int count, const char *input);

static void log_file_init(struct log_file_t *lf)
{
	spinlock_init(&lf->lock);
	INIT_LIST_HEAD(&lf->msgs);
	lf->fd = -1;
	lf->new_fd = -1;
}

static int log_file_open(struct log_file_t *lf, const char *fname)
{
	lf->fd = open(fname, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, S_IRUSR | S_IWUSR);
	if (lf->fd < 0) {
		log_emerg("log_file: open '%s': %s\n", fname, strerror(errno));
		return -1;
	}

	return 0;
}

static void purge(struct list_head *list)
{
	struct log_msg_t *msg;

	while (!list_empty(list)) {
		msg = list_first_entry(list, typeof(*msg), entry);
		list_del(&msg->entry);
		log_free_msg(msg);
	}
}

static void *log_thread(void *unused)
{
	struct log_file_t *lf;
	struct iovec iov[IOV_MAX];
	struct log_chunk_t *chunk;
	struct log_msg_t *msg;
	int iov_cnt;
	LIST_HEAD(msg_list);
	LIST_HEAD(free_list);
	sigset_t set;

	sigfillset(&set);
	sigdelset(&set, SIGKILL);
	sigdelset(&set, SIGSTOP);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	while (1) {
		pthread_mutex_lock(&lock);
		if (list_empty(&lf_queue))
			pthread_cond_wait(&cond, &lock);
		lf = list_first_entry(&lf_queue, typeof(*lf), entry);
		list_del(&lf->entry);
		pthread_mutex_unlock(&lock);

		iov_cnt = 0;

		while (1) {
			if (lf->new_fd != -1) {
				close(lf->fd);
				lf->fd = lf->new_fd;
				lf->new_fd = -1;
			}

			spin_lock(&lf->lock);
			if (list_empty(&lf->msgs)) {
				if (iov_cnt) {
					writev(lf->fd, iov, iov_cnt);
					purge(&free_list);
				}

				lf->queued = 0;
				if (lf->need_free) {
					spin_unlock(&lf->lock);
					close(lf->fd);
					if (lf->new_fd != -1)
						close(lf->new_fd);
					mempool_free(lf->lpd);
				} else
					spin_unlock(&lf->lock);

				break;
			}

			list_splice_init(&lf->msgs, &msg_list);
			spin_unlock(&lf->lock);

			while (!list_empty(&msg_list)) {
				msg = list_first_entry(&msg_list, typeof(*msg), entry);

				iov[iov_cnt].iov_base = msg->hdr->msg;
				iov[iov_cnt].iov_len = msg->hdr->len;
				if (++iov_cnt == IOV_MAX) {
					writev(lf->fd, iov, iov_cnt);
					purge(&free_list);
					iov_cnt = 0;
				}

				list_for_each_entry(chunk, msg->chunks, entry) {
					iov[iov_cnt].iov_base = chunk->msg;
					iov[iov_cnt].iov_len = chunk->len;
					if (++iov_cnt == IOV_MAX) {
						writev(lf->fd, iov, iov_cnt);
						iov_cnt = 0;
						purge(&free_list);
					}
				}

				list_move_tail(&msg->entry, &free_list);
			}
		}
	}

	return NULL;
}

static void queue_lf(struct log_file_t *lf)
{
	pthread_mutex_lock(&lock);
	list_add_tail(&lf->entry, &lf_queue);
	pthread_cond_signal(&cond);
	pthread_mutex_unlock(&lock);
}

static void queue_log(struct log_file_t *lf, struct log_msg_t *msg)
{
	int r;

	spin_lock(&lf->lock);
	list_add_tail(&msg->entry, &lf->msgs);
	if (lf->fd != -1) {
		r = lf->queued;
		lf->queued = 1;
	} else
		r = 1;
	spin_unlock(&lf->lock);

	if (!r)
		queue_lf(lf);
}

static void queue_log_list(struct log_file_t *lf, struct list_head *l)
{
	int r;

	spin_lock(&lf->lock);
	list_splice_init(l, &lf->msgs);
	if (lf->fd != -1) {
		r = lf->queued;
		lf->queued = 1;
	} else
		r = 1;
	spin_unlock(&lf->lock);

	if (!r)
		queue_lf(lf);
}


static void set_hdr(struct log_msg_t *msg, struct ap_session *ses)
{
	struct tm tm;
	char timestamp[32];

	localtime_r(&msg->timestamp.tv_sec, &tm);

	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm);
	sprintf(msg->hdr->msg, "%s[%s]: %s: %s%s%s", conf_color ? level_color[msg->level] : "",
		timestamp, level_name[msg->level],
		ses ? (ses->ifname[0] ? ses->ifname : ses->ctrl->ifname) : "",
		ses ? ": " : "",
		conf_color ? NORMAL_COLOR : "");
	msg->hdr->len = strlen(msg->hdr->msg);
}

static void init_interface_list(void)
{
    INIT_LIST_HEAD(&interface_log_list);
    spinlock_init(&interface_list_lock);
}

static struct log_file_t *find_interface_log_file(const char *interface_name)
{
    struct interface_log_entry_t *entry;
    
    if (!interface_name || interface_name[0] == '\0')
        return NULL;
    
    spin_lock(&interface_list_lock);
    
    list_for_each_entry(entry, &interface_log_list, entry) {
        if (strcmp(entry->interface_name, interface_name) == 0) {
            entry->last_used = time(NULL);
            spin_unlock(&interface_list_lock);
            return entry->log_file;
        }
    }
    
    spin_unlock(&interface_list_lock);
    return NULL;
}

static struct log_file_t *get_or_create_interface_log_file(const char *interface_name)
{
    struct interface_log_entry_t *entry;
    struct log_file_t *log_file = NULL;
    
    if (!interface_name || interface_name[0] == '\0')
        return NULL;
    
    spin_lock(&interface_list_lock);
    
    list_for_each_entry(entry, &interface_log_list, entry) {
        if (strcmp(entry->interface_name, interface_name) == 0) {
            entry->last_used = time(NULL);
            log_file = entry->log_file;
            spin_unlock(&interface_list_lock);
            return log_file;
        }
    }
    
    spin_unlock(&interface_list_lock);
    
    const log_rule_t *rule = NULL;
    for (int i = 0; i < log_rules_config.interface_rule_count; i++) {
        if (match_pattern(&log_rules_config.interface_rules[i], interface_name)) {
            if (!rule || log_rules_config.interface_rules[i].specificity > rule->specificity) {
                rule = &log_rules_config.interface_rules[i];
            }
        }
    }
    
    if (!rule) {
        return NULL;
    }
    
    char log_path[MAX_PATH_LEN];
    char temp[MAX_PATH_LEN];
    char *pattern = rule->log_pattern;
    char *dest = temp;
    char *end = temp + MAX_PATH_LEN - 1;
    
    snprintf(log_path, sizeof(log_path), "%s/", log_rules_config.interface_log_dir);
    
    while (*pattern && dest < end) {
        if (*pattern == '{') {
            if (strncmp(pattern, "{interface}", 11) == 0) {
                size_t len = strlen(interface_name);
                if (dest + len < end) {
                    strcpy(dest, interface_name);
                    dest += len;
                }
                pattern += 11;
            } else if (strncmp(pattern, "{match1}", 8) == 0 && rule->type == RULE_REGEX) {
                size_t len = strlen(interface_name);
                if (dest + len < end) {
                    strcpy(dest, interface_name);
                    dest += len;
                }
                pattern += 8;
            } else {
                *dest++ = *pattern++;
            }
        } else {
            *dest++ = *pattern++;
        }
    }
    *dest = '\0';
    
    strcat(log_path, temp);
    
    log_file = malloc(sizeof(struct log_file_t));
    if (!log_file) {
        printf("Failed to allocate log file for interface %s\n", interface_name);
        return NULL;
    }
    
    memset(log_file, 0, sizeof(struct log_file_t));
    spinlock_init(&log_file->lock);
    INIT_LIST_HEAD(&log_file->msgs);
    log_file->fd = -1;
    log_file->new_fd = -1;
    
    if (log_file_open(log_file, log_path) != 0) {
        printf("Failed to open log file for interface %s: %s\n", interface_name, log_path);
        free(log_file);
        return NULL;
    }
    
    entry = malloc(sizeof(struct interface_log_entry_t));
    if (!entry) {
        printf("Failed to allocate interface entry for %s\n", interface_name);
        free(log_file);
        return NULL;
    }
    
    memset(entry, 0, sizeof(struct interface_log_entry_t));
    strncpy(entry->interface_name, interface_name, sizeof(entry->interface_name) - 1);
    entry->interface_name[sizeof(entry->interface_name) - 1] = '\0';
    strncpy(entry->log_path, log_path, sizeof(entry->log_path) - 1);
    entry->log_path[sizeof(entry->log_path) - 1] = '\0';
    entry->log_file = log_file;
    entry->last_used = time(NULL);
    INIT_LIST_HEAD(&entry->entry);
    
    spin_lock(&interface_list_lock);
    list_add_tail(&entry->entry, &interface_log_list);
    spin_unlock(&interface_list_lock);
    
    printf("Created log file for interface %s: %s\n", interface_name, log_path);
    
    return log_file;
}

static void manage_file_descriptors(void)
{
    struct interface_log_entry_t *entry, *oldest = NULL;
    time_t oldest_time = time(NULL);
    int count = 0;
    
    spin_lock(&interface_list_lock);
    
    list_for_each_entry(entry, &interface_log_list, entry) {
        if (entry->log_file && entry->log_file->fd != -1) {
            count++;
            if (entry->last_used < oldest_time) {
                oldest_time = entry->last_used;
                oldest = entry;
            }
        }
    }
    
    if (count >= MAX_OPEN_INTERFACE_FILES && oldest) {
        printf("Closing least recently used interface log: %s (last used: %ld)\n",
                 oldest->interface_name, oldest_time);
        
        if (oldest->log_file->fd != -1) {
            close(oldest->log_file->fd);
            oldest->log_file->fd = -1;
        }
    }
    
    spin_unlock(&interface_list_lock);
}

static void ensure_interface_log_file_open(struct interface_log_entry_t *entry)
{
    if (!entry || !entry->log_file)
        return;
    
    if (entry->log_file->fd == -1) {
        if (entry->log_path[0] != '\0') {
            int fd = open(entry->log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, S_IRUSR | S_IWUSR);
            if (fd >= 0) {
                entry->log_file->fd = fd;
                printf("Reopened log file for interface %s: %s\n", 
                         entry->interface_name, entry->log_path);
            } else {
                printf("Failed to reopen log file for interface %s: %s\n", 
                         entry->interface_name, strerror(errno));
            }
        }
    }
    
    entry->last_used = time(NULL);
}

static void add_interface_to_list(const char *interface_name)
{
    struct interface_log_entry_t *entry;
    
    if (!interface_name || interface_name[0] == '\0')
        return;
    
    spin_lock(&interface_list_lock);
    list_for_each_entry(entry, &interface_log_list, entry) {
        if (strcmp(entry->interface_name, interface_name) == 0) {
            spin_unlock(&interface_list_lock);
            return;
        }
    }
    spin_unlock(&interface_list_lock);
    
    int matches_rule = 0;
    for (int i = 0; i < log_rules_config.interface_rule_count; i++) {
        if (match_pattern(&log_rules_config.interface_rules[i], interface_name)) {
            matches_rule = 1;
            break;
        }
    }
    
    if (!matches_rule) {
        log_debug("Interface %s doesn't match any rule, skipping\n", interface_name);
        return;
    }
    
    entry = malloc(sizeof(struct interface_log_entry_t));
    if (!entry) {
        log_emerg("Failed to allocate interface entry for %s\n", interface_name);
        return;
    }
    
    memset(entry, 0, sizeof(struct interface_log_entry_t));
    strncpy(entry->interface_name, interface_name, sizeof(entry->interface_name) - 1);
    entry->interface_name[sizeof(entry->interface_name) - 1] = '\0';
    entry->log_file = NULL;
    entry->last_used = 0;
    INIT_LIST_HEAD(&entry->entry);
    
    spin_lock(&interface_list_lock);
    list_add_tail(&entry->entry, &interface_log_list);
    spin_unlock(&interface_list_lock);
    
    log_debug("Registered interface for logging: %s\n", interface_name);
}

static void per_interface_log(struct log_target_t *t, struct log_msg_t *msg, struct ap_session *ses)
{
    if (ses && !conf_copy) {
        log_free_msg(msg);
        return;
    }

    set_hdr(msg, ses);
    
    if (ses) {
        const char *ifname = ses->ifname[0] ? ses->ifname : ses->ctrl->ifname;
        
        manage_file_descriptors();
        
        struct log_file_t *interface_lf = NULL;
        struct interface_log_entry_t *entry = NULL;
        
        spin_lock(&interface_list_lock);
        list_for_each_entry(entry, &interface_log_list, entry) {
            if (strcmp(entry->interface_name, ifname) == 0) {
                interface_lf = entry->log_file;
                break;
            }
        }
        spin_unlock(&interface_list_lock);
        
        if (interface_lf) {
            ensure_interface_log_file_open(entry);
            
            queue_log(interface_lf, msg);
            return;
        } else {
            interface_lf = get_or_create_interface_log_file(ifname);
            if (interface_lf) {
                queue_log(interface_lf, msg);
                return;
            } 
        }
    }

    log_free_msg(msg);
}

static void general_log(struct log_target_t *t, struct log_msg_t *msg, struct ap_session *ses)
{
	if (ses && !conf_copy) {
		log_free_msg(msg);
		return;
	}

	set_hdr(msg, ses);
	queue_log(log_file, msg);
}

static struct ap_private *find_pd(struct ap_session *ses, void *pd_key)
{
	struct ap_private *pd;
	struct list_head *pos, *next;

	list_for_each_safe(pos, next, &ses->pd_list) {
		pd = list_entry(pos, typeof(*pd), entry);
		if (pd->key == pd_key) {
			return pd;
		}
	}

	return NULL;
}

static struct log_file_pd_t *find_lpd(struct ap_session *ses, void *pd_key)
{
	struct ap_private *pd = find_pd(ses, pd_key);

	if (!pd)
		return NULL;

	return container_of(pd, struct log_file_pd_t, pd);
}

static struct fail_log_pd_t *find_fpd(struct ap_session *ses, void *pd_key)
{
	struct ap_private *pd = find_pd(ses, pd_key);

	if (!pd)
		return NULL;

	return container_of(pd, struct fail_log_pd_t, pd);
}

static void per_user_log_rule(struct log_target_t *t, struct log_msg_t *msg, struct ap_session *ses)
{
	struct log_file_pd_t *lpd;

	if (!ses) {
		log_free_msg(msg);
		return;
	}

	lpd = find_lpd(ses, &pd_key_log_rule);

	if (!lpd) {
		log_free_msg(msg);
		return;
	}

	set_hdr(msg, ses);
	queue_log(&lpd->lf, msg);
}

static void per_user_log(struct log_target_t *t, struct log_msg_t *msg, struct ap_session *ses)
{
	struct log_file_pd_t *lpd;

	if (!ses) {
		log_free_msg(msg);
		return;
	}

	lpd = find_lpd(ses, &pd_key1);

	if (!lpd) {
		log_free_msg(msg);
		return;
	}

	set_hdr(msg, ses);
	queue_log(&lpd->lf, msg);
}

static void per_session_log(struct log_target_t *t, struct log_msg_t *msg, struct ap_session *ses)
{
	struct log_file_pd_t *lpd;

	if (!ses) {
		log_free_msg(msg);
		return;
	}

	lpd = find_lpd(ses, &pd_key2);

	if (!lpd) {
		log_free_msg(msg);
		return;
	}

	set_hdr(msg, ses);
	queue_log(&lpd->lf, msg);
}

static void fail_log(struct log_target_t *t, struct log_msg_t *msg, struct ap_session *ses)
{
	struct fail_log_pd_t *fpd;

	if (!ses || !conf_fail_log) {
		log_free_msg(msg);
		return;
	}

	fpd = find_fpd(ses, &pd_key3);

	if (!fpd) {
		log_free_msg(msg);
		return;
	}

	set_hdr(msg, ses);
	list_add_tail(&msg->entry, &fpd->msgs);
}

static void fail_reopen(void)
{
	const char *fname = conf_get_opt("log", "log-fail-file");
	int old_fd = -1;
 	int fd = open(fname, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		log_emerg("log_file: open '%s': %s\n", fname, strerror(errno));
		return;
	}

	spin_lock(&fail_log_file->lock);
	if (fail_log_file->queued)
		fail_log_file->new_fd = fd;
	else {
		old_fd = fail_log_file->fd;
		fail_log_file->fd = fd;
	}
	spin_unlock(&fail_log_file->lock);

	if (old_fd != -1)
		close(old_fd);
}

static int reopen_log_file(struct log_file_t *log, const char *config_key)
{
    const char *fname = conf_get_opt("log", config_key);
    if (!fname) {
        log_emerg("log_file: no %s configured\n", config_key);
        return -1;
    }

    int fd = open(fname, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 
                  S_IRUSR | S_IWUSR);
    if (fd < 0) {
        log_emerg("log_file: open '%s': %s\n", fname, strerror(errno));
        return -1;
    }

    int old_fd = -1;
    spin_lock(&log->lock);
    if (log->queued) {
        log->new_fd = fd;
    } else {
        old_fd = log->fd;
        log->fd = fd;
    }
    spin_unlock(&log->lock);

    if (old_fd != -1) {
        close(old_fd);
    }

    return 0;
}

static int reopen_interface_log_file(struct interface_log_entry_t *entry)
{
    if (!entry || !entry->log_file)
        return -1;
    
    int old_fd = -1;
    int new_fd = open(entry->log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, S_IRUSR | S_IWUSR);
    
    if (new_fd < 0) {
        printf("log_file: failed to reopen interface log '%s': %s\n", 
                 entry->log_path, strerror(errno));
        return -1;
    }
    
    spin_lock(&entry->log_file->lock);
    if (entry->log_file->queued) {
        entry->log_file->new_fd = new_fd;
        spin_unlock(&entry->log_file->lock);
    } else {
        old_fd = entry->log_file->fd;
        entry->log_file->fd = new_fd;
        spin_unlock(&entry->log_file->lock);
        
        if (old_fd != -1) {
            close(old_fd);
        }
    }
    
    printf("Reopened interface log file: %s\n", entry->log_path);
    return 0;
}

static void reopen_all_interface_logs(void)
{
    struct interface_log_entry_t *entry;
    int count = 0, success = 0;
    
    printf("Reopening all interface log files...\n");
    
    spin_lock(&interface_list_lock);
    
    list_for_each_entry(entry, &interface_log_list, entry) {
        if (entry->log_file && entry->log_path[0] != '\0') {
            count++;
            if (reopen_interface_log_file(entry) == 0) {
                success++;
            }
        }
    }
    
    spin_unlock(&interface_list_lock);
    
    printf("Reopened %d/%d interface log files\n", success, count);
}

static void general_reopen(void)
{
	int main_log_result = reopen_log_file(log_file, "log-file");

    if (main_log_result != 0) {
        log_emerg("log_file: partial reopen failure (main:%d, ipoe:%d)\n",
                    main_log_result);
    }
}

static void free_lpd(struct log_file_pd_t *lpd)
{
	struct log_msg_t *msg;

	spin_lock(&lpd->lf.lock);
	list_del(&lpd->pd.entry);
	lpd->lf.need_free = 1;
	if (lpd->lf.queued)
		spin_unlock(&lpd->lf.lock);
	else {
		while (!list_empty(&lpd->lf.msgs)) {
			msg = list_entry(lpd->lf.msgs.next, typeof(*msg), entry);
			list_del(&msg->entry);
			log_free_msg(msg);
		}
		if (lpd->lf.fd != -1)
			close(lpd->lf.fd);
		if (lpd->lf.new_fd != -1)
			close(lpd->lf.new_fd);
		spin_unlock(&lpd->lf.lock);
		mempool_free(lpd);
	}
}

static void ev_ses_authorized2(struct ap_session *ses)
{
	struct fail_log_pd_t *fpd;
	struct log_msg_t *msg;

	fpd = find_fpd(ses, &pd_key3);
	if (!fpd)
		return;

	while (!list_empty(&fpd->msgs)) {
		msg = list_entry(fpd->msgs.next, typeof(*msg), entry);
		list_del(&msg->entry);
		log_free_msg(msg);
	}

	list_del(&fpd->pd.entry);
	mempool_free(fpd);
}

static void ev_ses_authorized1(struct ap_session *ses)
{
	struct log_file_pd_t *lpd;
	char *fname;

	lpd = find_lpd(ses, &pd_key1);
	if (!lpd)
		return;

	fname = _malloc(PATH_MAX);
	if (!fname) {
		log_emerg("log_file: out of memory\n");
		return;
	}

	strcpy(fname, conf_per_user_dir);
	strcat(fname, "/");
	strcat(fname, ses->username);
	if (conf_per_session) {
		if (mkdir(fname, S_IRWXU) && errno != EEXIST) {
			log_emerg("log_file: mkdir '%s': %s'\n", fname, strerror(errno));
			goto out_err;
		}
		strcat(fname, "/");
		strcat(fname, ses->sessionid);
	}
	strcat(fname, ".log");

	if (log_file_open(&lpd->lf, fname))
		goto out_err;

	_free(fname);

	if (!list_empty(&lpd->lf.msgs)) {
		lpd->lf.queued = 1;
		queue_lf(&lpd->lf);
	}

	return;

out_err:
	_free(fname);
	free_lpd(lpd);
}

static void ev_ses_authorized_log_rules(struct ap_session *ses)
{
	struct log_file_pd_t *lpd;
	char *fname;

    const log_rule_t *rule = find_best_rule(log_rules_config.user_rules, 
                                               log_rules_config.user_rule_count, 
                                               ses->username);
    if (!rule) {
        return;
    }

	lpd = find_lpd(ses, &pd_key_log_rule);
	if (!lpd)
		return;

	fname = _malloc(PATH_MAX);
	if (!fname) {
		log_emerg("log_file: out of memory\n");
		return;
	}

	strcpy(fname, log_rules_config.user_log_dir);
	strcat(fname, "/");
	strcat(fname, ses->username);
	strcat(fname, ".log");

	if (log_file_open(&lpd->lf, fname))
		goto out_err;

	_free(fname);

	if (!list_empty(&lpd->lf.msgs)) {
		lpd->lf.queued = 1;
		queue_lf(&lpd->lf);
	}

	return;

out_err:
	_free(fname);
	free_lpd(lpd);
}

static void ev_ctrl_started(struct ap_session *ses)
{
	struct log_file_pd_t *lpd;
	struct fail_log_pd_t *fpd;
	char *fname;

	if (conf_per_user_dir) {
		lpd = mempool_alloc(lpd_pool);
		if (!lpd) {
			log_emerg("log_file: out of memory\n");
			return;
		}
		memset(lpd, 0, sizeof(*lpd));
		lpd->pd.key = &pd_key1;
		log_file_init(&lpd->lf);
		lpd->lf.lpd = lpd;
		list_add_tail(&lpd->pd.entry, &ses->pd_list);
	}

    if (log_rules_config.user_rule_count > 0) {
		lpd = mempool_alloc(lpd_pool);
		if (!lpd) {
			log_emerg("log_file: out of memory\n");
			return;
		}
		memset(lpd, 0, sizeof(*lpd));
		lpd->pd.key = &pd_key_log_rule;
		log_file_init(&lpd->lf);
		lpd->lf.lpd = lpd;
		list_add_tail(&lpd->pd.entry, &ses->pd_list);
	}

	if (conf_per_session_dir) {
		lpd = mempool_alloc(lpd_pool);
		if (!lpd) {
			log_emerg("log_file: out of memory\n");
			return;
		}
		memset(lpd, 0, sizeof(*lpd));
		lpd->pd.key = &pd_key2;
		log_file_init(&lpd->lf);
		lpd->lf.lpd = lpd;

		fname = _malloc(PATH_MAX);
		if (!fname) {
			mempool_free(lpd);
			log_emerg("log_file: out of memory\n");
			return;
		}

		lpd->tmp = temp_seq++;
		strcpy(fname, conf_per_session_dir);
		strcat(fname, "/tmp");
		sprintf(fname + strlen(fname), "%lu", lpd->tmp);

		if (log_file_open(&lpd->lf, fname)) {
			mempool_free(lpd);
			_free(fname);
			return;
		}

		_free(fname);

		list_add_tail(&lpd->pd.entry, &ses->pd_list);
	}

	if (conf_fail_log) {
		fpd = mempool_alloc(fpd_pool);
		if (!fpd) {
			log_emerg("log_file: out of memory\n");
			return;
		}
		memset(fpd, 0, sizeof(*fpd));
		fpd->pd.key = &pd_key3;
		INIT_LIST_HEAD(&fpd->msgs);
		list_add_tail(&fpd->pd.entry, &ses->pd_list);
	}
}

static void ev_ctrl_finished(struct ap_session *ses)
{
	struct log_file_pd_t *lpd;
	struct fail_log_pd_t *fpd;
	char *fname;

	fpd = find_fpd(ses, &pd_key3);
	if (fpd) {
		queue_log_list(fail_log_file, &fpd->msgs);
		list_del(&fpd->pd.entry);
		mempool_free(fpd);
	}

	lpd = find_lpd(ses, &pd_key1);
	if (lpd)
		free_lpd(lpd);

	lpd = find_lpd(ses, &pd_key_log_rule);
	if (lpd)
		free_lpd(lpd);

	lpd = find_lpd(ses, &pd_key2);
	if (lpd) {
		if (lpd->tmp) {
			fname = _malloc(PATH_MAX);
			if (fname) {
				strcpy(fname, conf_per_session_dir);
				strcat(fname, "/tmp");
				sprintf(fname + strlen(fname), "%lu", lpd->tmp);
				if (unlink(fname))
					log_emerg("log_file: unlink '%s': %s\n", fname, strerror(errno));
				_free(fname);
			} else
				log_emerg("log_file: out of memory\n");
		}
		free_lpd(lpd);
	}
}

static void ev_ses_starting(struct ap_session *ses)
{
	struct log_file_pd_t *lpd;
	char *fname1, *fname2;

	lpd = find_lpd(ses, &pd_key2);
	if (!lpd)
		return;

	fname1 = _malloc(PATH_MAX);
	if (!fname1) {
		log_emerg("log_file: out of memory\n");
		return;
	}

	fname2 = _malloc(PATH_MAX);
	if (!fname2) {
		log_emerg("log_file: out of memory\n");
		_free(fname1);
		return;
	}

	strcpy(fname1, conf_per_session_dir);
	strcat(fname1, "/tmp");
	sprintf(fname1 + strlen(fname1), "%lu", lpd->tmp);

	strcpy(fname2, conf_per_session_dir);
	strcat(fname2, "/");
	strcat(fname2, ses->sessionid);
	strcat(fname2, ".log");

	if (rename(fname1, fname2))
		log_emerg("log_file: rename '%s' to '%s': %s\n", fname1, fname2, strerror(errno));

	lpd->tmp = 0;

	_free(fname1);
	_free(fname2);
}

static struct log_target_t general_target =
{
	.log = general_log,
	.reopen = general_reopen,
};

static struct log_target_t per_interface_target =
{
	.log = per_interface_log,
    .reopen = reopen_all_interface_logs,
};


static struct log_target_t per_user_rule_target =
{
	.log = per_user_log_rule,
};

static struct log_target_t per_user_target =
{
	.log = per_user_log,
};

static struct log_target_t per_session_target =
{
	.log = per_session_log,
};

static struct log_target_t fail_log_target =
{
	.log = fail_log,
	.reopen = fail_reopen,
};

void log_config_init(log_config_t *config) {
    memset(config, 0, sizeof(log_config_t));
    strcpy(config->log_dir, "/var/log/micro-bng");
    strcpy(config->interface_log_dir, "/var/log/micro-bng/interfaces");
    strcpy(config->user_log_dir, "/var/log/micro-bng/users");
}


int log_config_parse(log_config_t *config, const char *filename) 
{
    FILE *fp;
    char line[MAX_LINE_LEN];
    char section[32] = {0};
    int line_num = 0;
    
    fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open config file %s: %s\n", filename, strerror(errno));
        return -1;
    }
    
    char old_log_dir[MAX_PATH_LEN];
    char old_interface_dir[MAX_PATH_LEN];
    char old_user_dir[MAX_PATH_LEN];
    
    strcpy(old_log_dir, config->log_dir);
    strcpy(old_interface_dir, config->interface_log_dir);
    strcpy(old_user_dir, config->user_log_dir);
    
    config->interface_rule_count = 0;
    config->user_rule_count = 0;
    
    for (int i = 0; i < config->interface_rule_count; i++) {
        free_regex(&config->interface_rules[i]);
    }
    for (int i = 0; i < config->user_rule_count; i++) {
        free_regex(&config->user_rules[i]);
    }
    
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        trim_whitespace(line);

        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        
        if (strncmp(line, "log-dir=", 8) == 0) {
            strcpy(config->log_dir, line + 8);
            trim_whitespace(config->log_dir);
            
            if (strcmp(config->interface_log_dir, old_interface_dir) == 0) {
                snprintf(config->interface_log_dir, MAX_PATH_LEN, "%s/interfaces", config->log_dir);
            }
            if (strcmp(config->user_log_dir, old_user_dir) == 0) {
                snprintf(config->user_log_dir, MAX_PATH_LEN, "%s/users", config->log_dir);
            }
            continue;
        }
        
        if (strncmp(line, "interface-log-dir=", 18) == 0) {
            strcpy(config->interface_log_dir, line + 18);
            trim_whitespace(config->interface_log_dir);
            continue;
        }
        
        if (strncmp(line, "user-log-dir=", 13) == 0) {
            strcpy(config->user_log_dir, line + 13);
            trim_whitespace(config->user_log_dir);
            continue;
        }
        
        if (line[0] == '[' && line[strlen(line)-1] == ']') {
            strncpy(section, line + 1, strlen(line) - 2);
            section[strlen(line) - 2] = '\0';
            trim_whitespace(section);
            continue;
        }
        
        if (strcmp(section, "interfaces") == 0) {
            if (config->interface_rule_count >= MAX_RULES) {
                fprintf(stderr, "Too many interface rules at line %d\n", line_num);
                continue;
            }
            
            log_rule_t *rule = &config->interface_rules[config->interface_rule_count];
            strncpy(rule->pattern, line, MAX_PATTERN_LEN - 1);
            rule->pattern[MAX_PATTERN_LEN - 1] = '\0';
            
            rule->type = detect_rule_type(rule->pattern);
            rule->specificity = calculate_specificity(rule->pattern, rule->type);
            
            if (rule->type == RULE_REGEX) {
                snprintf(rule->log_pattern, MAX_PATH_LEN, "{interface}.log");
            } else {
                if (rule->type == RULE_EXACT) {
                    snprintf(rule->log_pattern, MAX_PATH_LEN, "%s.log", rule->pattern);
                } else {
                    snprintf(rule->log_pattern, MAX_PATH_LEN, "{interface}.log");
                }
            }
            
            if (rule->type == RULE_REGEX) {
                if (compile_regex(rule) != 0) {
                    fprintf(stderr, "Invalid regex '%s' at line %d\n", rule->pattern, line_num);
                    continue;
                }
            }
            
            config->interface_rule_count++;
        }
        else if (strcmp(section, "users") == 0) {
            if (config->user_rule_count >= MAX_RULES) {
                fprintf(stderr, "Too many user rules at line %d\n", line_num);
                continue;
            }
            
            log_rule_t *rule = &config->user_rules[config->user_rule_count];
            strncpy(rule->pattern, line, MAX_PATTERN_LEN - 1);
            rule->pattern[MAX_PATTERN_LEN - 1] = '\0';
            
            rule->type = detect_rule_type(rule->pattern);
            rule->specificity = calculate_specificity(rule->pattern, rule->type);
            
            if (rule->type == RULE_REGEX) {
                snprintf(rule->log_pattern, MAX_PATH_LEN, "{username}.log");
            } else {
                if (rule->type == RULE_EXACT) {
                    snprintf(rule->log_pattern, MAX_PATH_LEN, "%s.log", rule->pattern);
                } else {
                    snprintf(rule->log_pattern, MAX_PATH_LEN, "{username}.log");
                }
            }
            
            if (rule->type == RULE_REGEX) {
                if (compile_regex(rule) != 0) {
                    fprintf(stderr, "Invalid regex '%s' at line %d\n", rule->pattern, line_num);
                    continue;
                }
            }
            
            config->user_rule_count++;
        }
        else if (section[0] != '\0') {
            fprintf(stderr, "Unknown section '%s' at line %d\n", section, line_num);
        }
    }
    
    fclose(fp);
    
    if (config->log_dir[0] == '\0') {
        strcpy(config->log_dir, old_log_dir);
    }
    if (config->interface_log_dir[0] == '\0') {
        strcpy(config->interface_log_dir, old_interface_dir);
    }
    if (config->user_log_dir[0] == '\0') {
        strcpy(config->user_log_dir, old_user_dir);
    }
    
    return 0;
}

static int match_pattern(const log_rule_t *rule, const char *input) {
    switch (rule->type) {
        case RULE_EXACT:
            return strcmp(rule->pattern, input) == 0;
            
        case RULE_WILDCARD: {
            const char *pattern = rule->pattern;
            const char *str = input;
            
            while (*pattern) {
                if (*pattern == '*') {
                    while (*pattern == '*') pattern++;
                    
                    if (*pattern == '\0') return 1;
                    
                    while (*str) {
                        if (match_pattern_simple(pattern, str)) {
                            return 1;
                        }
                        str++;
                    }
                    return 0;
                }
                else if (*pattern == '?') {
                    if (*str == '\0') return 0;
                    pattern++;
                    str++;
                }
                else {
                    if (*pattern != *str) return 0;
                    pattern++;
                    str++;
                }
            }
            
            return *str == '\0';
        }
            
        case RULE_REGEX:
            return regexec(&rule->regex, input, 0, NULL, 0) == 0;
            
        default:
            return 0;
    }
}

static int match_pattern_simple(const char *pattern, const char *str) {
    while (*pattern) {
        if (*pattern == '*') {
            pattern++;
            while (*pattern == '*') pattern++;
            
            if (*pattern == '\0') return 1;
            
            while (*str) {
                if (match_pattern_simple(pattern, str)) {
                    return 1;
                }
                str++;
            }
            return 0;
        }
        else if (*pattern == '?') {
            if (*str == '\0') return 0;
            pattern++;
            str++;
        }
        else {
            if (*pattern != *str) return 0;
            pattern++;
            str++;
        }
    }
    
    return *str == '\0';
}

const log_rule_t* find_best_rule(const log_rule_t *rules, int count, const char *input) {
    const log_rule_t *best = NULL;
    int best_score = -1;
    
    for (int i = 0; i < count; i++) {
        if (match_pattern(&rules[i], input)) {
            if (best == NULL || rules[i].specificity > best_score) {
                best = &rules[i];
                best_score = rules[i].specificity;
            }
        }
    }
    
    return best;
}

static int build_log_path(const log_config_t *config, const log_rule_t *rule, 
                         const char *input, const char *username, const char *interface,
                         char *output, size_t output_size) {
    char temp[MAX_PATH_LEN];
    char *pattern = rule->log_pattern;
    char *dest = temp;
    char *end = temp + MAX_PATH_LEN - 1;
    
    if (rule >= config->interface_rules && 
        rule < config->interface_rules + config->interface_rule_count) {
        snprintf(output, output_size, "%s/", config->interface_log_dir);
    } else {
        snprintf(output, output_size, "%s/", config->user_log_dir);
    }
    
    while (*pattern && dest < end) {
        if (*pattern == '{') {
            if (strncmp(pattern, "{interface}", 11) == 0) {
                if (interface) {
                    size_t len = strlen(interface);
                    if (dest + len < end) {
                        strcpy(dest, interface);
                        dest += len;
                    }
                    pattern += 11;
                } else {
                    size_t len = strlen(input);
                    if (dest + len < end) {
                        strcpy(dest, input);
                        dest += len;
                    }
                    pattern += 11;
                }
            }
            else if (strncmp(pattern, "{username}", 10) == 0) {
                if (username) {
                    size_t len = strlen(username);
                    if (dest + len < end) {
                        strcpy(dest, username);
                        dest += len;
                    }
                    pattern += 10;
                } else {
                    size_t len = strlen(input);
                    if (dest + len < end) {
                        strcpy(dest, input);
                        dest += len;
                    }
                    pattern += 10;
                }
            }
            else if (strncmp(pattern, "{match1}", 8) == 0 && rule->type == RULE_REGEX) {
                pattern += 8;
                if (input) {
                    size_t len = strlen(input);
                    if (dest + len < end) {
                        strcpy(dest, input);
                        dest += len;
                    }
                }
            }
            else {
                *dest++ = *pattern++;
            }
        }
        else {
            *dest++ = *pattern++;
        }
    }
    
    *dest = '\0';
    
    size_t current_len = strlen(output);
    if (current_len + strlen(temp) < output_size) {
        strcat(output, temp);
        return 0;
    }
    
    return -1;
}

int get_interface_log_file(const log_config_t *config, const char *interface,
                          char *logfile, size_t logfile_size) {
    if (!interface || interface[0] == '\0') {
        snprintf(logfile, logfile_size, "%s/unknown.log", config->interface_log_dir);
        return -1;
    }
    
    const log_rule_t *rule = find_best_rule(config->interface_rules, 
                                           config->interface_rule_count, 
                                           interface);
    
    if (rule) {
        return build_log_path(config, rule, interface, NULL, interface, 
                             logfile, logfile_size);
    }
    
    logfile[0]='\0';
    return -1;
}

int get_user_log_file(const log_config_t *config, const char *username,
                     char *logfile, size_t logfile_size) {
    if (!username || username[0] == '\0') {
        snprintf(logfile, logfile_size, "%s/unknown.log", config->user_log_dir);
        return -1;
    }

    const log_rule_t *rule = find_best_rule(config->user_rules, 
                                           config->user_rule_count, 
                                           username);

    if (rule) {
        return build_log_path(config, rule, username, username, NULL, 
                             logfile, logfile_size);
    }
    
    logfile[0]='\0';
    return -1;
}

static void trim_whitespace(char *str) {
    char *start = str;
    char *end;
    
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }
    
    if (*start == '\0') {
        str[0] = '\0';
        return;
    }
    
    if (start != str) {
        char *dst = str;
        char *src = start;
        while ((*dst++ = *src++) != '\0');
    }
    
    end = str + strlen(str) - 1;
    while (end >= str && isspace((unsigned char)*end)) {
        end--;
    }
    
    *(end + 1) = '\0';
}

static rule_type_t detect_rule_type(const char *pattern) {
    const char *p = pattern;
    int has_regex_chars = 0;
    
    if (*p == '^') p++;
    
    while (*p) {
        if (*p == '[' || *p == '(' || *p == '+' || *p == '?' || 
            (*p == '\\' && *(p+1) && strchr("[]().*+?{}|^$", *(p+1)))) {
            has_regex_chars = 1;
            break;
        }
        p++;
    }
    
    if (has_regex_chars) {
        return RULE_REGEX;
    }
    
    if (strchr(pattern, '*') || strchr(pattern, '?')) {
        return RULE_WILDCARD;
    }
    
    return RULE_EXACT;
}

static int calculate_specificity(const char *pattern, rule_type_t type) {
    int score = strlen(pattern) * 10;
    
    if (type == RULE_EXACT) score += 1000;
    else if (type == RULE_WILDCARD) score += 500;
    else if (type == RULE_REGEX) score += 200;
    
    if (type == RULE_WILDCARD && !strchr(pattern, '*')) {
        score += 100;
    }
    
    return score;
}

static int compile_regex(log_rule_t *rule) {
    int ret = regcomp(&rule->regex, rule->pattern, REG_EXTENDED | REG_NOSUB);
    if (ret != 0) {
        char error_buf[256];
        regerror(ret, &rule->regex, error_buf, sizeof(error_buf));
        fprintf(stderr, "Regex compilation failed: %s\n", error_buf);
        return -1;
    }
    return 0;
}

static void free_regex(log_rule_t *rule) {
    if (rule->type == RULE_REGEX) {
        regfree(&rule->regex);
    }
}

void log_config_cleanup(log_config_t *config) {
    for (int i = 0; i < config->interface_rule_count; i++) {
        free_regex(&config->interface_rules[i]);
    }
    for (int i = 0; i < config->user_rule_count; i++) {
        free_regex(&config->user_rules[i]);
    }
    
    config->interface_rule_count = 0;
    config->user_rule_count = 0;
}

static void load_log_rules_config(void) 
{
    char logfile[MAX_PATH_LEN];
    
    log_config_init(&log_rules_config);
    
    if (log_config_parse(&log_rules_config, "/etc/micro-bng/log-rules.conf") < 0) {
        fprintf(stderr, "Failed to parse config\n");
        return;
    }

    if (log_rules_config.user_rule_count > 0) {
        log_debug("user_rule_count: %d\n", log_rules_config.user_rule_count);
        log_register_target(&per_user_rule_target);
        triton_event_register_handler(EV_SES_AUTHORIZED, (triton_event_func)ev_ses_authorized_log_rules);
    }
    
    printf("Log directory: %s\n", log_rules_config.log_dir);
    printf("Interface log directory: %s\n", log_rules_config.interface_log_dir);
    printf("User log directory: %s\n", log_rules_config.user_log_dir);
    printf("Interface rules: %d\n", log_rules_config.interface_rule_count);
    printf("User rules: %d\n", log_rules_config.user_rule_count);
    
}

static void reload_log_rules(void)
{
    log_config_cleanup(&log_rules_config);

    char logfile[MAX_PATH_LEN];
    
    if (log_config_parse(&log_rules_config, "/etc/micro-bng/log-rules.conf") < 0) {
        fprintf(stderr, "Failed to parse config\n");
        return;
    }

    printf("Log directory: %s\n", log_rules_config.log_dir);
    printf("Interface log directory: %s\n", log_rules_config.interface_log_dir);
    printf("User log directory: %s\n", log_rules_config.user_log_dir);
    printf("Interface rules: %d\n", log_rules_config.interface_rule_count);
    printf("User rules: %d\n", log_rules_config.user_rule_count);
}

static void init(void)
{
	const char *opt;

	pthread_create(&log_thr, NULL, log_thread, NULL);

	lpd_pool = mempool_create(sizeof(struct log_file_pd_t));
	fpd_pool = mempool_create(sizeof(struct fail_log_pd_t));

	opt = conf_get_opt("log", "log-file");
	if (opt) {
		log_file = malloc(sizeof(*log_file));
		memset(log_file, 0, sizeof(*log_file));
		log_file_init(log_file);
		if (log_file_open(log_file, opt)) {
			log_emerg("log_file:init:log_file_open: failed\n");
			free(log_file);
			_exit(EXIT_FAILURE);
		}
	}

	opt = conf_get_opt("log", "log-fail-file");
	if (opt) {
		fail_log_file = malloc(sizeof(*fail_log_file));
		memset(fail_log_file, 0, sizeof(*fail_log_file));
		log_file_init(fail_log_file);
		if (log_file_open(fail_log_file, opt)) {
			log_emerg("log_file:init:log_file_open: failed\n");
			free(fail_log_file);
			_exit(EXIT_FAILURE);
		}
		conf_fail_log = 1;
	}

	opt = conf_get_opt("log","color");
	if (opt && atoi(opt) > 0)
		conf_color = 1;

	opt = conf_get_opt("log", "per-user-dir");
	if (opt)
		conf_per_user_dir = _strdup(opt);

	opt = conf_get_opt("log", "per-session-dir");
	if (opt)
		conf_per_session_dir = _strdup(opt);

	opt = conf_get_opt("log", "per-session");
	if (opt && atoi(opt) > 0)
		conf_per_session = 1;

	opt = conf_get_opt("log", "copy");
	if (opt && atoi(opt) > 0)
		conf_copy = 1;

    init_interface_list();
    load_log_rules_config();

	log_register_target(&general_target);
    log_register_target(&per_interface_target);

	if (conf_per_user_dir) {
		log_register_target(&per_user_target);
		triton_event_register_handler(EV_SES_AUTHORIZED, (triton_event_func)ev_ses_authorized1);
	}

	if (conf_per_session_dir) {
		log_register_target(&per_session_target);
		triton_event_register_handler(EV_SES_STARTING, (triton_event_func)ev_ses_starting);
	}

	if (conf_fail_log) {
		log_register_target(&fail_log_target);
		triton_event_register_handler(EV_SES_AUTHORIZED, (triton_event_func)ev_ses_authorized2);
	}

	triton_event_register_handler(EV_CTRL_STARTED, (triton_event_func)ev_ctrl_started);
	triton_event_register_handler(EV_CTRL_FINISHED, (triton_event_func)ev_ctrl_finished);

    triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)reload_log_rules);
}

DEFINE_INIT(1, init);
