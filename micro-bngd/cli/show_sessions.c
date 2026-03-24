#include <stdio.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <signal.h>
#include <arpa/inet.h>
#include <linux/if_link.h>

#include "triton.h"
#include "events.h"
#include "ppp.h"
#include "ipdb.h"
#include "cli.h"
#include "utils.h"
#include "log.h"
#include "memdebug.h"

#include "vppapi.h"

#define CELL_SIZE 128
#define DEF_COLUMNS "ifname,username,calling-sid,ip,rate-limit,type,comp,state,uptime"

struct column_t
{
	struct list_head entry;
	const char *name;
	const char *desc;
	void (*print)(struct ap_session *ses, char *buf);
};

struct col_t
{
	struct list_head entry;
	struct column_t *column;
	int width;
	int hidden;
};

struct row_t
{
	struct list_head entry;
	char *match_key;
	char *order_key;
  struct ap_session *ses;
	struct list_head cell_list;
};

struct cell_t
{
	struct list_head entry;
	struct col_t *col;
	char buf[CELL_SIZE + 1];
};


enum oneuser_matchkey {
	MATCHKEY_NONE,
	MATCHKEY_USERNAME,
	MATCHKEY_MAC,
	MATCHKEY_SID,
};

static LIST_HEAD(col_list);
static char *conf_def_columns = NULL;

static __thread struct rtnl_link_stats64 stats;
static __thread int stats_set;

void show_one_user(struct ap_session *ses, void *cli);
void print_uptime(struct ap_session *ses, char *buf);
void get_stats(struct ap_session *ses);

void __export cli_show_ses_register(const char *name, const char *desc, void (*print)(struct ap_session *ses, char *buf))
{
	struct column_t *c = malloc(sizeof(*c));
	c->name = name;
	c->desc = desc;
	c->print = print;
	list_add_tail(&c->entry, &col_list);
}

static void show_traffic_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "");
}

static void show_ses_help(char * const *f, int f_cnt, void *cli)
{
	struct column_t *col;
	char buf[129];

	cli_send(cli, "show sessions [columns] [order <column>] [match <column> <regexp>] - shows sessions\r\n");
	cli_send(cli, "\tcolumns:\r\n");

	list_for_each_entry(col, &col_list, entry) {
		snprintf(buf, 128, "\t\t%s - %s\r\n", col->name, col->desc);
		cli_send(cli, buf);
	}
}

static void show_oneuser_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "show session username=<username>|MAC=<MAC address>|sid=<sid> - shows session\r\n");
}

static struct column_t *find_column(const char *name)
{
	struct column_t *col;

	list_for_each_entry(col, &col_list, entry) {
		if (strcmp(col->name, name))
			continue;
		return col;
	}

	return NULL;
}

static void free_row(struct row_t *row)
{
	struct cell_t *cell;

	while (!list_empty(&row->cell_list)) {
		cell = list_entry(row->cell_list.next, typeof(*cell), entry);
		list_del(&cell->entry);
		_free(cell);
	}

	_free(row);
}

static void insert_row(struct list_head *list, struct row_t *row)
{
	struct row_t *row2, *row3;

	row3 = NULL;
	list_for_each_entry(row2, list, entry) {
		if (strcmp(row->order_key, row2->order_key) <= 0) {
			row3 = row2;
			break;
		}
	}
	if (row3)
		list_add_tail(&row->entry, &row3->entry);
	else
		list_add_tail(&row->entry, list);
}

static void format_bytes(char *buf, unsigned long long bytes)
{
	const char *suffix;
	unsigned int m;
	double d;

	if (bytes < 1024) {
		sprintf(buf, "%u B", (unsigned)bytes);
		return;
	}

	if (bytes < 1024*1024) {
		suffix = "KiB";
		m = 1024;
	} else if (bytes < 1024*1024*1024) {
		suffix = "MiB";
		m = 1024*1024;
	} else {
		suffix = "GiB";
		m = 1024*1024*1024;
	}

	d = (double)bytes/m;
	sprintf(buf, "%.1f %s", d, suffix);
}

static void print_ip6_dp_for_realtime(struct ap_session *ses, char *buf)
{
	inet_ntop(AF_INET6, &ses->ip6dp_4showsessions, buf, 64);
	char *ptr = strchr(buf, 0);
	sprintf(ptr, "/%i", ses->ip6dp_prefixlen);
}

static void print_ip6_for_realtime(struct ap_session *ses, char *buf)
{
	inet_ntop(AF_INET6, &ses->ip6addr_4showsessions, buf, 64);
	char *ptr = strchr(buf, 0);
	sprintf(ptr, "/%i", ses->ip6addr_prefixlen);
}

static void print_ip_for_realtime(struct ap_session *ses, char *buf)
{
	if (!ses->peeraddr_4showsessions) {
		print_ip6_for_realtime(ses,buf);
		return;
	}

	u_inet_ntoa(ses->peeraddr_4showsessions, buf);
}

static void print_ip6_dp(struct ap_session *ses, char *buf)
{
	struct ipv6db_addr_t *a;
	char *ptr;

	if (!ses->ipv6_dp) {
		*buf = 0;
		return;
	}

	a = list_entry(ses->ipv6_dp->prefix_list.next, typeof(*a), entry);
	inet_ntop(AF_INET6, &a->addr, buf, 64);
	ptr = strchr(buf, 0);
	sprintf(ptr, "/%i", a->prefix_len);
}

static void print_ip6(struct ap_session *ses, char *buf)
{
	struct ipv6db_addr_t *a;
	struct in6_addr addr;
	char *ptr;

	if (!ses->ipv6 || list_empty(&ses->ipv6->addr_list)) {
		*buf = 0;
		return;
	}

	a = list_entry(ses->ipv6->addr_list.next, typeof(*a), entry);
	if (a->prefix_len == 0) {
		*buf = 0;
		return;
	}

	build_ip6_addr(a, ses->ipv6->peer_intf_id, &addr);

	inet_ntop(AF_INET6, &addr, buf, 64);
	ptr = strchr(buf, 0);
	sprintf(ptr, "/%i", a->prefix_len);
}

static void print_ip(struct ap_session *ses, char *buf)
{
	if (!ses->ipv4) {
		print_ip6(ses,buf);
		return;
	}

	u_inet_ntoa(ses->ipv4->peer_addr, buf);
}

static int show_ses_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	char *columns = NULL;
	struct column_t *match_key = NULL;
	char *match_pattern = NULL;
	struct column_t *order_key = NULL;
	pcre *re = NULL;
	const char *pcre_err;
	int pcre_offset;
	struct column_t *column;
	struct col_t *col;
	struct row_t *row;
	struct cell_t *cell;
	char *ptr1, *ptr2;
	int i, n, total_width, def_columns = 0;
	struct ap_session *ses, *dumpses;
	char *buf = NULL;
	int match_key_f = 0, order_key_f = 0;
  int show_stats = 0;
	LIST_HEAD(c_list);
	LIST_HEAD(r_list);
	LIST_HEAD(t_list);
  LIST_HEAD(s_list);

	for (i = 2; i < f_cnt; i++) {
		if (!strcmp(f[i], "order")) {
			if (i == f_cnt - 1)
				return CLI_CMD_SYNTAX;
			order_key = find_column(f[++i]);
			if (!order_key) {
				cli_sendv(cli, "unknown column %s\r\n", f[i]);
				return CLI_CMD_OK;
			}
		} else if (!strcmp(f[i], "match")) {
			if (i >= f_cnt - 2)
				return CLI_CMD_SYNTAX;
			match_key = find_column(f[++i]);
			if (!match_key) {
				cli_sendv(cli, "unknown column %s\r\n", f[i]);
				return CLI_CMD_OK;
			}
			match_pattern = f[++i];
		} else if (!columns)
			columns = f[i];
		else
			return CLI_CMD_SYNTAX;
	}

	if (match_key) {
		re = pcre_compile2(match_pattern, 0, NULL, &pcre_err, &pcre_offset, NULL);
		if (!re) {
			cli_sendv(cli, "match: %s at %i\r\n", pcre_err, pcre_offset);
			return CLI_CMD_OK;
		}
	}

  pthread_rwlock_rdlock(&ses_lock);
  list_for_each_entry(ses, &ses_list, entry) {
    dumpses = calloc(1, sizeof(struct ap_session));
    memcpy(dumpses, ses, sizeof(struct ap_session));

    if (ses->ipv4 /*&& ses->ipv4->owner*/) {
      dumpses->peeraddr_4showsessions = ses->ipv4->peer_addr;
    }

    if (ses->ipv6 /*&& ses->ipv6->owner*/) {
      struct ipv6db_addr_t *a;
    	if (!ses->ipv6 || list_empty(&ses->ipv6->addr_list)) {
    		
    	} else {
      	a = list_entry(ses->ipv6->addr_list.next, typeof(*a), entry);
      	if (a->prefix_len != 0) {
          	build_ip6_addr(a, ses->ipv6->peer_intf_id, &dumpses->ip6addr_4showsessions);
            dumpses->ip6addr_prefixlen =  a->prefix_len;
      	}
      }
    }

    if (ses->ipv6_dp) {
      struct ipv6db_addr_t *a;
      a = list_entry(ses->ipv6_dp->prefix_list.next, typeof(*a), entry);
      memcpy(&dumpses->ip6dp_4showsessions, &a->addr, sizeof(struct in6_addr));
      dumpses->ip6dp_prefixlen = a->prefix_len;
    }

    if (ses->comp) {
      dumpses->comp_4showsessions = strdup(ses->comp);
    }

    if (ses->vrf_name) {
        dumpses->vrf_name = strdup(ses->vrf_name);
      }

    if (ses->username) {
      dumpses->username = strdup(ses->username);
    }

    if(ses->ctrl->name) {
      dumpses->ctrl_name = strdup(ses->ctrl->name);
    }
    if(ses->ctrl->ifname) {
      dumpses->ctrl_ifname = strdup(ses->ctrl->ifname);
    }
    if(ses->ctrl->service_name) {
      dumpses->ctrl_service_name = strdup(ses->ctrl->service_name);
    }
    if(ses->ctrl->calling_station_id) {
      dumpses->ctrl_calling_station_id = strdup(ses->ctrl->calling_station_id);
    }
    if(ses->ctrl->called_station_id) {
      dumpses->ctrl_called_station_id = strdup(ses->ctrl->called_station_id);
    }
    
    list_add_tail(&dumpses->entry, &s_list);
  }
  
  pthread_rwlock_unlock(&ses_lock);

	if (!columns) {
		columns = (conf_def_columns) ? conf_def_columns : DEF_COLUMNS;
		def_columns = 1;
	}

	columns = _strdup(columns);
	ptr1 = columns;
  if(strstr(columns, "x-bytes") || strstr(columns, "x-pkts"))
    show_stats = 1;
	while (1) {
		ptr2 = strchr(ptr1, ',');
		if (ptr2)
			*ptr2 = 0;
		column = find_column(ptr1);
		if (column == match_key)
			match_key_f = 1;
		if (column == order_key)
			order_key_f = 1;
		if (column) {
			col = _malloc(sizeof(*col));
			col->column = column;
			col->width = strlen(column->name);
			col->hidden = 0;
			list_add_tail(&col->entry, &c_list);
		} else {
			if (!def_columns) {
				cli_sendv(cli, "unknown column %s\r\n", ptr1);
				_free(columns);
				goto out;
			}
		}
		if (!ptr2)
			break;
		ptr1 = ptr2 + 1;
	}
	_free(columns);

	if (match_key && !match_key_f) {
		col = _malloc(sizeof(*col));
		col->column = match_key;
		col->width = 0;
		col->hidden = 1;
		list_add_tail(&col->entry, &c_list);
	}

	if (order_key && !order_key_f) {
		col = _malloc(sizeof(*col));
		col->column = order_key;
		col->width = 0;
		col->hidden = 1;
		list_add_tail(&col->entry, &c_list);
	}

	list_for_each_entry(ses, &s_list, entry) {
		stats_set = 0;
		row = _malloc(sizeof(*row));
		if (!row)
			goto oom;
		memset(row, 0, sizeof(*row));
		INIT_LIST_HEAD(&row->cell_list);
		if (match_key || order_key) {
			list_add_tail(&row->entry, &t_list);
      list_for_each_entry(col, &c_list, entry) {
  			char buf[CELL_SIZE];
  			if (col->column == order_key) {
    			col->column->print(ses, buf);
  				row->order_key = strdup(buf);
          row->ses = ses;
  			}
        if (col->column == match_key) {
    			col->column->print(ses, buf);
  				row->match_key = strdup(buf);
          row->ses = ses;
        }
  		}
		} else {
			list_add_tail(&row->entry, &r_list);
      if(show_stats)
        get_stats(ses);
  		list_for_each_entry(col, &c_list, entry) {
  			cell = _malloc(sizeof(*cell));
  			if (!cell)
  				goto oom;
  			cell->col = col;
  			list_add_tail(&cell->entry, &row->cell_list);
  			col->column->print(ses, cell->buf);
  			n = strlen(cell->buf);
  			if (n > col->width)
  				col->width = n;
  			if (col->column == order_key)
  				row->order_key = cell->buf;
  			if (col->column == match_key)
  				row->match_key = cell->buf;
  		}
    }
	}

	if (order_key || match_key) {
		while(!list_empty(&t_list)) {
			row = list_entry(t_list.next, typeof(*row), entry);
			list_del(&row->entry);
			if (match_key) {
				if (pcre_exec(re, NULL, row->match_key, strlen(row->match_key), 0, 0, NULL, 0) < 0) {
          if(row->match_key)
            free(row->match_key);
          if(row->order_key)
            free(row->order_key);
					free_row(row);
					continue;
				}
			}
      if(show_stats)
        get_stats(row->ses);
      list_for_each_entry(col, &c_list, entry) {
  			cell = _malloc(sizeof(*cell));
  			if (!cell)
  				goto oom;
  			cell->col = col;
  			list_add_tail(&cell->entry, &row->cell_list);
  			col->column->print(row->ses, cell->buf);
  			n = strlen(cell->buf);
  			if (n > col->width)
  				col->width = n;
  		}
			if (order_key)
				insert_row(&r_list, row);
			else
				list_add_tail(&row->entry, &r_list);
		}
	}

	total_width = -1;
	list_for_each_entry(col, &c_list, entry) {
		if (col->hidden)
			continue;
		total_width += col->width + 3;
	}

	if (total_width < 0)
		/* No column to print */
		goto early_out;

	buf = _malloc(total_width + 3);
	if (!buf)
		goto oom;

	ptr1 = buf;
	list_for_each_entry(col, &c_list, entry) {
		if (col->hidden)
			continue;
		n = strlen(col->column->name);
		if (col->width > n + 1) {
			ptr2 = ptr1;
			memset(ptr1, ' ', col->width/2 - n/2 + 1);
			ptr1 += col->width/2 - n/2 + 1;
			sprintf(ptr1, "%s", col->column->name);
			ptr1 = strchr(ptr1, 0);
			memset(ptr1, ' ', col->width + 2 - (ptr1 - ptr2));
			ptr1 += col->width + 2 - (ptr1 - ptr2);
			*ptr1 = '|';
			ptr1++;
		} else if (col->width > n) {
			sprintf(ptr1, " %s  |", col->column->name);
			ptr1 = strchr(ptr1, 0);
		} else {
			sprintf(ptr1, " %s |", col->column->name);
			ptr1 = strchr(ptr1, 0);
		}
	}

	strcpy(ptr1 - 1, "\r\n");
	cli_send(cli, buf);

	ptr1 = buf;
	list_for_each_entry(col, &c_list, entry) {
		if (col->hidden)
			continue;
		memset(ptr1, '-', col->width + 2);
		ptr1 += col->width + 2;
		*ptr1 = '+';
		ptr1++;
	}

	strcpy(ptr1 - 1, "\r\n");
	cli_send(cli, buf);

	while (!list_empty(&r_list)) {
		row = list_entry(r_list.next, typeof(*row), entry);
		ptr1 = buf;
		list_for_each_entry(cell, &row->cell_list, entry) {
			if (cell->col->hidden)
				continue;
			ptr2 = ptr1;
			sprintf(ptr1, " %s ", cell->buf);
			ptr1 = strchr(ptr1, 0);
			n = ptr1 - ptr2;
			if (n - 2 < cell->col->width) {
				memset(ptr1, ' ', cell->col->width + 2 - (ptr1 - ptr2));
				ptr1 += cell->col->width + 2 - (ptr1 - ptr2);
			}
			*ptr1 = '|';
			ptr1++;
		}
		strcpy(ptr1 - 1, "\r\n");
		cli_send(cli, buf);
		list_del(&row->entry);
    if(row->match_key)
      free(row->match_key);
    if(row->order_key)
      free(row->order_key);
		free_row(row);
	}

	_free(buf);

out:

  while (!list_empty(&s_list)) {
    dumpses = list_entry(s_list.next, typeof(*dumpses), entry);
    list_del(&dumpses->entry);
    if(dumpses->comp_4showsessions) free(dumpses->comp_4showsessions);
    if(dumpses->vrf_name) free(dumpses->vrf_name);
    if(dumpses->username) free(dumpses->username);
    if(dumpses->ctrl_name) free(dumpses->ctrl_name);
    if(dumpses->ctrl_ifname) free(dumpses->ctrl_ifname);
    if(dumpses->ctrl_service_name) free(dumpses->ctrl_service_name);
    if(dumpses->ctrl_calling_station_id) free(dumpses->ctrl_calling_station_id);
    if(dumpses->ctrl_called_station_id) free(dumpses->ctrl_called_station_id);
    free(dumpses);
  }

	while (!list_empty(&c_list)) {
		col = list_entry(c_list.next, typeof(*col), entry);
		list_del(&col->entry);
		_free(col);
	}

	if (re)
		pcre_free(re);

	return CLI_CMD_OK;

oom:
	cli_send(cli, "out of memory");
early_out:
	if (buf)
		_free(buf);

  while (!list_empty(&s_list)) {
    dumpses = list_entry(s_list.next, typeof(*dumpses), entry);
    list_del(&dumpses->entry);
    if(dumpses->comp_4showsessions) free(dumpses->comp_4showsessions);
    if(dumpses->vrf_name) free(dumpses->vrf_name);
    if(dumpses->username) free(dumpses->username);
    if(dumpses->ctrl_name) free(dumpses->ctrl_name);
    if(dumpses->ctrl_ifname) free(dumpses->ctrl_ifname);
    if(dumpses->ctrl_service_name) free(dumpses->ctrl_service_name);
    if(dumpses->ctrl_calling_station_id) free(dumpses->ctrl_calling_station_id);
    if(dumpses->ctrl_called_station_id) free(dumpses->ctrl_called_station_id);
    free(dumpses);
  }

	while (!list_empty(&t_list)) {
		row = list_entry(t_list.next, typeof(*row), entry);
		list_del(&row->entry);
		free_row(row);
	}
	goto out;
}

static void print_netns(struct ap_session *ses, char *buf)
{
	snprintf(buf, CELL_SIZE, "%s", ses->net->name);
}

static void print_vrf(struct ap_session *ses, char *buf)
{
	if (ses->vrf_name)
		snprintf(buf, CELL_SIZE, "%s", ses->vrf_name);
	else
		*buf = 0;
}

static void print_ifname(struct ap_session *ses, char *buf)
{
	snprintf(buf, CELL_SIZE, "%s", ses->ifname);
}

static void print_username(struct ap_session *ses, char *buf)
{
	if (ses->username)
		snprintf(buf, CELL_SIZE, "%s", ses->username);
	else
		*buf = 0;
}

static void print_type(struct ap_session *ses, char *buf)
{
	snprintf(buf, CELL_SIZE, "%s", ses->ctrl->name);
}

static void print_type_for_realtime(struct ap_session *ses, char *buf)
{
  if(ses->ctrl_name)
    snprintf(buf, CELL_SIZE, "%s", ses->ctrl_name);
  else
    *buf = 0;
}

static void print_state(struct ap_session *ses, char *buf)
{
	char *state;
	switch (ses->state) {
		case AP_STATE_STARTING:
			state = "start";
			break;
		case AP_STATE_ACTIVE:
			state = "active";
			break;
		case AP_STATE_FINISHING:
			state = "finish";
			break;
		default:
			state = "unk";
	}
	sprintf(buf, "%s", state);
}

void print_uptime(struct ap_session *ses, char *buf)
{
	time_t uptime;
	int day,hour,min,sec;
	char time_str[24];

	if (ses->stop_time)
		uptime = ses->stop_time - ses->start_time;
	else {
		uptime = _time();
		uptime -= ses->start_time;
	}

	day = uptime/ (24*60*60); uptime %= (24*60*60);
	hour = uptime / (60*60); uptime %= (60*60);
	min = uptime / 60;
	sec = uptime % 60;
	if (day)
		snprintf(time_str, sizeof(time_str), "%i.%02i:%02i:%02i", day, hour, min, sec);
	else
		snprintf(time_str, sizeof(time_str), "%02i:%02i:%02i", hour, min, sec);

	sprintf(buf, "%s", time_str);
}

static void print_uptime_raw(struct ap_session *ses, char *buf)
{
	time_t uptime;

	if (ses->stop_time)
		uptime = ses->stop_time - ses->start_time;
	else
		uptime = _time() - ses->start_time;

	sprintf(buf, "%lu", (unsigned long)uptime);
}

static void print_calling_sid(struct ap_session *ses, char *buf)
{
	snprintf(buf, CELL_SIZE, "%s", ses->ctrl->calling_station_id);
}

static void print_called_sid(struct ap_session *ses, char *buf)
{
	snprintf(buf, CELL_SIZE, "%s", ses->ctrl->called_station_id);
}

static void print_calling_sid_for_realtime(struct ap_session *ses, char *buf)
{
  if(ses->ctrl_calling_station_id)
    snprintf(buf, CELL_SIZE, "%s", ses->ctrl_calling_station_id);
  else
    *buf = 0;
}

static void print_called_sid_for_realtime(struct ap_session *ses, char *buf)
{
  if(ses->ctrl_called_station_id)
    snprintf(buf, CELL_SIZE, "%s", ses->ctrl_called_station_id);
  else
    *buf = 0;
}

static void print_sid(struct ap_session *ses, char *buf)
{
	snprintf(buf, CELL_SIZE, "%s", ses->sessionid);
}

static void print_comp(struct ap_session *ses, char *buf)
{
	if (ses->comp)
		snprintf(buf, CELL_SIZE, "%s", ses->comp);
	else
		buf[0] = 0;
}

static void print_comp_for_realtime(struct ap_session *ses, char *buf)
{
	if (ses->comp_4showsessions)
		snprintf(buf, CELL_SIZE, "%s", ses->comp_4showsessions);
	else
		buf[0] = 0;
}

void get_stats(struct ap_session *ses) {
	pppoe_session_accounting_t accounting;
 	vpp_api_pppoe_session_accounting(ses->ppp_info.addr, ses->ipv4? ses->ipv4->peer_addr:0, &accounting, ses->is_ipoe);
	stats.rx_bytes = accounting.acct_input_octets + accounting.acct_input_octets_ipv6;
	stats.tx_bytes = accounting.acct_output_octets + accounting.acct_output_octets_ipv6;
	stats.rx_packets = accounting.acct_input_packets + accounting.acct_input_packets_ipv6;
	stats.tx_packets = accounting.acct_output_packets + accounting.acct_output_packets_ipv6;

	/*stats.rx_bytes = ses->acct_rx_bytes;
	stats.tx_bytes = ses->acct_tx_bytes;
	stats.rx_packets = ses->acct_rx_packets;
	stats.tx_packets = ses->acct_tx_packets;*/
}

static void print_traffic(struct ap_session *ses, char *buf)
{

  pppoe_session_accounting_t accounting;
  vpp_api_pppoe_session_accounting(ses->ppp_info.addr, ses->ipv4? ses->ipv4->peer_addr:0, &accounting, ses->is_ipoe);
  
  snprintf(buf, CELL_SIZE, "{tx:%llu, rx:%llu}", 
    accounting.acct_output_octets + accounting.acct_output_octets_ipv6,
    accounting.acct_input_octets + accounting.acct_input_octets_ipv6);
}

static void print_rx_bytes(struct ap_session *ses, char *buf)
{
	/*if (!stats_set) {
		get_stats(ses);
		stats_set = 1;
	}*/
	format_bytes(buf, stats.rx_bytes);
}

static void print_tx_bytes(struct ap_session *ses, char *buf)
{
	/*if (!stats_set) {
		get_stats(ses);
		stats_set = 1;
	}*/
	format_bytes(buf, stats.tx_bytes);
}

static void print_rx_bytes_raw(struct ap_session *ses, char *buf)
{
	/*if (!stats_set) {
		get_stats(ses);
		stats_set = 1;
	}*/
	sprintf(buf, "%llu", stats.rx_bytes);
}

static void print_tx_bytes_raw(struct ap_session *ses, char *buf)
{
	/*if (!stats_set) {
		get_stats(ses);
		stats_set = 1;
	}*/
	sprintf(buf, "%llu", stats.tx_bytes);
}

static void print_rx_pkts(struct ap_session *ses, char *buf)
{
	/*if (!stats_set) {
		get_stats(ses);
		stats_set = 1;
	}*/
	sprintf(buf, "%llu", stats.rx_packets);
}

static void print_tx_pkts(struct ap_session *ses, char *buf)
{
	/*if (!stats_set) {
		get_stats(ses);
		stats_set = 1;
	}*/
	sprintf(buf, "%llu", stats.tx_packets);
}

static void print_inbound_if(struct ap_session *ses, char *buf)
{
	if (ses->ctrl->ifname)
		snprintf(buf, CELL_SIZE, "%s", ses->ctrl->ifname);
}

static void print_service_name(struct ap_session *ses, char *buf)
{
	if (ses->ctrl->service_name)
		snprintf(buf, CELL_SIZE, "%s", ses->ctrl->service_name);
}

static void print_inbound_if_for_realtime(struct ap_session *ses, char *buf)
{
  *buf = 0;
	if (ses->ctrl_ifname)
		snprintf(buf, CELL_SIZE, "%s", ses->ctrl_ifname);
}

static void print_service_name_for_realtime(struct ap_session *ses, char *buf)
{
  if (ses->ctrl_service_name)
    snprintf(buf, CELL_SIZE, "%s", ses->ctrl_service_name);
  else
    *buf = 0;

}

static void print_rate_limit(struct ap_session *ses, char *buf)
{
	sprintf(buf, "%d/%d", ses->microbng_bandwidth_max_up, ses->microbng_bandwidth_max_down);
}

static int show_oneuser_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
  struct ap_session *ses;
  enum oneuser_matchkey match_key = MATCHKEY_NONE;
  char *match_value = NULL;
  char mac_str[CELL_SIZE];

  if(f_cnt < 3)
    return CLI_CMD_SYNTAX;

  if( !strncmp(f[2], "username=", 9) ) {
    match_key =  MATCHKEY_USERNAME;
    match_value = f[2] + 9;
  } else if( !strncmp(f[2], "MAC=", 4) ) {
    match_key = MATCHKEY_MAC;
    match_value = f[2] + 4;
  } else if( !strncmp(f[2], "sid=", 4) ) {
    match_key = MATCHKEY_SID;
    match_value = f[2] + 4;
  }

  if(match_key == MATCHKEY_NONE)
    return CLI_CMD_SYNTAX;

  log_debug("match_key=%d, match_value=%s\n", match_key, match_value);

  pthread_rwlock_rdlock(&ses_lock);
  list_for_each_entry(ses, &ses_list, entry) {
    if( match_key==MATCHKEY_USERNAME && (ses->username && !strcmp(match_value, ses->username)) ) {
      show_one_user(ses, cli);
      break;
    }
    else if( match_key==MATCHKEY_MAC ) {
      snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
        ses->ppp_info.addr[0], ses->ppp_info.addr[1], ses->ppp_info.addr[2], 
        ses->ppp_info.addr[3], ses->ppp_info.addr[4], ses->ppp_info.addr[5]);
      if(!strcasecmp(match_value, mac_str)) {
        show_one_user(ses, cli);
        break;
      }
    }
    else if( match_key==MATCHKEY_SID && !strcmp(match_value, ses->sessionid) ) {
      show_one_user(ses, cli);
      break;
    }
  }
	pthread_rwlock_unlock(&ses_lock);
  return CLI_CMD_OK;
}

void show_one_user(struct ap_session *ses, void *cli)
{

  char buf[256];
  pppoe_session_accounting_t accounting;
  vpp_api_pppoe_session_accounting(ses->ppp_info.addr, ses->ipv4? ses->ipv4->peer_addr:0, &accounting, ses->is_ipoe);
  cli_sendv(cli, "  MAC=%02x:%02x:%02x:%02x:%02x:%02x login=%s SessionID=0x%04x (net=0x%04x)\n",
    ses->ppp_info.addr[0], ses->ppp_info.addr[1], ses->ppp_info.addr[2], 
    ses->ppp_info.addr[3], ses->ppp_info.addr[4], ses->ppp_info.addr[5],
    ses->username?:"", ses->ppp_info.pppoe_sid, htons(ses->ppp_info.pppoe_sid));

  print_state(ses, buf);
  cli_sendv(cli, "  State: %s", buf);
  print_uptime(ses, buf);
  cli_sendv(cli, ", Uptime: %s", buf);
  cli_sendv(cli, ", Acct-SessionID: %s\n", ses->sessionid);

  print_type(ses, buf);
  cli_sendv(cli, "  type: %s,", buf);
  print_inbound_if(ses, buf);
  cli_sendv(cli, " inbound-if: %s\n", buf);

  print_rate_limit(ses, buf);
  cli_sendv(cli, "  Rate-Limit=%s\n", buf);

  if(ses->ipv4) {
    u_inet_ntoa(ses->ipv4->peer_addr, buf);
    cli_sendv(cli, "  IP=%s\n", buf);
    /*u_inet_ntoa(conf_dns1, buf);
    cli_sendv(cli, " DNS1=%s", buf);
    u_inet_ntoa(conf_dns2, buf);
    cli_sendv(cli, " DNS2=%s\n", buf);*/
    cli_sendv(cli, "    Statistics");
    format_bytes(buf, accounting.acct_input_octets);
    cli_sendv(cli, " rx-bytes=%s,", buf);
    format_bytes(buf, accounting.acct_output_octets);
    cli_sendv(cli, " tx-bytes=%s,", buf);
    cli_sendv(cli, " rx-packets=%llu,", accounting.acct_input_packets);
    cli_sendv(cli, " tx-packets=%llu,", accounting.acct_output_packets);
    cli_sendv(cli, " rx-bytes-raw=%llu,", accounting.acct_input_octets);
    cli_sendv(cli, " tx-bytes-raw=%llu\n", accounting.acct_output_octets);
  }
  
  if(ses->ipv6) {
    print_ip6(ses, buf);
    cli_sendv(cli, "  IP6=%s", buf);
    print_ip6_dp(ses, buf);
    cli_sendv(cli, ", IP6-DP=%s\n", buf);
    cli_sendv(cli, "    Statistics");
    format_bytes(buf, accounting.acct_input_octets_ipv6);
    cli_sendv(cli, " rx-bytes=%s,", buf);
    format_bytes(buf, accounting.acct_output_octets_ipv6);
    cli_sendv(cli, " tx-bytes=%s,", buf);
    cli_sendv(cli, " rx-packets=%llu,", accounting.acct_input_packets_ipv6);
    cli_sendv(cli, " tx-packets=%llu,", accounting.acct_output_packets_ipv6);
    cli_sendv(cli, " rx-bytes-raw=%llu,", accounting.acct_input_octets_ipv6);
    cli_sendv(cli, " tx-bytes-raw=%llu\n", accounting.acct_output_octets_ipv6);
  } else {
    //cli_sendv(cli, "  IP6=  IP6-DP=\n");
  }

  cli_sendv(cli, "  Total Statistics");
  format_bytes(buf, accounting.acct_input_octets + accounting.acct_input_octets_ipv6);
  cli_sendv(cli, " rx-bytes=%s,", buf);
  format_bytes(buf, accounting.acct_output_octets + accounting.acct_output_octets_ipv6);
  cli_sendv(cli, " tx-bytes=%s,", buf);
  cli_sendv(cli, " rx-packets=%llu,", accounting.acct_input_packets + accounting.acct_input_packets_ipv6);
  cli_sendv(cli, " tx-packets=%llu,", accounting.acct_output_packets + accounting.acct_output_packets_ipv6);
  cli_sendv(cli, " rx-bytes-raw=%llu,", accounting.acct_input_octets + accounting.acct_input_octets_ipv6);
  cli_sendv(cli, " tx-bytes-raw=%llu\n", accounting.acct_output_octets + accounting.acct_output_octets_ipv6);

}


static void show_traffic(struct ap_session *ses, void *cli)
{

  char buf[256];
  pppoe_session_accounting_t accounting;
  vpp_api_pppoe_session_accounting(ses->ppp_info.addr, ses->ipv4? ses->ipv4->peer_addr:0, &accounting, ses->is_ipoe);
  print_traffic(ses, buf);
  cli_sendv(cli, "%s", buf);
}

static int show_traffic_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
  struct ap_session *ses;
  enum oneuser_matchkey match_key = MATCHKEY_NONE;
  char *match_value = NULL;
  char mac_str[CELL_SIZE];

  if(f_cnt < 3)
    return CLI_CMD_SYNTAX;

  if( !strncmp(f[2], "username=", 9) ) {
    match_key =  MATCHKEY_USERNAME;
    match_value = f[2] + 9;
  } else if( !strncmp(f[2], "MAC=", 4) ) {
    match_key = MATCHKEY_MAC;
    match_value = f[2] + 4;
  } else if( !strncmp(f[2], "sid=", 4) ) {
    match_key = MATCHKEY_SID;
    match_value = f[2] + 4;
  }

  if(match_key == MATCHKEY_NONE)
    return CLI_CMD_SYNTAX;

  log_debug("match_key=%d, match_value=%s\n", match_key, match_value);

  pthread_rwlock_rdlock(&ses_lock);
  list_for_each_entry(ses, &ses_list, entry) {
    if( match_key==MATCHKEY_USERNAME && (ses->username && !strcmp(match_value, ses->username)) ) {
      show_traffic(ses, cli);
      break;
    }
    else if( match_key==MATCHKEY_MAC ) {
      snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
        ses->ppp_info.addr[0], ses->ppp_info.addr[1], ses->ppp_info.addr[2], 
        ses->ppp_info.addr[3], ses->ppp_info.addr[4], ses->ppp_info.addr[5]);
      if(!strcasecmp(match_value, mac_str)) {
        show_traffic(ses, cli);
        break;
      }
    }
    else if( match_key==MATCHKEY_SID && !strcmp(match_value, ses->sessionid) ) {
      show_traffic(ses, cli);
      break;
    }
  }
	pthread_rwlock_unlock(&ses_lock);
  return CLI_CMD_OK;
}

static void load_config(void *data)
{
	const char *opt = NULL;
	char *ptr = NULL;

	opt = conf_get_opt("cli", "sessions-columns");
	if (opt && strlen(opt) > 0) {
		ptr = _realloc(conf_def_columns, strlen(opt) + 1);
		if (ptr) {
			memcpy(ptr, opt, strlen(opt) + 1);
			conf_def_columns = ptr;
		} else
			log_error("cli: Discard option sessions-columns:"
				  " memory allocation error\n");
	}
	if (ptr == NULL && conf_def_columns) {
		_free(conf_def_columns);
		conf_def_columns = NULL;
	}
}

static void init(void)
{
	load_config(NULL);

	cli_register_simple_cmd2(show_ses_exec, show_ses_help, 2, "show", "sessions");
  cli_register_simple_cmd2(show_oneuser_exec, show_oneuser_help, 2, "show", "session");
  cli_register_simple_cmd2(show_traffic_exec, show_traffic_help, 2, "show", "traffic");

	cli_show_ses_register("traffic", "rx/tx bytes (json)", print_traffic);
	cli_show_ses_register("netns", "network namespace name", print_netns);
	cli_show_ses_register("vrf", "vrf name", print_vrf);
	cli_show_ses_register("ifname", "interface name", print_ifname);
	cli_show_ses_register("username", "user name", print_username);
	cli_show_ses_register("ip", "IP address", print_ip_for_realtime);
	cli_show_ses_register("ip6", "IPv6 address", print_ip6_for_realtime);
	cli_show_ses_register("ip6-dp", "IPv6 delegated prefix", print_ip6_dp_for_realtime);
	cli_show_ses_register("type", "connection type", print_type_for_realtime);
	cli_show_ses_register("state", "state of session", print_state);
	cli_show_ses_register("uptime", "uptime (human readable)", print_uptime);
	cli_show_ses_register("uptime-raw", "uptime (in seconds)", print_uptime_raw);
	cli_show_ses_register("calling-sid", "calling station id", print_calling_sid_for_realtime);
	cli_show_ses_register("called-sid", "called station id", print_called_sid_for_realtime);
	cli_show_ses_register("sid", "session id", print_sid);
	cli_show_ses_register("comp", "compression/encryption method", print_comp_for_realtime);
	cli_show_ses_register("rx-bytes", "received bytes (human readable)", print_rx_bytes);
	cli_show_ses_register("tx-bytes", "transmitted bytes (human readable)", print_tx_bytes);
	cli_show_ses_register("rx-bytes-raw", "received bytes", print_rx_bytes_raw);
	cli_show_ses_register("tx-bytes-raw", "transmitted bytes", print_tx_bytes_raw);
	cli_show_ses_register("rx-pkts", "received packets", print_rx_pkts);
	cli_show_ses_register("tx-pkts", "transmitted packets", print_tx_pkts);
	cli_show_ses_register("inbound-if", "inbound interface", print_inbound_if_for_realtime);
	cli_show_ses_register("service-name", "PPPoE service name", print_service_name_for_realtime);
	cli_show_ses_register("rate-limit", "MicroBNG rate limit", print_rate_limit);

	triton_event_register_handler(EV_CONFIG_RELOAD, load_config);
}

DEFINE_INIT(12, init);
