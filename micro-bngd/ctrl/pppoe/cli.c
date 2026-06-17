#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "triton.h"
#include "cli.h"
#include "ppp.h"
#include "memdebug.h"

#include "pppoe.h"

static void show_interfaces(void *cli)
{
	struct pppoe_serv_t *serv;

	cli_send(cli, "interface:   connections:    state:\r\n");
	cli_send(cli, "-----------------------------------\r\n");

	pthread_rwlock_rdlock(&serv_lock);
	list_for_each_entry(serv, &serv_list, entry) {
		cli_sendv(cli, "%9s    %11u    %6s\r\n", serv->ifname, serv->conn_cnt, serv->stopping ? "stop" : "active");
	}
	pthread_rwlock_unlock(&serv_lock);
}

static void intf_help(char * const *fields, int fields_cnt, void *client)
{
	uint8_t show = 7;

	if (fields_cnt >= 3) {
		show &= (strcmp(fields[1], "add")) ? ~1 : ~0;
		show &= (strcmp(fields[1], "del")) ? ~2 : ~0;
		show &= (strcmp(fields[1], "show")) ? ~4 : ~0;
		if (show == 0) {
			cli_sendv(client, "Invalid action \"%s\"\r\n",
				  fields[2]);
			show = 7;
		}
	}
	if (show & 1)
		cli_send(client,
			 "pppoe add interface <name>"
			 " - start pppoe server on specified interface\r\n");
	if (show & 2)
		cli_send(client,
			 "pppoe del interface <name>"
			 " - stop pppoe server on specified interface and"
			 " drop his connections\r\n");
	if (show & 4)
		cli_send(client,
			 "pppoe show interface"
			 " - show interfaces on which pppoe server"
			 " started\r\n\r\n");
}

static void add_intf_help(char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "pppoe add interface <name>"
		 " - start pppoe server on specified interface\r\n");
}

static void del_intf_help(char * const *fields, int fields_cnt, void *client)
{
	cli_send(client,
		 "pppoe del interface <name>"
		 " - stop pppoe server on specified interface and"
		 " drop his connections\r\n");
}

static void show_intf_help(char * const *fields, int fields_cnt, void *client)
{
	cli_send(client,
		 "pppoe show interface"
		 " - show interfaces on which pppoe server"
		 " started\r\n\r\n");
}

static int intf_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	if (fields_cnt == 2)
		goto help;

	if (fields_cnt == 3) {
		if (!strcmp(fields[1], "show"))
			show_interfaces(client);
		else
			goto help;

		return CLI_CMD_OK;
	}

	if (fields_cnt != 4)
		goto help;

	if (!strcmp(fields[1], "add"))
		pppoe_server_start(fields[3], client);
	else if (!strcmp(fields[1], "del"))
		pppoe_server_stop(fields[3]);
	else
		goto help;

	return CLI_CMD_OK;
help:
	intf_help(fields, fields_cnt, client);
	return CLI_CMD_OK;
}

static int add_intf_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	if (fields_cnt != 4)
		goto help;

	pppoe_server_start(fields[3], client);

	return CLI_CMD_OK;
help:
	add_intf_help(fields, fields_cnt, client);
	return CLI_CMD_OK;
}

static int del_intf_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	if (fields_cnt != 4)
		goto help;

	pppoe_server_stop(fields[3]);

	return CLI_CMD_OK;
help:
	del_intf_help(fields, fields_cnt, client);
	return CLI_CMD_OK;
}
static int show_intf_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	if (fields_cnt != 3)
		goto help;

	show_interfaces(client);
	
	return CLI_CMD_OK;
help:
	show_intf_help(fields, fields_cnt, client);
	return CLI_CMD_OK;
}


//===================================

static int show_stat_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "pppoe:\r\n");
	cli_sendv(client, "  active: %u\r\n", stat_session_active);
	cli_sendv(client, "  starting: %u\r\n", stat_starting);
	cli_sendv(client, "  filtered: %lu\r\n", stat_filtered);
	cli_sendv(client, "  sent PADS: %lu\r\n", stat_PADS_sent);
	cli_sendv(client, "  recv PADR(dup): %lu(%lu)\r\n", stat_PADR_recv, stat_PADR_dup_recv);
	cli_sendv(client, "  sent PADO: %lu\r\n", stat_PADO_sent);
	cli_sendv(client, "  delayed PADO: %u\r\n", stat_delayed_pado);
	cli_sendv(client, "  drop PADI: %lu\r\n", stat_PADI_drop);
	cli_sendv(client, "  recv PADI: %lu\r\n", stat_PADI_recv);
	cli_sendv(client, "  recv PADI/sec: %lu\r\n", PADI_per_Second);

	return CLI_CMD_OK;
}

//===================================

static void set_verbose_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "pppoe set verbose <n> - set verbosity of pppoe logging\r\n");
}

static void set_interface_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "pppoe set interface <name> service-name <sn1,sn2> - Sets one or more service names for a specific interface\r\n"
		"pppoe set interface <name> accept-any-service <1|0> - Enables or disables accepting a blank service name on a specific interface\r\n"
		"pppoe set interface <name> accept-blank-service <1|0> - Enables or disables accepting any service name on a specific interface\r\n\r\n");
}

static void clear_service_name_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "pppoe clear service-name interface <name>  - Clears all service-name settings on a specific interface\r\n\r\n");
}

static void set_pado_delay_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "pppoe set PADO-delay <delay[,delay1:count1[,delay2:count2[,...]]]> - set PADO delays (ms)\r\n");
	cli_send(cli, "pppoe set PADO-delay interface <name> <delay[,delay1:count1[,delay2:count2[,...]]]> - set PADO delays (ms) on a specific interface\r\n");
}

static void set_service_name_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "pppoe set service-name <name> - Sets the global service-name to respond with\r\n");
	cli_send(cli, "pppoe set service-name accept-any-service <1|0> - Enables or disables accepting any service name globally\r\n");
	cli_send(cli, "pppoe set service-name accept-blank-service <1|0> - Enables or disables accepting a blank service name globally\r\n\r\n");
}

static void set_ac_name_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "pppoe set AC-Name <name> - set AC-Name tag value\r\n\r\n");
}

static void show_verbose_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "pppoe show verbose - show current verbose value\r\n");
}

static void show_pado_delay_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "pppoe show PADO-delay - show current PADO delay value\r\n");
    cli_send(cli, "pppoe show PADO-delay interface <name> - show current PADO delay value on a specific interface\r\n\r\n");
}

static void show_service_name_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "pppoe show service-name - Display the active global service-name\r\n");
	cli_send(cli, "pppoe show service-name interface <name> -  Shows the active service-name on a specific interface\r\n\r\n");
}

static void show_ac_name_help(char * const *f, int f_cnt, void *cli)
{
	cli_send(cli, "pppoe show AC-Name - show current AC-Name tag value\r\n");
}

static int show_verbose_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt != 3)
		return CLI_CMD_SYNTAX;

	cli_sendv(cli, "%i\r\n", conf_verbose);

	return CLI_CMD_OK;
}

static int show_pado_delay_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt == 4 || f_cnt > 5)
		return CLI_CMD_SYNTAX;

    if (f_cnt == 3) {
	    cli_sendv(cli, "%s\r\n", conf_pado_delay);
    }
    else {
        if(!strcmp(f[3], "interface") ) {
            struct interface_pado_delay_s *data;
            char *iface = f[4];
            hashtable_rc_t hashrt = obj_hashtable_ts_get(ptr_conf_interface_pado_delay, iface, strlen(iface), (void * *)&data);
            if(hashrt == HASH_TABLE_OK) {
                char *ptr_pado = strchr(data->conf_pado_delay, ',');
                cli_sendv(cli, "%s\r\n", ptr_pado?ptr_pado+1:"0");
                obj_hashtable_ts_nodes_unlock(ptr_conf_interface_pado_delay, iface, strlen(iface));
            }
            else {
                cli_sendv(cli, "0\r\n");
            }
        }
        else {
            return CLI_CMD_SYNTAX;
        }
    }

	return CLI_CMD_OK;
}

static int show_service_name_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt < 3)
		return CLI_CMD_SYNTAX;

	if(f_cnt == 3) {
		if (conf_service_name[0]) {
			int i = 0;
			do {
			    cli_sendv(cli, "%s", conf_service_name[i]);
			    i++;
			    if (conf_service_name[i]) { cli_sendv(cli, ","); }
			} while(conf_service_name[i]);
			cli_sendv(cli, "\r\n");
		} else
			cli_sendv(cli, "*\r\n");
		cli_sendv(cli, "accept-blank-service=%d\r\n", conf_accept_blank_service);
		cli_sendv(cli, "accept-any-service=%d\r\n", conf_accept_any_service);
	} else if(f_cnt == 5 && !strcmp(f[3], "interface")) {
		struct pppoe_interface_config_t *interface_conf = NULL;
		for(int i=0; i<MAX_CONF_INTERFACES; i++) {
			if(conf_interface_config[i].ifname == NULL)
				break;
			if(!strcmp(conf_interface_config[i].ifname, f[4])) {
				interface_conf = &conf_interface_config[i];
				break;
			}
		}
		
		if(interface_conf) {
			if (interface_conf->service_name[0]) {
				int i = 0;
				do {
				    cli_sendv(cli, "%s", interface_conf->service_name[i]);
				    i++;
				    if (interface_conf->service_name[i]) { cli_sendv(cli, ","); }
				} while(interface_conf->service_name[i]);
				cli_sendv(cli, "\r\n");
			} else
				cli_sendv(cli, "*\r\n");
			cli_sendv(cli, "accept-blank-service=%d\r\n", interface_conf->accept_blank_service);
			cli_sendv(cli, "accept-any-service=%d\r\n", interface_conf->accept_any_service);
		} else {
			cli_sendv(cli, "No service name configured.\r\n");;
    }
	}
	return CLI_CMD_OK;
}

static int show_ac_name_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt != 3)
		return CLI_CMD_SYNTAX;

	cli_sendv(cli, "%s\r\n", conf_ac_name);

	return CLI_CMD_OK;
}

static int set_verbose_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt != 4)
		return CLI_CMD_SYNTAX;

	if (!strcmp(f[3], "0"))
		conf_verbose = 0;
	else if (!strcmp(f[3], "1"))
		conf_verbose = 1;
	else
		return CLI_CMD_INVAL;

	return CLI_CMD_OK;
}

static int set_interface_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt != 6)
		return CLI_CMD_SYNTAX;

	struct pppoe_interface_config_t *interface_conf = NULL;
	for(int i=0; i<MAX_CONF_INTERFACES; i++) {
		if(conf_interface_config[i].ifname == NULL) {
			conf_interface_config[i].ifname = _strdup(f[3]);
			interface_conf = &conf_interface_config[i];
			break;
		}
    
		if(!strcmp(conf_interface_config[i].ifname, f[3])) {
			interface_conf = &conf_interface_config[i];
			break;
		}
	}

	if(interface_conf == NULL)
		return CLI_CMD_FAILED;

	if(!strncmp(f[4], "service-name", sizeof("service-name") - 1)) {
		if (interface_conf->service_name[0]) {
			int i = 0;
			do {
			    _free(interface_conf->service_name[i]);
			    i++;
			} while(interface_conf->service_name[i]);
			interface_conf->service_name[0] = NULL;
		}
		char *conf_service_name_string = _strdup(f[5]);
		char *p = strtok (conf_service_name_string, ",");
		int i = 0;
		while (p != NULL && i<255) {
		    interface_conf->service_name[i++] = _strdup(p);
				printf("sn=%s\n", interface_conf->service_name[i-1]);
		    p = strtok(NULL, ",");
		}
		interface_conf->service_name[i] = NULL;
		_free(conf_service_name_string);
		printf(" %s,service-name=%s\n", interface_conf->ifname, f[5]);
	} else if (!strncmp(f[4], "accept-any-service", sizeof("accept-any-service") - 1)) {
		interface_conf->accept_any_service = strtol(f[5], NULL, 10);
		printf(" %s,accept-any-service=%d\n", interface_conf->ifname, interface_conf->accept_any_service);
	} else if (!strncmp(f[4], "accept-blank-service", sizeof("accept-blank-service") - 1)) {
		interface_conf->accept_blank_service = strtol(f[5], NULL, 10);
		printf(" %s,accept-blank-service=%d\n", interface_conf->ifname, interface_conf->accept_blank_service);
	}
	else
		return CLI_CMD_INVAL;

	return CLI_CMD_OK;
}

static int clear_service_name_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt != 5)
		return CLI_CMD_SYNTAX;
	
	for(int i=0; i<MAX_CONF_INTERFACES; i++) {
		if(conf_interface_config[i].ifname == NULL)
			break;
		printf("%s,%s\n", conf_interface_config[i].ifname, f[4]);

		if(!strcmp(conf_interface_config[i].ifname, f[4])) {

      // free the current interface config
      if (conf_interface_config[i].service_name[0]) {
    		int aa = 0;
    		do {
    		    _free(conf_interface_config[i].service_name[aa]);
    		    aa++;
    		} while(conf_interface_config[i].service_name[aa]);
    		conf_interface_config[i].service_name[0] = NULL;
    	}
      _free(conf_interface_config[i].ifname);
      conf_interface_config[i].ifname = NULL;

      int j;
      for(j=i; j<MAX_CONF_INTERFACES-1; j++) {
        memcpy(&conf_interface_config[j], &conf_interface_config[j+1], sizeof(struct pppoe_interface_config_t));
        if(conf_interface_config[j+1].ifname == NULL)
          break;
      }

      // lastest
    	conf_interface_config[j].service_name[0] = NULL;
      conf_interface_config[j].ifname = NULL;
      
			break;
		}
	}

	return CLI_CMD_OK;
}

static int set_pado_delay_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt !=4 && f_cnt != 6)
		return CLI_CMD_SYNTAX;

    if (f_cnt == 4) {
    	if (dpado_parse(f[3]))
    		return CLI_CMD_INVAL;
    }
    else {
        if( !strcmp(f[3], "interface") ) {
            char iface_pado_str[256];
            snprintf(iface_pado_str, sizeof(iface_pado_str), "%s,%s", f[4], f[5]);
            if (dpado_parse_iface(iface_pado_str))
                return CLI_CMD_INVAL;
        }
        else {
            return CLI_CMD_SYNTAX;
        }
    }
    
	return CLI_CMD_OK;
}

static int set_service_name_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt < 4)
		return CLI_CMD_SYNTAX;

	if ( !strcmp(f[3], "accept-blank-service") && f_cnt == 5) {
		conf_accept_blank_service = strtol(f[4], NULL, 10);
	} else if ( !strcmp(f[3], "accept-any-service") && f_cnt == 5) {
		conf_accept_any_service = strtol(f[4], NULL, 10);
	} else if(f_cnt == 4) {
		if (conf_service_name[0]) {
			int i = 0;
			do {
			    _free(conf_service_name[i]);
			    i++;
			} while(conf_service_name[i]);
			conf_service_name[0] = NULL;
		}
		if (!strcmp(f[3], "*"))
			conf_service_name[0] = NULL;
		else {
		    char *conf_service_name_string = _strdup(f[3]);
		    char *p = strtok (conf_service_name_string, ",");
		    int i = 0;
		    while (p != NULL && i<255) {
			conf_service_name[i++] = _strdup(p);
			p = strtok(NULL, ",");
		    }
		    conf_service_name[i] = NULL;
		    _free(conf_service_name_string);
		}
	} else
		return CLI_CMD_SYNTAX;
	
	return CLI_CMD_OK;
}

static int set_ac_name_exec(const char *cmd, char * const *f, int f_cnt, void *cli)
{
	if (f_cnt != 4)
		return CLI_CMD_SYNTAX;

	_free(conf_ac_name);
	conf_ac_name = _strdup(f[3]);

	return CLI_CMD_OK;
}
//===================================



static void show_hashtable_help(char * const *fields, int fields_cnt, void *client)
{
	cli_send(client, "pppoe show hashtable - show PPPoE myhashtable element counters\r\n");
	cli_send(client, "  Checks declared num_elements against counted nodes for cookie_2_conn and mac_sessid_2_conn.\r\n");
}

static void show_obj_hashtable_line(void *client, const char *ifname, const char *table_name,
					 obj_hash_table_t *table)
{
	myhashtable_stats_t st;
	hashtable_rc_t rc;

	rc = obj_hashtable_ts_get_stats(table, &st);
	if (rc != HASH_TABLE_OK) {
		cli_sendv(client, "%s %-22s error=%d\r\n", ifname ? ifname : "-", table_name, rc);
		return;
	}

	cli_sendv(client,
		"%-16s %-22s size=%-6lu declared=%-8u counted=%-8u used-buckets=%-6u max-chain=%-4u mismatch=%s\r\n",
		ifname ? ifname : "-",
		table_name,
		(unsigned long)st.size,
		st.declared_elements,
		st.actual_elements,
		st.used_buckets,
		st.max_chain,
		(st.declared_elements == st.actual_elements) ? "no" : "YES");
}

static void show_hash64_hashtable_line(void *client, const char *ifname, const char *table_name,
					    hash64_table_t *table)
{
	myhashtable_stats_t st;
	hashtable_rc_t rc;

	rc = hashtable64_ts_get_stats(table, &st);
	if (rc != HASH_TABLE_OK) {
		cli_sendv(client, "%s %-22s error=%d\r\n", ifname ? ifname : "-", table_name, rc);
		return;
	}

	cli_sendv(client,
		"%-16s %-22s size=%-6lu declared=%-8u counted=%-8u used-buckets=%-6u max-chain=%-4u mismatch=%s\r\n",
		ifname ? ifname : "-",
		table_name,
		(unsigned long)st.size,
		st.declared_elements,
		st.actual_elements,
		st.used_buckets,
		st.max_chain,
		(st.declared_elements == st.actual_elements) ? "no" : "YES");
}

static int show_hashtable_exec(const char *cmd, char * const *fields, int fields_cnt, void *client)
{
	struct pppoe_serv_t *serv;
	unsigned int total_conn_cnt = 0;
	unsigned int total_cookie_declared = 0;
	unsigned int total_cookie_counted = 0;
	unsigned int total_mac_declared = 0;
	unsigned int total_mac_counted = 0;

	if (fields_cnt != 3)
		goto help;

	cli_send(client, "PPPoE myhashtable statistics:\r\n");
	cli_send(client, "interface        table                  size   declared counted  used-buckets max-chain mismatch\r\n");
	cli_send(client, "------------------------------------------------------------------------------------------------\r\n");

	pthread_rwlock_rdlock(&serv_lock);
	list_for_each_entry(serv, &serv_list, entry) {
		myhashtable_stats_t cookie_st;
		myhashtable_stats_t mac_st;

		show_obj_hashtable_line(client, serv->ifname, "cookie_2_conn", &serv->cookie_2_conn);
		show_hash64_hashtable_line(client, serv->ifname, "mac_sessid_2_conn", &serv->mac_sessid_2_conn);

		if (obj_hashtable_ts_get_stats(&serv->cookie_2_conn, &cookie_st) == HASH_TABLE_OK) {
			total_cookie_declared += cookie_st.declared_elements;
			total_cookie_counted += cookie_st.actual_elements;
		}
		if (hashtable64_ts_get_stats(&serv->mac_sessid_2_conn, &mac_st) == HASH_TABLE_OK) {
			total_mac_declared += mac_st.declared_elements;
			total_mac_counted += mac_st.actual_elements;
		}
		total_conn_cnt += serv->conn_cnt;
	}
	pthread_rwlock_unlock(&serv_lock);

	cli_send(client, "------------------------------------------------------------------------------------------------\r\n");
	cli_sendv(client, "totals: conn_cnt=%u cookie_declared=%u cookie_counted=%u mac_declared=%u mac_counted=%u\r\n",
		total_conn_cnt,
		total_cookie_declared,
		total_cookie_counted,
		total_mac_declared,
		total_mac_counted);

	if (ptr_conf_interface_pado_delay) {
		show_obj_hashtable_line(client, "global", "conf_interface_pado_delay", ptr_conf_interface_pado_delay);
	}

	return CLI_CMD_OK;

help:
	show_hashtable_help(fields, fields_cnt, client);
	return CLI_CMD_OK;
}

static void init(void)
{
	cli_register_simple_cmd2(show_stat_exec, NULL, 2, "show", "stat");

	cli_register_simple_cmd2(show_ac_name_exec, show_ac_name_help,
				 3, "pppoe", "show", "AC-Name");
	cli_register_simple_cmd2(set_ac_name_exec, set_ac_name_help,
				 3, "pppoe", "set", "AC-Name");

	cli_register_simple_cmd2(add_intf_exec, add_intf_help, 3, "pppoe", "add", "interface");
	cli_register_simple_cmd2(del_intf_exec, del_intf_help, 3, "pppoe", "del", "interface");
	cli_register_simple_cmd2(show_intf_exec, show_intf_help, 3, "pppoe", "show", "interface");

	cli_register_simple_cmd2(show_hashtable_exec, show_hashtable_help,
				 3, "pppoe", "show", "hashtable");

	cli_register_simple_cmd2(set_service_name_exec, set_service_name_help,
				 3, "pppoe", "set", "service-name");
	
	cli_register_simple_cmd2(set_interface_exec, set_interface_help, 3, "pppoe", "set", "interface");

	cli_register_simple_cmd2(show_service_name_exec, show_service_name_help,
					 3, "pppoe", "show", "service-name");

	cli_register_simple_cmd2(clear_service_name_exec, clear_service_name_help, 4, "pppoe", "clear", "service-name", "interface");
	cli_register_simple_cmd2(set_pado_delay_exec, set_pado_delay_help,
				 3, "pppoe", "set", "PADO-delay");
	cli_register_simple_cmd2(show_pado_delay_exec, show_pado_delay_help,
				 3, "pppoe", "show", "PADO-delay");
	
	cli_register_simple_cmd2(set_verbose_exec, set_verbose_help, 3, "pppoe", "set", "verbose");
	cli_register_simple_cmd2(show_verbose_exec, show_verbose_help,
				 3, "pppoe", "show", "verbose");
}

DEFINE_INIT(22, init);
