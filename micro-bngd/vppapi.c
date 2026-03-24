#include <stdio.h>

#include <vapi/vpe.api.vapi.h>

#include <vapi/interface.api.vapi.h>
#include <vapi/tapv2.api.vapi.h>
#include <vapi/pppoe.api.vapi.h>
#include <vapi/policer.api.vapi.h>
#include <vapi/classify.api.vapi.h>
#include <vapi/ip.api.vapi.h>
#include <vapi/memclnt.api.vapi.h>
#include <vpp-api/client/stat_client.h>

#include <vppinfra/mem.h>

#include "triton.h"
#include "vppapi.h"

DEFINE_VAPI_MSG_IDS_VPE_API_JSON
DEFINE_VAPI_MSG_IDS_MEMCLNT_API_JSON
DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON
DEFINE_VAPI_MSG_IDS_TAPV2_API_JSON
DEFINE_VAPI_MSG_IDS_PPPOE_API_JSON
DEFINE_VAPI_MSG_IDS_POLICER_API_JSON
DEFINE_VAPI_MSG_IDS_CLASSIFY_API_JSON
DEFINE_VAPI_MSG_IDS_IP_API_JSON

typedef struct
{
	bool last_called;
	size_t num_ifs;
	u32 *sw_if_indexes;
	bool *seen;
	int called;
} sw_interface_dump_ctx;

typedef struct
{
	int called;
	int expected_retval;
	u32 sw_if_index_storage;
} test_pppoe_add_del_session_ctx_t;

vapi_ctx_t ctx;
vapi_ctx_t ctx_acct;

pthread_mutex_t vpp_api_mutex;
pthread_mutex_t vpp_api_acct_mutex;

void __export vpp_api_connection()
{
  vapi_error_e rv = vapi_ctx_alloc (&ctx);
  if( rv != VAPI_OK ) {
    printf("vapi_ctx_alloc failed\n");
		exit(1);
  }
  rv = vapi_connect_ex (ctx, "vbng", NULL, 64,
			32, VAPI_MODE_NONBLOCKING, true,
			true);
  if( rv != VAPI_OK ) {
    printf("vapi_connect_ex failed\n");
		exit(1);
  }

  pthread_mutex_init(&vpp_api_mutex, NULL);
}

void __export vpp_api_connection_acct()
{
  vapi_error_e rv = vapi_ctx_alloc (&ctx_acct);
  if( rv != VAPI_OK ) {
    printf("vapi_ctx_alloc failed\n");
		exit(1);
  }
  rv = vapi_connect_ex (ctx_acct, "vbng_acct", NULL, 64,
			32, VAPI_MODE_NONBLOCKING, true,
			true);
  if( rv != VAPI_OK ) {
    printf("vapi_connect_ex failed\n");
		exit(1);
  }

  pthread_mutex_init(&vpp_api_acct_mutex, NULL);
}

vapi_error_e
show_version_cb (vapi_ctx_t ctx, void *callback_ctx, vapi_msg_id_t id, void *msg)
{
  vapi_msg_show_version_reply *p = msg;
  printf
    ("show_version_reply: program: `%s', version: `%s', build directory: "
     "`%s', build date: `%s'\n", p->payload.program, p->payload.version, p->payload.build_directory,
     p->payload.build_date);
  ++*(int *) callback_ctx;
  return VAPI_OK;
}

void __export vpp_api_show_version()
{
	pthread_mutex_lock(&vpp_api_mutex);

  printf ("--- Receive show version using generic callback - nonblocking "
	  "API ---\n");
  vapi_error_e rv;
  vapi_msg_show_version *sv = vapi_alloc_show_version (ctx);
  vapi_msg_show_version_hton (sv);
  while (VAPI_EAGAIN == (rv = vapi_send (ctx, sv)))
    ;
  int called = 0;
  vapi_set_generic_event_cb (ctx, show_version_cb, &called);
  while (VAPI_EAGAIN == (rv = vapi_dispatch_one (ctx)))
    ;
	usleep(100);
	pthread_mutex_unlock(&vpp_api_mutex);
}

vapi_error_e
sw_interface_dump_cb (struct vapi_ctx_s *ctx, void *callback_ctx,
					vapi_error_e rv, bool is_last,
					vapi_payload_sw_interface_details * reply)
{
	sw_interface_dump_ctx *dctx = callback_ctx;
	if (is_last)
		{
			dctx->last_called = true;
		}
	else
		{
			printf ("Interface dump entry: [%u]: %s\n", reply->sw_if_index,
				reply->interface_name);
			size_t i = 0;
			for (i = 0; i < dctx->num_ifs; ++i)
	{
		if (dctx->sw_if_indexes[i] == reply->sw_if_index)
			{
				dctx->seen[i] = true;
			}
	}
		}
	++dctx->called;
	return VAPI_OK;
}

void __export vpp_api_show_interface()
{
	pthread_mutex_lock(&vpp_api_mutex);

	const size_t num_ifs = 5;
	u32 sw_if_indexes[num_ifs];
	clib_memset (&sw_if_indexes, 0xff, sizeof (sw_if_indexes));
	
	bool seen[num_ifs];
	int i;
	
	sw_interface_dump_ctx dctx = { false, num_ifs, sw_if_indexes, seen, 0 };
	vapi_msg_sw_interface_dump *dump;
	vapi_error_e rv;
	for (i = 0; i < 1; ++i)
		{
			dctx.last_called = false;
			clib_memset (&seen, 0, sizeof (seen));
			dump = vapi_alloc_sw_interface_dump (ctx, 0);
			while (VAPI_EAGAIN ==
			 (rv =
				vapi_sw_interface_dump (ctx, dump, sw_interface_dump_cb,
							&dctx)))
			 ;

			while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
			    ;
		}
	usleep(100);
	pthread_mutex_unlock(&vpp_api_mutex);
}

vapi_error_e
pppoe_add_del_session_cb (vapi_ctx_t ctx, void *caller_ctx,
				vapi_error_e rv, bool is_last,
				vapi_payload_pppoe_add_del_session_reply * p)
{
	test_pppoe_add_del_session_ctx_t *clc = caller_ctx;
	clc->sw_if_index_storage = p->sw_if_index;
	++clc->called;
	return VAPI_OK;
}

u32 __export vpp_api_ipoe_add_del_session(u32 ip_address, u8 *mac_address, u16 session_id, char *acct_session_id, u32 sw_if_index, u8 *user_name, u32 vlan_id, u8 is_add)
{
	pthread_mutex_lock(&vpp_api_mutex);

	//printf ("--- Add/delete pppoe session using nonblocking API ---\n");

	test_pppoe_add_del_session_ctx_t clcs;
	clib_memset (&clcs, 0, sizeof (clcs));
	
	vapi_msg_pppoe_add_del_session *cl = vapi_alloc_pppoe_add_del_session (ctx);
    cl->payload.is_ipoe = 1;
	cl->payload.is_add = is_add;
	cl->payload.session_id = session_id;
	cl->payload.vlan_id = vlan_id;
  cl->payload.prefix_len = 0;

  clib_memset(cl->payload.user_name, 0, 16);

  clib_memset(cl->payload.acct_session_id, 0, 16);
  clib_memcpy(cl->payload.acct_session_id, acct_session_id, strlen(acct_session_id)>16? 16:strlen(acct_session_id));

	cl->payload.sw_if_index = sw_if_index;
	
	cl->payload.client_ip.af = ADDRESS_IP4;

	cl->payload.client_ip.un.ip4[0] = ( ip_address ) & 0xFF;
	cl->payload.client_ip.un.ip4[1] = ( ip_address >> 8 ) & 0xFF;
	cl->payload.client_ip.un.ip4[2] = ( ip_address >> 16 ) & 0xFF;
	cl->payload.client_ip.un.ip4[3] = ( ip_address >> 24 ) & 0xFF;

	int j;
	/*for (j = 0; j < 6; ++j) {
		cl->payload.client_mac[j] = mac_address[j];
	}*/

	for (j = 0; j < strlen(user_name) && j < 15; ++j) {
		cl->payload.user_name[j] = user_name[j];
	}

      vapi_error_e rv;
	  while (VAPI_EAGAIN ==
	     (rv =
	          vapi_pppoe_add_del_session (ctx, cl, pppoe_add_del_session_cb, &clcs)))
      ;

	  while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
      ;

	usleep(100);
	pthread_mutex_unlock(&vpp_api_mutex);

	return clcs.sw_if_index_storage;
}

u32 __export vpp_api_pppoe_add_del_session(u32 ip_address, u8 *mac_address, u16 session_id, char *acct_session_id, u32 sw_if_index, u8 *user_name, u32 vlan_id, u8 is_add)
{
	pthread_mutex_lock(&vpp_api_mutex);

	//printf ("--- Add/delete pppoe session using nonblocking API ---\n");

	test_pppoe_add_del_session_ctx_t clcs;
	clib_memset (&clcs, 0, sizeof (clcs));
	
	vapi_msg_pppoe_add_del_session *cl = vapi_alloc_pppoe_add_del_session (ctx);
    cl->payload.is_ipoe = 0;
	cl->payload.is_add = is_add;
	cl->payload.session_id = session_id;
	cl->payload.vlan_id = vlan_id;
  cl->payload.prefix_len = 0;

  clib_memset(cl->payload.user_name, 0, 16);

  clib_memset(cl->payload.acct_session_id, 0, 16);
  clib_memcpy(cl->payload.acct_session_id, acct_session_id, strlen(acct_session_id)>16? 16:strlen(acct_session_id));

	cl->payload.sw_if_index = sw_if_index;
	
	cl->payload.client_ip.af = ADDRESS_IP4;

	cl->payload.client_ip.un.ip4[0] = ( ip_address ) & 0xFF;
	cl->payload.client_ip.un.ip4[1] = ( ip_address >> 8 ) & 0xFF;
	cl->payload.client_ip.un.ip4[2] = ( ip_address >> 16 ) & 0xFF;
	cl->payload.client_ip.un.ip4[3] = ( ip_address >> 24 ) & 0xFF;

	int j;
	for (j = 0; j < 6; ++j) {
		cl->payload.client_mac[j] = mac_address[j];
	}

	for (j = 0; j < strlen(user_name) && j < 15; ++j) {
		cl->payload.user_name[j] = user_name[j];
	}

      vapi_error_e rv;
	  while (VAPI_EAGAIN ==
	     (rv =
	          vapi_pppoe_add_del_session (ctx, cl, pppoe_add_del_session_cb, &clcs)))
      ;

	  while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
      ;
	/*printf ("Created pppoe with Client-MAC %02x:%02x:%02x:%02x:%02x:%02x --> "
		"sw_if_index %d\n",
		mac_address[0], mac_address[1], mac_address[2],
		mac_address[3], mac_address[4], mac_address[5],
		clcs.sw_if_index_storage);*/

	usleep(100);
	pthread_mutex_unlock(&vpp_api_mutex);

	return clcs.sw_if_index_storage;
}

u32 __export vpp_api_ipv6_pppoe_add_del_session(u8 *ipv6_address, u8 prefix_len, u8 *mac_address, u16 session_id, char *acct_session_id, u32 sw_if_index, u8 *user_name, u32 vlan_id, u8 is_add)
{
	pthread_mutex_lock(&vpp_api_mutex);

	//printf ("--- IPV6 Add/delete pppoe session using nonblocking API ---\n");

	test_pppoe_add_del_session_ctx_t clcs;
	clib_memset (&clcs, 0, sizeof (clcs));
	
	vapi_msg_pppoe_add_del_session *cl = vapi_alloc_pppoe_add_del_session (ctx);
    cl->payload.is_ipoe = 0;
	cl->payload.is_add = is_add;
	cl->payload.session_id = session_id;
	cl->payload.vlan_id = vlan_id;
	cl->payload.prefix_len = prefix_len;

  clib_memset(cl->payload.user_name, 0, 16);

  clib_memset(cl->payload.acct_session_id, 0, 16);
  clib_memcpy(cl->payload.acct_session_id, acct_session_id, strlen(acct_session_id)>16? 16:strlen(acct_session_id));

	cl->payload.sw_if_index = sw_if_index;

	cl->payload.client_ip.af = ADDRESS_IP6;
  if(ipv6_address) {
  	for(int i=0; i<16; i++) {
  		cl->payload.client_ip.un.ip6[i] = ipv6_address[i];
  	}
  }
	
	int j;
	for (j = 0; j < 6; ++j)
	{
		cl->payload.client_mac[j] = mac_address[j];
	}
  
	for (j = 0; j < strlen(user_name) && j < 15; ++j) {
		cl->payload.user_name[j] = user_name[j];
	}

      vapi_error_e rv;
	  while (VAPI_EAGAIN ==
	     (rv =
	          vapi_pppoe_add_del_session (ctx, cl, pppoe_add_del_session_cb, &clcs)))
      ;

	  while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
      ;
	/*printf ("Created pppoe with Client-MAC %02x:%02x:%02x:%02x:%02x:%02x --> "
		"sw_if_index %d\n",
		mac_address[0], mac_address[1], mac_address[2],
		mac_address[3], mac_address[4], mac_address[5],
		clcs.sw_if_index_storage);*/

	usleep(100);
	pthread_mutex_unlock(&vpp_api_mutex);

	return clcs.sw_if_index_storage;
}

typedef struct
{
	int called;
	int expected_retval;
	u32 *stats_index;
} test_ip_route_add_del_ctx_t;

vapi_error_e
ip_route_add_del_cb (vapi_ctx_t ctx, void *caller_ctx,
				vapi_error_e rv, bool is_last,
				vapi_payload_ip_route_add_del_reply * p)
{
	test_ip_route_add_del_ctx_t *clc = caller_ctx;
	*clc->stats_index = p->stats_index;
	++clc->called;
	return VAPI_OK;
}

void __export vpp_api_ip_route_add_del(u32 prefix, u8 prefix_len, u32 nexthop, u32 sw_if_index, u32 table_id, bool is_add)
{
	pthread_mutex_lock(&vpp_api_mutex);

	//printf ("--- Add/delete IP route using nonblocking API ---\n");

	u32 stats_index;
	clib_memset (&stats_index, 0xff, sizeof (stats_index));
	test_ip_route_add_del_ctx_t clcs;
	clib_memset (&clcs, 0, sizeof (clcs));
	
	vapi_msg_ip_route_add_del *cl = vapi_alloc_ip_route_add_del (ctx, 64);
	
	cl->payload.is_add = is_add;
    cl->payload.is_multipath = 0;
    cl->payload.route.prefix.address.af = ADDRESS_IP4;
    cl->payload.route.prefix.address.un.ip4[0] = ( prefix ) & 0xFF;
	cl->payload.route.prefix.address.un.ip4[1] = ( prefix >> 8 ) & 0xFF;
	cl->payload.route.prefix.address.un.ip4[2] = ( prefix >> 16 ) & 0xFF;
	cl->payload.route.prefix.address.un.ip4[3] = ( prefix >> 24 ) & 0xFF;
    cl->payload.route.prefix.len = prefix_len;
    cl->payload.route.table_id = table_id;
    cl->payload.route.n_paths = 1;
    cl->payload.route.paths[0].nh.address.ip4[0] = ( nexthop ) & 0xFF;
	cl->payload.route.paths[0].nh.address.ip4[1] = ( nexthop >> 8 ) & 0xFF;
	cl->payload.route.paths[0].nh.address.ip4[2] = ( nexthop >> 16 ) & 0xFF;
	cl->payload.route.paths[0].nh.address.ip4[3] = ( nexthop >> 24 ) & 0xFF;
    cl->payload.route.paths[0].sw_if_index = sw_if_index;
    cl->payload.route.paths[0].table_id = table_id;

	clcs.stats_index = &stats_index;

	/*printf ("Add IP route with Client-IP %d.%d.%d.%d/%d via %d.%d.%d.%d (%u) --> "
		"stats_index %d\n",
		cl->payload.route.prefix.address.un.ip4[0], cl->payload.route.prefix.address.un.ip4[1], cl->payload.route.prefix.address.un.ip4[2], 
		cl->payload.route.prefix.address.un.ip4[3], prefix_len,
		cl->payload.route.paths[0].nh.address.ip4[0], cl->payload.route.paths[0].nh.address.ip4[1], cl->payload.route.paths[0].nh.address.ip4[2], 
		cl->payload.route.paths[0].nh.address.ip4[3], sw_if_index,
		stats_index);*/

	vapi_error_e rv;
	while (VAPI_EAGAIN == (rv = vapi_ip_route_add_del (ctx, cl, ip_route_add_del_cb, &clcs)));
	while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
      ;

	usleep(100);
	pthread_mutex_unlock(&vpp_api_mutex);
}

void __export vpp_api_ipv6_route_add_del(u8 *prefix, u8 prefix_len, u8 *nexthop, u32 sw_if_index, u32 table_id, bool is_add)
{
	pthread_mutex_lock(&vpp_api_mutex);

	//printf ("--- Add/delete IPv6 route using nonblocking API ---\n");

	u32 stats_index;
  int i;
  
	clib_memset (&stats_index, 0xff, sizeof (stats_index));
	test_ip_route_add_del_ctx_t clcs;
	clib_memset (&clcs, 0, sizeof (clcs));
	
	vapi_msg_ip_route_add_del *cl = vapi_alloc_ip_route_add_del (ctx, 64);
	
  cl->payload.is_add = is_add;
  cl->payload.is_multipath = 0;
  cl->payload.route.prefix.address.af = ADDRESS_IP6;
  if(prefix) {
  	for(int i=0; i<16; i++) {
  		cl->payload.route.prefix.address.un.ip6[i] = prefix[i];
  	}
  }
  cl->payload.route.prefix.len = prefix_len;

  cl->payload.route.table_id = table_id;
  cl->payload.route.n_paths = 1;

  if(nexthop) {
  	for(i=0; i<16; i++) {
  		cl->payload.route.paths[0].nh.address.ip6[i] = nexthop[i];
  	}
  }

  cl->payload.route.paths[0].sw_if_index = sw_if_index;
  cl->payload.route.paths[0].table_id = table_id;

	clcs.stats_index = &stats_index;

	vapi_error_e rv;
	while (VAPI_EAGAIN == (rv = vapi_ip_route_add_del (ctx, cl, ip_route_add_del_cb, &clcs)));
	while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
      ;
	/*printf ("Add IP route with Client-IPv6 ");
  for(i=0; i<8; i++) {
		printf("%x%02x:", prefix[i*2], prefix[i*2+1]);
	}

  printf(" via ");

  if(nexthop) {
    for(i=0; i<8; i++) {
  		printf("%x%02x:", nexthop[i*2], nexthop[i*2+1]);
  	}
  }
  printf (" (%u) --> stats_index %d\n",sw_if_index,
		stats_index);*/
	usleep(100);
	pthread_mutex_unlock(&vpp_api_mutex);
}

typedef struct
{
  bool last_called;
  u32 sw_if_index;
  u8 *if_name;
  int called;
} test_get_iface_by_name_ctx_t;

vapi_error_e
get_iface_by_name_cb (struct vapi_ctx_s *ctx, void *callback_ctx,
		      vapi_error_e rv, bool is_last,
		      vapi_payload_sw_interface_details * reply)
{
  test_get_iface_by_name_ctx_t *dctx = callback_ctx;
  if (is_last)
    {
      dctx->last_called = true;
    }
  else
    {
      printf ("Interface dump entry: [%u]: %s <-> %s\n", reply->sw_if_index,
	      reply->interface_name, dctx->if_name);
      size_t i = 0;
      if(!strcmp(dctx->if_name, reply->interface_name)) {
      	  dctx->sw_if_index = reply->sw_if_index;
      }
     
    }
  ++dctx->called;
  return VAPI_OK;
}

u32 __export vpp_api_get_iface_by_name(u8 *ifname)
{
	pthread_mutex_lock(&vpp_api_mutex);

  test_get_iface_by_name_ctx_t dctx = { false, ~0, ifname, 0 };
  vapi_msg_sw_interface_dump *dump;
  vapi_error_e rv;

  dump = vapi_alloc_sw_interface_dump (ctx, 0);
  while (VAPI_EAGAIN ==
     (rv =
      vapi_sw_interface_dump (ctx, dump, get_iface_by_name_cb,
			      &dctx)))
     ;
  while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
  ;

	usleep(100);
	pthread_mutex_unlock(&vpp_api_mutex);
  return dctx.sw_if_index;
}

typedef struct
{
	int called;
	int expected_retval;
} test_sw_interface_add_del_address_ctx_t;

vapi_error_e
sw_interface_add_del_address_cb (vapi_ctx_t ctx, void *caller_ctx,
				vapi_error_e rv, bool is_last,
				vapi_payload_sw_interface_add_del_address_reply * p)
{
	test_sw_interface_add_del_address_ctx_t *clc = caller_ctx;
	++clc->called;
	return VAPI_OK;
}

void __export vpp_api_sw_interface_add_del_ipv6_address(u32 id, u8 *prefix, u8 prefix_len, bool is_add)
{
	pthread_mutex_lock(&vpp_api_mutex);

	//printf ("--- Add/delete IPv6 address using nonblocking API ---\n");

	u32 retval;
	clib_memset (&retval, 0xff, sizeof (retval));
	test_sw_interface_add_del_address_ctx_t clcs;
	clib_memset (&clcs, 0, sizeof (clcs));
	
	vapi_msg_sw_interface_add_del_address *cl = vapi_alloc_sw_interface_add_del_address (ctx);
	
	cl->payload.sw_if_index = id;
	cl->payload.is_add = is_add;
	cl->payload.prefix.address.af = ADDRESS_IP6;
	for(int i=0; i<16; i++) {
		cl->payload.prefix.address.un.ip6[i] = prefix[i];
	}
	cl->payload.prefix.len = prefix_len;

	vapi_error_e rv;
	while (VAPI_EAGAIN == (rv = vapi_sw_interface_add_del_address (ctx, cl, sw_interface_add_del_address_cb, &clcs)));
	while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
    ;
    
	/*printf ("Add IP to sw_if_index %u ",
		id);
	for(int i=0; i<16; i+=2) {
		printf("%02x%02x:", cl->payload.prefix.address.un.ip6[i], cl->payload.prefix.address.un.ip6[i+1]);
	}
	printf("\n");*/

	usleep(100);
	pthread_mutex_unlock(&vpp_api_mutex);
}

void __export vpp_api_sw_interface_add_del_address(u32 id, u32 prefix, u8 prefix_len, bool is_add)
{
	pthread_mutex_lock(&vpp_api_mutex);

	//printf ("--- Add/delete IP address using nonblocking API ---\n");

	u32 retval;
	clib_memset (&retval, 0xff, sizeof (retval));
	test_sw_interface_add_del_address_ctx_t clcs;
	clib_memset (&clcs, 0, sizeof (clcs));
	
	vapi_msg_sw_interface_add_del_address *cl = vapi_alloc_sw_interface_add_del_address (ctx);
	
	cl->payload.sw_if_index = id;
	cl->payload.is_add = is_add;
	cl->payload.prefix.address.af = ADDRESS_IP4;
	cl->payload.prefix.address.un.ip4[0] = ( prefix ) & 0xFF;
	cl->payload.prefix.address.un.ip4[1] = ( prefix >> 8 ) & 0xFF;
	cl->payload.prefix.address.un.ip4[2] = ( prefix >> 16 ) & 0xFF;
	cl->payload.prefix.address.un.ip4[3] = ( prefix >> 24 ) & 0xFF;
	cl->payload.prefix.len = prefix_len;

	vapi_error_e rv;
	while (VAPI_EAGAIN == (rv = vapi_sw_interface_add_del_address (ctx, cl, sw_interface_add_del_address_cb, &clcs)));
	while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
    ;
    
	/*printf ("Add IP to sw_if_index %u via %d.%d.%d.%d/%d\n",
		id, cl->payload.prefix.address.un.ip4[0], cl->payload.prefix.address.un.ip4[1], cl->payload.prefix.address.un.ip4[2], 
		cl->payload.prefix.address.un.ip4[3], prefix_len);*/

	usleep(100);
	pthread_mutex_unlock(&vpp_api_mutex);
}

typedef struct
{
	int called;
	u32 policer_index;
} test_policer_add_del_ctx_t;

vapi_error_e
policer_add_del_cb (vapi_ctx_t ctx, void *caller_ctx,
				vapi_error_e rv, bool is_last,
				vapi_payload_policer_add_del_reply * p)
{
	test_policer_add_del_ctx_t *clc = caller_ctx;
	clc->policer_index = p->policer_index;
	++clc->called;
	return VAPI_OK;
}

u32 __export vpp_api_policer_add_del(u8 *name, u32 cir, u64 cb, u32 eir, u64 eb, bool is_add)
{
	pthread_mutex_lock(&vpp_api_mutex);

	//printf ("--- Add/delete policer using nonblocking API ---\n");

	u32 retval;
	clib_memset (&retval, 0xff, sizeof (retval));
	test_policer_add_del_ctx_t clcs;
	clib_memset (&clcs, 0, sizeof (clcs));
	
	vapi_msg_policer_add_del *cl = vapi_alloc_policer_add_del (ctx);
	
	snprintf(cl->payload.name, sizeof(cl->payload.name), "%s", name);
	cl->payload.is_add = is_add;
	cl->payload.cir = cir;
	cl->payload.cb = cb;
	cl->payload.eir = eir;
	cl->payload.eb = eb;
	cl->payload.rate_type = SSE2_QOS_RATE_API_KBPS;
	cl->payload.round_type = SSE2_QOS_ROUND_API_TO_CLOSEST;
	cl->payload.type = SSE2_QOS_POLICER_TYPE_API_1R2C; //SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_2698;
	cl->payload.conform_action.type = SSE2_QOS_ACTION_API_TRANSMIT;
	cl->payload.exceed_action.type = SSE2_QOS_ACTION_API_DROP;

	vapi_error_e rv;
	while (VAPI_EAGAIN == (rv = vapi_policer_add_del (ctx, cl, policer_add_del_cb, &clcs)));
	while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
    ;
    
	/*printf ("Add policer %s cir %u cb %lu eir %u eb %lu policer_index %u\n",
		name, cir, cb, eir, eb, clcs.policer_index);*/

	usleep(100);
	pthread_mutex_unlock(&vpp_api_mutex);

	return clcs.policer_index;
}

typedef struct
{
	int called;
	int retval;
} test_policer_update_ctx_t;

vapi_error_e
policer_update_cb (vapi_ctx_t ctx, void *caller_ctx,
				vapi_error_e rv, bool is_last,
				vapi_payload_policer_update_reply * p)
{
	test_policer_update_ctx_t *clc = caller_ctx;
	clc->retval = p->retval;
	++clc->called;
	return VAPI_OK;
}

u32 __export vpp_api_policer_update(u32 policer_index, u32 cir, u64 cb, u32 eir, u64 eb)
{
	pthread_mutex_lock(&vpp_api_mutex);

	//printf ("--- Update policer using nonblocking API ---\n");

	u32 retval;
	clib_memset (&retval, 0xff, sizeof (retval));
	test_policer_update_ctx_t clcs;
	clib_memset (&clcs, 0, sizeof (clcs));
	
	vapi_msg_policer_update *cl = vapi_alloc_policer_update (ctx);

	cl->payload.policer_index = policer_index;
	cl->payload.infos.cir = cir;
	cl->payload.infos.cb = cb;
	cl->payload.infos.eir = eir;
	cl->payload.infos.eb = eb;
	cl->payload.infos.rate_type = SSE2_QOS_RATE_API_KBPS;
	cl->payload.infos.round_type = SSE2_QOS_ROUND_API_TO_CLOSEST;
	cl->payload.infos.type = SSE2_QOS_POLICER_TYPE_API_1R2C; //SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_2698;
	cl->payload.infos.conform_action.type = SSE2_QOS_ACTION_API_TRANSMIT;
	cl->payload.infos.exceed_action.type = SSE2_QOS_ACTION_API_DROP;

	vapi_error_e rv;
	while (VAPI_EAGAIN == (rv = vapi_policer_update (ctx, cl, policer_update_cb, &clcs)));
	while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
    ;

	/*printf ("Update policer_index %u cir %u cb %lu eir %u eb %lu retval %d\n",
		policer_index, cir, cb, eir, eb, clcs.retval);*/
	usleep(100);
	pthread_mutex_unlock(&vpp_api_mutex);
	return clcs.retval;
}

typedef struct
{
	int called;
	u32 new_table_index;
} test_classify_add_del_table_ctx_t;

vapi_error_e
classify_add_del_table_cb (vapi_ctx_t ctx, void *caller_ctx,
				vapi_error_e rv, bool is_last,
				vapi_payload_classify_add_del_table_reply * p)
{
	test_classify_add_del_table_ctx_t *clc = caller_ctx;
	clc->new_table_index = p->new_table_index;
	++clc->called;
	return VAPI_OK;
}

u32 __export vpp_api_classify_add_del_table(u32 skip_n_vectors, u32 match_n_vectors, u8 *mask, u32 mask_len, u32 table_index, bool is_add)
{
	pthread_mutex_lock(&vpp_api_mutex);

	//printf ("--- Add/delete classify table using nonblocking API ---\n");

	u32 retval;
	clib_memset (&retval, 0xff, sizeof (retval));
	test_classify_add_del_table_ctx_t clcs;
	clib_memset (&clcs, 0, sizeof (clcs));
	
	vapi_msg_classify_add_del_table *cl = vapi_alloc_classify_add_del_table (ctx, 32);

	cl->payload.is_add = is_add;
	cl->payload.nbuckets = 8;
	cl->payload.skip_n_vectors = skip_n_vectors;
	cl->payload.match_n_vectors = match_n_vectors;
	cl->payload.del_chain = 0;
	cl->payload.table_index = table_index;
	cl->payload.next_table_index = ~0;
	cl->payload.miss_next_index = ~0;
	cl->payload.memory_size = 1 << 30;
	cl->payload.current_data_flag = 0;
	cl->payload.current_data_offset = 0;
	memcpy(cl->payload.mask, mask, mask_len);
	cl->payload.mask_len = mask_len;

	vapi_error_e rv;
	while (VAPI_EAGAIN == (rv = vapi_classify_add_del_table (ctx, cl, classify_add_del_table_cb, &clcs)));
	while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
    ;
	/*printf ("Add classify table (new_table_index %u)\n",
		clcs.new_table_index);*/
	usleep(100);
	pthread_mutex_unlock(&vpp_api_mutex);
	return clcs.new_table_index;
}

typedef struct
{
	int called;
} test_classify_add_del_session_ctx_t;

vapi_error_e
classify_add_del_session_cb (vapi_ctx_t ctx, void *caller_ctx,
				vapi_error_e rv, bool is_last,
				vapi_payload_classify_add_del_session_reply * p)
{
	test_classify_add_del_session_ctx_t *clc = caller_ctx;
	++clc->called;
	return VAPI_OK;
}

void __export vpp_api_classify_add_del_session(u32 table_index, u32 policer_index, u8 *match, u32 match_len, bool is_add)
{
	pthread_mutex_lock(&vpp_api_mutex);

	//printf ("--- Add/delete classify session using nonblocking API ---\n");

	u32 retval;
	clib_memset (&retval, 0xff, sizeof (retval));
	test_classify_add_del_session_ctx_t clcs;
	clib_memset (&clcs, 0, sizeof (clcs));
	
	vapi_msg_classify_add_del_session *cl = vapi_alloc_classify_add_del_session (ctx, 64);

	cl->payload.is_add = is_add;
	cl->payload.table_index = table_index;
	cl->payload.hit_next_index = policer_index;
	cl->payload.opaque_index = 1;
	cl->payload.advance = 0;
	cl->payload.action = 0;
	cl->payload.metadata = 0;
	memcpy(cl->payload.match, match, match_len);
	cl->payload.match_len = match_len;

	vapi_error_e rv;
	while (VAPI_EAGAIN == (rv = vapi_classify_add_del_session (ctx, cl, classify_add_del_session_cb, &clcs)));
	while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
    ;

	/*printf ("Add classify session table_index %u policer_index %u\n",
		table_index, policer_index);*/
	usleep(100);
	pthread_mutex_unlock(&vpp_api_mutex);
}

typedef struct
{
	int called;
} test_policer_classify_set_interface_ctx_t;

vapi_error_e
policer_classify_set_interface_cb (vapi_ctx_t ctx, void *caller_ctx,
				vapi_error_e rv, bool is_last,
				vapi_payload_policer_classify_set_interface_reply * p)
{
	test_policer_classify_set_interface_ctx_t *clc = caller_ctx;
	++clc->called;
	return VAPI_OK;
}

void __export vpp_api_policer_classify_set_interface(u32 sw_if_index, u32 ip4_table_index, u32 ip6_table_index, u32 l2_table_index, bool is_add)
{
	pthread_mutex_lock(&vpp_api_mutex);

	//printf ("--- Set policer classify interface using nonblocking API ---\n");

	u32 retval;
	clib_memset (&retval, 0xff, sizeof (retval));
	test_policer_classify_set_interface_ctx_t clcs;
	clib_memset (&clcs, 0, sizeof (clcs));
	
	vapi_msg_policer_classify_set_interface *cl = vapi_alloc_policer_classify_set_interface (ctx);

	cl->payload.is_add = is_add;
	cl->payload.sw_if_index = sw_if_index;
	cl->payload.ip4_table_index = ip4_table_index;
	cl->payload.ip6_table_index = ip6_table_index;
	cl->payload.l2_table_index = l2_table_index;

	vapi_error_e rv;
	while (VAPI_EAGAIN == (rv = vapi_policer_classify_set_interface (ctx, cl, policer_classify_set_interface_cb, &clcs)));
	while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
    ;
    
	/*printf ("Set policer classify interface sw_if_index %u ip4_table_index %u\n",
		sw_if_index, ip4_table_index);*/
	usleep(100);
	pthread_mutex_unlock(&vpp_api_mutex);
}

typedef struct
{
	int retval;
} test_sw_interface_set_unnumbered_ctx_t;

vapi_error_e
sw_interface_set_unnumbered_cb (vapi_ctx_t ctx, void *caller_ctx,
				vapi_error_e rv, bool is_last,
				vapi_payload_sw_interface_set_unnumbered_reply * p)
{
	test_sw_interface_set_unnumbered_ctx_t *clc = caller_ctx;
	clc->retval = p->retval;
	return VAPI_OK;
}

int __export vpp_api_sw_interface_set_unnumbered(u32 unnumbered_sw_if_index, u32 sw_if_index, bool is_add)
{
	pthread_mutex_lock(&vpp_api_mutex);

	//printf ("--- Set interface numbered using nonblocking API ---\n");

	test_sw_interface_set_unnumbered_ctx_t clcs;
	clib_memset (&clcs, 0, sizeof (clcs));
	
	vapi_msg_sw_interface_set_unnumbered *cl = vapi_alloc_sw_interface_set_unnumbered (ctx);
	
	cl->payload.is_add = is_add;
	cl->payload.sw_if_index = sw_if_index;
	cl->payload.unnumbered_sw_if_index = unnumbered_sw_if_index;

	vapi_error_e rv;
	while (VAPI_EAGAIN == (rv = vapi_sw_interface_set_unnumbered (ctx, cl, sw_interface_set_unnumbered_cb, &clcs)));
	while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx)))
    ;
    
	/*printf ("Set interface unnumbered retval %i sw_if_index %u unnumbered_sw_if_index %u\n",
		clcs.retval, sw_if_index, unnumbered_sw_if_index);*/

	usleep(100);
	pthread_mutex_unlock(&vpp_api_mutex);
	return clcs.retval;
}

typedef struct
{
	int called;
	u64 acct_input_octets;
	u64 acct_output_octets;
	u64 acct_input_packets;
	u64 acct_output_packets; 
	u64 acct_input_octets_ipv6;
	u64 acct_output_octets_ipv6;
	u64 acct_input_packets_ipv6;
	u64 acct_output_packets_ipv6;
} test_pppoe_session_accounting_ctx_t;

vapi_error_e
pppoe_session_accounting_cb (vapi_ctx_t ctx, void *caller_ctx,
				vapi_error_e rv, bool is_last,
				vapi_payload_pppoe_session_accounting_reply * p)
{
	test_pppoe_session_accounting_ctx_t *clc = caller_ctx;
	++clc->called;
	clc->acct_input_octets = p->acct_input_octets;
	clc->acct_output_octets = p->acct_output_octets;
	clc->acct_input_packets = p->acct_input_packets;
	clc->acct_output_packets = p->acct_output_packets;
	clc->acct_input_octets_ipv6 = p->acct_input_octets_ipv6;
	clc->acct_output_octets_ipv6 = p->acct_output_octets_ipv6;
	clc->acct_input_packets_ipv6 = p->acct_input_packets_ipv6;
	clc->acct_output_packets_ipv6 = p->acct_output_packets_ipv6;

	return VAPI_OK;
}

void __export vpp_api_pppoe_session_accounting(u8 *mac_address, u32 ip_address, pppoe_session_accounting_t *accounting, u8 is_ipoe)
{
	pthread_mutex_lock(&vpp_api_acct_mutex);

	//printf ("--- Get pppoe session accounting using nonblocking API ---\n");

	u32 retval;
	clib_memset (&retval, 0xff, sizeof (retval));
	test_pppoe_session_accounting_ctx_t clcs;
	clib_memset (&clcs, 0, sizeof (clcs));
	
	vapi_msg_pppoe_session_accounting *cl = vapi_alloc_pppoe_session_accounting (ctx_acct);

	int j;
	for (j = 0; j < 6; ++j)
	{
		cl->payload.client_mac[j] = mac_address[j];
	}

    cl->payload.client_ip.af = ADDRESS_IP4;

	cl->payload.client_ip.un.ip4[0] = ( ip_address ) & 0xFF;
	cl->payload.client_ip.un.ip4[1] = ( ip_address >> 8 ) & 0xFF;
	cl->payload.client_ip.un.ip4[2] = ( ip_address >> 16 ) & 0xFF;
	cl->payload.client_ip.un.ip4[3] = ( ip_address >> 24 ) & 0xFF;

    cl->payload.is_ipoe = is_ipoe;

	/*printf ("(1) Get pppoe session accounting client_ip %u.%u.%u.%u\n",
		cl->payload.client_ip.un.ip4[0], cl->payload.client_ip.un.ip4[1], 
		cl->payload.client_ip.un.ip4[2], cl->payload.client_ip.un.ip4[3]
	);*/

	vapi_error_e rv;
	while (VAPI_EAGAIN == (rv = vapi_pppoe_session_accounting (ctx_acct, cl, pppoe_session_accounting_cb, &clcs)));
	while (VAPI_EAGAIN == (rv = vapi_dispatch (ctx_acct)))
    ;
    
	/*printf ("(2) accouting %u %u %u %u - %u %u %u %u\n",
		clcs.acct_input_octets, clcs.acct_output_octets, clcs.acct_input_packets, clcs.acct_output_packets,
		clcs.acct_input_octets_ipv6, clcs.acct_output_octets_ipv6, clcs.acct_input_packets_ipv6, clcs.acct_output_packets_ipv6
	);*/

	accounting->acct_input_octets = clcs.acct_input_octets;
	accounting->acct_output_octets = clcs.acct_output_octets;
	accounting->acct_input_packets = clcs.acct_input_packets;
	accounting->acct_output_packets = clcs.acct_output_packets;
	accounting->acct_input_octets_ipv6 = clcs.acct_input_octets_ipv6;
	accounting->acct_output_octets_ipv6 = clcs.acct_output_octets_ipv6;
	accounting->acct_input_packets_ipv6 = clcs.acct_input_packets_ipv6;
	accounting->acct_output_packets_ipv6 = clcs.acct_output_packets_ipv6;

	usleep(100);
	pthread_mutex_unlock(&vpp_api_acct_mutex);
}

