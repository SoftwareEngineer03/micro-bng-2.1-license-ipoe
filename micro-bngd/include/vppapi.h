#include <stdio.h>

#include <vapi/vapi.h>

extern vapi_ctx_t ctx;
extern vapi_ctx_t ctx_acct;

typedef struct
{
	u64 acct_input_octets;
	u64 acct_output_octets;
	u64 acct_input_packets;
	u64 acct_output_packets;
	u64 acct_input_octets_ipv6;
	u64 acct_output_octets_ipv6;
	u64 acct_input_packets_ipv6;
	u64 acct_output_packets_ipv6;
} pppoe_session_accounting_t;

void vpp_api_connection();
void vpp_api_connection_acct();
void vpp_api_show_version();
void vpp_api_show_interface();
u32 vpp_api_pppoe_add_del_session(u32 ip_address, u8 *mac_address, u16 session_id, char *acct_session_id, u32 sw_if_index, u8 *user_name, u32 vlan_id, u8 is_add);
u32 vpp_api_ipv6_pppoe_add_del_session(u8 *ipv6_address, u8 prefix_len, u8 *mac_address, u16 session_id, char *acct_session_id, u32 sw_if_index, u8 *user_name, u32 vlan_id, u8 is_add);
void vpp_api_ip_route_add_del(u32 prefix, u8 prefix_len, u32 nexthop, u32 sw_if_index, u32 table_id, bool is_add);
void vpp_api_ipv6_route_add_del(u8 *prefix, u8 prefix_len, u8 *nexthop, u32 sw_if_index, u32 table_id, bool is_add);
u32 vpp_api_get_iface_by_name(u8 *ifname);
void vpp_api_sw_interface_add_del_address(u32 id, u32 prefix, u8 prefix_len, bool is_add);
void vpp_api_sw_interface_add_del_ipv6_address(u32 id, u8 *prefix, u8 prefix_len, bool is_add);
u32 vpp_api_policer_add_del(u8 *name, u32 cir, u64 cb, u32 eir, u64 eb, bool is_add);
u32 vpp_api_policer_update(u32 policer_index, u32 cir, u64 cb, u32 eir, u64 eb);
u32 vpp_api_classify_add_del_table(u32 skip_n_vectors, u32 match_n_vectors, u8 *mask, u32 mask_len, u32 table_index, bool is_add);
void vpp_api_classify_add_del_session(u32 table_index, u32 policer_index, u8 *match, u32 match_len, bool is_add);
void vpp_api_policer_classify_set_interface(u32 sw_if_index, u32 ip4_table_index, u32 ip6_table_index, u32 l2_table_index, bool is_add);
int vpp_api_sw_interface_set_unnumbered(u32 unnumbered_sw_if_index, u32 sw_if_index, bool is_add);
void vpp_api_pppoe_session_accounting(u8 *mac_address, pppoe_session_accounting_t *accounting);

