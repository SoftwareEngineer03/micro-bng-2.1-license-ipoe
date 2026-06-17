#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <arpa/inet.h>

#include "triton.h"
#include "log.h"
#include "mempool.h"

#include "ap_net.h"
#include "pppoe.h"

#include "memdebug.h"

#define MAX_NET 2
#define HASH_BITS 0xffff

struct tree {
	pthread_mutex_t lock;
	struct rb_root root;
};

struct disc_net {
	struct triton_context_t ctx;
	struct triton_md_handler_t hnd;
	const struct ap_net *net;
	int refs;
	struct tree tree[0];
};

static uint8_t bc_addr[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static mempool_t pkt_pool;

static struct disc_net *nets[MAX_NET];
static int net_cnt;
static pthread_mutex_t nets_lock = PTHREAD_MUTEX_INITIALIZER;

static struct disc_net *ppp_nets[MAX_NET];
static int ppp_net_cnt;
static pthread_mutex_t ppp_nets_lock = PTHREAD_MUTEX_INITIALIZER;

static void disc_close(struct triton_context_t *ctx);
static int disc_read(struct triton_md_handler_t *h);
static int ppp_ses_read(struct triton_md_handler_t *h);

static struct disc_net *init_net(const struct ap_net *net)
{
	struct sockaddr_ll addr;
	int i, f = 1;
	struct disc_net *n;
	struct tree *tree;
	int sock;

	if (net_cnt == MAX_NET - 1)
		return NULL;

	sock = net->socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PPP_DISC));
	if (sock < 0)
		return NULL;

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_PPP_DISC);

	net->setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &f, sizeof(f));

	if (net->bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
		log_error("pppoe: disc: bind: %s\n", strerror(errno));
		close(sock);
		return NULL;
	}

	fcntl(sock, F_SETFD, FD_CLOEXEC);
	net->set_nonblocking(sock, 1);

	n = _malloc(sizeof(*net) + (HASH_BITS + 1) * sizeof(struct tree));
	tree = n->tree;

	for (i = 0; i <= HASH_BITS; i++) {
		pthread_mutex_init(&tree[i].lock, NULL);
		tree[i].root = RB_ROOT;
	}

	n->ctx.close = disc_close;
	n->ctx.before_switch = log_switch;
	n->hnd.fd = sock;
	n->hnd.read = disc_read;
	n->net = net;
	n->refs = 1;

	triton_context_register(&n->ctx, NULL);
	triton_md_register_handler(&n->ctx, &n->hnd);
	triton_md_enable_handler(&n->hnd, MD_MODE_READ);

	nets[net_cnt++] = n;

	triton_context_wakeup(&n->ctx);

	return n;
}

static struct disc_net *init_ppp_net(const struct ap_net *net)
{
	struct sockaddr_ll addr;
	int i, f = 1;
	struct disc_net *n;
	struct tree *tree;
	int sock;

	if (ppp_net_cnt == MAX_NET - 1)
		return NULL;

	sock = net->socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PPP_SES));
	if (sock < 0)
		return NULL;

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_PPP_SES);

	net->setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &f, sizeof(f));

	if (net->bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
		log_error("pppoe: ppp ses: bind: %s\n", strerror(errno));
		close(sock);
		return NULL;
	}

	fcntl(sock, F_SETFD, FD_CLOEXEC);
	net->set_nonblocking(sock, 1);

	n = _malloc(sizeof(*net) + (HASH_BITS + 1) * sizeof(struct tree));
	tree = n->tree;

	for (i = 0; i <= HASH_BITS; i++) {
		pthread_mutex_init(&tree[i].lock, NULL);
		tree[i].root = RB_ROOT;
	}

  log_debug(" ### init_ppp_net\n");

	n->ctx.close = disc_close;
	n->ctx.before_switch = log_switch;
	n->hnd.fd = sock;
	n->hnd.read = ppp_ses_read;
	n->net = net;
	n->refs = 1;

	triton_context_register(&n->ctx, NULL);
	triton_md_register_handler(&n->ctx, &n->hnd);
	triton_md_enable_handler(&n->hnd, MD_MODE_READ);

	ppp_nets[ppp_net_cnt++] = n;

	triton_context_wakeup(&n->ctx);

	return n;
}

static void free_net(struct disc_net *net)
{
	int i;

	pthread_mutex_lock(&nets_lock);
	for (i = 0; i < MAX_NET; i++) {
		if (nets[i] == net) {
			memcpy(nets + i, nets + i + 1, net_cnt - i - 1);
			net_cnt--;
			break;
		}
	}
	pthread_mutex_unlock(&nets_lock);

	_free(net);
}

static void free_ppp_net(struct disc_net *net)
{
	int i;

	pthread_mutex_lock(&ppp_nets_lock);
	for (i = 0; i < MAX_NET; i++) {
		if (ppp_nets[i] == net) {
			memcpy(ppp_nets + i, ppp_nets + i + 1, ppp_net_cnt - i - 1);
			ppp_net_cnt--;
			break;
		}
	}
	pthread_mutex_unlock(&ppp_nets_lock);

	_free(net);
}

static struct disc_net *find_net(const struct ap_net *net)
{
	int i;

	for (i = 0; i < net_cnt; i++) {
		if (nets[i]->net == net)
			return nets[i];
	}

	return NULL;
}

static struct disc_net *find_ppp_net(const struct ap_net *net)
{
	int i;

	for (i = 0; i < ppp_net_cnt; i++) {
		if (ppp_nets[i]->net == net)
			return ppp_nets[i];
	}

	return NULL;
}


int pppoe_disc_start(struct pppoe_serv_t *serv)
{
	struct disc_net *net = find_net(serv->net);
	struct rb_node **p, *parent = NULL;
	struct tree *t;
	int ifindex = serv->ifindex, i;
	struct pppoe_serv_t *n = NULL;

	if (!net) {
		pthread_mutex_lock(&nets_lock);

		net = find_net(serv->net);
		if (!net)
			net = init_net(serv->net);

		pthread_mutex_unlock(&nets_lock);

		if (!net)
			return -1;
	}

	if (net->hnd.fd == -1)
		return -1;

	t = &net->tree[ifindex & HASH_BITS];

	pthread_mutex_lock(&t->lock);

	p = &t->root.rb_node;
  
  log_debug("pppoe: disc: attempt ifindex %s, %d\n", serv->ifname, ifindex);

	while (*p) {
		parent = *p;
		n = rb_entry(parent, typeof(*n), node);
		i = n->ifindex;

		if (ifindex < i)
			p = &(*p)->rb_left;
		else if (ifindex > i)
			p = &(*p)->rb_right;
		else {
			pthread_mutex_unlock(&t->lock);
			log_error("pppoe: disc: attempt to add duplicate ifindex\n");
			return -1;
		}
	}

	rb_link_node(&serv->node, parent, p);
	rb_insert_color(&serv->node, &t->root);

	__sync_add_and_fetch(&net->refs, 1);

	pthread_mutex_unlock(&t->lock);

	return net->hnd.fd;
}

int pppoe_ppp_ses_start(struct pppoe_serv_t *serv)
{
	struct disc_net *net = find_ppp_net(serv->net);
	struct rb_node **p, *parent = NULL;
	struct tree *t;
	int ifindex = serv->ifindex, i;
	struct pppoe_serv_t *n = NULL;

	if (!net) {
		pthread_mutex_lock(&ppp_nets_lock);

		net = find_ppp_net(serv->net);
		if (!net)
			net = init_ppp_net(serv->net);

		pthread_mutex_unlock(&ppp_nets_lock);

		if (!net)
			return -1;
	}

	if (net->hnd.fd == -1)
		return -1;

	t = &net->tree[ifindex & HASH_BITS];

	pthread_mutex_lock(&t->lock);

	p = &t->root.rb_node;

  log_debug("pppoe: sess: attempt ifindex %s, %d\n", serv->ifname, ifindex);

	while (*p) {
		parent = *p;
		n = rb_entry(parent, typeof(*n), node);
		i = n->ifindex;

		if (ifindex < i)
			p = &(*p)->rb_left;
		else if (ifindex > i)
			p = &(*p)->rb_right;
		else {
			pthread_mutex_unlock(&t->lock);
			log_error("pppoe: sess: attempt to add duplicate ifindex\n");
			return -1;
		}
	}

	rb_link_node(&serv->node, parent, p);
	rb_insert_color(&serv->node, &t->root);

	__sync_add_and_fetch(&net->refs, 1);

	pthread_mutex_unlock(&t->lock);

	return net->hnd.fd;
}

void pppoe_disc_stop(struct pppoe_serv_t *serv)
{
	struct disc_net *n = find_net(serv->net);
	if (!n) {
		log_warn("pppoe: disc: stop requested for unregistered interface %s\n", serv->ifname);
		return;
	}
	struct tree *t = &n->tree[serv->ifindex & HASH_BITS];

	pthread_mutex_lock(&t->lock);
	rb_erase(&serv->node, &t->root);
	pthread_mutex_unlock(&t->lock);

	if (__sync_sub_and_fetch(&n->refs, 1) == 0)
		free_net(n);
}

void pppoe_ppp_ses_stop(struct pppoe_serv_t *serv)
{
	struct disc_net *n = find_ppp_net(serv->net);
	if (!n) {
		log_warn("pppoe: sess: stop requested for unregistered interface %s\n", serv->ifname);
		return;
	}
	struct tree *t = &n->tree[serv->ifindex & HASH_BITS];

	pthread_mutex_lock(&t->lock);
	rb_erase(&serv->node, &t->root);
	pthread_mutex_unlock(&t->lock);

	if (__sync_sub_and_fetch(&n->refs, 1) == 0)
		free_ppp_net(n);
}

static int forward(struct disc_net *net, int ifindex, uint8_t *pkt, int len)
{
	struct pppoe_serv_t *n;
	struct tree *t = &net->tree[ifindex & HASH_BITS];
	struct rb_node **p = &t->root.rb_node, *parent = NULL;
	int r = 0;
	struct ethhdr *ethhdr = (struct ethhdr *)(pkt + 4);

	pthread_mutex_lock(&t->lock);

	while (*p) {
		parent = *p;
		n = rb_entry(parent, typeof(*n), node);

		if (ifindex < n->ifindex)
			p = &(*p)->rb_left;
		else if (ifindex > n->ifindex)
			p = &(*p)->rb_right;
		else {
            /*log_debug("forward(%s, %d): comparing... %x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x : %x:%x:%x:%x:%x:%x\n",
                n->ifname ,ifindex,
                ethhdr->h_source[0], ethhdr->h_source[1], ethhdr->h_source[2], ethhdr->h_source[3], ethhdr->h_source[4], ethhdr->h_source[5],
                ethhdr->h_dest[0], ethhdr->h_dest[1], ethhdr->h_dest[2], ethhdr->h_dest[3], ethhdr->h_dest[4], ethhdr->h_dest[5],
                n->hwaddr[0], n->hwaddr[1], n->hwaddr[2], n->hwaddr[3], n->hwaddr[4], n->hwaddr[5]);*/
			if (!memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN) || !memcmp(ethhdr->h_dest, n->hwaddr, ETH_ALEN)) {
				*(int *)pkt = len;
				triton_context_call(&n->ctx, (triton_event_func)pppoe_serv_read, pkt);
				r = 1;
			}
			break;
		}
	}

	pthread_mutex_unlock(&t->lock);

	return r;
}

static int forward_ppp(struct disc_net *net, int ifindex, uint8_t *pkt, int len)
{
	struct pppoe_serv_t *n;
	struct tree *t = &net->tree[ifindex & HASH_BITS];
	struct rb_node **p = &t->root.rb_node, *parent = NULL;
	int r = 0;
	struct ethhdr *ethhdr = (struct ethhdr *)(pkt + 4);

	pthread_mutex_lock(&t->lock);

	while (*p) {
		parent = *p;
		n = rb_entry(parent, typeof(*n), node);

		if (ifindex < n->ifindex)
			p = &(*p)->rb_left;
		else if (ifindex > n->ifindex)
			p = &(*p)->rb_right;
		else {
            /*log_debug("forward_ppp(): comparing... ethhdr->h_dest, n->hwaddr: %x:%x:%x:%x:%x:%x <-> %x:%x:%x:%x:%x:%x\n",
                ethhdr->h_dest[0], ethhdr->h_dest[1], ethhdr->h_dest[2], ethhdr->h_dest[3], ethhdr->h_dest[4], ethhdr->h_dest[5],
                n->hwaddr[0], n->hwaddr[1], n->hwaddr[2], n->hwaddr[3], n->hwaddr[4], n->hwaddr[5]);*/
			if (!memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN) || !memcmp(ethhdr->h_dest, n->hwaddr, ETH_ALEN)) {
				*(int *)pkt = len;
				triton_context_call(&n->ctx, (triton_event_func)pppoe_serv_read, pkt);
				r = 1;
			}
			break;
		}
	}

	pthread_mutex_unlock(&t->lock);

	return r;
}

static void notify_down(struct disc_net *net, int ifindex)
{
	struct pppoe_serv_t *n;
	struct tree *t = &net->tree[ifindex & HASH_BITS];
	struct rb_node **p = &t->root.rb_node, *parent = NULL;

	pthread_mutex_lock(&t->lock);

	while (*p) {
		parent = *p;
		n = rb_entry(parent, typeof(*n), node);

		if (ifindex < n->ifindex)
			p = &(*p)->rb_left;
		else if (ifindex > n->ifindex)
			p = &(*p)->rb_right;
		else {
			triton_context_call(&n->ctx, (triton_event_func)_server_stop, n);
			break;
		}
	}

	pthread_mutex_unlock(&t->lock);
}

static void disc_stop(struct disc_net *net)
{
	struct pppoe_serv_t *s;
	struct rb_node *n;
	int i;

	triton_md_unregister_handler(&net->hnd, 1);
	triton_context_unregister(&net->ctx);

	for (i = 0; i <= HASH_BITS; i++) {
		struct tree *t = &net->tree[i];

		pthread_mutex_lock(&t->lock);
		for (n = rb_first(&t->root); n; n = rb_next(n)) {
			s = rb_entry(n, typeof(*s), node);
			triton_context_call(&s->ctx, (triton_event_func)_server_stop, s);
		}
		pthread_mutex_unlock(&t->lock);
	}

	if (__sync_sub_and_fetch(&net->refs, 1) == 0)
		free_net(net);
}


static int disc_read(struct triton_md_handler_t *h)
{
	struct disc_net *net = container_of(h, typeof(*net), hnd);
	uint8_t *pack = NULL;
	struct ethhdr *ethhdr;
	struct pppoe_hdr *hdr;
	int n;
	struct sockaddr_ll src;
	socklen_t slen = sizeof(src);

	while (1) {
		if (!pack)
			pack = mempool_alloc(pkt_pool);

		n = net->net->recvfrom(h->fd, pack + 4, ETHER_MAX_LEN, MSG_DONTWAIT, (struct sockaddr *)&src, &slen);

		if (n < 0) {
			if (errno == EAGAIN)
				break;

			log_error("pppoe: disc: read: %s\n", strerror(errno));

			if (errno == ENETDOWN) {
				notify_down(net, src.sll_ifindex);
				continue;
			}

			if (errno == EBADE) {
				disc_stop(net);
				return 1;
			}
			continue;
		}

		ethhdr = (struct ethhdr *)(pack + 4);

//    if ( ntohs(ethhdr->h_proto) != ETH_P_PPP_DISC && ntohs(ethhdr->h_proto) != ETH_P_PPP_SES)
//      continue;

		hdr = (struct pppoe_hdr *)(pack + 4 + ETH_HLEN);

		if (n < ETH_HLEN + sizeof(*hdr)) {
			if (conf_verbose)
				log_warn("pppoe: short packet received (%i)\n", n);
			continue;
		}

		if (mac_filter_check(ethhdr->h_source)) {
			__sync_add_and_fetch(&stat_filtered, 1);
			continue;
		}

		//if (memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN) && memcmp(ethhdr->h_dest, serv->hwaddr, ETH_ALEN))
		//	continue;

		if (!memcmp(ethhdr->h_source, bc_addr, ETH_ALEN)) {
			if (conf_verbose)
				log_warn("pppoe: discarding packet (host address is broadcast)\n");
			continue;
		}

		if ((ethhdr->h_source[0] & 1) != 0) {
			if (conf_verbose)
				log_warn("pppoe: discarding packet (host address is not unicast)\n");
			continue;
		}

		if (n < ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length)) {
			if (conf_verbose)
				log_warn("pppoe: short packet received\n");
			continue;
		}

		if (hdr->ver != 1) {
			if (conf_verbose)
				log_warn("pppoe: discarding packet (unsupported version %i)\n", hdr->ver);
			continue;
		}

		if (hdr->type != 1) {
			if (conf_verbose)
				log_warn("pppoe: discarding packet (unsupported type %i)\n", hdr->type);
			continue;
		}

		if (forward(net, src.sll_ifindex, pack, n))
			pack = NULL;

    //usleep(100);

	}

	mempool_free(pack);

	return 0;
}


static int ppp_ses_read(struct triton_md_handler_t *h)
{
	struct disc_net *net = container_of(h, typeof(*net), hnd);
	uint8_t *pack = NULL;
	struct ethhdr *ethhdr;
	struct pppoe_hdr *hdr;
	int n;
	struct sockaddr_ll src;
	socklen_t slen = sizeof(src);

	while (1) {
		if (!pack)
			pack = mempool_alloc(pkt_pool);

		n = net->net->recvfrom(h->fd, pack + 4, ETHER_MAX_LEN, MSG_DONTWAIT, (struct sockaddr *)&src, &slen);
		if (n < 0) {
			if (errno == EAGAIN)
				break;

			log_error("pppoe: disc: read: %s\n", strerror(errno));

			if (errno == ENETDOWN) {
				notify_down(net, src.sll_ifindex);
				continue;
			}

			if (errno == EBADE) {
				disc_stop(net);
				return 1;
			}
			continue;
		}

		ethhdr = (struct ethhdr *)(pack + 4);

//    if ( ntohs(ethhdr->h_proto) != ETH_P_PPP_DISC && ntohs(ethhdr->h_proto) != ETH_P_PPP_SES)
//      continue;

		hdr = (struct pppoe_hdr *)(pack + 4 + ETH_HLEN);

		if (n < ETH_HLEN + sizeof(*hdr)) {
			if (conf_verbose)
				log_warn("pppoe: short packet received (%i)\n", n);
			continue;
		}

		if (mac_filter_check(ethhdr->h_source)) {
			__sync_add_and_fetch(&stat_filtered, 1);
			continue;
		}

		//if (memcmp(ethhdr->h_dest, bc_addr, ETH_ALEN) && memcmp(ethhdr->h_dest, serv->hwaddr, ETH_ALEN))
		//	continue;

		if (!memcmp(ethhdr->h_source, bc_addr, ETH_ALEN)) {
			if (conf_verbose)
				log_warn("pppoe: discarding packet (host address is broadcast)\n");
			continue;
		}

		if ((ethhdr->h_source[0] & 1) != 0) {
			if (conf_verbose)
				log_warn("pppoe: discarding packet (host address is not unicast)\n");
			continue;
		}

		if (n < ETH_HLEN + sizeof(*hdr) + ntohs(hdr->length)) {
			if (conf_verbose)
				log_warn("pppoe: short packet received\n");
			continue;
		}

		if (hdr->ver != 1) {
			if (conf_verbose)
				log_warn("pppoe: discarding packet (unsupported version %i)\n", hdr->ver);
			continue;
		}

		if (hdr->type != 1) {
			if (conf_verbose)
				log_warn("pppoe: discarding packet (unsupported type %i)\n", hdr->type);
			continue;
		}

		if (forward_ppp(net, src.sll_ifindex, pack, n))
			pack = NULL;

    //usleep(100);

	}

	mempool_free(pack);

	return 0;
}

static void disc_close(struct triton_context_t *ctx)
{
	struct disc_net *n = container_of(ctx, typeof(*n), ctx);

	triton_md_unregister_handler(&n->hnd, 1);
	triton_context_unregister(ctx);
}

static void init()
{
	pkt_pool = mempool_create(ETHER_MAX_LEN + 4);
}

DEFINE_INIT(1, init);


