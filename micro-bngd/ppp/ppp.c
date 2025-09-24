#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <features.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_pppox.h>
#include <netinet/ip6.h>
#include "linux_ppp.h"

#include "crypto.h"

#include "triton.h"

#include "ap_session.h"
#include "events.h"
#include "ppp.h"
#include "ppp_fsm.h"
#include "ipdb.h"
#include "log.h"
#include "spinlock.h"
#include "mempool.h"
#include "vppapi.h"

#include "memdebug.h"

int __export conf_ppp_verbose;
int conf_unit_cache;
static int conf_unit_preallocate;

#define PPP_BUF_SIZE 8192
static mempool_t buf_pool;

int dflt_down_speed = 30000;
int dflt_up_speed = 30000;
double down_burst_factor = 1;
double up_burst_factor = 1;


static LIST_HEAD(layers);

struct layer_node_t
{
	struct list_head entry;
	int order;
	struct list_head items;
};

struct pppunit_cache
{
	struct list_head entry;
	int fd;
	int unit_idx;
};

static pthread_t uc_thr;
static pthread_mutex_t uc_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t uc_cond = PTHREAD_COND_INITIALIZER;
static LIST_HEAD(uc_list);
static int uc_size;
static mempool_t uc_pool;

static int ppp_chan_read(struct triton_md_handler_t*);
static int ppp_unit_read(struct triton_md_handler_t*);
static void init_layers(struct ppp_t *);
static void _free_layers(struct ppp_t *);
static void start_first_layer(struct ppp_t *);
static int setup_ppp_mru(struct ppp_t *ppp);

void __export ppp_init(struct ppp_t *ppp)
{
	memset(ppp, 0, sizeof(*ppp));
	INIT_LIST_HEAD(&ppp->layers);
	INIT_LIST_HEAD(&ppp->chan_handlers);
	INIT_LIST_HEAD(&ppp->unit_handlers);
	ppp->fd = -1;
	ppp->chan_fd = -1;
	ppp->unit_fd = -1;
	ppp->vid = -1;

	ap_session_init(&ppp->ses);
}

int __export establish_ppp(struct ppp_t *ppp)
{
	if (ap_shutdown)
		return -1;

	/* Open an instance of /dev/ppp and connect the channel to it */
	/*if (net->ppp_ioctl(ppp->fd, PPPIOCGCHAN, &ppp->chan_idx) == -1) {
		log_ppp_error("ioctl(PPPIOCGCHAN): %s\n", strerror(errno));
		return -1;
	}

	ppp->chan_fd = net->ppp_open();
	if (ppp->chan_fd < 0) {
		log_ppp_error("open(chan) /dev/ppp: %s\n", strerror(errno));
		return -1;
	}

	fcntl(ppp->chan_fd, F_SETFD, fcntl(ppp->chan_fd, F_GETFD) | FD_CLOEXEC);

	net->set_nonblocking(ppp->chan_fd, 1);

	if (net->ppp_ioctl(ppp->chan_fd, PPPIOCATTCHAN, &ppp->chan_idx) < 0) {
		log_ppp_error("ioctl(PPPIOCATTCHAN): %s\n", strerror(errno));
		goto exit_close_chan;
	}*/

	init_layers(ppp);
	if (list_empty(&ppp->layers)) {
		log_ppp_error("no layers to start\n");
		goto exit_close_chan;
	}

	//ppp->chan_hnd.fd = ppp->chan_fd;
	//ppp->chan_hnd.read = ppp_chan_read;

	if (conf_unit_preallocate) {
		if (connect_ppp_channel(ppp))
			goto exit_close_chan;
	} else
		log_ppp_debug("ppp establishing\n");

	if (ap_session_starting(&ppp->ses))
		goto exit_close_chan;

	//triton_md_register_handler(ppp->ses.ctrl->ctx, &ppp->chan_hnd);
	//triton_md_enable_handler(&ppp->chan_hnd, MD_MODE_READ);

	start_first_layer(ppp);

	return 0;

exit_close_chan:
	close(ppp->chan_fd);

	return -1;
}

int __export connect_ppp_channel(struct ppp_t *ppp)
{
	struct pppunit_cache *uc = NULL;
	struct ifreq ifr;

	/*if (ppp->unit_fd != -1) {
		if (setup_ppp_mru(ppp))
			goto exit_close_unit;
		return 0;
	}*/

	/*if (uc_size) {
		pthread_mutex_lock(&uc_lock);
		if (!list_empty(&uc_list)) {
			uc = list_entry(uc_list.next, typeof(*uc), entry);
			list_del(&uc->entry);
			--uc_size;
		}
		pthread_mutex_unlock(&uc_lock);
	}*/

	/*if (uc) {
		ppp->unit_fd = uc->fd;
		ppp->ses.unit_idx = uc->unit_idx;
		mempool_free(uc);
	} else {
		ppp->unit_fd = net->ppp_open();
		if (ppp->unit_fd < 0) {
			log_ppp_error("open(unit) /dev/ppp: %s\n", strerror(errno));
			goto exit;
		}

		fcntl(ppp->unit_fd, F_SETFD, fcntl(ppp->unit_fd, F_GETFD) | FD_CLOEXEC);

		if (net->ppp_ioctl(ppp->unit_fd, PPPIOCNEWUNIT, &ppp->ses.unit_idx) < 0) {
			log_ppp_error("ioctl(PPPIOCNEWUNIT): %s\n", strerror(errno));
			goto exit_close_unit;
		}

		if (fcntl(ppp->unit_fd, F_SETFL, O_NONBLOCK)) {
			log_ppp_error("ppp: cannot set nonblocking mode: %s\n", strerror(errno));
			goto exit_close_unit;
		}
	}

	if (net->ppp_ioctl(ppp->chan_fd, PPPIOCCONNECT, &ppp->ses.unit_idx) < 0) {
		log_ppp_error("ioctl(PPPIOCCONNECT): %s\n", strerror(errno));
		goto exit_close_unit;
	}*/

	//sprintf(ppp->ses.ifname, "ppp%i", ppp->ses.unit_idx);
	//sprintf(ppp->ses.ifname, "ppp%u", ppp->pppoe_sid);
	//sprintf(ppp->ses.ifname, "vlan.%d", ppp->vid);
	sprintf(ppp->ses.ifname, "%s", ppp->ses.ctrl->ifname);

	log_ppp_info1("connect: %s <--> %s(%s)\n", ppp->ses.ifname, ppp->ses.ctrl->name, ppp->ses.chan_name);

	/*memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, ppp->ses.ifname);
	if (net->sock_ioctl(SIOCGIFINDEX, &ifr)) {
		log_ppp_error("ioctl(SIOCGIFINDEX): %s\n", strerror(errno));
		goto exit_close_unit;
	}
	ppp->ses.ifindex = ifr.ifr_ifindex;*/

	//setup_ppp_mru(ppp);

	ap_session_set_ifindex(&ppp->ses);

	//ppp->unit_hnd.fd = ppp->unit_fd;
	//ppp->unit_hnd.read = ppp_unit_read;

	log_ppp_debug("ppp connected\n");

	//triton_md_register_handler(ppp->ses.ctrl->ctx, &ppp->unit_hnd);
	//triton_md_enable_handler(&ppp->unit_hnd, MD_MODE_READ);

	return 0;

exit_close_unit:
	//close(ppp->unit_fd);
	//ppp->unit_fd = -1;
exit:
	return -1;
}

static void destroy_ppp_channel(struct ppp_t *ppp)
{
	//triton_md_unregister_handler(&ppp->chan_hnd, 1);
	close(ppp->fd);
	ppp->fd = -1;
	ppp->chan_fd = -1;

	_free_layers(ppp);

  //pthread_mutex_lock(&ppp->lock);
	if (ppp->buf) {
//    free(ppp->buf);
		mempool_free(ppp->buf);
    ppp->buf = NULL;
  }
  //pthread_mutex_unlock(&ppp->lock);


}

static int setup_ppp_mru(struct ppp_t *ppp)
{
	struct ifreq ifr;

	if (ppp->mtu) {
		memset(&ifr, 0, sizeof(ifr));
		strcpy(ifr.ifr_name, ppp->ses.ifname);
		ifr.ifr_mtu = ppp->mtu;
		if (net->sock_ioctl(SIOCSIFMTU, &ifr)) {
			log_ppp_error("failed to set MTU: %s\n", strerror(errno));
			return -1;
		}
	}

	if (ppp->mru) {
		if (net->ppp_ioctl(ppp->unit_fd, PPPIOCSMRU, &ppp->mru)) {
			log_ppp_error("failed to set unit MRU: %s\n", strerror(errno));
			return -1;
		}
		if (net->ppp_ioctl(ppp->chan_fd, PPPIOCSMRU, &ppp->mru) &&
		    errno != EIO && errno != ENOTTY) {
			log_ppp_error("lcp:mru: failed to set channel MRU: %s\n", strerror(errno));
			return -1;
		}
	}

	return 0;
}

static void destablish_ppp(struct ppp_t *ppp)
{
	struct pppunit_cache *uc = NULL;

  if(ppp->ses.ipv6_started) {
    struct ipv6db_addr_t *a;
    if (ppp->ses.ipv6 && !list_empty(&ppp->ses.ipv6->addr_list)) {
      struct in6_addr ipv6addr;
      log_ppp_debug(" [del destablish_ppp] IPV6CP PPPOE SID : %04x\n", ppp->pppoe_sid);
      a = list_entry(ppp->ses.ipv6->addr_list.next, typeof(*a), entry);
      if (a->prefix_len == 0) {
        //return;
      } else {
      
        build_ip6_addr(a, ppp->ses.ipv6->peer_intf_id, &ipv6addr);
        /*for(int i=0; i<8; i++) {
          printf("%x%02x:", ipv6addr.s6_addr[i*2], ipv6addr.s6_addr[i*2+1]);
        }
        printf("\n");*/

        vpp_api_ipv6_route_add_del(ipv6addr.s6_addr, 128, NULL, ~0, 0, 0);

        /* download ipv6 policer */
        u8 match_down[64];
        memset(match_down, 0, sizeof(match_down));
        memcpy(&match_down[38], ipv6addr.s6_addr, 16);
        vpp_api_classify_add_del_session(ppp->ses.download_ipv6_classify_table_index, ppp->ses.vpp_policer_id_down, match_down, sizeof(match_down), 0);
      }
      log_ppp_debug(" [del destablish_ppp] DEL PPPOE SESSION : %04x\n", ppp->pppoe_sid);
      vpp_api_ipv6_pppoe_add_del_session(ipv6addr.s6_addr, 128, ppp->client_mac, ppp->pppoe_sid, "", ~0, "", 0, 0);
    }
  }

	if (ppp->unit_fd < 0) {
		ap_session_finished(&ppp->ses);
		destroy_ppp_channel(ppp);
		return;
	}

	if (conf_unit_cache) {
		struct ifreq ifr;

		if (ppp->ses.net != def_net) {
			if (net->move_link(def_net, ppp->ses.ifindex)) {
				log_ppp_warn("failed to attach to default namespace\n");
				triton_md_unregister_handler(&ppp->unit_hnd, 1);
				goto skip;
			}
			ppp->ses.net = def_net;
			net = def_net;
			ppp->ses.ifindex = net->get_ifindex(ppp->ses.ifname);
		}

		sprintf(ifr.ifr_newname, "ppp%i", ppp->ses.unit_idx);
		if (strcmp(ifr.ifr_newname, ppp->ses.ifname)) {
			strncpy(ifr.ifr_name, ppp->ses.ifname, IFNAMSIZ);
			if (net->sock_ioctl(SIOCSIFNAME, &ifr)) {
				log_ppp_warn("failed to rename ppp to default name\n");
				triton_md_unregister_handler(&ppp->unit_hnd, 1);
				goto skip;
			}
		}
	}

	if (conf_unit_cache) {
		triton_md_unregister_handler(&ppp->unit_hnd, 0);

		uc = mempool_alloc(uc_pool);
		uc->fd = ppp->unit_fd;
		uc->unit_idx = ppp->ses.unit_idx;
	} else
		triton_md_unregister_handler(&ppp->unit_hnd, 1);

skip:
	ap_session_finished(&ppp->ses);

	ppp->unit_fd = -1;

	destroy_ppp_channel(ppp);

	log_ppp_debug("ppp destablished\n");

	if (uc) {
		pthread_mutex_lock(&uc_lock);
		list_add_tail(&uc->entry, &uc_list);
		if (++uc_size > conf_unit_cache)
			pthread_cond_signal(&uc_cond);
		pthread_mutex_unlock(&uc_lock);
	}
}

static void *uc_thread(void *unused)
{
	struct pppunit_cache *uc;
	int fd;
	sigset_t set;

	sigfillset(&set);
	sigdelset(&set, SIGKILL);
	sigdelset(&set, SIGSTOP);

	pthread_sigmask(SIG_BLOCK, &set, NULL);

	while (1) {
		pthread_mutex_lock(&uc_lock);
		if (uc_size > conf_unit_cache) {
			uc = list_entry(uc_list.next, typeof(*uc), entry);
			list_del(&uc->entry);
			--uc_size;
			pthread_mutex_unlock(&uc_lock);

			fd = uc->fd;

			mempool_free(uc);

			close(fd);
			continue;
		}
		pthread_cond_wait(&uc_cond, &uc_lock);
		pthread_mutex_unlock(&uc_lock);
	}

	return NULL;
}

/*void print_buf(uint8_t *buf, int size)
{
	int i;
	for(i=0;i<size;i++)
		printf("%x ",buf[i]);
	printf("\n");
}*/

int __export ppp_packet_read(struct ppp_t *ppp)
{
  uint8_t *pack = ppp->pack;

	struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);
  struct ppp_handler_t *ppp_h;
	uint16_t proto;

	proto = ntohs(*(uint16_t*)(pack + sizeof(*hdr) + ETH_HLEN));
  //log_ppp_debug("ppp_packet_read proto: 0x%x\n", proto);
  if(proto == PPP_IPV6) {
    pthread_mutex_lock(&ppp->lock);
    int ip6_offset = sizeof(*hdr) + ETH_HLEN + sizeof(proto);
    const struct ip6_hdr *ipv6_h = (struct ip6_hdr*)(pack + ip6_offset);
    //log_ppp_debug("ppp_packet_read ip6_nxt: %d\n", ipv6_h->ip6_nxt);
    if(ipv6_h->ip6_nxt == IPPROTO_UDP) {
      ppp_dhcpv6_read(ppp);
    } else if(ipv6_h->ip6_nxt == IPPROTO_ICMPV6) {
      ppp_ipv6_nd_read(ppp);
    }
    ppp->is_processing = 0;
    pthread_mutex_unlock(&ppp->lock);
    return 0;
  }

  pthread_mutex_lock(&ppp->lock);
	if (!ppp->buf)
		//ppp->buf = calloc(1, PPP_BUF_SIZE);
		ppp->buf = mempool_alloc(buf_pool);
  //pthread_mutex_unlock(&ppp->lock);

	ppp->buf_size = htons(hdr->length);
  memcpy(ppp->buf, pack + sizeof(*hdr) + ETH_HLEN, ppp->buf_size);
  
	if (ppp->buf_size < 0) {
		if (errno != EAGAIN) {
			log_ppp_error("ppp_packet_read: %s\n", strerror(errno));
			ap_session_terminate(&ppp->ses, TERM_NAS_ERROR, 1);
      
      //pthread_mutex_lock(&ppp->lock);
      ppp->is_processing = 0;
      //pthread_mutex_unlock(&ppp->lock);

      pthread_mutex_unlock(&ppp->lock);
      
			return 1;
		}
    goto cont;
	}

	if (ppp->buf_size == 0)
		goto cont;

	if (ppp->buf_size < 2) {
		log_ppp_error("ppp_packet_read: short read %i\n", ppp->buf_size);
    goto cont;
	}

    
	list_for_each_entry(ppp_h, &ppp->chan_handlers, entry) {
		if (ppp_h->proto == proto) {
			ppp_h->recv(ppp_h);
      //triton_context_call(ppp->ses.ctrl->ctx, (void (*)(void *))ppp_h->recv, ppp_h);

			goto cont;
		}
	}


    list_for_each_entry(ppp_h, &ppp->unit_handlers, entry) {
          if (ppp_h->proto == proto) {
            ppp_h->recv(ppp_h);
            //triton_context_call(ppp->ses.ctrl->ctx, (void (*)(void *))ppp_h->recv, ppp_h);

            goto cont;
          }
        }

		lcp_send_proto_rej(ppp, proto);
		//log_ppp_warn("ppp_chan_read: discarding unknown packet %x\n", proto);

cont:

  //pthread_mutex_lock(&ppp->lock);
	//mempool_free(ppp->buf);
	if(ppp->buf) {
    mempool_free(ppp->buf);
//  	free(ppp->buf);
  	ppp->buf = NULL;
  }

  //pthread_mutex_lock(&ppp->lock);
  ppp->is_processing = 0;
  //pthread_mutex_unlock(&ppp->lock);
    
  pthread_mutex_unlock(&ppp->lock);

	return 0;

  
}

int __export ppp_chan_send(struct ppp_t *ppp, void *data, int size)
{
    if (!ppp || !data || size <= 0 || size > (ETHER_MAX_LEN - ETH_HLEN - sizeof(struct pppoe_hdr))) {
        log_ppp_error("ppp_chan_send: invalid parameters (ppp=%p, data=%p, size=%d)\n", 
                     ppp, data, size);
        return -EINVAL;
    }

	int n = 0;

  /*int i;
  int proto = ntohs(*(uint16_t*)(data));
  for(i = 0; i < 100; i++) {
    if(!ppp->is_processing)
      break;
    if(i % 100 == 0)
      log_debug("ppp_chan_send is_processing %s proto:0x%x (%d) 0000000000000000000000000000000000000000000\n", ppp->ses.sessionid, proto, i);
    usleep(10);
  }*/

  //pthread_mutex_lock(&ppp->lock);
  //ppp->is_processing = 1;
  //pthread_mutex_unlock(&ppp->lock);

  uint8_t pack[ETHER_MAX_LEN];

  memset(pack, 0, sizeof(pack));
  
  struct ethhdr *ethhdr = (struct ethhdr *)pack;
  struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);

  memcpy(ethhdr->h_source, ppp->hwaddr, ETH_ALEN);
  memcpy(ethhdr->h_dest, ppp->addr, ETH_ALEN);
  ethhdr->h_proto = htons(ETH_P_PPP_SES);

  hdr->ver = 1;
  hdr->type = 1;
  hdr->code = 0;
  hdr->sid = htons(ppp->pppoe_sid);
  hdr->length = htons(size);


	//log_ppp_debug("ppp_chan_send: sid: %d, size: %d\n", ppp->pppoe_sid, size);

	struct sockaddr_ll addr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_PPP_SES),
		.sll_ifindex = ppp->ifindex,
		.sll_halen = ETH_ALEN,
	};

	int len = ETH_HLEN + sizeof(*hdr) + size;

  memcpy(pack+ETH_HLEN+sizeof(*hdr), data, size);

  //pthread_mutex_lock(&ppp->lock);
  //ppp->is_processing = 0;
  //pthread_mutex_unlock(&ppp->lock);
  
	n = net->sendto(ppp->ppp_sock, pack, len, MSG_DONTWAIT, (struct sockaddr *)&addr, sizeof(addr));
  if (n < size)
		log_ppp_error("ppp_chan_send: short write %i, excpected %i\n", n, len);

	return n;
}

int __export ppp_unit_send(struct ppp_t *ppp, void *data, int size)
{
    if (!ppp || !data || size <= 0 || size > (ETHER_MAX_LEN - ETH_HLEN - sizeof(struct pppoe_hdr))) {
        log_ppp_error("ppp_unit_send: invalid parameters (ppp=%p, data=%p, size=%d)\n", 
                     ppp, data, size);
        return -EINVAL;
    }

	int n = 0;

  /*int i;
  int proto = ntohs(*(uint16_t*)(data));
  for(i = 0; i < 100; i++) {
    if(!ppp->is_processing)
      break;
    if(i % 100 == 0)
      log_debug("ppp_unit_send is_processing %s proto:0x%x (%d) 0000000000000000000000000000000000000000000\n", ppp->ses.sessionid, proto, i);
    usleep(10);
  }*/

  //pthread_mutex_lock(&ppp->lock);
  //ppp->is_processing = 1;
  //pthread_mutex_unlock(&ppp->lock);

  uint8_t pack[ETHER_MAX_LEN];

  memset(pack, 0, sizeof(pack));
  
  struct ethhdr *ethhdr = (struct ethhdr *)pack;
  struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);

  memcpy(ethhdr->h_source, ppp->hwaddr, ETH_ALEN);
  memcpy(ethhdr->h_dest, ppp->addr, ETH_ALEN);
  ethhdr->h_proto = htons(ETH_P_PPP_SES);

  hdr->ver = 1;
  hdr->type = 1;
  hdr->code = 0;
  hdr->sid = htons(ppp->pppoe_sid);
  hdr->length = htons(size);


	//log_ppp_debug("ppp_unit_send: sid: %d, size: %d\n", ppp->pppoe_sid, size);

	struct sockaddr_ll addr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_PPP_SES),
		.sll_ifindex = ppp->ifindex,
		.sll_halen = ETH_ALEN,
	};

	int len = ETH_HLEN + sizeof(*hdr) + size;

  memcpy(pack+ETH_HLEN+sizeof(*hdr), data, size);
  
  //pthread_mutex_lock(&ppp->lock);
  //ppp->is_processing = 0;
  //pthread_mutex_unlock(&ppp->lock);
  
	n = net->sendto(ppp->ppp_sock, pack, len, MSG_DONTWAIT, (struct sockaddr *)&addr, sizeof(addr));
  if (n < size)
		log_ppp_error("ppp_unit_send: short write %i, excpected %i\n", n, len);

	return n;
}

int __export ppp_data_send(struct ppp_info_s *ppp, void *data, int size)
{
    if (!ppp || !data || size <= 0 || size > (ETHER_MAX_LEN - ETH_HLEN - sizeof(struct pppoe_hdr))) {
        log_ppp_error("ppp_data_send: invalid parameters (ppp=%p, data=%p, size=%d)\n", 
                     ppp, data, size);
        return -EINVAL;
    }

	int n = 0;

  uint8_t pack[ETHER_MAX_LEN];

  memset(pack, 0, sizeof(pack));
  
  struct ethhdr *ethhdr = (struct ethhdr *)pack;
  struct pppoe_hdr *hdr = (struct pppoe_hdr *)(pack + ETH_HLEN);

  memcpy(ethhdr->h_source, ppp->hwaddr, ETH_ALEN);
  memcpy(ethhdr->h_dest, ppp->addr, ETH_ALEN);
  ethhdr->h_proto = htons(ETH_P_PPP_SES);

  hdr->ver = 1;
  hdr->type = 1;
  hdr->code = 0;
  hdr->sid = htons(ppp->pppoe_sid);
  hdr->length = htons(size);


	//log_ppp_debug("ppp_data_send: sid: %d, size: %d\n", ppp->pppoe_sid, size);

	struct sockaddr_ll addr = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_PPP_SES),
		.sll_ifindex = ppp->ifindex,
		.sll_halen = ETH_ALEN,
	};

	int len = ETH_HLEN + sizeof(*hdr) + size;

  memcpy(pack+ETH_HLEN+sizeof(*hdr), data, size);
  
  //pthread_mutex_lock(&ppp->lock);
  //ppp->is_processing = 0;
  //pthread_mutex_unlock(&ppp->lock);
  
	n = net->sendto(ppp->ppp_sock, pack, len, MSG_DONTWAIT, (struct sockaddr *)&addr, sizeof(addr));
  if (n < size)
		log_ppp_error("ppp_unit_send: short write %i, excpected %i\n", n, len);

	return n;
}

static int ppp_chan_read(struct triton_md_handler_t *h)
{
	struct ppp_t *ppp = container_of(h, typeof(*ppp), chan_hnd);
	struct ppp_handler_t *ppp_h;
	uint16_t proto;

	if (!ppp->buf)
		ppp->buf = mempool_alloc(buf_pool);

	while(1) {
cont:
		ppp->buf_size = net->read(h->fd, ppp->buf, PPP_BUF_SIZE);
		if (ppp->buf_size < 0) {
			if (errno != EAGAIN) {
				log_ppp_error("ppp_chan_read: %s\n", strerror(errno));
				ap_session_terminate(&ppp->ses, TERM_NAS_ERROR, 1);
				return 1;
			}
			break;
		}

		if (ppp->buf_size == 0)
			break;

		if (ppp->buf_size < 2) {
			log_ppp_error("ppp_chan_read: short read %i\n", ppp->buf_size);
			continue;
		}

		proto = ntohs(*(uint16_t*)ppp->buf);
		list_for_each_entry(ppp_h, &ppp->chan_handlers, entry) {
			if (ppp_h->proto == proto) {
				ppp_h->recv(ppp_h);
				if (ppp->fd == -1) {
					//ppp->ses.ctrl->finished(ppp);
					return 1;
				}
				goto cont;
			}
		}

                list_for_each_entry(ppp_h, &ppp->unit_handlers, entry) {
                        if (ppp_h->proto == proto)
                                goto cont;
                }

		lcp_send_proto_rej(ppp, proto);
		//log_ppp_warn("ppp_chan_read: discarding unknown packet %x\n", proto);
	}

	mempool_free(ppp->buf);
	ppp->buf = NULL;

	return 0;
}

static int ppp_unit_read(struct triton_md_handler_t *h)
{
	struct ppp_t *ppp = container_of(h, typeof(*ppp), unit_hnd);
	struct ppp_handler_t *ppp_h;
	uint16_t proto;

	if (!ppp->buf)
		ppp->buf = mempool_alloc(buf_pool);

	while (1) {
cont:
		ppp->buf_size = net->read(h->fd, ppp->buf, PPP_BUF_SIZE);
		if (ppp->buf_size < 0) {
			if (errno != EAGAIN) {
				log_ppp_error("ppp_unit_read: %s\n",strerror(errno));
				ap_session_terminate(&ppp->ses, TERM_NAS_ERROR, 1);
				return 1;
			}
			break;
		}

		if (ppp->buf_size == 0)
			break;

		if (ppp->buf_size < 2) {
			log_ppp_error("ppp_unit_read: short read %i\n", ppp->buf_size);
			continue;
		}

		proto=ntohs(*(uint16_t*)ppp->buf);
		list_for_each_entry(ppp_h, &ppp->unit_handlers, entry) {
			if (ppp_h->proto == proto) {
				ppp_h->recv(ppp_h);
				if (ppp->fd == -1) {
					//ppp->ses.ctrl->finished(ppp);
					return 1;
				}
				goto cont;
			}
		}
		lcp_send_proto_rej(ppp, proto);
		//log_ppp_warn("ppp_unit_read: discarding unknown packet %x\n", proto);
	}

	mempool_free(ppp->buf);
	ppp->buf = NULL;

	return 0;
}

void ppp_recv_proto_rej(struct ppp_t *ppp, uint16_t proto)
{
	struct ppp_handler_t *ppp_h;

	list_for_each_entry(ppp_h, &ppp->chan_handlers, entry) {
		if (ppp_h->proto == proto) {
			if (ppp_h->recv_proto_rej)
				ppp_h->recv_proto_rej(ppp_h);
			return;
		}
	}

	list_for_each_entry(ppp_h, &ppp->unit_handlers, entry) {
		if (ppp_h->proto == proto) {
			if (ppp_h->recv_proto_rej)
				ppp_h->recv_proto_rej(ppp_h);
			return;
		}
	}
}

static void __ppp_layer_started(struct ppp_t *ppp, struct ppp_layer_data_t *d)
{
	struct layer_node_t *n = d->node;
	int f = 0;

	list_for_each_entry(d, &n->items, entry) {
		if (!d->started && !d->passive) return;
		if (d->started && !d->optional)
			f = 1;
	}

	if (!f)
		return;

	if (n->entry.next == &ppp->layers) {
		if (ppp->ses.state == AP_STATE_STARTING)
			ap_session_activate(&ppp->ses);
	} else {
		n = list_entry(n->entry.next, typeof(*n), entry);
		list_for_each_entry(d, &n->items, entry) {
			d->starting = 1;
			if (d->layer->start(d)) {
				ap_session_terminate(&ppp->ses, TERM_NAS_ERROR, 0);
				return;
			}
		}
	}
}

void __export ppp_layer_started(struct ppp_t *ppp, struct ppp_layer_data_t *d)
{
	if (d->started)
		return;

	d->started = 1;

	__ppp_layer_started(ppp, d);
}

void __export ppp_layer_passive(struct ppp_t *ppp, struct ppp_layer_data_t *d)
{
	if (d->started)
		return;

	d->passive = 1;

	__ppp_layer_started(ppp, d);
}

void __export ppp_layer_finished(struct ppp_t *ppp, struct ppp_layer_data_t *d)
{
	struct layer_node_t *n = d->node;

	d->finished = 1;
	d->starting = 0;

	list_for_each_entry(n, &ppp->layers, entry) {
		list_for_each_entry(d, &n->items, entry) {
			if (d->starting && !d->finished)
				return;
		}
	}

	destablish_ppp(ppp);
}

int __export ppp_terminate(struct ap_session *ses, int hard)
{
	struct ppp_t *ppp = container_of(ses, typeof(*ppp), ses);
	struct layer_node_t *n;
	struct ppp_layer_data_t *d;
	int s = 0;

	if (hard) {
		destablish_ppp(ppp);
		return 0;
	}

	list_for_each_entry(n,&ppp->layers,entry) {
		list_for_each_entry(d,&n->items,entry) {
			if (d->starting) {
				s = 1;
				d->layer->finish(d);
			}
		}
	}

	if (!s) {
		destablish_ppp(ppp);
		return 0;
	}

	return 1;
}

void __export ppp_register_chan_handler(struct ppp_t *ppp,struct ppp_handler_t *h)
{
	list_add_tail(&h->entry,&ppp->chan_handlers);
}
void __export ppp_register_unit_handler(struct ppp_t *ppp,struct ppp_handler_t *h)
{
	list_add_tail(&h->entry,&ppp->unit_handlers);
}
void __export ppp_unregister_handler(struct ppp_t *ppp,struct ppp_handler_t *h)
{
	list_del(&h->entry);
}

static int get_layer_order(const char *name)
{
	if (!strcmp(name,"lcp")) return 0;
	if (!strcmp(name,"auth")) return 1;
	if (!strcmp(name,"ccp")) return 2;
	if (!strcmp(name,"ipcp")) return 2;
	if (!strcmp(name,"ipv6cp")) return 2;
	return -1;
}

int __export ppp_register_layer(const char *name, struct ppp_layer_t *layer)
{
	int order;
	struct layer_node_t *n,*n1;

	order = get_layer_order(name);

	if (order < 0)
		return order;

	list_for_each_entry(n, &layers, entry) {
		if (order > n->order)
			continue;
		if (order < n->order) {
			n1 = _malloc(sizeof(*n1));
			memset(n1, 0, sizeof(*n1));
			n1->order = order;
			INIT_LIST_HEAD(&n1->items);
			list_add_tail(&n1->entry, &n->entry);
			n = n1;
		}
		goto insert;
	}
	n1 = _malloc(sizeof(*n1));
	memset(n1, 0, sizeof(*n1));
	n1->order = order;
	INIT_LIST_HEAD(&n1->items);
	list_add_tail(&n1->entry, &layers);
	n = n1;
insert:
	list_add_tail(&layer->entry, &n->items);

	return 0;
}
void __export ppp_unregister_layer(struct ppp_layer_t *layer)
{
	list_del(&layer->entry);
}

static void init_layers(struct ppp_t *ppp)
{
	struct layer_node_t *n, *n1;
	struct ppp_layer_t *l;
	struct ppp_layer_data_t *d;

	list_for_each_entry(n,&layers,entry) {
		n1 = _malloc(sizeof(*n1));
		memset(n1, 0, sizeof(*n1));
		INIT_LIST_HEAD(&n1->items);
		list_add_tail(&n1->entry, &ppp->layers);
		list_for_each_entry(l, &n->items, entry) {
			d = l->init(ppp);
			d->layer = l;
			d->started = 0;
			d->node = n1;
			list_add_tail(&d->entry, &n1->items);
		}
	}
}

static void _free_layers(struct ppp_t *ppp)
{
	struct layer_node_t *n;
	struct ppp_layer_data_t *d;

	while (!list_empty(&ppp->layers)) {
		n = list_entry(ppp->layers.next, typeof(*n), entry);
		while (!list_empty(&n->items)) {
			d = list_entry(n->items.next, typeof(*d), entry);
			list_del(&d->entry);
			d->layer->free(d);
		}
		list_del(&n->entry);
		_free(n);
	}
}

static void start_first_layer(struct ppp_t *ppp)
{
	struct layer_node_t *n;
	struct ppp_layer_data_t *d;

	n = list_entry(ppp->layers.next, typeof(*n), entry);
	list_for_each_entry(d, &n->items, entry) {
		d->starting = 1;
		if (d->layer->start(d)) {
			ap_session_terminate(&ppp->ses, TERM_NAS_ERROR, 0);
			return;
		}
	}
}

struct ppp_layer_data_t *ppp_find_layer_data(struct ppp_t *ppp, struct ppp_layer_t *layer)
{
	struct layer_node_t *n;
	struct ppp_layer_data_t *d;

	list_for_each_entry(n,&ppp->layers,entry) {
		list_for_each_entry(d,&n->items,entry) {
			if (d->layer == layer)
				return d;
		}
	}

	return NULL;
}

static int parse_dflt_shaper(const char *opt, int *down_speed, int *up_speed)
{
	char *endptr;

	*down_speed = strtol(opt, &endptr, 10);

	if (*endptr != '/'){
		*up_speed = *down_speed;
		return 0;
	}

	opt = endptr + 1;
	*up_speed = strtol(opt, &endptr, 10);
	return 0;
}

static void load_config(void)
{
	const char *opt;

	opt = conf_get_opt("ppp", "verbose");
	if (opt && atoi(opt) >= 0)
		conf_ppp_verbose = atoi(opt) > 0;

	opt = conf_get_opt("ppp", "unit-cache");
	if (opt && atoi(opt) > 0)
		conf_unit_cache = atoi(opt);
	else
		conf_unit_cache = 0;

	opt = conf_get_opt("ppp", "unit-preallocate");
	if (opt)
		conf_unit_preallocate = atoi(opt);
	else
		conf_unit_preallocate = 0;

  opt = conf_get_opt("shaper", "rate-limit");
  if (opt)
    parse_dflt_shaper(opt, &dflt_down_speed, &dflt_up_speed);
  
  opt = conf_get_opt("shaper", "down-burst-factor");
  if (opt)
    down_burst_factor = strtod(opt, NULL);

  opt = conf_get_opt("shaper", "up-burst-factor");
  if (opt)
    up_burst_factor = strtod(opt, NULL);
  
}

static void init(void)
{
	buf_pool = mempool_create(PPP_BUF_SIZE);
	uc_pool = mempool_create(sizeof(struct pppunit_cache));

	load_config();
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)load_config);

	pthread_create(&uc_thr, NULL, uc_thread, NULL);
}

DEFINE_INIT(2, init);
