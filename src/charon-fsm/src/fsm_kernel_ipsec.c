/*
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
 * Copyright (C) 2006-2015 Tobias Brunner
 * Copyright (C) 2005-2009 Martin Willi
 * Copyright (C) 2008 Andreas Steffen
 * Copyright (C) 2006-2007 Fabian Hartmann, Noah Heusser
 * Copyright (C) 2006 Daniel Roethlisberger
 * Copyright (C) 2005 Jan Hutter
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <linux/socket.h>
#include <linux/ipsec.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/udp.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <nss_cmn.h>
#include <nss_crypto.h>
#include <daemon.h>

#include "fsm_kernel_ipsec.h"
#include "fsm_kernel_net.h"
#include "fsm_netlink_crypto.h"
#include "fsm_netlink_ipsec.h"
#include "fsm_netlink_ip.h"
#include "fsm_listener.h"
#include "fsm_utils.h"

#include <hydra.h>
#include <utils/utils.h>
#include <utils/debug.h>
#include <threading/mutex.h>
#include <collections/array.h>
#include <collections/hashtable.h>
#include <collections/linked_list.h>
#include <processing/jobs/callback_job.h>
#include <crypto/rngs/rng.h>

#define MIN_REPLAY_WINDOW 32
#define MAX_REPLAY_WINDOW 1024

#define IPSEC_DIR_STR(inbound) ((inbound) ? "inbound" : "outbound")

typedef struct private_fsm_kernel_ipsec_t private_fsm_kernel_ipsec_t;

/**
 * Private variables and functions of fsm_kernel class.
 */
struct private_fsm_kernel_ipsec_t
{
	/**
	 * Public part of the fsm_kernel_t object
	 */
	fsm_kernel_ipsec_t public;

	/**
	 * Mutex to lock access to installed SAs
	 */
	mutex_t *sas_mutex;

	/**
	 * Mutex to lock access to installed tunnels
	 */
	mutex_t *tunnels_mutex;

	/**
	 * Mutex to lock access to installed routes
	 */
	mutex_t *routes_mutex;

	/**
	 * Mutex to lock access to installed shunts
	 */
	mutex_t *shunts_mutex;

	/**
	 * List of tunnels
	 */
	linked_list_t *tunnels;

	/**
	 * List of SAs
	 */
	linked_list_t *sas;

	/**
	 * List of installed routes
	 */
	linked_list_t *routes;

	/**
	 * List of installed shunt routes
	 */
	linked_list_t *shunts;

	/**
	 * FSM Netlink Crypto object
	 */
	fsm_netlink_crypto_t *nl_crypto;

	/**
	 * FSM Netlink IPsec object
	 */
	fsm_netlink_ipsec_t *nl_ipsec;

	/**
	 * FSM Netlink IPv4 object
	 */
	fsm_netlink_ip_t *nl_ipv4;

	/**
	 * FSM Netlink IPv6 object
	 */
	fsm_netlink_ip_t *nl_ipv6;

	/**
	 * Random number generator
	 */
	rng_t *rng;

	/**
	 * Bus listener
	 */
	fsm_listener_t *listener;

	/**
	 * whether to actually install virtual IPs
	 */
	bool install_virtual_ip;
};

typedef struct iproute_t iproute_t;
struct iproute_t
{
	/**
	 * Reference count for the route, which may be installed by more
	 * than one policy.
	 */
	refcount_t ref;

	/**
	 * Destination subnet
	 */
	host_t *subnet;

	/**
	 * Prefix len
	 */
	u_int8_t prefixlen;

	/**
	 * Tunnel ifname
	 */
	char ifname[IFNAMSIZ];

	/**
	 * Gateway
	 */
	host_t *gw;

	/**
	 * Source IP
	 */
	host_t *src_ip;
};

typedef struct flow_t flow_t;
struct flow_t
{
	/**
	 * flow rule tuple
	 */
	struct
	{
		u_int32_t src[4];
		u_int32_t src_port;
		u_int32_t dst[4];
		u_int32_t dst_port;
		u_int32_t proto;
	} tuple;

	/**
	 * FSM Netlink IP object pointer
	 */
	fsm_netlink_ip_t *nl_ip;
};

typedef struct tunnel_t tunnel_t;

struct tunnel_t
{
	/**
	 * Reference count
	 */
	refcount_t ref;

	/**
	 * Unique ID of the IKE SA this tunnel is associated with.
	 */
	u_int32_t ike_sa_id;

	/**
	 * Interface name of the tunnel. This is assigned by the NSS IPsec driver.
	 */
	char ifname[IFNAMSIZ];

	/**
	 * Virtual IP of the tunnel, as assigned by the IKE exchange.
	 */
	host_t *vip;

	/**
	 * Local host IP
	 */
	host_t *lip;

	/**
	 * Remote peer IP
	 */
	host_t *rip;

	/**
	 * Mutex to protect this tunnel.
	 */
	mutex_t *mutex;

	/**
	 * Flow rule for this tunnel.
	 */
	flow_t *flow;
};


typedef struct sa_t sa_t;
struct sa_t
{
	/**
	 * Pointer to FSM ipsec instance
	 */
	private_fsm_kernel_ipsec_t *ipsec;

	/**
	 * Pointer to associated tunnel
	 */
	tunnel_t *tunnel;

	/**
	 * Request ID.
	 */
	u_int32_t reqid;

	/**
	 * Security Parameter Index (SPI) associted with this SA.
	 */
	u_int32_t spi;

	/**
	 * src IP and port for this SA.
	 */
	host_t *src;

	/**
	 * dst IP and port for this SA.
	 */
	host_t *dst;

	/**
	 * protocol for this SA.
	 */
	u_int8_t protocol;

	/**
	 * TRUE if this is an inbound SA.
	 */
	bool decap;

	/**
	 * TRUE if this SA requires NAT encapsulation
	 */
	bool nat;

	/**
	 * SA lifetime info used to initiate rekeying and SA EOL
	 */
	lifetime_cfg_t lifetime;

	/**
	 * Crypto index for this SA.
	 */
	u_int32_t crypto_index;

	/**
	 * Mutex to protect this SA.
	 */
	mutex_t *mutex;

	/**
	 * Replay window
	 */
	u_int32_t replay_window;

	/**
	 * SA family (AF_INET or AF_INET6)
	 */
	u_int32_t family;

	/**
	 * IPv4/IPv6 SA rule
	 */
	struct
	{
		u_int32_t src[4];
		u_int32_t dst[4];
		u_int32_t spi;
		u_int32_t ttl_hl;
	} rule;

	/**
	 * Encryption algorithm
	 */
	u_int16_t enc_alg;

	/**
	 * Encryption key length
	 */
	u_int32_t enc_len;

	/**
	 * Integrity algorithm
	 */
	u_int16_t int_alg;

	/**
	 * Integrity key length
	 */
	u_int32_t int_len;

	/**
	 * DSCP mark value
	 */
	mark_t mark;
};

/**
 * Used to keep track of SA lifetimes.
 */
typedef struct sa_expire_t sa_expire_t;
struct sa_expire_t
{
	/**
	 * Pointer to FSM ipsec instance
	 */
	private_fsm_kernel_ipsec_t *ipsec;

	/**
	 * SA entry
	 */
	sa_t *sa;

	/**
	 * hard offset
	 */
	u_int32_t hard_offset;
};

typedef struct icv_len_t icv_len_t;
struct icv_len_t
{
	u_int16_t int_alg;
	u_int16_t icv_len;
};

static icv_len_t icv_len[] =
{
	{ AUTH_HMAC_SHA1_96, 12 },
	{ AUTH_HMAC_SHA1_160, 20 },
	{ AUTH_HMAC_SHA2_256_96, 12 },
	{ AUTH_HMAC_SHA2_256_128, 16 },
};

/**
 * Look up a crypto algorithm name and key size
 */
static bool icv_len_lookup(u_int16_t int_alg, icv_len_t **icv_len_ptr)
{
	bool found = FALSE;
	u_int32_t i = 0;
	u_int32_t count = countof(icv_len);

	if (!icv_len_ptr)
	{
		return FALSE;
	}

	for (i = 0; i < count; i++)
	{
		if (icv_len[i].int_alg == int_alg)
		{
			*icv_len_ptr = &icv_len[i];
			DBG2(DBG_KNL, "%s: int_alg %N icv_len %u", __FUNCTION__,
				integrity_algorithm_names, int_alg, icv_len[i].icv_len);
			found = TRUE;
			break;
		}
	}

	return found;
}

static bool match_route_by_subnet_ifname(iproute_t *route, host_t *subnet,
	char *ifname)
{
	if (!route || !subnet || !ifname)
	{
		return FALSE;
	}
	return (route->subnet->equals(route->subnet, subnet) &&
		!strncmp(route->ifname, ifname, sizeof(route->ifname)));
}

static bool match_sa_by_spi_and_ips(sa_t *item, u_int32_t *spi,
	host_t *src, host_t *dst)
{
	if (!item || !spi || !src || !dst)
	{
		return FALSE;
	}
	return ((item->spi == *spi) && item->src->equals(item->src, src) &&
		item->dst->equals(item->dst, dst));
}

static bool match_sa_by_spi_inbound(sa_t *item, u_int32_t *spi,
	bool *inbound)
{
	if (!item || !spi || !inbound)
	{
		return FALSE;
	}
	return ((item->spi == *spi) && (item->decap == *inbound));
}

static bool match_tunnel_by_ips(tunnel_t *tunnel, host_t *lip, host_t *rip)
{
	if (!tunnel || !lip || !rip)
	{
		return FALSE;
	}
	return (tunnel->lip->equals(tunnel->lip, lip) &&
		tunnel->rip->equals(tunnel->rip, rip));
}

static bool match_tunnel_by_id(tunnel_t *tunnel, u_int32_t *ike_sa_id)
{
	if (!tunnel || !ike_sa_id)
	{
		return FALSE;
	}
	return (tunnel->ike_sa_id == *ike_sa_id);
}

METHOD(kernel_ipsec_t, get_features, kernel_feature_t,
	private_fsm_kernel_ipsec_t *this)
{
	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec", __FUNCTION__);

	return 0;
}

METHOD(kernel_ipsec_t, get_spi, status_t,
	private_fsm_kernel_ipsec_t *this, host_t *src, host_t *dst,
	u_int8_t protocol, u_int32_t *spi)
{
	bool result = FALSE;

	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec", __FUNCTION__);

	if (!this || !spi)
	{
		return INVALID_ARG;
	}

	if (!this->rng)
	{
		this->rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK);
		if (!this->rng)
		{
			DBG1(DBG_KNL, "%s: unable to create RNG", __FUNCTION__);
			return FAILED;
		}
	}

	result = this->rng->get_bytes(this->rng, sizeof(u_int32_t),
		(u_int8_t *)spi);
	return (result ? SUCCESS : FAILED);
}

METHOD(kernel_ipsec_t, get_cpi, status_t,
	private_fsm_kernel_ipsec_t *this, host_t *src, host_t *dst,
	u_int16_t *cpi)
{
	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec", __FUNCTION__);

	return NOT_SUPPORTED;
}

static job_requeue_t sa_expired(sa_expire_t *entry)
{
	status_t status = FAILED;
	u_int32_t hard_offset;

	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec", __FUNCTION__);

	if (!entry || !entry->sa || !entry->ipsec || !entry->ipsec->sas)
	{
		goto requeue_none;
	}

	/* Check SA to be sure it still exists */
	entry->ipsec->sas_mutex->lock(entry->ipsec->sas_mutex);
	status = entry->ipsec->sas->find_first(entry->ipsec->sas, NULL,
		(void **)&entry->sa);
	entry->ipsec->sas_mutex->unlock(entry->ipsec->sas_mutex);
	if ((status != SUCCESS) || !entry->sa->mutex)
	{
		goto requeue_none;
	}

	hard_offset = entry->hard_offset;
	/* Call kernel_handler expire, which will rekey/delete the SA */
	hydra->kernel_interface->expire(hydra->kernel_interface,
		entry->sa->protocol, entry->sa->spi, entry->sa->dst,
		(hard_offset == 0));

	if (hard_offset)
	{
		/* soft limit reached, schedule hard expire */
		entry->hard_offset = 0;
		return JOB_RESCHEDULE(hard_offset);
	}

requeue_none:
	return JOB_REQUEUE_NONE;
}

/**
 * Schedule a job to handle IPsec SA expiration
 */
static void schedule_expiration(private_fsm_kernel_ipsec_t *this, sa_t *sa)
{
	lifetime_cfg_t *lifetime = NULL;
	sa_expire_t *entry = NULL;
	callback_job_t *job = NULL;
	u_int32_t timeout = 0;

	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec", __FUNCTION__);

	if (!this)
	{
		return;
	}

	if (!sa)
	{
		DBG2(DBG_KNL, "%s: Could not schedule rekey/expire timer, sa NULL",
			__FUNCTION__);
		return;
	}

	if (!sa->lifetime.time.life)
	{
		/* no expiration at all */
		return;
	}

	INIT(entry,
		.ipsec = this,
		.sa = sa,
		);

	if (!entry)
	{
		DBG2(DBG_KNL, "%s: could not init entry, no expiration scehduled!",
			__FUNCTION__);
		return;
	}

	/* schedule a rekey first, a hard timeout will be scheduled then, if any */
	lifetime = &sa->lifetime;
	entry->hard_offset = lifetime->time.life - lifetime->time.rekey;
	timeout = lifetime->time.rekey;

	if (lifetime->time.life <= lifetime->time.rekey ||
		lifetime->time.rekey == 0)
	{
		/* no rekey, schedule hard timeout */
		entry->hard_offset = 0;
		timeout = lifetime->time.life;
	}

	job = callback_job_create((callback_job_cb_t)sa_expired, entry,
		(callback_job_cleanup_t)free, (callback_job_cancel_t)free);

	if (!job)
	{
		DBG2(DBG_KNL, "%s: could not init job, no expiration scheduled!",
			__FUNCTION__);
		free(entry);
		return;
	}

	lib->scheduler->schedule_job(lib->scheduler, (job_t *)job, timeout);
	DBG2(DBG_KNL, "%s: Scheduled %s expiration job in %us", __FUNCTION__,
		(entry->hard_offset ? "soft" : "hard"), timeout);
}

static status_t delete_route(iproute_t *route, mutex_t *mutex,
	linked_list_t *list)
{
	status_t status = SUCCESS;
	chunk_t addr = chunk_empty;

	if (!route || !mutex || !list || !route->subnet || !route->gw ||
		!route->src_ip)
	{
		return INVALID_ARG;
	}

	/* Only delete the route if there are no more references */
	if (!ref_put(&route->ref))
	{
		return SUCCESS;
	}

	mutex->lock(mutex);
	list->remove(list, route, NULL);
	mutex->unlock(mutex);
	DBG2(DBG_KNL,
		"%s: Removing route for dst_net %H prefix %u gw %H ifname %s src_ip %H",
		__FUNCTION__, route->subnet, route->prefixlen, route->gw, route->ifname,
		route->src_ip);
	addr = route->subnet->get_address(route->subnet);
	if (!addr.ptr || !addr.len)
	{
		DBG2(DBG_KNL,
		"%s: Failed to remove route for dst_net %H prefix %u gw %H ifname %s "
		"src_ip %H", __FUNCTION__, route->subnet, route->prefixlen, route->gw,
		route->ifname, route->src_ip);
		status = FAILED;
		goto exitout;
	}

	status = hydra->kernel_interface->del_route(hydra->kernel_interface, addr,
		route->prefixlen, route->gw, route->src_ip, route->ifname);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL,
		"%s: Failed to remove route for dst_net %H prefix %u gw %H ifname %s "
		"src_ip %H", __FUNCTION__, route->subnet, route->prefixlen, route->gw,
		route->ifname, route->src_ip);
		goto exitout;
	}

exitout:
	DESTROY_IF(route->subnet);
	DESTROY_IF(route->gw);
	DESTROY_IF(route->src_ip);
	free(route);

	return status;
}

void flush_rules(sa_t *sa, private_fsm_kernel_ipsec_t *this)
{
	status_t status = SUCCESS;

	if (!this || !sa || !sa->mutex)
	{
		return;
	}

	sa->mutex->lock(sa->mutex);
	if (sa->decap)
	{
		status = this->nl_ipsec->del_decap_sa(this->nl_ipsec,
			sa->tunnel->ifname, &sa->rule.src[0], &sa->rule.dst[0], sa->family,
			sa->rule.spi, sa->rule.ttl_hl);
	}
	else
	{
		status = this->nl_ipsec->del_encap_sa(this->nl_ipsec,
			sa->tunnel->ifname, &sa->rule.src[0], &sa->rule.dst[0], sa->family,
			sa->rule.spi, sa->rule.ttl_hl);
	}

	if (sa->family == AF_INET)
	{
		DBG2(DBG_KNL, "%s: %s %s rule for SPI 0x%08x src 0x%08x dst 0x%08x",
			__FUNCTION__,
			((status != SUCCESS) ? "Could not delete" : "Deleted"),
			(sa->decap ? "decap" : "encap"), sa->rule.spi, sa->rule.src[0],
			sa->rule.dst[0]);
	}
	else
	{
		DBG2(DBG_KNL,
			"%s: %s %s rule for SPI 0x%08x src %08x:%08x:%08x:%08x "
			"dst %08x:%08x:%08x:%08x", __FUNCTION__,
			((status != SUCCESS) ? "Could not delete" : "Deleted"),
			(sa->decap ? "decap" : "encap"), sa->rule.spi, sa->rule.src[0],
			sa->rule.src[1], sa->rule.src[2], sa->rule.src[3], sa->rule.dst[0],
			sa->rule.dst[1], sa->rule.dst[2], sa->rule.dst[3]);
	}

	sa->mutex->unlock(sa->mutex);
}

static status_t destroy_tunnel(private_fsm_kernel_ipsec_t *this,
	tunnel_t *tunnel)
{
	status_t status = SUCCESS;

	if (!this || !tunnel)
	{
		return INVALID_ARG;
	}

	/* Delete flow rule */
	if (tunnel->flow)
	{
		if (tunnel->flow->nl_ip)
		{
			tunnel->flow->nl_ip->del_flow(tunnel->flow->nl_ip,
				&tunnel->flow->tuple.src[0], tunnel->flow->tuple.src_port,
				&tunnel->flow->tuple.dst[0], tunnel->flow->tuple.dst_port,
				tunnel->flow->tuple.proto);
		}
		free(tunnel->flow);
		tunnel->flow = NULL;
	}

	status = this->nl_ipsec->destroy_tunnel(this->nl_ipsec, tunnel->ifname);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: Could not destroy tunnel %s for IKE SA %u",
			__FUNCTION__, tunnel->ifname, tunnel->ike_sa_id);
		return status;
	}

	/* Remove the tunnel from the list and free the memory */
	this->tunnels_mutex->lock(this->tunnels_mutex);
	this->tunnels->remove(this->tunnels, tunnel, NULL);
	this->tunnels_mutex->unlock(this->tunnels_mutex);
	DESTROY_IF(tunnel->vip);
	DESTROY_IF(tunnel->lip);
	DESTROY_IF(tunnel->rip);
	tunnel->mutex->unlock(tunnel->mutex);
	DESTROY_IF(tunnel->mutex);
	free(tunnel);

	return status;
}

static void delete_sa(sa_t *sa, private_fsm_kernel_ipsec_t *this)
{
	if (!this || !sa)
	{
		return;
	}

	if (!sa->mutex || !this->sas_mutex)
	{
		return;
	}

	sa->mutex->lock(sa->mutex);
	/* Remove the sa from the list */
	this->sas_mutex->lock(this->sas_mutex);
	if (this->sas)
	{
		this->sas->remove(this->sas, sa, NULL);
	}
	this->sas_mutex->unlock(this->sas_mutex);

	/* Delete the rules */
	flush_rules(sa, this);

	/* Delete the crypto rule */
	this->nl_crypto->del_session(this->nl_crypto, sa->crypto_index);

	DESTROY_IF(sa->src);
	DESTROY_IF(sa->dst);

	/* Decrease the tunnel reference count, and destroy the tunnel if no
	 * other SAs are using it.
	 */
	if (sa->tunnel && sa->tunnel->mutex)
	{
		sa->tunnel->mutex->lock(sa->tunnel->mutex);
		if (ref_put(&sa->tunnel->ref))
		{
			status_t status = FAILED;
			status = destroy_tunnel(this, sa->tunnel);
			if (status == SUCCESS)
			{
				sa->tunnel = NULL;
			}
		}
		if (sa->tunnel && sa->tunnel->mutex)
		{
			sa->tunnel->mutex->unlock(sa->tunnel->mutex);
		}
	}

	sa->mutex->unlock(sa->mutex);
}

METHOD(kernel_ipsec_t, del_sa, status_t,
	private_fsm_kernel_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, u_int16_t cpi, mark_t mark)
{
	status_t status = FAILED;
	sa_t *sa = NULL;

	if (!this || !src || !dst)
	{
		return INVALID_ARG;
	}
	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec protocol %u spi 0x%08x",
		__FUNCTION__, protocol, spi);

	this->sas_mutex->lock(this->sas_mutex);
	if (!this->sas)
	{
		this->sas_mutex->unlock(this->sas_mutex);
		return INVALID_ARG;
	}

	status = this->sas->find_first(this->sas,
		(linked_list_match_t)match_sa_by_spi_and_ips,
		(void **)&sa, &spi, src, dst);
	this->sas_mutex->unlock(this->sas_mutex);

	if ((status == SUCCESS) && sa)
	{
		delete_sa(sa, this);
		free(sa);
	}

	return status;
}

#define IP_ADDR_LEN(family) ((family == AF_INET) ? 4 : 16)

static status_t populate_addr_from_ts(u_int32_t family, traffic_selector_t *ts,
	u_int32_t *addr_ptr)
{
	chunk_t addr = chunk_empty;

	if (!addr_ptr || !ts)
	{
		return INVALID_ARG;
	}

	addr = ts->get_from_address(ts);
	if (!addr.ptr || !addr.len)
	{
		DBG2(DBG_KNL, "%s: get_address failed for %R", __FUNCTION__, ts);
		return FAILED;
	}

	if (addr.len != IP_ADDR_LEN(family))
	{
		DBG2(DBG_KNL, "%s: invalid address length %u, expected %u",
			__FUNCTION__, addr.len, IP_ADDR_LEN(family));
		return FAILED;
	}

	/* The address is natively in network byte order when returned
	 * from ts>get_from_address(ts), so we need to translate to
	 * host order.
	 */
	if (family == AF_INET)
	{
		*addr_ptr = ntohl(*(uint32_t *)addr.ptr);
	}
	else
	{
		u_int32_t *ptr;
		u_int8_t i;
		size_t len = IP_ADDR_LEN(family) / sizeof(u_int32_t);

		ptr = (u_int32_t *)addr.ptr;
		for(i = 0; i < len; i++)
		{
#if BYTE_ORDER == LITTLE_ENDIAN
			addr_ptr[(len - i - 1)] = ntohl(ptr[i]);
#else
			addr_ptr[i] = ptr[i];
#endif
		}
	}

	return SUCCESS;
}

static status_t populate_addr_from_host(u_int32_t family, host_t *host,
	u_int32_t *addr_ptr)
{
	chunk_t addr = chunk_empty;

	if (!addr_ptr || !host)
	{
		return INVALID_ARG;
	}

	addr = host->get_address(host);
	if (!addr.ptr || !addr.len)
	{
		DBG2(DBG_KNL, "%s: get_address failed for %H", __FUNCTION__, host);
		return FAILED;
	}

	if (addr.len != IP_ADDR_LEN(family))
	{
		DBG2(DBG_KNL, "%s: invalid address length %u, expected %u",
			__FUNCTION__, addr.len, IP_ADDR_LEN(family));
		return FAILED;
	}

	/* The address is natively in network byte order when returned
	 * from host->get_address(host), so we need to translate to
	 * host order.
	 */
	if (family == AF_INET)
	{
		*addr_ptr = ntohl(*(uint32_t *)addr.ptr);
	}
	else
	{
		u_int32_t *ptr;
		u_int8_t i;
		size_t len = IP_ADDR_LEN(family) / sizeof(u_int32_t);

		ptr = (u_int32_t *)addr.ptr;
		for(i = 0; i < len; i++)
		{
#if BYTE_ORDER == LITTLE_ENDIAN
			addr_ptr[(len - i - 1)] = ntohl(ptr[i]);
#else
			addr_ptr[i] = ptr[i];
#endif
		}
	}

	return SUCCESS;
}

static status_t populate_sa(sa_t *sa)
{
	status_t status = SUCCESS;

	if (!sa || !sa->src || !sa->dst)
	{
		status = INVALID_ARG;
		goto exitfunc;
	}

	DBG3(DBG_KNL, "%s: src %H dst %H family %s", __FUNCTION__,  sa->src,
		sa->dst, ((sa->family == AF_INET) ? "AF_INET" : "AF_INET6"));

	status = populate_addr_from_host(sa->family, sa->src, &sa->rule.src[0]);
	if (status != SUCCESS)
	{
		goto exitfunc;
	}

	status = populate_addr_from_host(sa->family, sa->dst, &sa->rule.dst[0]);
	if (status != SUCCESS)
	{
		goto exitfunc;
	}

	sa->rule.spi = ntohl(sa->spi);
	/* TODO: Make this configurable? */
	sa->rule.ttl_hl = 64;

exitfunc:
	return status;
}

static status_t add_crypto_rule(private_fsm_kernel_ipsec_t *this,
	sa_t *sa, u_int16_t enc_alg, chunk_t enc_key, u_int16_t int_alg,
	chunk_t int_key)
{
	status_t status = FAILED;

	if (!this || !sa)
	{
		DBG2(DBG_KNL, "%s: Invalid arguments", __FUNCTION__);
		return INVALID_ARG;
	}

	/* Create the crypto session */
	status = this->nl_crypto->add_session(this->nl_crypto, enc_alg, enc_key,
		int_alg, int_key, sa->family, sa->nat, sa->decap, &sa->crypto_index);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: Could not add crypto session!", __FUNCTION__);
		return status;
	}

	return status;
}

static status_t add_decap_sa(private_fsm_kernel_ipsec_t *this, sa_t *sa)
{
	status_t status = FAILED;
	bool seq_skip = FALSE;
	bool trailer_skip = FALSE;
	bool use_pattern = FALSE;
	icv_len_t *icv = NULL;

	if (!this || !sa || !this->nl_ipsec)
	{
		DBG2(DBG_KNL, "%s: Invalid arguments", __FUNCTION__);
		status = INVALID_ARG;
		goto errorexit;
	}

	if (!icv_len_lookup(sa->int_alg, &icv) || !icv)
	{
		status = FAILED;
		goto errorexit;
	}

	status = this->nl_ipsec->add_decap_sa(this->nl_ipsec, sa->tunnel->ifname,
		&sa->rule.src[0], &sa->rule.dst[0], sa->family, sa->rule.spi,
		sa->rule.ttl_hl, sa->crypto_index, icv->icv_len,
		(u_int16_t)sa->replay_window, sa->nat, seq_skip, trailer_skip,
		use_pattern);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: Failed to add decap rule", __FUNCTION__);
	}

errorexit:
	return status;
}

static status_t add_ip_flow_rule(private_fsm_kernel_ipsec_t *this, sa_t *sa)
{
	status_t status = FAILED;
	flow_t *flow = NULL;
	bool valid = FALSE;
	char *ifname = NULL;
	char src_ifname[IFNAMSIZ];
	char dst_ifname[IFNAMSIZ];

	if (!this || !sa || !this->nl_ipv4 || !this->nl_ipv6 || !sa->tunnel)
	{
		DBG2(DBG_KNL, "%s: Invalid arguments", __FUNCTION__);
		status = INVALID_ARG;
		goto errorexit;
	}

	INIT(flow);

	if (!flow)
	{
		DBG2(DBG_KNL, "%s: Could not allocate flow object", __FUNCTION__);
		goto errorexit;
	}

	if (sa->family == AF_INET)
	{
		flow->nl_ip = this->nl_ipv4;
	}
	else
	{
		flow->nl_ip = this->nl_ipv6;
	}

	/* Get the destination interface name */
	valid = hydra->kernel_interface->get_interface(hydra->kernel_interface,
		sa->dst, &ifname);
	if (!valid || !ifname)
	{
		DBG2(DBG_KNL, "%s: get_interface failed for dst %H",
			__FUNCTION__, sa->dst);
		goto errorexit;
	}

	copy_ifname(dst_ifname, ifname);
	free(ifname);

	/* The source interface name is the name of the tunnel */
	memcpy(src_ifname, sa->tunnel->ifname, IFNAMSIZ);

	/* Populate the flow structure */
	flow->tuple.proto = (sa->nat) ? IPPROTO_UDP : sa->protocol;
	flow->tuple.src_port = (sa->nat) ? sa->dst->get_port(sa->dst) : 0;
	flow->tuple.dst_port = (sa->nat) ? sa->src->get_port(sa->src) : 0;

	status = populate_addr_from_host(sa->family, sa->dst, &flow->tuple.src[0]);
	if (status != SUCCESS)
	{
		goto errorexit;
	}

	status = populate_addr_from_host(sa->family, sa->src, &flow->tuple.dst[0]);
	if (status != SUCCESS)
	{
		goto errorexit;
	}

	status = flow->nl_ip->add_flow(flow->nl_ip, &flow->tuple.src[0],
		flow->tuple.src_port, &flow->tuple.dst[0], flow->tuple.dst_port,
		flow->tuple.proto, src_ifname, dst_ifname);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: Failed to add IP flow rule", __FUNCTION__);
		goto errorexit;
	}

	sa->tunnel->mutex->lock(sa->tunnel->mutex);
	sa->tunnel->flow = flow;
	sa->tunnel->mutex->unlock(sa->tunnel->mutex);

errorexit:
	if ((status != SUCCESS) && flow)
	{
		free(flow);
		sa->tunnel->mutex->lock(sa->tunnel->mutex);
		sa->tunnel->flow = NULL;
		sa->tunnel->mutex->unlock(sa->tunnel->mutex);
	}

	return status;
}

iproute_t *prepare_route(private_fsm_kernel_ipsec_t *this,
	traffic_selector_t *dst_ts, char *dst_ifname, host_t *src_ip)
{
	status_t status = SUCCESS;
	iproute_t *route = NULL;
	char *ifname = NULL;
	bool valid = FALSE;

	if (!this || !dst_ts)
	{
		DBG2(DBG_KNL, "%s: Invalid arguments", __FUNCTION__);
		return NULL;
	}

	INIT(route,
		.ref = 1,
		);

	if (!route)
	{
		DBG2(DBG_KNL, "%s: Could not alloc route", __FUNCTION__);
		status = FAILED;
		goto exitfunc;
	}

	/* Prepare the destination network from the dst_ts */
	dst_ts->to_subnet(dst_ts, &route->subnet, &route->prefixlen);
	if (!route->subnet)
	{
		DBG2(DBG_KNL, "%s: Could not get subnet from %R", __FUNCTION__,
			dst_ts);
		status = FAILED;
		goto exitfunc;
	}

	if (route->subnet->is_anyaddr(route->subnet) || (dst_ifname != NULL))
	{
		/* This handles the default route and anything using the
		 * tunnel dev, since dst_ifname is set in that case.
		 */
		route->gw = host_create_any(route->subnet->get_family(route->subnet));
		if (!route->gw)
		{
			DBG2(DBG_KNL, "%s: Could not create gateway", __FUNCTION__);
			status = FAILED;
			goto exitfunc;
		}

		if (!src_ip)
		{
			route->src_ip =
				host_create_any(route->subnet->get_family(route->subnet));
		}
		else
		{
			route->src_ip = src_ip->clone(src_ip);
		}

		if (!route->src_ip)
		{
			DBG2(DBG_KNL, "%s: Could not create src_ip", __FUNCTION__);
			status = FAILED;
			goto exitfunc;
		}

	}
	else
	{
		if (dst_ts->is_host(dst_ts, NULL))
		{
			/* For explicit hosts, look up the next hop to use as the
			 * gateway for the route.
			 */
			route->gw = hydra->kernel_interface->get_nexthop(
				hydra->kernel_interface, route->subnet, route->prefixlen, NULL);
			if (!route->gw)
			{
				DBG2(DBG_KNL, "%s: Could not create gateway", __FUNCTION__);
				status = FAILED;
				goto exitfunc;
			}

			/* Use the gateway to look up the local source address. */
			route->src_ip = hydra->kernel_interface->get_source_addr(
				hydra->kernel_interface, route->gw, NULL);
			if (!route->src_ip)
			{
				DBG2(DBG_KNL, "%s: Could not get source address for gw %H",
					__FUNCTION__, route->gw);
				status = FAILED;
				goto exitfunc;
			}
			status = SUCCESS;
		}
		else
		{
			/* See if there is an interface that has an address that falls
			 * within this traffic selector. If so, use that address as the
			 * source address for the route.
			 */
			status = hydra->kernel_interface->get_address_by_ts(
				hydra->kernel_interface, dst_ts, &route->src_ip, NULL);
			if ((status != SUCCESS) || !route->src_ip)
			{
				/* Since no local interface has an address in the ts range,
				 * look up the next hop to use as the gateway for the route.
				 */
				route->gw = hydra->kernel_interface->get_nexthop(
					hydra->kernel_interface, route->subnet, route->prefixlen,
					NULL);
				if (!route->gw)
				{
					/* Since there is no next hop found, use %any for the
					 * source address.
					 */
					route->src_ip = host_create_any(
						route->subnet->get_family(route->subnet));
					if (!route->src_ip)
					{
						DBG2(DBG_KNL,
							"%s: Could not get src address for dst_ts %R",
							__FUNCTION__, dst_ts);
						status = FAILED;
						goto exitfunc;
					}
				}
				else
				{
					/* A gateway was found, use it to look up the source
					 * address of the interface for the route.
					 */
					route->src_ip = hydra->kernel_interface->get_source_addr(
						hydra->kernel_interface, route->gw, NULL);
					if (!route->src_ip)
					{
						DBG2(DBG_KNL,
							"%s: Could not get source address for gw %H",
							__FUNCTION__, route->gw);
						status = FAILED;
						goto exitfunc;
					}
				}
			}

			/* In case no gateway was set above, use %any. */
			if (!route->gw)
			{
				route->gw =
					host_create_any(route->subnet->get_family(route->subnet));
				if (!route->gw)
				{
					DBG2(DBG_KNL, "%s: Could not create gateway", __FUNCTION__);
					status = FAILED;
					goto exitfunc;
				}
			}
			status = SUCCESS;
		}
	}

	if (!dst_ifname)
	{
		/* Look up the interface name for the source address. */
		valid = hydra->kernel_interface->get_interface(hydra->kernel_interface,
			route->src_ip, &ifname);
		if (!valid || !ifname)
		{
			DBG2(DBG_KNL, "%s: Could not get interface name for src_ip %H",
				__FUNCTION__, route->src_ip);
			goto exitfunc;
		}

		status = copy_ifname(route->ifname, ifname);
		free(ifname);
	}
	else
	{
		status = copy_ifname(route->ifname, dst_ifname);
	}

	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: copy_ifname failed", __FUNCTION__);
		goto exitfunc;
	}

exitfunc:
	if (status != SUCCESS)
	{
		if (route)
		{
			DESTROY_IF(route->src_ip);
			DESTROY_IF(route->gw);
			DESTROY_IF(route->subnet);
			free(route);
			route = NULL;
		}
	}

	return route;
}

static status_t install_route(private_fsm_kernel_ipsec_t *this,
	traffic_selector_t *dst_ts, mutex_t *mutex, linked_list_t *list,
	char *ifname, host_t *src_ip)
{
	status_t status = SUCCESS;
	iproute_t *route = NULL;
	iproute_t *listroute = NULL;
	chunk_t addr = chunk_empty;

	if (!this || !dst_ts || !mutex || !list)
	{
		return INVALID_ARG;
	}

	route = prepare_route(this, dst_ts, ifname, src_ip);
	if (!route)
	{
		DBG2(DBG_KNL, "%s: Could not prepare route", __FUNCTION__);
		status = FAILED;
		goto exitfunc;
	}

	addr = route->subnet->get_address(route->subnet);
	if (!addr.ptr || !addr.len)
	{
		DBG2(DBG_KNL, "%s: Could not get address from subnet %H",
			__FUNCTION__, route->subnet);
		status = FAILED;
		goto exitfunc;
	}

	/* Check to see if this route already exists; if so, increment refcount.
	 * If not, create it and add to the list.
	 */
	mutex->lock(mutex);
	status = list->find_first(list,
		(linked_list_match_t)match_route_by_subnet_ifname, (void **)&listroute,
		route->subnet, &route->ifname[0]);
	mutex->unlock(mutex);

	if ((status != SUCCESS) || !listroute)
	{
		DBG2(DBG_KNL,
			"%s: Adding route for dst_net %H prefix %u gw %H src %H ifname %s",
			__FUNCTION__, route->subnet, route->prefixlen, route->gw,
			route->src_ip, route->ifname);

		status = hydra->kernel_interface->add_route(hydra->kernel_interface,
			addr, route->prefixlen, route->gw, route->src_ip,
			&route->ifname[0]);

		switch (status)
		{
			case SUCCESS:
				DBG2(DBG_KNL, "%s: Installed source route for %H",
					__FUNCTION__, route->subnet);
				mutex->lock(mutex);
				list->insert_last(list, route);
				mutex->unlock(mutex);
				break;
			case ALREADY_DONE:
				DBG2(DBG_KNL, "%s: Source route for %H already installed",
					__FUNCTION__, route->subnet);
				mutex->lock(mutex);
				list->insert_last(list, route);
				mutex->unlock(mutex);
				status = SUCCESS;
				break;
			default:
				DBG2(DBG_KNL, "%s: unable to install source route for %H",
					__FUNCTION__, route->subnet);
				DESTROY_IF(route->subnet);
				DESTROY_IF(route->gw);
				DESTROY_IF(route->src_ip);
				free(route);
				route = NULL;
				break;
		}
	}
	else if ((status == SUCCESS) && listroute)
	{
		DESTROY_IF(route->subnet);
		DESTROY_IF(route->gw);
		DESTROY_IF(route->src_ip);
		free(route);
		ref_get(&listroute->ref);
	}

exitfunc:
	if (status != SUCCESS)
	{
		delete_route(route, mutex, list);
	}

	return status;
}

static status_t add_route(private_fsm_kernel_ipsec_t *this, sa_t *sa,
	traffic_selector_t *dst_ts)
{
	status_t status = FAILED;

	if (!this || !sa || !dst_ts || !this->routes || !this->routes_mutex)
	{
		return INVALID_ARG;
	}

	status = install_route(this, dst_ts, this->routes_mutex, this->routes,
		&sa->tunnel->ifname[0], NULL);

	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: Failed to install route for %R", __FUNCTION__,
			dst_ts);
	}

	return status;
}

static status_t add_encap_flow(private_fsm_kernel_ipsec_t *this, sa_t *sa,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts, u_int32_t family)
{
	status_t status = FAILED;
	u_int32_t src[4];
	u_int32_t dst[4];
	u_int32_t proto = 0;
	icv_len_t *icv = NULL;

	if (!this || !sa || !src_ts || !dst_ts)
	{
		return INVALID_ARG;
	}

	if (!icv_len_lookup(sa->int_alg, &icv) || !icv)
	{
		return FAILED;
	}

	proto = dst_ts->get_protocol(dst_ts);
	if (!proto)
	{
		DBG1(DBG_KNL, "%s: Protocol %u not supported for encap flows",
			__FUNCTION__, proto);
		status = INVALID_ARG;
		goto exitfunc;
	}

	status = populate_addr_from_ts(family, dst_ts, &dst[0]);
	if (status != SUCCESS)
	{
		goto exitfunc;
	}

	status = populate_addr_from_ts(family, src_ts, &src[0]);
	if (status != SUCCESS)
	{
		goto exitfunc;
	}

	status = this->nl_ipsec->add_encap_flow(this->nl_ipsec,
		sa->tunnel->ifname, &src[0], &dst[0], family, proto, &sa->rule.src[0],
		&sa->rule.dst[0], sa->family, sa->rule.spi, sa->rule.ttl_hl,
		sa->crypto_index, icv->icv_len, (u_int16_t)sa->replay_window, sa->nat,
		FALSE, FALSE, FALSE, sa->mark.value);

exitfunc:
	return status;
}

static status_t add_encap_subnet(private_fsm_kernel_ipsec_t *this, sa_t *sa,
	traffic_selector_t *dst_ts, u_int32_t family)
{
	status_t status = FAILED;
	u_int32_t proto = 0;
	icv_len_t *icv = NULL;
	u_int32_t msk[4];
	host_t *subnet = NULL;
	host_t *netmask = NULL;
	u_int32_t sub[4];
	u_int8_t mask;

	if (!this || !sa || !dst_ts)
	{
		return INVALID_ARG;
	}

	if (!icv_len_lookup(sa->int_alg, &icv) || !icv)
	{
		return FAILED;
	}

	proto = dst_ts->get_protocol(dst_ts);
	if (!proto)
	{
		/* A protocol of 0 denotes %any, which is 0xFF in NSS */
		proto = 0xFF;
	}

	/* Prepare the destination network from the dst_ts */
	dst_ts->to_subnet(dst_ts, &subnet, &mask);
	if (!subnet)
	{
		DBG2(DBG_KNL, "%s: Could not get subnet from %R", __FUNCTION__,
			dst_ts);
		status = FAILED;
		goto exitfunc;
	}

	netmask = host_create_netmask(family, mask);
	if (!netmask)
	{
		DBG2(DBG_KNL, "%s: Could not create netmask from %R", __FUNCTION__,
			dst_ts);
		status = FAILED;
		goto exitfunc;
	}

	status = populate_addr_from_host(family, netmask, &msk[0]);
	if (status != SUCCESS)
	{
		goto exitfunc;
	}

	status = populate_addr_from_host(family, subnet, &sub[0]);
	if (status != SUCCESS)
	{
		goto exitfunc;
	}

	status = this->nl_ipsec->add_encap_subnet(this->nl_ipsec,
		sa->tunnel->ifname, &sub[0], &msk[0], family, proto,
		&sa->rule.src[0], &sa->rule.dst[0], sa->family, sa->rule.spi,
		sa->rule.ttl_hl, sa->crypto_index, icv->icv_len,
		(u_int16_t)sa->replay_window, sa->nat, FALSE, FALSE, FALSE,
		sa->mark.value);

exitfunc:
	DESTROY_IF(netmask);
	DESTROY_IF(subnet);

	return status;
}

METHOD(kernel_ipsec_t, add_sa, status_t,
	private_fsm_kernel_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, u_int32_t reqid, mark_t mark,
	u_int32_t tfc, lifetime_cfg_t *lifetime, u_int16_t enc_alg, chunk_t enc_key,
	u_int16_t int_alg, chunk_t int_key, ipsec_mode_t mode,
	u_int16_t ipcomp, u_int16_t cpi, u_int32_t replay_window,
	bool initiator, bool encap, bool esn, bool inbound, bool update,
	linked_list_t *src_ts, linked_list_t *dst_ts)
{
	tunnel_t *tunnel = NULL;
	sa_t *sa = NULL;
	status_t status = FAILED;
	host_t *lip = (inbound) ? dst : src;
	host_t *rip = (inbound) ? src : dst;
	refcount_t ref = 0;

	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec mode %N protocol %u "
		"spi 0x%08x %s mark value 0x%08x mask 0x%08x NAT %s",
		__FUNCTION__, ipsec_mode_names, mode, protocol, spi,
		IPSEC_DIR_STR(inbound), mark.value, mark.mask,
		((encap) ? "enabled" : "disabled"));

	if (!this || !src || !dst || !lifetime || !src_ts || !dst_ts)
	{
		DBG1(DBG_KNL, "%s: Invalid arguments", __FUNCTION__);
		return INVALID_ARG;
	}

	if (!this->tunnels || !this->sas || !this->tunnels_mutex ||
		!this->sas_mutex)
	{
		return INVALID_ARG;
	}

	if (mode != MODE_TUNNEL)
	{
		DBG1(DBG_KNL, "%s: Mode %N and protocol %u not supported", __FUNCTION__,
			ipsec_mode_names, mode, protocol);
		return NOT_SUPPORTED;
	}

	/* Get the tunnel */
	this->tunnels_mutex->lock(this->tunnels_mutex);
	status = this->tunnels->find_first(this->tunnels,
		(linked_list_match_t)match_tunnel_by_ips,
		(void **)&tunnel, lip, rip);
	this->tunnels_mutex->unlock(this->tunnels_mutex);
	if ((status != SUCCESS) || !tunnel)
	{
		DBG1(DBG_KNL, "%s: Could not locate tunnel for lip %H rip %H",
			__FUNCTION__, lip, rip);
		return FAILED;
	}

	/* See if we created an SA for this SPI already */
	this->sas_mutex->lock(this->sas_mutex);
	status = this->sas->find_first(this->sas,
		(linked_list_match_t)match_sa_by_spi_inbound,
		(void **)&sa, &spi, &inbound);
	this->sas_mutex->unlock(this->sas_mutex);
	if ((status == SUCCESS) && sa)
	{
		DBG2(DBG_KNL, "%s: IPsec SA already created for SPI 0x%08x %s",
			__FUNCTION__, spi, IPSEC_DIR_STR(inbound));
		return SUCCESS;
	}

	sa = NULL;

	/* Create an sa_t object */
	INIT(sa,
		.ipsec = this,
		.tunnel = tunnel,
		.reqid = reqid,
		.spi = spi,
		.src = src->clone(src),
		.dst = dst->clone(dst),
		.protocol = protocol,
		.decap = inbound,
		.nat = encap,
		.lifetime = *lifetime,
		.mutex = mutex_create(MUTEX_TYPE_RECURSIVE),
		.replay_window = replay_window,
		.enc_alg = enc_alg,
		.enc_len = enc_key.len,
		.int_alg = int_alg,
		.int_len = int_key.len,
		.mark = mark,
		);

	if (!sa)
	{
		DBG1(DBG_KNL, "%s: Failed to allocate mem for SPI 0x%08x %s",
			__FUNCTION__, spi, IPSEC_DIR_STR(inbound));
		return FAILED;
	}

	if (!sa->mutex || !sa->src || !sa->dst)
	{
		DBG1(DBG_KNL, "%s: Failed to allocate mem for SPI 0x%08x %s",
			__FUNCTION__, spi, IPSEC_DIR_STR(inbound));
		status = FAILED;
		goto errorexit;
	}


	if ((replay_window < (u_int32_t)MIN_REPLAY_WINDOW) ||
		(replay_window > (u_int32_t)MAX_REPLAY_WINDOW))
	{
		DBG1(DBG_KNL,
			"%s: Invalid replay window value %u. Must be %u-%u.",
			__FUNCTION__, replay_window, MIN_REPLAY_WINDOW, MAX_REPLAY_WINDOW);
		status = FAILED;
		goto errorexit;
	}

	sa->mutex->lock(sa->mutex);
	/* Add to the linked list */
	this->sas_mutex->lock(this->sas_mutex);
	this->sas->insert_last(this->sas, sa);
	this->sas_mutex->unlock(this->sas_mutex);

	sa->family = sa->dst->get_family(sa->dst);
	status = populate_sa(sa);
	if (status != SUCCESS)
	{
		goto errorexit;
	}

	status = add_crypto_rule(this, sa, enc_alg, enc_key, int_alg, int_key);
	if (status != SUCCESS)
	{
		DBG1(DBG_KNL, "%s: Crypto setup failed for SPI 0x%08x %s",
			__FUNCTION__, spi, IPSEC_DIR_STR(inbound));
		goto errorexit;
	}

	/* Increment the tunnel reference count so it's clear an SA is using it. */
	tunnel->mutex->lock(tunnel->mutex);
	ref = ref_get(&tunnel->ref);
	DBG2(DBG_KNL, "%s: IKE SA %u tunnel refcount %u", __FUNCTION__,
		tunnel->ike_sa_id, ref);
	tunnel->mutex->unlock(tunnel->mutex);

	if (inbound)
	{
		/* Decap rules are tied to the SPI, so we need a new one even if this
		 * SA is rekeying.
		 */
		status = add_decap_sa(this, sa);
		if (status != SUCCESS)
		{
			DBG1(DBG_KNL, "%s: Failed to add decap rule for SPI 0x%08x %s",
				__FUNCTION__, spi, IPSEC_DIR_STR(inbound));
			goto delsa;
		}

		if (!tunnel->flow)
		{
			/* Need an IP flow rule for this tunnel */
			status = add_ip_flow_rule(this, sa);
			if (status != SUCCESS)
			{
				DBG1(DBG_KNL, "%s: Failed to add flow rule for ifname %s",
					__FUNCTION__, tunnel->ifname);
				goto delsa;
			}
		}
		else
		{
			DBG2(DBG_KNL, "%s: Flow rule exists for ifname %s", __FUNCTION__,
				tunnel->ifname);
		}
	}
	else
	{
		enumerator_t *enumerator = NULL;
		traffic_selector_t *ts = NULL;

		enumerator = dst_ts->create_enumerator(dst_ts);

		if (enumerator)
		{
			/* For each destination traffic selector, install a route. */
			while (enumerator->enumerate(enumerator, &ts))
			{
				status = add_route(this, sa, ts);
				if (status != SUCCESS)
				{
					DBG1(DBG_KNL, "%s: Failed to add route for %R",
						__FUNCTION__, ts);
					enumerator->destroy(enumerator);
					goto delsa;
				}
			}
			enumerator->destroy(enumerator);
		}
	}

	/* Schedule rekey/expiration for this SA */
	schedule_expiration(this, sa);
	sa->mutex->unlock(sa->mutex);

	return status;

delsa:
	sa->mutex->unlock(sa->mutex);
	delete_sa(sa, this);
	free(sa);
	return FAILED;

errorexit:
	if (sa)
	{
		DESTROY_IF(sa->src);
		DESTROY_IF(sa->dst);
		DESTROY_IF(sa->mutex);
		free(sa);
	}
	return FAILED;
}

METHOD(kernel_ipsec_t, update_sa, status_t,
	private_fsm_kernel_ipsec_t *this, u_int32_t spi, u_int8_t protocol,
	u_int16_t cpi, host_t *src, host_t *dst, host_t *new_src, host_t *new_dst,
	bool old_encap, bool new_encap, mark_t mark)
{
	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec proto %u", __FUNCTION__,
		protocol);

	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, flush_sas, status_t, private_fsm_kernel_ipsec_t *this)
{
	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec", __FUNCTION__);

	if (!this || !this->sas_mutex)
	{
		return INVALID_ARG;
	}

	this->sas_mutex->lock(this->sas_mutex);
	if (this->sas)
	{
		this->sas->invoke_function(this->sas,
			(linked_list_invoke_t)delete_sa, this);
		this->sas->destroy_function(this->sas, free);
	}
	this->sas_mutex->unlock(this->sas_mutex);

	return SUCCESS;
}

METHOD(kernel_ipsec_t, query_sa, status_t,
	private_fsm_kernel_ipsec_t *this, host_t *src, host_t *dst,
	u_int32_t spi, u_int8_t protocol, mark_t mark,
	u_int64_t *bytes, u_int64_t *packets, time_t *time)
{
	status_t status = FAILED;

	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec", __FUNCTION__);

	if (!this || !this->nl_ipsec || !src || !dst || !bytes || !packets ||
		!time)
	{
		return NOT_SUPPORTED;
	}

	*bytes = 0;
	*time = 0;
	*packets = 0;

	status = this->nl_ipsec->get_stats(this->nl_ipsec, ntohl(spi), bytes,
		packets, time);
	if (status != SUCCESS)
	{
		status = NOT_SUPPORTED;
	}

	return status;
}


static status_t delete_shunt(private_fsm_kernel_ipsec_t *this,
	traffic_selector_t *dst_ts)
{
	status_t status = SUCCESS;
	iproute_t *route = NULL;
	iproute_t *listroute = NULL;

	if (!this || !dst_ts)
	{
		return INVALID_ARG;
	}

	route = prepare_route(this, dst_ts, NULL, NULL);
	if (!route)
	{
		DBG2(DBG_KNL, "%s: Could not prepare route for %R", __FUNCTION__,
			dst_ts);
		status = FAILED;
		goto exitfunc;
	}

	/* If there is a route installed for this policy, remove it. */
	this->shunts_mutex->lock(this->shunts_mutex);
	status = this->shunts->find_first(this->shunts,
		(linked_list_match_t)match_route_by_subnet_ifname, (void **)&listroute,
		route->subnet, &route->ifname[0]);
	this->shunts_mutex->unlock(this->shunts_mutex);

	if ((status == SUCCESS) && listroute)
	{
		status = delete_route(listroute, this->shunts_mutex, this->shunts);
		if (status != SUCCESS)
		{
			DBG2(DBG_KNL, "%s: Failed to delete route for %R", __FUNCTION__,
				dst_ts);
			goto exitfunc;
		}
	}

exitfunc:
	if (route)
	{
		DESTROY_IF(route->src_ip);
		DESTROY_IF(route->gw);
		DESTROY_IF(route->subnet);
		free(route);
	}
	return status;
}

static status_t add_shunt(private_fsm_kernel_ipsec_t *this,
	traffic_selector_t *dst_ts)
{
	status_t status = SUCCESS;

	if (!this || !dst_ts)
	{
		return INVALID_ARG;
	}

	DBG2(DBG_KNL, "%s: Installing shunt for %R", __FUNCTION__, dst_ts);

	if (!this || !dst_ts || !this->shunts || !this->shunts_mutex)
	{
		return INVALID_ARG;
	}

	status = install_route(this, dst_ts, this->shunts_mutex, this->shunts,
		NULL, NULL);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: Failed to install route for %R", __FUNCTION__,
			dst_ts);
	}

	return status;
}

METHOD(kernel_ipsec_t, add_policy, status_t,
	private_fsm_kernel_ipsec_t *this, host_t *src, host_t *dst,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
	policy_dir_t direction, policy_type_t type, ipsec_sa_cfg_t *sa,
	mark_t mark, policy_priority_t priority)
{
	status_t status = SUCCESS;
	sa_t *currsa = NULL;
	u_int32_t ts_family = AF_INET;

	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec src %H dst %H ts %R===%R dir"
		" %N type %u prio %u mark value 0x%08x mask 0x%08x", __FUNCTION__, src,
		dst, src_ts, dst_ts, policy_dir_names, direction, type, priority,
		mark.value, mark.mask);

	if (!this || !src || !dst || !src_ts || !dst_ts || !sa || !this->sas_mutex)
	{
		return INVALID_ARG;
	}

	if ((direction == POLICY_OUT) && (type == POLICY_PASS))
	{
		/* Install a shunt policy */
		return add_shunt(this, dst_ts);
	}

	/* We only handle the outbound (encap) policies here. */
	if ((direction != POLICY_OUT) || (type != POLICY_IPSEC) ||
		!sa->esp.use || (sa->mode != MODE_TUNNEL))
	{
		return SUCCESS;
	}

	this->sas_mutex->lock(this->sas_mutex);
	if (this->sas)
	{
		status = this->sas->find_first(this->sas,
			(linked_list_match_t)match_sa_by_spi_and_ips,
			(void **)&currsa, &sa->esp.spi, src, dst);
	}
	this->sas_mutex->unlock(this->sas_mutex);
	if ((status != SUCCESS) || !currsa || !currsa->mutex)
	{
		return FAILED;
	}

	currsa->mutex->lock(currsa->mutex);

	/* Set the TS and SA families */
	ts_family = (src_ts->get_type(src_ts) == TS_IPV4_ADDR_RANGE) ?
		AF_INET : AF_INET6;

	/* There are four cases of traffic selectors:
	 * host-host - Handled with explicit encap flow rules
	 * host-subnet - Handled with an encap subnet rule for the dst subnet
	 * subnet-host - Handled with an encap subnet rule which specifies the host
	 * subnet-subnet - Handled with an encap subnet rule for the dst subnet
	 *
	 * Another special case is where a host is specified without a protocol.
	 * These are programmed as subnet rules, as NSS can only handle them as
	 * such.
	 */
	if (src_ts->is_host(src_ts, NULL) && dst_ts->is_host(dst_ts, NULL) &&
		dst_ts->get_protocol(dst_ts))
	{
		/* host-host */
		status = add_encap_flow(this, currsa, src_ts, dst_ts, ts_family);
	}
	else
	{
		/* host-subnet, subnet-host, and subnet-subnet, and host-host where
		 * the protocol is %any.
		 */
		status = add_encap_subnet(this, currsa, dst_ts, ts_family);
	}

	DBG2(DBG_KNL, "%s: %s encap rule for %R===%R", __FUNCTION__,
		((status != SUCCESS) ? "Failed to add" : "Added"), src_ts, dst_ts);

	currsa->mutex->unlock(currsa->mutex);
	return status;
}

METHOD(kernel_ipsec_t, query_policy, status_t,
	private_fsm_kernel_ipsec_t *this, traffic_selector_t *src_ts,
	traffic_selector_t *dst_ts, policy_dir_t direction, mark_t mark,
	time_t *use_time)
{
	return NOT_SUPPORTED;
}

METHOD(kernel_ipsec_t, del_policy, status_t,
	private_fsm_kernel_ipsec_t *this, host_t *src, host_t *dst,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
	policy_dir_t direction, policy_type_t type, ipsec_sa_cfg_t *sa,
	mark_t mark, policy_priority_t priority)
{
	status_t status = SUCCESS;
	sa_t *currsa = NULL;
	host_t *subnet = NULL;
	u_int8_t mask = 0;
	iproute_t *route = NULL;
	u_int32_t spi = 0;

	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec dir %R===%R %N",
		__FUNCTION__, src_ts, dst_ts, policy_dir_names, direction);

	if (!this || !src_ts || !dst_ts || !src || !dst || !sa || !this->sas_mutex)
	{
		return INVALID_ARG;
	}

	/* Handle shunt policies */
	if ((direction == POLICY_OUT) && (type == POLICY_PASS))
	{
		return delete_shunt(this, dst_ts);
	}

	/* We only handle the outbound (encap) IPSEC ESP tunnel policies here. */
	if ((direction != POLICY_OUT) || (type != POLICY_IPSEC) ||
		!sa->esp.use || (sa->mode != MODE_TUNNEL))
	{
		return SUCCESS;
	}

	spi = sa->esp.spi;

	this->sas_mutex->lock(this->sas_mutex);
	if (this->sas)
	{
		status = this->sas->find_first(this->sas,
			(linked_list_match_t)match_sa_by_spi_and_ips, (void **)&currsa,
			&spi, src, dst);
	}
	this->sas_mutex->unlock(this->sas_mutex);
	if ((status != SUCCESS) || !currsa)
	{
		DBG2(DBG_KNL, "%s: Could not find SA for SPI 0x%08x src %H dst %H",
			__FUNCTION__, spi, src, dst);
		goto exitfunc;
	}

	/* Prepare the destination network from the dst_ts */
	dst_ts->to_subnet(dst_ts, &subnet, &mask);
	if (!subnet)
	{
		DBG2(DBG_KNL, "%s: Could not get subnet from %R", __FUNCTION__, dst_ts);
		status = FAILED;
		goto exitfunc;
	}

	/* If there is a route installed for this policy, remove it. */
	this->routes_mutex->lock(this->routes_mutex);
	status = this->routes->find_first(this->routes,
		(linked_list_match_t)match_route_by_subnet_ifname, (void **)&route,
		subnet, &currsa->tunnel->ifname[0]);
	this->routes_mutex->unlock(this->routes_mutex);

	if ((status == SUCCESS) && route)
	{
		status = delete_route(route, this->routes_mutex, this->routes);
		if (status != SUCCESS)
		{
			DBG2(DBG_KNL, "%s: Failed to delete route for %R", __FUNCTION__,
				dst_ts);
		}
	}

exitfunc:
	return status;
}

METHOD(kernel_ipsec_t, flush_policies, status_t,
	private_fsm_kernel_ipsec_t *this)
{
	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec", __FUNCTION__);
	return SUCCESS;
}


METHOD(kernel_ipsec_t, bypass_socket, bool,
	private_fsm_kernel_ipsec_t *this, int fd, int family)
{
	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec", __FUNCTION__);

	return TRUE;
}

METHOD(kernel_ipsec_t, enable_udp_decap, bool,
	private_fsm_kernel_ipsec_t *this, int fd, int family, u_int16_t port)
{
	int type = UDP_ENCAP_ESPINUDP;
	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec", __FUNCTION__);

	if (setsockopt(fd, IPPROTO_UDP, UDP_ENCAP, &type, sizeof(type)) < 0)
	{
		DBG1(DBG_KNL, "%s: unable to set UDP_ENCAP: %s",
			__FUNCTION__, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

static status_t update_tunnel(private_fsm_kernel_ipsec_t *this,
	ike_sa_t *ike_sa, tunnel_t *tunnel)
{
	host_t *vip = NULL;
	enumerator_t *enumerator = NULL;
	status_t status = FAILED;

	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec", __FUNCTION__);
	if (!this || !ike_sa || !tunnel)
	{
		return INVALID_ARG;
	}

	if (!tunnel->vip)
	{
		return FAILED;
	}

	enumerator = ike_sa->create_virtual_ip_enumerator(ike_sa, TRUE);
	if (enumerator)
	{
		while (enumerator->enumerate(enumerator, &vip))
		{
			if (!vip->is_anyaddr(vip))
			{
				/* Add ip to tunnel
				 * Note - if the IP is already installed, it will be reference
				 * counted such that it is not removed too early. This is
				 * particularly important during reauthentication, as the
				 * removal of the old SA will trigger removal of the IP.
				 */
				status = hydra->kernel_interface->add_ip(
					hydra->kernel_interface, vip, -1, tunnel->ifname);
				if (status != SUCCESS)
				{
					DBG2(DBG_KNL, "%s: Could not add vip to %s", __FUNCTION__,
						tunnel->ifname);
					continue;
				}

				/* Save ip to tunnel */
				tunnel->vip->destroy(tunnel->vip);
				tunnel->vip = vip->clone(vip);
			}
		}
		enumerator->destroy(enumerator);
	}

	return status;
}

METHOD(fsm_kernel_ipsec_t, create_tunnel, status_t,
	private_fsm_kernel_ipsec_t *this, ike_sa_t *ike_sa)
{
	tunnel_t *tunnel = NULL;
	enumerator_t *enumerator = NULL;
	host_t *vip = NULL;
	host_t *host = NULL;
	status_t status = FAILED;
	fsm_kernel_net_t *net = fsm_kernel_net_get_instance();
	u_int32_t ike_sa_id = 0;

	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec", __FUNCTION__);

	if (!this || !ike_sa || !net)
	{
		DBG2(DBG_KNL, "%s: Invalid arguments", __FUNCTION__);
		return INVALID_ARG;
	}

	if (!this->nl_ipsec || !this->tunnels || !this->tunnels_mutex)
	{
		DBG2(DBG_KNL, "%s: Invalid arguments", __FUNCTION__);
		return INVALID_ARG;
	}

	/* Check to see if this tunnel was already created */
	ike_sa_id = ike_sa->get_unique_id(ike_sa);
	this->tunnels_mutex->lock(this->tunnels_mutex);
	status = this->tunnels->find_first(this->tunnels,
		(linked_list_match_t)match_tunnel_by_id,
		(void **)&tunnel, &ike_sa_id);
	this->tunnels_mutex->unlock(this->tunnels_mutex);
	if ((status == SUCCESS) && tunnel)
	{
		DBG2(DBG_KNL, "%s: tunnel already created for IKE SA %d, updating vip",
			__FUNCTION__, ike_sa_id);
		tunnel->mutex->lock(tunnel->mutex);
		status = update_tunnel(this, ike_sa, tunnel);
		tunnel->mutex->unlock(tunnel->mutex);
		return status;
	}

	/* Create a tunnel object*/
	INIT(tunnel,
		.ref = 1,
		.ike_sa_id = ike_sa_id,
		.mutex = mutex_create(MUTEX_TYPE_RECURSIVE),
		.flow = NULL,
		);

	if (!tunnel)
	{
		DBG2(DBG_KNL, "%s: Could not allocate tunnel object", __FUNCTION__);
		return FAILED;
	}

	if (!tunnel->mutex)
	{
		DBG2(DBG_KNL, "%s: Could not create tunnel mutex", __FUNCTION__);
		free(tunnel);
		return FAILED;
	}

	/* Lock tunnel mutex */
	tunnel->mutex->lock(tunnel->mutex);

	/* Send message to NSS ipsec driver to create tunnel. The ifname is
	 * returned from the call.
	 */
	status = this->nl_ipsec->create_tunnel(this->nl_ipsec, tunnel->ifname);
	if (status != SUCCESS)
	{
		DBG1(DBG_KNL, "%s: Could not create tunnel", __FUNCTION__);
		DESTROY_IF(tunnel->mutex);
		free(tunnel);
		return status;
	}

	DBG2(DBG_KNL, "%s: Created tunnel %s for IKE SA %d",
		__FUNCTION__, tunnel->ifname, tunnel->ike_sa_id);

	/* Save the local and remote IPs for this tunnel */
	host = ike_sa->get_my_host(ike_sa);
	tunnel->lip = host->clone(host);
	host = ike_sa->get_other_host(ike_sa);
	tunnel->rip = host->clone(host);

	/* Add it to the tunnel list */
	this->tunnels_mutex->lock(this->tunnels_mutex);
	this->tunnels->insert_last(this->tunnels, tunnel);
	this->tunnels_mutex->unlock(this->tunnels_mutex);

	/* Admin the interface up */
	status = net->activate_iface(net, tunnel->ifname);
	if (status != SUCCESS)
	{
		DBG1(DBG_KNL, "%s: Could not activate %s", __FUNCTION__,
			tunnel->ifname);
		destroy_tunnel(this, tunnel);
		return status;
	}

	DBG2(DBG_KNL, "%s: Activated %s", __FUNCTION__,
		tunnel->ifname);

	/* Assign the virtual IP */
	enumerator = ike_sa->create_virtual_ip_enumerator(ike_sa, TRUE);
	if (enumerator)
	{
		while (enumerator->enumerate(enumerator, &vip))
		{
			/* This code currently assumes only one vip is ever assigned */
			if (!vip->is_anyaddr(vip))
			{
				/* Add new ip */
				status = hydra->kernel_interface->add_ip(
					hydra->kernel_interface, vip, -1, tunnel->ifname);
				if (status != SUCCESS)
				{
					DBG2(DBG_KNL, "%s: Could not add vip to %s", __FUNCTION__,
						tunnel->ifname);
					break;
				}
				DBG2(DBG_KNL, "%s: Added vip to %s", __FUNCTION__,
					tunnel->ifname);

				/* Save virtual ip to tunnel */
				tunnel->vip = vip->clone(vip);

				break;
			}
		}
		enumerator->destroy(enumerator);
	}

	tunnel->mutex->unlock(tunnel->mutex);

	return status;
}

METHOD(fsm_kernel_ipsec_t, migrate_tunnel, status_t,
	private_fsm_kernel_ipsec_t *this, u_int32_t old_ike_sa_id,
	u_int32_t new_ike_sa_id)
{
	status_t status = FAILED;
	tunnel_t *tunnel = NULL;

	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec", __FUNCTION__);

	if (!this)
	{
		DBG2(DBG_KNL, "%s: Invalid argument", __FUNCTION__);
		return INVALID_ARG;
	}

	if (!this->tunnels)
	{
		DBG2(DBG_KNL, "%s: Invalid argument", __FUNCTION__);
		return INVALID_ARG;
	}

	this->tunnels_mutex->lock(this->tunnels_mutex);
	status = this->tunnels->find_first(this->tunnels,
		(linked_list_match_t)match_tunnel_by_id,
		(void **)&tunnel, &old_ike_sa_id);
	this->tunnels_mutex->unlock(this->tunnels_mutex);
	if ((status != SUCCESS) || !tunnel)
	{
		DBG2(DBG_KNL, "%s: Could not find tunnel for IKE SA %u", __FUNCTION__,
			old_ike_sa_id);
		return FAILED;
	}

	tunnel->mutex->lock(tunnel->mutex);
	tunnel->ike_sa_id = new_ike_sa_id;

	DBG2(DBG_KNL, "%s: Migrated tunnel %s from IKE SA %u to %u", __FUNCTION__,
		tunnel->ifname, old_ike_sa_id, new_ike_sa_id);
	tunnel->mutex->unlock(tunnel->mutex);

	return status;
}

METHOD(fsm_kernel_ipsec_t, delete_tunnel, status_t,
	private_fsm_kernel_ipsec_t *this, u_int32_t ike_sa_id)
{
	tunnel_t *tunnel = NULL;
	status_t status = FAILED;

	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec", __FUNCTION__);
	if (!this)
	{
		DBG2(DBG_KNL, "%s: Invalid argument", __FUNCTION__);
		return INVALID_ARG;
	}

	if (!this->nl_ipsec || !this->tunnels || !this->tunnels_mutex)
	{
		DBG2(DBG_KNL, "%s: Invalid argument", __FUNCTION__);
		return INVALID_ARG;
	}

	/* Find the tunnel */
	this->tunnels_mutex->lock(this->tunnels_mutex);
	status = this->tunnels->find_first(this->tunnels,
		(linked_list_match_t)match_tunnel_by_id,
		(void **)&tunnel, &ike_sa_id);
	this->tunnels_mutex->unlock(this->tunnels_mutex);
	if ((status != SUCCESS) || !tunnel)
	{
		DBG2(DBG_KNL, "%s: Could not find tunnel for IKE SA %u", __FUNCTION__,
			ike_sa_id);
		return SUCCESS;
	}

	/* Decrement the refcount and destroy the tunnel if no SAs are using it. */
	tunnel->mutex->lock(tunnel->mutex);
	if (ref_put(&tunnel->ref))
	{
		DBG2(DBG_KNL, "%s: Destroying tunnel for IKE SA %u (%s)", __FUNCTION__,
			ike_sa_id, tunnel->ifname);
		status = destroy_tunnel(this, tunnel);
	}

	if (tunnel && tunnel->mutex)
	{
		tunnel->mutex->unlock(tunnel->mutex);
	}
	return status;
}

METHOD(fsm_kernel_ipsec_t, get_tunnel_iface, status_t,
	private_fsm_kernel_ipsec_t *this, u_int32_t ike_sa_id, char **iface)
{
	status_t status = SUCCESS;
	tunnel_t *tunnel = NULL;

	if (!this || !this->tunnels_mutex || !this->tunnels || !iface)
	{
		return INVALID_ARG;
	}

	/* Find the tunnel */
	this->tunnels_mutex->lock(this->tunnels_mutex);
	status = this->tunnels->find_first(this->tunnels,
		(linked_list_match_t)match_tunnel_by_id,
		(void **)&tunnel, &ike_sa_id);
	this->tunnels_mutex->unlock(this->tunnels_mutex);
	if ((status != SUCCESS) || !tunnel)
	{
		DBG2(DBG_KNL, "%s: Could not find tunnel for IKE SA %u", __FUNCTION__,
			ike_sa_id);
		return FAILED;
	}

	tunnel->mutex->lock(tunnel->mutex);
	*iface = &tunnel->ifname[0];
	tunnel->mutex->unlock(tunnel->mutex);

	return status;
}

METHOD(kernel_ipsec_t, destroy, void, private_fsm_kernel_ipsec_t *this)
{
	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec", __FUNCTION__);

	if (!this)
	{
		return;
	}

	if (this->listener)
	{
		charon->bus->remove_listener(charon->bus, &this->listener->listener);
		this->listener->destroy(this->listener);
	}

	DESTROY_IF(this->tunnels_mutex);
	DESTROY_IF(this->tunnels);
	DESTROY_IF(this->sas);
	DESTROY_IF(this->sas_mutex);
	DESTROY_IF(this->routes);
	DESTROY_IF(this->routes_mutex);
	DESTROY_IF(this->shunts);
	DESTROY_IF(this->shunts_mutex);
	DESTROY_IF(this->nl_crypto);
	DESTROY_IF(this->nl_ipsec);
	DESTROY_IF(this->nl_ipv4);
	DESTROY_IF(this->nl_ipv6);
	DESTROY_IF(this->rng);

	free(this);
}

/*
 * Described in header.
 */
fsm_kernel_ipsec_t *fsm_kernel_ipsec_create(void)
{
	private_fsm_kernel_ipsec_t *this = NULL;

	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec", __FUNCTION__);

	if (!lib || !lib->crypto)
	{
		return NULL;
	}

	INIT(this,
		.public =
		{
			.interface =
			{
				.get_features = _get_features,
				.get_spi = _get_spi,
				.get_cpi = _get_cpi,
				.add_sa  = _add_sa,
				.update_sa = _update_sa,
				.query_sa = _query_sa,
				.del_sa = _del_sa,
				.flush_sas = _flush_sas,
				.add_policy = _add_policy,
				.query_policy = _query_policy,
				.del_policy = _del_policy,
				.flush_policies = _flush_policies,
				.bypass_socket = _bypass_socket,
				.enable_udp_decap = _enable_udp_decap,
				.destroy = _destroy,
			},
			.create_tunnel = _create_tunnel,
			.migrate_tunnel = _migrate_tunnel,
			.delete_tunnel = _delete_tunnel,
			.get_tunnel_iface = _get_tunnel_iface,
		},
		.tunnels = linked_list_create(),
		.tunnels_mutex = mutex_create(MUTEX_TYPE_RECURSIVE),
		.sas = linked_list_create(),
		.sas_mutex = mutex_create(MUTEX_TYPE_RECURSIVE),
		.routes = linked_list_create(),
		.routes_mutex = mutex_create(MUTEX_TYPE_RECURSIVE),
		.shunts = linked_list_create(),
		.shunts_mutex = mutex_create(MUTEX_TYPE_RECURSIVE),
		.install_virtual_ip = lib->settings->get_bool(lib->settings,
			"%s.install_virtual_ip", TRUE, lib->ns),
		);

	if (!this)
	{
		DBG1(DBG_KNL, "%s: Failed to allocate memory!", __FUNCTION__);
		goto exitcleanup;
	}

	if (!this->tunnels || !this->tunnels_mutex || !this->sas ||
		!this->sas_mutex || !this->routes || !this->routes_mutex ||
		!this->shunts || !this->shunts_mutex)
	{
		DBG1(DBG_KNL,
			"%s: Failed to allocate memory for components!", __FUNCTION__);
		goto exitcleanup;
	}

	/* Create FSM netlink crypto interface */
	this->nl_crypto = fsm_netlink_crypto_create();
	if (!this->nl_crypto)
	{
		DBG1(DBG_KNL, "%s: Failed to allocate nl_crypto!", __FUNCTION__);
		goto exitcleanup;
	}

	/* Create FSM netlink ipsec interface */
	this->nl_ipsec = fsm_netlink_ipsec_create();
	if (!this->nl_ipsec)
	{
		DBG1(DBG_KNL, "%s: Failed to allocate nl_ipsec!", __FUNCTION__);
		goto exitcleanup;
	}

	/* Create FSM netlink ip interface for IPv4 */
	this->nl_ipv4 = fsm_netlink_ip_create(AF_INET);
	if (!this->nl_ipv4)
	{
		DBG1(DBG_KNL, "%s: Could not allocate nl_ipv4!", __FUNCTION__);
		goto exitcleanup;
	}

	/* Create FSM netlink ip interface for IPv6 */
	this->nl_ipv6 = fsm_netlink_ip_create(AF_INET6);
	if (!this->nl_ipv6)
	{
		DBG1(DBG_KNL, "%s: Failed to allocate nl_ipv6!", __FUNCTION__);
		goto exitcleanup;
	}

	/* register bus listener */
	this->listener = fsm_listener_create(&this->public);
	if (!this->listener)
	{
		DBG1(DBG_KNL, "%s: Failed to allocate fsm_listener!", __FUNCTION__);
		goto exitcleanup;
	}
	charon->bus->add_listener(charon->bus, &this->listener->listener);

	return (fsm_kernel_ipsec_t *)this;

exitcleanup:
	if (this)
	{
		this->public.interface.destroy(&this->public.interface);
	}
	return NULL;
}
