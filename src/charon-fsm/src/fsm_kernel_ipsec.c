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
	 * FSM Netlink Crypto object
	 */
	fsm_netlink_crypto_t *nl_crypto;

	/**
	 * FSM Netlink IPsec object
	 */
	fsm_netlink_ipsec_t *nl_ipsec;

	/**
	 * FSM Netlink IP object
	 */
	fsm_netlink_ip_t *nl_ip;

	/**
	 * Random number generator
	 */
	rng_t *rng;

	/**
	 * Bus listener
	 */
	fsm_listener_t *listener;
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
	 * Reference count
	 */
	refcount_t ref;

	/**
	 * IP family (AF_INET or AF_INET6)
	 */
	u_int32_t family;

	/**
	 * IPv4 flow rule tuple
	 */
	struct
	{
		u_int32_t src;
		u_int32_t src_port;
		u_int32_t dst;
		u_int32_t dst_port;
		u_int32_t proto;
	} v4_tuple;

	/* TODO: Add IPv6 support */
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
	 * Flow rule for this SA.
	 */
	flow_t *flow;

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
	 * IPv4 encap/decap SA rule
	 */
	struct
	{
		u_int32_t src;
		u_int32_t dst;
		u_int32_t spi;
		u_int32_t ttl;
	} v4;

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

	/* TODO: Add IPv6 support */
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

static bool match_sa_by_reqid_inbound(sa_t *item, u_int32_t *reqid,
	bool *inbound)
{
	if (!item || !reqid || !inbound)
	{
		return FALSE;
	}
	return ((item->decap == *inbound) && (item->reqid == *reqid));
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

	if (!this || !sa)
	{
		return;
	}

	if (!sa->lifetime.time.life)
	{   /* no expiration at all */
		return;
	}

	if (!sa)
	{
		DBG2(DBG_KNL, "%s: Could not schedule rekey/expire timer, sa NULL",
			__FUNCTION__);
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

static void delete_route(private_fsm_kernel_ipsec_t *this, iproute_t *route)
{
	chunk_t addr = chunk_empty;

	if (!this || !route || !this->routes_mutex || !this->routes ||
		!route->subnet || !route->gw || !route->src_ip)
	{
		return;
	}

	/* Only delete the route if there are no more references */
	if (!ref_put(&route->ref))
	{
		return;
	}

	this->routes_mutex->lock(this->routes_mutex);
	this->routes->remove(this->routes, route, NULL);
	this->routes_mutex->unlock(this->routes_mutex);
	DBG2(DBG_KNL,
		"%s: Removing route for dst_net %H prefix %u ifname %s",
		__FUNCTION__, route->subnet, route->prefixlen, route->ifname);
	addr = route->subnet->get_address(route->subnet);
	if (!addr.ptr || !addr.len)
	{
		return;
	}

	hydra->kernel_interface->del_route(hydra->kernel_interface, addr,
		route->prefixlen, route->gw, route->src_ip, route->ifname);
	DESTROY_IF(route->subnet);
	DESTROY_IF(route->gw);
	DESTROY_IF(route->src_ip);
	free(route);
}

void flush_rules(sa_t *sa, private_fsm_kernel_ipsec_t *this)
{
	status_t status = SUCCESS;

	if (!this || !sa || !sa->mutex)
	{
		return;
	}

	sa->mutex->lock(sa->mutex);
	if (sa->family == AF_INET)
	{
		if (sa->decap)
		{
			status = this->nl_ipsec->del_decap_sa(this->nl_ipsec,
				sa->tunnel->ifname, &sa->v4.src, &sa->v4.dst, sa->family,
				sa->v4.spi, sa->v4.ttl);
		}
		else
		{
			status = this->nl_ipsec->del_encap_sa(this->nl_ipsec,
				sa->tunnel->ifname, &sa->v4.src, &sa->v4.dst, sa->family,
				sa->v4.spi, sa->v4.ttl);
		}

		DBG2(DBG_KNL, "%s: %s %s rule for SPI 0x%08x src 0x%08x dst 0x%08x",
			__FUNCTION__,
			((status != SUCCESS) ? "Could not delete" : "Deleted"),
			(sa->decap ? "decap" : "encap"), sa->v4.spi, sa->v4.src,
			sa->v4.dst);
	}

	/* TODO: Add IPv6 support */

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

	/* Delete flow rule (if applicable) */
	if (sa->flow && ref_put(&sa->flow->ref))
	{
		if (sa->flow->family == AF_INET)
		{
			this->nl_ip->del_flow(this->nl_ip, &sa->flow->v4_tuple.src,
				sa->flow->v4_tuple.src_port, &sa->flow->v4_tuple.dst,
				sa->flow->v4_tuple.dst_port, sa->flow->family,
				sa->flow->v4_tuple.proto);
			free(sa->flow);
			sa->flow = NULL;
		}
		/* TODO: Add IPv6 support */
	}

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

	if (!this->sas)
	{
		return INVALID_ARG;
	}

	this->sas_mutex->lock(this->sas_mutex);
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

static status_t populate_v4_sa(sa_t *sa)
{
	status_t status = SUCCESS;
	chunk_t addr = chunk_empty;

	if (!sa)
	{
		status = INVALID_ARG;
		goto exitfunc;
	}

	addr = sa->src->get_address(sa->src);
	if (!addr.ptr || !addr.len)
	{
		status = FAILED;
		goto exitfunc;
	}
	sa->v4.src = ntohl(*(uint32_t *)addr.ptr);

	addr = sa->dst->get_address(sa->dst);
	if (!addr.ptr || !addr.len)
	{
		status = FAILED;
		goto exitfunc;
	}
	sa->v4.dst = ntohl(*(uint32_t *)addr.ptr);

	sa->v4.spi = ntohl(sa->spi);
	/* TODO: Make this configurable? */
	sa->v4.ttl = 64;

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
		int_alg, int_key, sa->nat, sa->decap, &sa->crypto_index);
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
		&sa->v4.src, &sa->v4.dst, sa->family, sa->v4.spi,
		sa->v4.ttl, sa->crypto_index, icv->icv_len,
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
	chunk_t addr = chunk_empty;
	bool valid = FALSE;
	char *ifname = NULL;
	size_t ifname_len = 0;
	char src_ifname[IFNAMSIZ];
	char dst_ifname[IFNAMSIZ];

	if (!this || !sa || !this->nl_ip)
	{
		DBG2(DBG_KNL, "%s: Invalid arguments", __FUNCTION__);
		status = INVALID_ARG;
		goto errorexit;
	}

	INIT(flow,
		.ref = 1,
		);

	if (!flow)
	{
		DBG2(DBG_KNL, "%s: Could not allocate flow object", __FUNCTION__);
		goto errorexit;
	}
	flow->family = (u_int32_t)sa->dst->get_family(sa->dst);

	/* TODO: Add IPv6 Support */
	if (flow->family != AF_INET)
	{
		DBG2(DBG_KNL, "%s: IP family %u not supported", __FUNCTION__,
			flow->family);
		status = NOT_SUPPORTED;
		goto errorexit;
	}

	/* Populate the flow structure */

	/* In the case of NAT_T, the protocol is UDP */
	flow->v4_tuple.proto = (sa->nat) ? IPPROTO_UDP : sa->protocol;

	addr = sa->dst->get_address(sa->dst);
	if (!addr.ptr || !addr.len)
	{
		DBG2(DBG_KNL, "%s: get_address failed for dst", __FUNCTION__);
		goto errorexit;
	}
	flow->v4_tuple.src = ntohl(*(uint32_t *)addr.ptr);
	flow->v4_tuple.src_port =
		(sa->nat) ? (u_int32_t)sa->dst->get_port(sa->dst) : 0;

	addr = sa->src->get_address(sa->src);
	if (!addr.ptr || !addr.len)
	{
		DBG2(DBG_KNL, "%s: get_address failed for src", __FUNCTION__);
		goto errorexit;
	}
	flow->v4_tuple.dst = ntohl(*(uint32_t *)addr.ptr);
	flow->v4_tuple.dst_port =
		(sa->nat) ? (u_int32_t)sa->src->get_port(sa->src) : 0;

	/* Get the destination interface name */
	valid = hydra->kernel_interface->get_interface(hydra->kernel_interface,
		sa->dst, &ifname);
	if (!valid || !ifname)
	{
		DBG2(DBG_KNL, "%s: get_interface failed for dst %H", __FUNCTION__,
			sa->dst);
		goto errorexit;
	}

	ifname_len = strlen(ifname);
	/* Truncate the ifname if it's too large */
	if (ifname_len > IFNAMSIZ)
	{
		ifname[ifname_len - 1] = '\0';
		ifname_len = IFNAMSIZ;
	}
	memset(dst_ifname, 0, IFNAMSIZ);
	memcpy(dst_ifname, ifname, ifname_len);
	free(ifname);

	/* The source interface name is the name of the tunnel */
	memcpy(src_ifname, sa->tunnel->ifname, IFNAMSIZ);

	status = this->nl_ip->add_flow(this->nl_ip, &flow->v4_tuple.src,
		flow->v4_tuple.src_port, &flow->v4_tuple.dst, flow->v4_tuple.dst_port,
		flow->family, flow->v4_tuple.proto, src_ifname, dst_ifname);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: Failed to add IP flow rule", __FUNCTION__);
		goto errorexit;
	}

	sa->flow = flow;

errorexit:
	if ((status != SUCCESS) && flow)
	{
		free(flow);
		sa->flow = NULL;
	}

	return status;
}

static status_t migrate_ip_flow_rule(private_fsm_kernel_ipsec_t *this,
	sa_t *rekeysa, sa_t *sa)
{
	status_t status = FAILED;

	if (!this || !sa || !rekeysa)
	{
		DBG2(DBG_KNL, "%s: Invalid arguments", __FUNCTION__);
		status = INVALID_ARG;
		goto errorexit;
	}

	/* First check the (unlikely) case that the flow rule is not valid on
	 * the existing SA. If this is so, go ahead and create a new one.
	 * Otherwise, proceed with migration.
	 */
	if (!rekeysa->flow)
	{
		DBG2(DBG_KNL, "%s: Warning - rekeysa flow rule is NULL!", __FUNCTION__);
		status = add_ip_flow_rule(this, sa);
		if (status != SUCCESS)
		{
			DBG2(DBG_KNL, "%s: Could not add flow rule for SPI 0x%08x %s",
				__FUNCTION__, sa->spi, IPSEC_DIR_STR(sa->decap));
			goto errorexit;
		}
	}
	else
	{
		refcount_t ref;
		ref = ref_get(&rekeysa->flow->ref);
		DBG2(DBG_KNL, "%s: flow ref count %d", __FUNCTION__, ref);
		sa->flow = rekeysa->flow;
		status = SUCCESS;
	}

errorexit:
	return status;
}

static void add_route(private_fsm_kernel_ipsec_t *this, sa_t *sa,
	traffic_selector_t *dst_ts)
{
	status_t status = FAILED;
	iproute_t *route = NULL;
	iproute_t *listroute = NULL;
	chunk_t addr = chunk_empty;

	if (!this || !sa || !dst_ts || !this->routes || !this->routes_mutex)
	{
		return;
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
	this->routes_mutex->lock(this->routes_mutex);
	status = this->routes->find_first(this->routes,
		(linked_list_match_t)match_route_by_subnet_ifname, (void **)&listroute,
		route->subnet, &sa->tunnel->ifname[0]);
	this->routes_mutex->unlock(this->routes_mutex);

	if ((status != SUCCESS) || !listroute)
	{
		/* TODO: Add IPv6 support */
		route->gw = host_create_any(AF_INET);
		if (!route->gw)
		{
			DBG2(DBG_KNL, "%s: Could not create gateway", __FUNCTION__);
			status = FAILED;
			goto exitfunc;
		}

		route->src_ip = host_create_any(AF_INET);
		if (!route->src_ip)
		{
			DBG2(DBG_KNL, "%s: Could not create src_ip", __FUNCTION__);
			status = FAILED;
			goto exitfunc;
		}

		strncpy(route->ifname, sa->tunnel->ifname, IFNAMSIZ);

		DBG2(DBG_KNL,
			"%s: Adding route for dst_net %H prefix %u ifname %s",
			__FUNCTION__, route->subnet, route->prefixlen, route->ifname);

		status = hydra->kernel_interface->add_route(hydra->kernel_interface,
			addr, route->prefixlen, route->gw, route->src_ip,
			&route->ifname[0]);

		switch (status)
		{
			case SUCCESS:
				DBG2(DBG_KNL, "%s: Installed source route for %H",
					__FUNCTION__, route->subnet);
				this->routes_mutex->lock(this->routes_mutex);
				this->routes->insert_last(this->routes, route);
				this->routes_mutex->unlock(this->routes_mutex);
				break;
			case ALREADY_DONE:
				DBG2(DBG_KNL, "%s: Source route for %H already installed",
					__FUNCTION__, route->subnet);
				this->routes_mutex->lock(this->routes_mutex);
				this->routes->insert_last(this->routes, route);
				this->routes_mutex->unlock(this->routes_mutex);
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
		delete_route(this, route);
	}

	return;
}

static status_t add_encap_flow(private_fsm_kernel_ipsec_t *this, sa_t *sa,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts, u_int32_t family)
{
	status_t status = FAILED;
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

	if (family == AF_INET)
	{
		u_int32_t src = 0;
		u_int32_t dst = 0;
		chunk_t addr = chunk_empty;

		proto = dst_ts->get_protocol(dst_ts);

		addr = dst_ts->get_from_address(dst_ts);
		if (!addr.ptr || !addr.len)
		{
			status = FAILED;
			goto exitfunc;
		}
		dst = ntohl(*(uint32_t *)addr.ptr);

		addr = src_ts->get_from_address(src_ts);
		if (!addr.ptr || !addr.len)
		{
			status = FAILED;
			goto exitfunc;
		}
		src = ntohl(*(uint32_t *)addr.ptr);

		status = this->nl_ipsec->add_encap_flow(this->nl_ipsec,
			sa->tunnel->ifname, &src, &dst, family, proto, &sa->v4.src,
			&sa->v4.dst, sa->family, sa->v4.spi, sa->v4.ttl, sa->crypto_index,
			icv->icv_len, (u_int16_t)sa->replay_window, sa->nat, FALSE, FALSE,
			FALSE);
	}
	else
	{
		/* TODO: Add IPv6 support */
		status = NOT_SUPPORTED;
	}

exitfunc:
	return status;
}

static status_t add_encap_subnet(private_fsm_kernel_ipsec_t *this, sa_t *sa,
	traffic_selector_t *dst_ts, u_int32_t family)
{
	status_t status = FAILED;
	u_int32_t proto = 0;
	icv_len_t *icv = NULL;

	if (!this || !sa || !dst_ts)
	{
		return INVALID_ARG;
	}

	if (!icv_len_lookup(sa->int_alg, &icv) || !icv)
	{
		return FAILED;
	}

	if (family == AF_INET)
	{
		chunk_t addr = chunk_empty;
		host_t *subnet = NULL;
		u_int32_t sub = 0;
		u_int32_t msk = 0;
		u_int8_t mask = 0;

		proto = dst_ts->get_protocol(dst_ts);

		/* Prepare the destination network from the dst_ts */
		dst_ts->to_subnet(dst_ts, &subnet, &mask);
		if (!subnet)
		{
			DBG2(DBG_KNL, "%s: Could not get subnet from %R", __FUNCTION__,
				dst_ts);
			status = FAILED;
			goto exitfunc;
		}

		addr = subnet->get_address(subnet);
		if (!addr.ptr || !addr.len)
		{
			DBG2(DBG_KNL, "%s: Could not get address from subnet %H",
				__FUNCTION__, subnet);
			status = FAILED;
			goto exitfunc;
		}
		sub = ntohl(*(u_int32_t *)addr.ptr);
		msk = ~(1 << (32 - mask)) + 1;

		status = this->nl_ipsec->add_encap_subnet(this->nl_ipsec,
			sa->tunnel->ifname, &sub, &msk, family, proto, &sa->v4.src,
			&sa->v4.dst, sa->family, sa->v4.spi, sa->v4.ttl, sa->crypto_index,
			icv->icv_len, (u_int16_t)sa->replay_window, sa->nat, FALSE, FALSE,
			FALSE);
	}
	else
	{
		/* TODO: Add IPv6 support */
		status = NOT_SUPPORTED;
	}

exitfunc:
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
	sa_t *rekeysa = NULL;
	status_t status = FAILED;
	host_t *lip = (inbound) ? dst : src;
	host_t *rip = (inbound) ? src : dst;
	refcount_t ref = 0;

	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec mode %N protocol %u "
		"spi 0x%08x %s NAT %s",
		__FUNCTION__, ipsec_mode_names, mode, protocol, spi,
		IPSEC_DIR_STR(inbound), (encap) ? "enabled" : "disabled");

	if (!this || !src || !dst || !lifetime || !src_ts || !dst_ts)
	{
		DBG2(DBG_KNL, "%s: Invalid arguments", __FUNCTION__);
		return INVALID_ARG;
	}

	if (!this->tunnels || !this->sas || !this->tunnels_mutex ||
		!this->sas_mutex)
	{
		return INVALID_ARG;
	}

	if (mode != MODE_TUNNEL)
	{
		DBG2(DBG_KNL, "%s: Mode %N and protocol %u not supported", __FUNCTION__,
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
		DBG2(DBG_KNL, "%s: Could not locate tunnel for lip %H rip %H",
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

	/* We can tell if this SA is being rekeyed by matching the request
	 * ID to an existing SA. Since we already have a flow rule established, we
	 * need to migrate it to the new SA instead of recreating it.
	 *
	 * Also, we want to do this check here and now before the new SA is
	 * added to the list, because it will have the same reqid and direction.
	 */
	this->sas_mutex->lock(this->sas_mutex);
	status = this->sas->find_first(this->sas,
		(linked_list_match_t)match_sa_by_reqid_inbound,
		(void **)&rekeysa, &reqid, &inbound);
	this->sas_mutex->unlock(this->sas_mutex);
	if (status != SUCCESS)
	{
		rekeysa = NULL;
	}
	else
	{
		DBG2(DBG_KNL, "%s: src %H dst %H spi 0x%08x is rekeying to spi 0x%08x",
			__FUNCTION__, src, dst, rekeysa->spi, spi);
	}

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
		);

	if (!sa || !sa->mutex || !sa->src || !sa->dst)
	{
		DBG2(DBG_KNL, "%s: Failed to allocate mem for SPI 0x%08x %s",
			__FUNCTION__, spi, IPSEC_DIR_STR(inbound));
		status = FAILED;
		goto errorexit;
	}

	if ((replay_window < MIN_REPLAY_WINDOW) ||
		(replay_window > MAX_REPLAY_WINDOW))
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

	status = add_crypto_rule(this, sa, enc_alg, enc_key, int_alg, int_key);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: Crypto setup failed for SPI 0x%08x %s",
			__FUNCTION__, spi, IPSEC_DIR_STR(inbound));
		goto errorexit;
	}

	/* Increment the tunnel reference count so it's clear an SA is using it. */
	tunnel->mutex->lock(tunnel->mutex);
	ref = ref_get(&tunnel->ref);
	DBG2(DBG_KNL, "%s: IKE SA %u tunnel refcount %u", __FUNCTION__,
		tunnel->ike_sa_id, ref);
	tunnel->mutex->unlock(tunnel->mutex);

	sa->family = sa->dst->get_family(sa->dst);
	if (sa->family == AF_INET)
	{
		status = populate_v4_sa(sa);
	}
	else
	{
		/* TODO: Add IPv6 support */
		status = NOT_SUPPORTED;
	}

	if (status != SUCCESS)
	{
		goto delsa;
	}

	if (inbound)
	{
		/* Decap rules are tied to the SPI, so we need a new one even if this
		 * SA is rekeying.
		 */
		status = add_decap_sa(this, sa);
		if (status != SUCCESS)
		{
			DBG2(DBG_KNL, "%s: Failed to add decap rule for SPI 0x%08x %s",
				__FUNCTION__, spi, IPSEC_DIR_STR(inbound));
			goto delsa;
		}

		if (!rekeysa)
		{
			/* We aren't rekeying an existing SA, so we need a new flow rule */
			status = add_ip_flow_rule(this, sa);
			if (status != SUCCESS)
			{
				DBG2(DBG_KNL, "%s: Failed to add flow rule for SPI 0x%08x %s",
					__FUNCTION__, spi, IPSEC_DIR_STR(inbound));
				goto delsa;
			}
		}
		else
		{
			/* We are rekeying. Migrate the flow rule. */
			status = migrate_ip_flow_rule(this, rekeysa, sa);
			if (status != SUCCESS)
			{
				DBG2(DBG_KNL,
					"%s: Failed to migrate flow rule from SPI 0x%08x to "
					"SPI 0x%08x %s",
					__FUNCTION__, rekeysa->spi, spi, IPSEC_DIR_STR(inbound));
				goto delsa;
			}
			DBG2(DBG_KNL, "%s: Migrated flow rule from SPI 0x%08x to "
				"SPI 0x%08x %s",
				__FUNCTION__, rekeysa->spi, spi, IPSEC_DIR_STR(inbound));
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
				add_route(this, sa, ts);
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
	DESTROY_IF(sa->src);
	DESTROY_IF(sa->dst);
	sa->mutex->unlock(sa->mutex);
	free(sa);
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

METHOD(kernel_ipsec_t, add_policy, status_t,
	private_fsm_kernel_ipsec_t *this, host_t *src, host_t *dst,
	traffic_selector_t *src_ts, traffic_selector_t *dst_ts,
	policy_dir_t direction, policy_type_t type, ipsec_sa_cfg_t *sa,
	mark_t mark, policy_priority_t priority)
{
	status_t status = SUCCESS;
	sa_t *currsa = NULL;
	u_int32_t ts_family = AF_INET;

	DBG2(DBG_KNL, "Entering %s in fsm_kernel_ipsec dir %R===%R %N type %u",
		__FUNCTION__, src_ts, dst_ts, policy_dir_names, direction, type);

	if (!this || !src || !dst || !src_ts || !dst_ts || !sa || !this->sas_mutex)
	{
		return INVALID_ARG;
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
	 */
	if (src_ts->is_host(src_ts, NULL) && dst_ts->is_host(dst_ts, NULL))
	{
		/* host-host */
		status = add_encap_flow(this, currsa, src_ts, dst_ts, ts_family);
	}
	else
	{
		/* host-subnet, subnet-host, and subnet-subnet */
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
		delete_route(this, route);
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
		);

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
		DBG2(DBG_KNL, "%s: Could not create tunnel", __FUNCTION__);
		free(tunnel);
		tunnel->mutex->unlock(tunnel->mutex);
		return status;
	}

	DBG2(DBG_KNL, "%s: Created tunnel %s for IKE SA %d",
		__FUNCTION__, tunnel->ifname, tunnel->ike_sa_id);

	/* Assign the virtual IP */
	enumerator = ike_sa->create_virtual_ip_enumerator(ike_sa, TRUE);
	if (enumerator)
	{
		while (enumerator->enumerate(enumerator, &vip))
		{
			/* This code currently assumes only one vip is ever assigned */
			if (!vip->is_anyaddr(vip))
			{
				host_t *host = NULL;

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
					DBG2(DBG_KNL, "%s: Could not activate %s", __FUNCTION__,
						tunnel->ifname);
					status = SUCCESS;
				}
				DBG2(DBG_KNL, "%s: Activated %s", __FUNCTION__,
					tunnel->ifname);
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
	DESTROY_IF(this->nl_crypto);
	DESTROY_IF(this->nl_ipsec);
	DESTROY_IF(this->nl_ip);
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
		},
		.tunnels = linked_list_create(),
		.tunnels_mutex = mutex_create(MUTEX_TYPE_RECURSIVE),
		.sas = linked_list_create(),
		.sas_mutex = mutex_create(MUTEX_TYPE_RECURSIVE),
		.routes = linked_list_create(),
		.routes_mutex = mutex_create(MUTEX_TYPE_RECURSIVE),
		.rng = lib->crypto->create_rng(lib->crypto, RNG_WEAK),
		);

	/* Create FSM netlink crypto interface */
	this->nl_crypto = fsm_netlink_crypto_create();
	if (!this->nl_crypto)
	{
		goto exitcleanup;
	}

	/* Create FSM netlink ipsec interface */
	this->nl_ipsec = fsm_netlink_ipsec_create();
	if (!this->nl_ipsec)
	{
		goto exitcleanup;
	}

	/* Create FSM netlink ip interface */
	this->nl_ip = fsm_netlink_ip_create();
	if (!this->nl_ip)
	{
		goto exitcleanup;
	}

	/* register bus listener */
	this->listener = fsm_listener_create(&this->public);
	if (!this->listener)
	{
		goto exitcleanup;
	}
	charon->bus->add_listener(charon->bus, &this->listener->listener);

	return &this->public;

exitcleanup:
	destroy(this);
	return NULL;
}
