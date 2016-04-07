/*
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of The Linux Foundation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <net/if.h>
#include <time.h>
#include <collections/hashtable.h>
#include <threading/thread.h>
#include <threading/mutex.h>
#include <threading/semaphore.h>
#include <utils/utils.h>
#include <utils/debug.h>
#include <utils/chunk.h>
#include <netlink/msg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <sys/types.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <nss_def.h>
#include <nss_nl_if.h>
#include <nss_nlcmn_if.h>
#include <nss_ipsecmgr.h>
#include <nss_nlipsec_if.h>
#include "fsm_netlink_sock.h"
#include "fsm_netlink_ipsec.h"


typedef struct private_fsm_netlink_ipsec_t private_fsm_netlink_ipsec_t;

/**
 * Private data for FSM netlink ipsec object
 *
 */
struct private_fsm_netlink_ipsec_t
{
	/**
	 * Public part of FSM netlink ipsec object
	 */
	fsm_netlink_ipsec_t public;

	/**
	 * FSM netlink socket context (ipsec family)
	 */
	fsm_netlink_sock_t *nl_sock;

	/**
	 * FSM netlink multicast socket context (ipsec family and group)
	 */
	fsm_netlink_sock_t *nl_sock_mcast;

	/**
	 * Mutex to lock access to socket context
	 */
	mutex_t *mutex;

	/**
	 * Last created tunnel interface name
	 */
	char ifname[IFNAMSIZ];

	/**
	 * Hashtable for ipsec stats.  Uses spi as a key and returns the
	 * stats structure as the value.
	 */
	hashtable_t *stats;

	/**
	 * Mutex for locking stats hashtable
	 */
	mutex_t *stats_mutex;

	/**
	 * Semaphore for synchronizing messages sent/received
	 */
	semaphore_t *sem;

	/**
	 * Semaphore for notifying of errors received
	 */
	semaphore_t *err_sem;

	/**
	 * Thread handle for socket receiver function.
	 */
	thread_t *thread;

	/**
	 * Thread handle for stats listening function.
	 */
	thread_t *mcast_thread;
};

#define IPSEC_DEFAULT_TIMEOUT 1000
#define IPSEC_DEFAULT_ERR_TIMEOUT 200

typedef struct stats_t stats_t;
struct stats_t
{
	u_int32_t spi;
	u_int64_t bytes;
	u_int64_t count;
	time_t last_use_time;
};

static void ipsec_stats_destroy(void *val, const void *key)
{
	if (val)
	{
		free(val);
	}
}

static u_int ipsec_stats_hash(u_int32_t *spi)
{
	if (!spi)
	{
		return 0;
	}
	return chunk_hash(chunk_from_thing(*spi));
}

static bool ipsec_stats_equals(u_int32_t *spi, u_int32_t *other_spi)
{
	if (!spi || !other_spi)
	{
		return FALSE;
	}
	return (*spi == *other_spi);
}

CALLBACK(ipsec_receiver, void *, private_fsm_netlink_ipsec_t *this)
{
	status_t status = FAILED;
	thread_cancelability(TRUE);

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ipsec thread %u", __FUNCTION__,
		thread_current_id());

	while (TRUE)
	{
		/* Receive responses (messages parsed by callback) */
		status = this->nl_sock->recv_msgs(this->nl_sock);
		if (status != SUCCESS)
		{
			DBG2(DBG_KNL, "%s: Error receiving messages", __FUNCTION__);
			/* Post the error semaphore */
			if (this->err_sem)
			{
				this->err_sem->post(this->err_sem);
			}
		}
	}
	this->thread->detach(this->thread);
	this->thread = NULL;
	DBG2(DBG_KNL, "Exiting %s in fsm_netlink_ipsec thread %u", __FUNCTION__,
		thread_current_id());

	return NULL;
}

CALLBACK(ipsec_stats_listener, void *, private_fsm_netlink_ipsec_t *this)
{
	status_t status = FAILED;
	thread_cancelability(TRUE);

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ipsec thread %u", __FUNCTION__,
		thread_current_id());

	while (TRUE)
	{
		/* Receive responses (messages parsed by callback) */
		status = this->nl_sock_mcast->recv_msgs(this->nl_sock_mcast);
		if (status != SUCCESS)
		{
			DBG2(DBG_KNL, "%s: Error receiving messages", __FUNCTION__);
		}
	}
	this->mcast_thread->detach(this->mcast_thread);
	this->mcast_thread = NULL;
	DBG2(DBG_KNL, "Exiting %s in fsm_netlink_ipsec thread %u", __FUNCTION__,
		thread_current_id());

	return NULL;
}

CALLBACK(ipsec_mcast_resp, void, private_fsm_netlink_ipsec_t *this,
	struct nss_nlcmn *cm, void *data)
{
	struct nss_ipsecmgr_sa_stats *nss_stats = NULL;
	struct nss_nlipsec_rule *rule_ptr = NULL;
	stats_t *stats = NULL;

	DBG3(DBG_KNL, "Entering %s in fsm_netlink_ipsec", __FUNCTION__);

	if (!this || !cm || !data)
	{
		DBG2(DBG_KNL, "%s: Received invalid response from mcast socket",
			__FUNCTION__);
		return;
	}

	if (!this->stats_mutex || !this->stats)
	{
		DBG2(DBG_KNL, "%s: Invalid arguments", __FUNCTION__);
		return;
	}

	DBG3(DBG_KNL, "%s: Response received from mcast socket", __FUNCTION__);
	rule_ptr = (struct nss_nlipsec_rule *)data;

	if (rule_ptr->event.type != NSS_IPSECMGR_EVENT_SA_STATS)
	{
		DBG2(DBG_KNL, "%s: Received invalid event type %d from mcast socket",
			__FUNCTION__, rule_ptr->event.type);
		return;
	}

	nss_stats = &rule_ptr->event.data.stats;

	switch (nss_stats->sa.type)
	{
		case NSS_IPSECMGR_SA_TYPE_V4:
			DBG3(DBG_KNL,
				"%s: spi 0x%08x src 0x%08x dst 0x%08x ttl %u seq %u crypto %u "
				"bytes %u count %u", __FUNCTION__,
				nss_stats->sa.data.v4.spi_index,
				nss_stats->sa.data.v4.src_ip, nss_stats->sa.data.v4.dst_ip,
				nss_stats->sa.data.v4.ttl, nss_stats->seq_num,
				nss_stats->crypto_index, nss_stats->pkts.bytes,
				nss_stats->pkts.count);

			/* Add stats to hashtable */
			this->stats_mutex->lock(this->stats_mutex);
			/* See if we already have stats for this SA */
			stats = (stats_t *)this->stats->get(this->stats,
				&nss_stats->sa.data.v4.spi_index);

			if (stats == NULL)
			{
				INIT(stats,
					.last_use_time = nss_stats->pkts.bytes ?
						time_monotonic(NULL) : 0,
					.spi = nss_stats->sa.data.v4.spi_index,
					.bytes = nss_stats->pkts.bytes,
					.count = nss_stats->pkts.count,
					);

				if (!stats)
				{
					DBG2(DBG_KNL, "%s: Could not init stats", __FUNCTION__);
					this->stats_mutex->unlock(this->stats_mutex);
					return;
				}

				(stats_t *)this->stats->put(this->stats, &stats->spi, stats);
			}
			else
			{
				/* If there was traffic on the SA since the last mcast, update
				 * the values.
				 */
				if (nss_stats->pkts.bytes != 0)
				{
					stats->last_use_time = time_monotonic(NULL);
					stats->bytes += nss_stats->pkts.bytes;
					stats->count += nss_stats->pkts.count;
				}
			}

			this->stats_mutex->unlock(this->stats_mutex);
			break;
		case NSS_IPSECMGR_SA_TYPE_V6:
			/* TODO: Add IPv6 support */
			break;
		default:
			break;
	}
}

CALLBACK(ipsec_mcast_err, void, private_fsm_netlink_ipsec_t *this, void *msg)
{
	struct nlmsgerr *nlerr = (struct nlmsgerr *)msg;
	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ipsec", __FUNCTION__);

	if (!this || !msg)
	{
		DBG2(DBG_KNL, "%s: Received invalid response from socket",
			__FUNCTION__);
		return;
	}

	DBG2(DBG_KNL, "%s: Error received -- %s", __FUNCTION__,
		strerror_safe(nlerr->error));
}

CALLBACK(ipsec_err, void, private_fsm_netlink_ipsec_t *this, void *msg)
{
	struct nlmsgerr *nlerr = (struct nlmsgerr *)msg;
	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ipsec", __FUNCTION__);

	if (!this || !msg)
	{
		DBG2(DBG_KNL, "%s: Received invalid response from socket",
			__FUNCTION__);
		return;
	}

	/* Post the error semaphore */
	if (this->err_sem)
	{
		this->err_sem->post(this->err_sem);
	}

	DBG2(DBG_KNL, "%s: Error received -- %s", __FUNCTION__,
		strerror_safe(nlerr->error));
}

CALLBACK(ipsec_ack, void, private_fsm_netlink_ipsec_t *this, void *msg)
{
	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ipsec", __FUNCTION__);
}

CALLBACK(ipsec_resp, void, private_fsm_netlink_ipsec_t *this,
	struct nss_nlcmn *cm, void *data)
{
	struct nss_nlipsec_rule *rule_ptr;
	uint8_t cmd = 0;

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ipsec", __FUNCTION__);

	if (!this || !cm || !data)
	{
		DBG2(DBG_KNL, "%s: Received invalid response from socket",
			__FUNCTION__);
		return;
	}
	rule_ptr = (struct nss_nlipsec_rule *)data;
	cmd = nss_nlcmn_get_cmd(cm);
	switch (cmd)
	{
		case NSS_NLIPSEC_CMD_CREATE_TUNNEL:
			memcpy(this->ifname, rule_ptr->ifname, IFNAMSIZ);
			DBG2(DBG_KNL, "%s: Tunnel %s created", __FUNCTION__,
				this->ifname);
			if (NULL != this->sem)
			{
				this->sem->post(this->sem);
			}
			break;
		default:
			DBG2(DBG_KNL, "%s: Unexpected response from command %u",
				__FUNCTION__, cmd);
			break;
	}
}

static status_t ipsec_send_msg(private_fsm_netlink_ipsec_t *this,
	struct nss_nlipsec_rule *rule_ptr, uint16_t cmd)
{
	status_t status = SUCCESS;

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ipsec", __FUNCTION__);

	if (!this || !rule_ptr)
	{
		return INVALID_ARG;
	}

	if (!this->nl_sock || !this->err_sem)
	{
		return INVALID_ARG;
	}

	/* Init the message structure*/
	nss_nlipsec_rule_init(rule_ptr, (enum nss_nlipsec_cmd)cmd);

	/* send message */
	this->mutex->lock(this->mutex);
	status = this->nl_sock->send_msg(this->nl_sock, &rule_ptr->cm,
		rule_ptr);
	this->mutex->unlock(this->mutex);

	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: failed to send message cmd: %u", __FUNCTION__, cmd);
		return status;
	}

	DBG2(DBG_KNL, "%s: message sent cmd: %u", __FUNCTION__, cmd);

	/* See if there is an error. */
	if (!this->err_sem->timed_wait(this->err_sem, IPSEC_DEFAULT_ERR_TIMEOUT))
	{
		DBG2(DBG_KNL, "%s: Error message received.", __FUNCTION__);
		return FAILED;
	}

	return status;
}

METHOD(fsm_netlink_ipsec_t, create_tunnel, status_t,
	private_fsm_netlink_ipsec_t *this, char ifname[IFNAMSIZ])
{
	status_t status = SUCCESS;
	struct nss_nlipsec_rule rule = { { 0 } };

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ipsec", __FUNCTION__);

	if (!this)
	{
		return INVALID_ARG;
	}

	status = ipsec_send_msg(this, &rule, NSS_NLIPSEC_CMD_CREATE_TUNNEL);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: failed to send message", __FUNCTION__);
		return status;
	}

	if (!this->sem->timed_wait(this->sem, IPSEC_DEFAULT_TIMEOUT))
	{
		memcpy(ifname, this->ifname, IFNAMSIZ);
		if (ifname[0] == '\0')
		{
			DBG2(DBG_KNL, "%s: Invalid interface name returned!", __FUNCTION__);
			status = FAILED;
		}
	} else
	{
		DBG2(DBG_KNL, "%s: Timed out waiting for response", __FUNCTION__);
		status = FAILED;
	}

	return status;
}

METHOD(fsm_netlink_ipsec_t, destroy_tunnel, status_t,
	private_fsm_netlink_ipsec_t *this, char ifname[IFNAMSIZ])
{
	status_t status = SUCCESS;
	struct nss_nlipsec_rule rule = { { 0 } };

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ipsec", __FUNCTION__);

	if (!this)
	{
		return INVALID_ARG;
	}

	memcpy(rule.ifname, ifname, IFNAMSIZ);

	status = ipsec_send_msg(this, &rule, NSS_NLIPSEC_CMD_DESTROY_TUNNEL);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: failed to send message", __FUNCTION__);
		return status;
	}

	return status;
}

static status_t populate_v4_encap_flow(struct nss_nlipsec_rule *rule_ptr,
	u_int32_t inner_src, u_int32_t inner_dst, u_int32_t proto)
{
	status_t status = SUCCESS;
	struct nss_ipsecmgr_encap_v4_tuple *v4_tuple = NULL;

	if (!rule_ptr)
	{
		return INVALID_ARG;
	}

	rule_ptr->msg.flow.type = NSS_IPSECMGR_FLOW_TYPE_V4_TUPLE;
	v4_tuple = &rule_ptr->msg.flow.data.v4_tuple;

	v4_tuple->src_ip = inner_src;
	v4_tuple->dst_ip = inner_dst;
	v4_tuple->protocol = proto;

	DBG2(DBG_KNL, "%s: src 0x%08x dst 0x%08x proto %u", __FUNCTION__,
		inner_src, inner_dst, proto);
	return status;
}

static status_t populate_v4_encap_subnet(struct nss_nlipsec_rule *rule_ptr,
	u_int32_t subnet, u_int32_t mask, u_int32_t proto)
{
	status_t status = SUCCESS;
	struct nss_ipsecmgr_encap_v4_subnet *v4_subnet = NULL;

	if (!rule_ptr)
	{
		return INVALID_ARG;
	}

	rule_ptr->msg.flow.type = NSS_IPSECMGR_FLOW_TYPE_V4_SUBNET;
	v4_subnet = &rule_ptr->msg.flow.data.v4_subnet;
	v4_subnet->dst_subnet = subnet;
	v4_subnet->dst_mask = mask;
	v4_subnet->protocol = proto;

	DBG2(DBG_KNL, "%s: subnet 0x%08x mask 0x%08x proto %u", __FUNCTION__,
		subnet, mask, proto);
	return status;
}

static status_t populate_v4_sa(struct nss_nlipsec_rule *rule_ptr,
	u_int32_t outer_src, u_int32_t outer_dst, u_int32_t spi, u_int32_t ttl)
{
	status_t status = SUCCESS;
	struct nss_ipsecmgr_sa_v4 *v4_sa = NULL;

	if (!rule_ptr)
	{
		return INVALID_ARG;
	}

	rule_ptr->msg.sa.type = NSS_IPSECMGR_SA_TYPE_V4;
	v4_sa = &rule_ptr->msg.sa.data.v4;
	v4_sa->src_ip = outer_src;
	v4_sa->dst_ip = outer_dst;
	v4_sa->spi_index = spi;
	v4_sa->ttl = ttl;

	return status;
}

static status_t populate_sa_data(struct nss_nlipsec_rule *rule_ptr,
	u_int32_t crypto_index, u_int16_t icv_len, u_int16_t replay_win, bool nat,
	bool seq_skip, bool trailer_skip, bool use_pattern)
{
	status_t status = SUCCESS;
	struct nss_ipsecmgr_sa_data *sa_data = NULL;

	if (!rule_ptr)
	{
		return INVALID_ARG;
	}

	sa_data = &rule_ptr->msg.data;
	sa_data->crypto_index = crypto_index;
	sa_data->use_pattern = use_pattern;
	sa_data->esp.icv_len = icv_len;
	sa_data->esp.replay_win = replay_win;
	sa_data->esp.nat_t_req = nat;
	sa_data->esp.seq_skip = seq_skip;
	sa_data->esp.trailer_skip = trailer_skip;

	DBG2(DBG_KNL, "%s: crypto %u icv_len %u replay_win %u", __FUNCTION__,
		sa_data->crypto_index, sa_data->esp.icv_len, sa_data->esp.replay_win);

	return status;
}

METHOD(fsm_netlink_ipsec_t, add_encap_flow, status_t,
	private_fsm_netlink_ipsec_t *this, char ifname[IFNAMSIZ],
	u_int32_t *inner_src, u_int32_t *inner_dst, u_int32_t inner_family,
	u_int32_t protocol_nh, u_int32_t *outer_src, u_int32_t *outer_dst,
	u_int32_t outer_family, u_int32_t spi, u_int32_t ttl_hl,
	u_int32_t crypto_index, u_int16_t icv_len, u_int16_t replay_win, bool nat,
	bool seq_skip, bool trailer_skip, bool use_pattern)
{
	status_t status = SUCCESS;
	struct nss_nlipsec_rule rule = { { 0 } };

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ipsec", __FUNCTION__);

	if (!this || !inner_src || !inner_dst || !outer_src || !outer_dst)
	{
		return INVALID_ARG;
	}

	if ((inner_family != AF_INET) || (outer_family != AF_INET))
	{
		DBG2(DBG_KNL, "%s: Support for IPv6 unavailable", __FUNCTION__);
		return NOT_SUPPORTED;
	}

	memcpy(rule.ifname, ifname, IFNAMSIZ);

	status = populate_v4_encap_flow(&rule, *inner_src, *inner_dst, protocol_nh);
	if (status != SUCCESS)
	{
		return status;
	}

	status = populate_v4_sa(&rule, *outer_src, *outer_dst, spi, ttl_hl);
	if (status != SUCCESS)
	{
		return status;
	}

	status = populate_sa_data(&rule, crypto_index, icv_len, replay_win, nat,
		seq_skip, trailer_skip, use_pattern);
	if (status != SUCCESS)
	{
		return status;
	}

	status = ipsec_send_msg(this, &rule, NSS_NLIPSEC_CMD_CREATE_ENCAP_FLOW);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: failed to send message", __FUNCTION__);
		return status;
	}

	return status;
}

METHOD(fsm_netlink_ipsec_t, del_encap_flow, status_t,
	private_fsm_netlink_ipsec_t *this, char ifname[IFNAMSIZ],
	u_int32_t *inner_src, u_int32_t *inner_dst, u_int32_t inner_family,
	u_int32_t protocol_nh, u_int32_t *outer_src, u_int32_t *outer_dst,
	u_int32_t outer_family, u_int32_t spi, u_int32_t ttl_hl)
{
	status_t status = SUCCESS;
	struct nss_nlipsec_rule rule = { { 0 } };

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ipsec", __FUNCTION__);

	if (!this || !inner_src || !inner_dst || !outer_src || !outer_dst)
	{
		return INVALID_ARG;
	}

	if ((inner_family != AF_INET) || (outer_family != AF_INET))
	{
		DBG2(DBG_KNL, "%s: Support for IPv6 unavailable", __FUNCTION__);
		return NOT_SUPPORTED;
	}

	memcpy(rule.ifname, ifname, IFNAMSIZ);

	status = populate_v4_encap_flow(&rule, *inner_src, *inner_dst, protocol_nh);
	if (status != SUCCESS)
	{
		return status;
	}

	status = populate_v4_sa(&rule, *outer_src, *outer_dst, spi, ttl_hl);
	if (status != SUCCESS)
	{
		return status;
	}

	status = ipsec_send_msg(this, &rule, NSS_NLIPSEC_CMD_DESTROY_ENCAP_FLOW);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: failed to send message", __FUNCTION__);
		return status;
	}

	return status;
}

METHOD(fsm_netlink_ipsec_t, add_encap_subnet, status_t,
	private_fsm_netlink_ipsec_t *this, char ifname[IFNAMSIZ],
	u_int32_t *subnet, u_int32_t *mask, u_int32_t subnet_family,
	u_int32_t protocol_nh, u_int32_t *outer_src, u_int32_t *outer_dst,
	u_int32_t outer_family, u_int32_t spi, u_int32_t ttl_hl,
	u_int32_t crypto_index, u_int16_t icv_len, u_int16_t replay_win, bool nat,
	bool seq_skip, bool trailer_skip, bool use_pattern)
{
	status_t status = SUCCESS;
	struct nss_nlipsec_rule rule = { { 0 } };

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ipsec", __FUNCTION__);

	if (!this || !subnet || !mask || !outer_src || !outer_dst)
	{
		return INVALID_ARG;
	}

	if ((subnet_family != AF_INET) || (outer_family != AF_INET))
	{
		DBG2(DBG_KNL, "%s: Support for IPv6 unavailable", __FUNCTION__);
		return NOT_SUPPORTED;
	}

	memcpy(rule.ifname, ifname, IFNAMSIZ);

	status = populate_v4_encap_subnet(&rule, *subnet, *mask, protocol_nh);
	if (status != SUCCESS)
	{
		return status;
	}

	status = populate_v4_sa(&rule, *outer_src, *outer_dst, spi, ttl_hl);
	if (status != SUCCESS)
	{
		return status;
	}

	status = populate_sa_data(&rule, crypto_index, icv_len, replay_win, nat,
		seq_skip, trailer_skip, use_pattern);
	if (status != SUCCESS)
	{
		return status;
	}

	status = ipsec_send_msg(this, &rule, NSS_NLIPSEC_CMD_CREATE_ENCAP_FLOW);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: failed to send message", __FUNCTION__);
		return status;
	}

	return status;
}

METHOD(fsm_netlink_ipsec_t, del_encap_subnet, status_t,
	private_fsm_netlink_ipsec_t *this, char ifname[IFNAMSIZ],
	u_int32_t *subnet, u_int32_t *mask, u_int32_t subnet_family,
	u_int32_t protocol_nh, u_int32_t *outer_src, u_int32_t *outer_dst,
	u_int32_t outer_family, u_int32_t spi, u_int32_t ttl_hl)
{
	status_t status = SUCCESS;
	struct nss_nlipsec_rule rule = { { 0 } };

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ipsec", __FUNCTION__);

	if (!this || !subnet || !mask || !outer_src || !outer_dst)
	{
		return INVALID_ARG;
	}

	if ((subnet_family != AF_INET) || (outer_family != AF_INET))
	{
		DBG2(DBG_KNL, "%s: Support for IPv6 unavailable", __FUNCTION__);
		return NOT_SUPPORTED;
	}

	memcpy(rule.ifname, ifname, IFNAMSIZ);

	status = populate_v4_encap_subnet(&rule, *subnet, *mask, protocol_nh);
	if (status != SUCCESS)
	{
		return status;
	}

	status = populate_v4_sa(&rule, *outer_src, *outer_dst, spi, ttl_hl);
	if (status != SUCCESS)
	{
		return status;
	}

	status = ipsec_send_msg(this, &rule, NSS_NLIPSEC_CMD_DESTROY_ENCAP_FLOW);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: failed to send message", __FUNCTION__);
		return status;
	}

	return status;
}

METHOD(fsm_netlink_ipsec_t, del_encap_sa, status_t,
	private_fsm_netlink_ipsec_t *this, char ifname[IFNAMSIZ],
	u_int32_t *outer_src, u_int32_t *outer_dst, u_int32_t outer_family,
	u_int32_t spi, u_int32_t ttl_hl)
{
	status_t status = SUCCESS;
	struct nss_nlipsec_rule rule = { { 0 } };

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ipsec", __FUNCTION__);

	if (!this || !outer_src || !outer_dst)
	{
		return INVALID_ARG;
	}

	if (outer_family != AF_INET)
	{
		DBG2(DBG_KNL, "%s: Support for IPv6 unavailable", __FUNCTION__);
		return NOT_SUPPORTED;
	}

	memcpy(rule.ifname, ifname, IFNAMSIZ);

	status = populate_v4_sa(&rule, *outer_src, *outer_dst, spi, ttl_hl);
	if (status != SUCCESS)
	{
		return status;
	}

	status = ipsec_send_msg(this, &rule, NSS_NLIPSEC_CMD_DESTROY_ENCAP_SA);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: failed to send message", __FUNCTION__);
		return status;
	}

	if (this->stats_mutex && this->stats)
	{
		stats_t *stats;

		/* Remove stats related to this SA */
		this->stats_mutex->lock(this->stats_mutex);
		stats = this->stats->remove(this->stats, &spi);
		if (stats)
		{
			free(stats);
		}
		this->stats_mutex->unlock(this->stats_mutex);
	}

	return status;
}

METHOD(fsm_netlink_ipsec_t, add_decap_sa, status_t,
	private_fsm_netlink_ipsec_t *this, char ifname[IFNAMSIZ],
	u_int32_t *outer_src, u_int32_t *outer_dst, u_int32_t outer_family,
	u_int32_t spi, u_int32_t ttl_hl, u_int32_t crypto_index, u_int16_t icv_len,
	u_int16_t replay_win, bool nat, bool seq_skip, bool trailer_skip,
	bool use_pattern)
{
	status_t status = SUCCESS;
	struct nss_nlipsec_rule rule = { { 0 } };
	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ipsec", __FUNCTION__);

	if (!this || !outer_src || !outer_dst)
	{
		return INVALID_ARG;
	}

	if (outer_family != AF_INET)
	{
		DBG2(DBG_KNL, "%s: Support for IPv6 unavailable", __FUNCTION__);
		return NOT_SUPPORTED;
	}

	memcpy(rule.ifname, ifname, IFNAMSIZ);

	status = populate_v4_sa(&rule, *outer_src, *outer_dst, spi, ttl_hl);
	if (status != SUCCESS)
	{
		return status;
	}

	status = populate_sa_data(&rule, crypto_index, icv_len, replay_win, nat,
		seq_skip, trailer_skip, use_pattern);
	if (status != SUCCESS)
	{
		return status;
	}

	status = ipsec_send_msg(this, &rule, NSS_NLIPSEC_CMD_CREATE_DECAP_SA);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: failed to send message", __FUNCTION__);
		return status;
	}

	return status;
}

METHOD(fsm_netlink_ipsec_t, del_decap_sa, status_t,
	private_fsm_netlink_ipsec_t *this, char ifname[IFNAMSIZ],
	u_int32_t *outer_src, u_int32_t *outer_dst, u_int32_t outer_family,
	u_int32_t spi, u_int32_t ttl_hl)
{
	status_t status = SUCCESS;
	struct nss_nlipsec_rule rule = { { 0 } };
	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ipsec", __FUNCTION__);

	if (!this || !outer_src || !outer_dst)
	{
		return INVALID_ARG;
	}

	if (outer_family != AF_INET)
	{
		DBG2(DBG_KNL, "%s: Support for IPv6 unavailable", __FUNCTION__);
		return NOT_SUPPORTED;
	}

	memcpy(rule.ifname, ifname, IFNAMSIZ);

	status = populate_v4_sa(&rule, *outer_src, *outer_dst, spi, ttl_hl);
	if (status != SUCCESS)
	{
		return status;
	}

	status = ipsec_send_msg(this, &rule, NSS_NLIPSEC_CMD_DESTROY_DECAP_SA);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: failed to send message", __FUNCTION__);
		return status;
	}

	if (this->stats_mutex && this->stats)
	{
		stats_t *stats;

		/* Remove stats related to this SA */
		this->stats_mutex->lock(this->stats_mutex);
		stats = this->stats->remove(this->stats, &spi);
		if (stats)
		{
			free(stats);
		}
		this->stats_mutex->unlock(this->stats_mutex);
	}

	return status;
}

METHOD(fsm_netlink_ipsec_t, get_stats, status_t,
	private_fsm_netlink_ipsec_t *this, u_int32_t spi, u_int64_t *bytes,
	u_int64_t *count, time_t *time)
{
	status_t status = FAILED;
	stats_t *stats = NULL;

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ipsec", __FUNCTION__);

	if (!this || !bytes || !count || !time)
	{
		return INVALID_ARG;
	}

	if (!this->stats || !this->stats_mutex)
	{
		return INVALID_ARG;
	}

	this->stats_mutex->lock(this->stats_mutex);
	stats = this->stats->get(this->stats, &spi);
	if (stats != NULL)
	{
		*bytes = stats->bytes;
		*count = stats->count;
		*time = stats->last_use_time;
		status = SUCCESS;
	}
	this->stats_mutex->unlock(this->stats_mutex);

	return status;
}

METHOD(fsm_netlink_ipsec_t, destroy, void, private_fsm_netlink_ipsec_t *this)
{
	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ipsec", __FUNCTION__);

	if (!this)
	{
		return;
	}

	if (this->mcast_thread)
	{
		this->mcast_thread->detach(this->mcast_thread);
	}

	if (this->thread)
	{
		this->thread->detach(this->thread);
	}

	if (this->stats)
	{
		this->stats->destroy_function(this->stats, ipsec_stats_destroy);
	}

	DESTROY_IF(this->sem);
	DESTROY_IF(this->err_sem);
	DESTROY_IF(this->stats_mutex);
	DESTROY_IF(this->nl_sock_mcast);
	DESTROY_IF(this->nl_sock);
	DESTROY_IF(this->mutex);

	free(this);
}

/*
 * Described in header.
 */
fsm_netlink_ipsec_t *fsm_netlink_ipsec_create(void)
{
	private_fsm_netlink_ipsec_t *this;

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ipsec", __FUNCTION__);

	INIT(this,
		.public =
		{
			.create_tunnel = _create_tunnel,
			.destroy_tunnel = _destroy_tunnel,
			.add_encap_flow = _add_encap_flow,
			.del_encap_flow = _del_encap_flow,
			.add_encap_subnet = _add_encap_subnet,
			.del_encap_subnet = _del_encap_subnet,
			.del_encap_sa = _del_encap_sa,
			.add_decap_sa = _add_decap_sa,
			.del_decap_sa = _del_decap_sa,
			.get_stats = _get_stats,
			.destroy = _destroy,
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.stats_mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.sem = semaphore_create(0),
		.err_sem = semaphore_create(0),
		);

	memset(this->ifname, 0, IFNAMSIZ);

	this->nl_sock = fsm_netlink_sock_create(NSS_NLIPSEC_FAMILY, ipsec_resp,
		ipsec_ack, ipsec_err, this);
	if (this->nl_sock == NULL)
	{
		goto exitout;
	}

	this->nl_sock_mcast = fsm_netlink_sock_mcast_create(NSS_NLIPSEC_FAMILY,
		NSS_NLIPSEC_FAMILY, ipsec_mcast_resp, NULL, ipsec_mcast_err, this);
	if (this->nl_sock_mcast == NULL)
	{
		goto exitout;
	}

	/* Create the stats hashtable */
	this->stats = hashtable_create((hashtable_hash_t)ipsec_stats_hash,
		(hashtable_equals_t)ipsec_stats_equals, 64);
	if (this->stats == NULL)
	{
		goto exitout;
	}

	/* Spawn thread to listen to socket */
	this->thread = thread_create((thread_main_t)ipsec_receiver, this);
	if (this->thread == NULL)
	{
		goto exitout;
	}

	/* Spawn thread to listen to mcast socket */
	this->mcast_thread = thread_create((thread_main_t)ipsec_stats_listener,
		this);
	if (this->mcast_thread == NULL)
	{
		goto exitout;
	}

	return &this->public;

exitout:
	destroy(this);

	return NULL;
}
