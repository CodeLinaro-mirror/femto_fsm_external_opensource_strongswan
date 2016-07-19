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

#include <sys/socket.h>
#include <string.h>
#include <net/if.h>
#include <threading/thread.h>
#include <threading/mutex.h>
#include <threading/semaphore.h>
#include <utils/utils.h>
#include <utils/debug.h>
#include <nss_def.h>
#include <nss_nl_if.h>
#include <nss_cmn.h>
#include <nss_nlcmn_if.h>
#include <nss_ipv4.h>
#include <nss_ipv6.h>
#include <nss_nlipv4_if.h>
#include <nss_nlipv6_if.h>
#include <netlink/msg.h>
#include "fsm_netlink_sock.h"
#include "fsm_netlink_ip.h"

typedef struct private_fsm_netlink_ip_t private_fsm_netlink_ip_t;

/**
 * Private data for FSM netlink ip object
 *
 */
struct private_fsm_netlink_ip_t
{
	/**
	 * Public part of FSM netlink ip object
	 */
	fsm_netlink_ip_t public;

	/**
	 * FSM netlink socket context
	 */
	fsm_netlink_sock_t *nl_sock;

	/**
	 * Mutex to lock access to socket context
	 */
	mutex_t *mutex;

	/**
	 * Thread to receive messages on the socket
	 */
	thread_t *thread;

	/**
	 * Semaphore for notifying of errors received on the socket
	 */
	semaphore_t *err_sem;

	/**
	 * IP family (AF_INET or AF_INET6)
	 */
	u_int32_t family;
};

#define IP_DEFAULT_ERR_TIMEOUT 200

CALLBACK(ip_receiver, void *, private_fsm_netlink_ip_t *this)
{
	status_t status = FAILED;
	thread_cancelability(TRUE);

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ip thread %u", __FUNCTION__,
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
	DBG2(DBG_KNL, "Exiting %s in fsm_netlink_ip thread %u", __FUNCTION__,
		thread_current_id());

	return NULL;
}

static status_t ip_send_msg(private_fsm_netlink_ip_t *this, void *rulePtr,
	uint16_t cmd)
{
	status_t status = SUCCESS;
	struct nss_nlcmn *cm = NULL;

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ip", __FUNCTION__);

	if (!this || !rulePtr)
	{
		DBG2(DBG_KNL, "%s: Invalid arguments", __FUNCTION__);
		return INVALID_ARG;
	}

	if (!this->nl_sock || !this->err_sem)
	{
		DBG2(DBG_KNL, "%s: Invalid sock ctx", __FUNCTION__);
		return INVALID_ARG;
	}

	if (this->family == AF_INET)
	{
		/* Init the message structure*/
		nss_nlipv4_rule_init((struct nss_nlipv4_rule *)rulePtr,
			(enum nss_ipv4_message_types)cmd);
		cm = &((struct nss_nlipv4_rule *)rulePtr)->cm;
	}
	else
	{
		nss_nlipv6_rule_init((struct nss_nlipv6_rule *)rulePtr,
			(enum nss_ipv6_message_types)cmd);
		cm = &((struct nss_nlipv6_rule *)rulePtr)->cm;
	}

	/* send message */
	this->mutex->lock(this->mutex);
	status = this->nl_sock->send_msg(this->nl_sock, cm, rulePtr);
	this->mutex->unlock(this->mutex);

	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: failed to send message cmd: %u", __FUNCTION__, cmd);
		return status;
	}

	DBG2(DBG_KNL, "%s: message sent cmd: %u", __FUNCTION__, cmd);

	/* See if there is an error. */
	if (!this->err_sem->timed_wait(this->err_sem,
		IP_DEFAULT_ERR_TIMEOUT))
	{
		DBG2(DBG_KNL, "%s: Error message received.", __FUNCTION__);
		return FAILED;
	}

	return status;
}

CALLBACK(ip_resp, void, private_fsm_netlink_ip_t *this,
	struct nss_nlcmn *cm, void *data)
{
	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ip", __FUNCTION__);

	if (!this || !cm || !data)
	{
		DBG2(DBG_KNL, "%s: Received invalid response from socket",
			__FUNCTION__);
		return;
	}
}

CALLBACK(ip_ack, void, private_fsm_netlink_ip_t *this, void *msg)
{
	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ip", __FUNCTION__);
}

CALLBACK(ip_err, void, private_fsm_netlink_ip_t *this, void *msg)
{
	struct nlmsgerr *nlerr = (struct nlmsgerr *)msg;

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ip", __FUNCTION__);

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

	DBG2(DBG_KNL, "%s: Error received (%d) -- %s", __FUNCTION__,
		nlerr->error, strerror_safe(-nlerr->error));
}

static status_t add_v4_flow(private_fsm_netlink_ip_t *this,
	u_int32_t src, u_int32_t src_port, u_int32_t dst, u_int32_t dst_port,
	u_int8_t proto, char src_ifname[IFNAMSIZ], char dst_ifname[IFNAMSIZ])
{
	status_t status = FAILED;
	struct nss_nlipv4_rule v4_rule = { { 0 } };
	struct nss_ipv4_5tuple *v4_tuple = &v4_rule.nim.msg.rule_create.tuple;

	memcpy(v4_rule.flow_ifname, src_ifname, IFNAMSIZ);
	memcpy(v4_rule.return_ifname, dst_ifname, IFNAMSIZ);

	/* Set the connection valid Flag */
	v4_rule.nim.msg.rule_create.valid_flags |= NSS_IPV4_RULE_CREATE_CONN_VALID;

	v4_tuple->flow_ip = src;
	v4_tuple->flow_ident = src_port;
	v4_tuple->return_ip = dst;
	v4_tuple->return_ident = dst_port;
	v4_tuple->protocol = proto;

	DBG2(DBG_KNL, "%s: src 0x%08x port %u dst 0x%08x port %u proto %u",
		__FUNCTION__, src, src_port, dst, dst_port, proto);

	status = ip_send_msg(this, &v4_rule, NSS_IPV4_TX_CREATE_RULE_MSG);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: failed to send message", __FUNCTION__);
		return status;
	}

	DBG2(DBG_KNL, "%s: successfully sent message", __FUNCTION__);
	return status;
}

static status_t add_v6_flow(private_fsm_netlink_ip_t *this,
	u_int32_t *src, u_int32_t src_port, u_int32_t *dst, u_int32_t dst_port,
	u_int8_t proto, char src_ifname[IFNAMSIZ], char dst_ifname[IFNAMSIZ])
{
	status_t status = FAILED;
	struct nss_nlipv6_rule v6_rule = { { 0 } };
	struct nss_ipv6_5tuple *v6_tuple = &v6_rule.nim.msg.rule_create.tuple;

	if (!src || !dst)
	{
		return INVALID_ARG;
	}

	memcpy(v6_rule.flow_ifname, src_ifname, IFNAMSIZ);
	memcpy(v6_rule.return_ifname, dst_ifname, IFNAMSIZ);

	/* Set the connection valid Flag */
	v6_rule.nim.msg.rule_create.valid_flags |= NSS_IPV6_RULE_CREATE_CONN_VALID;

	memcpy(v6_tuple->flow_ip, src, sizeof(v6_tuple->flow_ip));
	memcpy(v6_tuple->return_ip, dst, sizeof(v6_tuple->return_ip));
	v6_tuple->protocol = proto;
	v6_tuple->flow_ident = src_port;
	v6_tuple->return_ident = dst_port;

	DBG2(DBG_KNL, "%s: src 0x%08x%08x%08x%08x port %u dst 0x%08x%08x%08x%08x "
				  "port %u proto %u",
		__FUNCTION__, src[0], src[1], src[2], src[3], src_port, dst[0], dst[1],
		dst[2], dst[3], dst_port, proto);

	status = ip_send_msg(this, (void *)&v6_rule, NSS_IPV6_TX_CREATE_RULE_MSG);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: failed to send message", __FUNCTION__);
		return status;
	}

	DBG2(DBG_KNL, "%s: successfully sent message", __FUNCTION__);
	return status;
}

METHOD(fsm_netlink_ip_t, add_flow, status_t, private_fsm_netlink_ip_t *this,
	u_int32_t *src, u_int32_t src_port, u_int32_t *dst, u_int32_t dst_port,
	u_int8_t proto, char src_ifname[IFNAMSIZ], char dst_ifname[IFNAMSIZ])
{
	status_t status = SUCCESS;

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ip src %s dst %s", __FUNCTION__,
		src_ifname, dst_ifname);

	if (!this || !src || !dst)
	{
		return INVALID_ARG;
	}

	switch(this->family)
	{
		case AF_INET:
			status = add_v4_flow(this, *src, src_port, *dst, dst_port, proto,
				src_ifname, dst_ifname);
			break;

		case AF_INET6:
			status = add_v6_flow(this, src, src_port, dst, dst_port, proto,
				src_ifname, dst_ifname);
			break;

		default:
			return NOT_SUPPORTED;
	}

	return status;
}

static status_t del_v4_flow(private_fsm_netlink_ip_t *this, u_int32_t src,
	u_int32_t src_port, u_int32_t dst, u_int32_t dst_port, u_int8_t proto)
{
	status_t status = FAILED;
	struct nss_nlipv4_rule v4_rule = { { 0 } };
	struct nss_ipv4_5tuple *v4_tuple = &v4_rule.nim.msg.rule_destroy.tuple;

	v4_tuple->flow_ip = src;
	v4_tuple->flow_ident = src_port;
	v4_tuple->return_ip = dst;
	v4_tuple->return_ident = dst_port;
	v4_tuple->protocol = proto;

	DBG2(DBG_KNL, "%s: src 0x%08x port %u dst 0x%08x port %u proto %u",
		__FUNCTION__, src, src_port, dst, dst_port, proto);

	status = ip_send_msg(this, (void *)&v4_rule, NSS_IPV4_TX_DESTROY_RULE_MSG);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: failed to send message", __FUNCTION__);
		return status;
	}

	DBG2(DBG_KNL, "%s: successfully sent message", __FUNCTION__);

	return status;
}

static status_t del_v6_flow(private_fsm_netlink_ip_t *this, u_int32_t *src,
	u_int32_t src_port, u_int32_t *dst, u_int32_t dst_port, u_int8_t proto)
{
	status_t status = FAILED;
	struct nss_nlipv6_rule v6_rule = { { 0 } };
	struct nss_ipv6_5tuple *v6_tuple = &v6_rule.nim.msg.rule_destroy.tuple;

	memcpy(v6_tuple->flow_ip, src, sizeof(v6_tuple->flow_ip));
	memcpy(v6_tuple->return_ip, dst, sizeof(v6_tuple->return_ip));
	v6_tuple->protocol = proto;
	v6_tuple->flow_ident = src_port;
	v6_tuple->return_ident = dst_port;

	DBG2(DBG_KNL, "%s: src 0x%08x%08x%08x%08x port %u dst 0x%08x%08x%08x%08x "
				  "port %u proto %u",
		__FUNCTION__, src[0], src[1], src[2], src[3], src_port, dst[0], dst[1],
		dst[2], dst[3], dst_port, proto);

	status = ip_send_msg(this, (void *)&v6_rule, NSS_IPV6_TX_DESTROY_RULE_MSG);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: failed to send message", __FUNCTION__);
		return status;
	}

	DBG2(DBG_KNL, "%s: successfully sent message", __FUNCTION__);

	return status;
}

METHOD(fsm_netlink_ip_t, del_flow, status_t, private_fsm_netlink_ip_t *this,
	u_int32_t *src, u_int32_t src_port, u_int32_t *dst, u_int32_t dst_port,
	u_int8_t proto)
{
	status_t status = SUCCESS;

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ip", __FUNCTION__);

	if (!this || !src || !dst)
	{
		return INVALID_ARG;
	}

	switch(this->family)
	{
		case AF_INET:
			status = del_v4_flow(this, *src, src_port, *dst, dst_port, proto);
			break;

		case AF_INET6:
			status = del_v6_flow(this, src, src_port, dst, dst_port, proto);
			break;

		default:
			return NOT_SUPPORTED;
	}

	return status;
}

METHOD(fsm_netlink_ip_t, destroy, void, private_fsm_netlink_ip_t *this)
{
	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ip", __FUNCTION__);

	if (!this)
	{
		return;
	}

	if (this->thread)
	{
		this->thread->detach(this->thread);
	}

	DESTROY_IF(this->nl_sock);
	DESTROY_IF(this->mutex);
	DESTROY_IF(this->err_sem);
	free(this);
}

/*
 * Described in header.
 */
fsm_netlink_ip_t *fsm_netlink_ip_create(u_int32_t family)
{
	private_fsm_netlink_ip_t *this;

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_ip", __FUNCTION__);

	if ((family != AF_INET) && (family != AF_INET6))
	{
		DBG2(DBG_KNL, "%s: IP family %u not supported", __FUNCTION__, family);
		return NULL;
	}

	INIT(this,
		.public =
		{
			.add_flow = _add_flow,
			.del_flow = _del_flow,
			.destroy = _destroy,
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.err_sem = semaphore_create(0),
		.family = family,
		);

	if (family == AF_INET)
	{
		this->nl_sock = fsm_netlink_sock_create(NSS_NLIPV4_FAMILY, ip_resp,
			ip_ack, ip_err, (void *)this);
	}
	else
	{
		this->nl_sock = fsm_netlink_sock_create(NSS_NLIPV6_FAMILY, ip_resp,
			ip_ack, ip_err, (void *)this);
	}

	if (this->nl_sock == NULL)
	{
		goto exitout;
	}

	/* Spawn thread to listen to socket */
	this->thread = thread_create((thread_main_t)ip_receiver, this);
	if (this->thread == NULL)
	{
		goto exitout;
	}

	return &this->public;

exitout:
	destroy(this);
	return NULL;
}
