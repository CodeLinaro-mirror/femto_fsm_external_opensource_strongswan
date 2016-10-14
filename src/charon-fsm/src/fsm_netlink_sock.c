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
#include <errno.h>
#include <utils/debug.h>
#include <nss_def.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <netlink/socket.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/utils.h>
#include <netlink/addr.h>
#include <nss_nlcmn_if.h>
#include <nss_nl_if.h>
#include "fsm_netlink_sock.h"

typedef struct private_fsm_netlink_sock_t private_fsm_netlink_sock_t;

struct private_fsm_netlink_sock_t
{
	/*
	 * Public data
	 */
	fsm_netlink_sock_t public;

	/*
	 * Netlink socket pointer
	 */
	struct nl_sock *sock;

	/*
	 * Netlink socket callback
	 */
	struct nl_cb *nl_cb;

	/*
	 * Netlink socket family ID
	 */
	int family_id;

	/*
	 * Netlink socket family name
	 */
	char *family_name;

	/*
	 * Netlink socket group ID
	 */
	int group_id;

	/*
	 * Caller response callback
	 */
	fsm_netlink_sock_resp_cb_t resp_cb_fn;

	/*
	 * Caller response callback
	 */
	fsm_netlink_sock_cb_t ack_cb_fn;

	/*
	 * Caller response callback
	 */
	fsm_netlink_sock_cb_t err_cb_fn;

	/*
	 * Caller context
	 */
	void *cb_data;
};

/*
 * sock_resp_cb()
 * 	Socket response handler
 */
static int sock_resp_cb(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = NULL;
	private_fsm_netlink_sock_t *this = (private_fsm_netlink_sock_t *)arg;
	void *data = NULL;

	if (!msg || !arg || !this)
	{
		DBG2(DBG_KNL, "%s: Invalid arguments", __FUNCTION__);
		return NL_SKIP;
	}

	DBG3(DBG_KNL, "Entering %s in fsm_netlink_sock family %s", __FUNCTION__,
		this->family_name);

	/* get the generic netlink header */
	gnlh = nlmsg_data(nlmsg_hdr(msg));
	if (!gnlh)
	{
		DBG2(DBG_KNL, "%s(%s): Could not get gnlh", __FUNCTION__,
			this->family_name);
		return NL_SKIP;
	}

	/* netlink generic data will be user data */
	data = genlmsg_user_hdr(gnlh);

	/* handle the data to the registered callback handle*/

	/* get the callback handler for the socket registered during alloc */
	if (!this->resp_cb_fn || !this->cb_data)
	{
		DBG2(DBG_KNL, "%s(%s): Invalid callback parameters", __FUNCTION__,
			this->family_name);
		return NL_SKIP;
	}

	this->resp_cb_fn(this->cb_data, (struct nss_nlcmn *)data, data);

	return NL_OK;
}

static int sock_noop_cb(struct nl_msg *msg, void *arg)
{
	/* This is to avoid compiler warnings about unused parameters */
	(void)msg;
	(void)arg;

	return NL_OK;
}

/*
 * sock_ack_cb()
 * 	Socket ACK handler
 */
static int sock_ack_cb(struct nl_msg *msg, void *arg)
{
	private_fsm_netlink_sock_t *this = (private_fsm_netlink_sock_t *)arg;

	if (!msg || !arg || !this)
	{
		DBG2(DBG_KNL, "%s: Invalid arguments", __FUNCTION__);
		return NL_SKIP;
	}

	DBG3(DBG_KNL, "Entering %s in fsm_netlink_sock family %s", __FUNCTION__,
		this->family_name);

	/* get the callback handler for the socket registered during alloc */
	if (!this->ack_cb_fn || !this->cb_data)
	{
		return NL_SKIP;
	}

	this->ack_cb_fn(this->cb_data, msg);

	return NL_OK;
}


/*
 * sock_err_cb()
 * 	Socket error handler
 */
static int sock_err_cb(struct sockaddr_nl *nla, struct nlmsgerr *nlerr,
	void *arg)
{
	private_fsm_netlink_sock_t *this = (private_fsm_netlink_sock_t *)arg;
	if (!nla || !nlerr || !arg)
	{
		DBG2(DBG_KNL, "%s: Invalid arguments", __FUNCTION__);
		return NL_SKIP;
	}

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_sock", __FUNCTION__);
	/* get the callback handler for the socket registered during alloc */
	if (!this->err_cb_fn || !this->cb_data)
	{
		return NL_SKIP;
	}

	this->err_cb_fn(this->cb_data, nlerr);

	return NL_OK;
}

METHOD(fsm_netlink_sock_t, send_msg, status_t, private_fsm_netlink_sock_t *this,
	struct nss_nlcmn *cm, void *data)
{
	struct nl_msg *msg = NULL;
	void *usr_hdr = NULL;
	int error = 0;
	status_t status = SUCCESS;
	uint16_t nlmsg_len = 0;
	uint8_t nlmsg_cmd = 0;

	if (!this || !cm || !data)
	{
		return INVALID_ARG;
	}

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_sock family %s", __FUNCTION__,
		this->family_name);

	/* allocate new message buffer */
	msg = nlmsg_alloc();
	if (msg == NULL)
	{
		DBG2(DBG_KNL, "%s(%s): unable to allocate message buffer", __FUNCTION__,
			this->family_name);
		status = FAILED;
		goto fail;
	}

	/* update message buffer with generic netlink specific parameters */
	nlmsg_len = nss_nlcmn_get_len(cm);
	nlmsg_cmd = nss_nlcmn_get_cmd(cm);
	usr_hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, this->family_id,
		nlmsg_len, NLM_F_REQUEST, nlmsg_cmd, NSS_NL_VER_MAJOR);
	if (NULL == usr_hdr)
	{
		DBG2(DBG_KNL, "%s(%s): genlmsg_put failed", __FUNCTION__,
			this->family_name);
		status = FAILED;
		goto free_msg;
	}

	memcpy(usr_hdr, data, nlmsg_len);

	/* send message to netlink bus */
	error = nl_send_auto(this->sock, msg);
	if (error < 0)
	{
		DBG2(DBG_KNL, "%s(%s): unable to send message: cmd %u error %d",
			__FUNCTION__, this->family_name, nlmsg_cmd, error);
		status = FAILED;
		goto free_msg;
	}

free_msg:
	nlmsg_free(msg);

fail:
	return status;
}

METHOD(fsm_netlink_sock_t, recv_msgs, status_t,
	private_fsm_netlink_sock_t *this)
{
	status_t status = SUCCESS;
	int error = 0;

	if (!this)
	{
		DBG2(DBG_KNL, "%s: Invalid argument", __FUNCTION__);
		return INVALID_ARG;
	}

	if (!this->sock || !this->family_name)
	{
		DBG2(DBG_KNL, "%s: Invalid argument", __FUNCTION__);
		return INVALID_ARG;
	}

	DBG3(DBG_KNL, "Entering %s in fsm_netlink_sock family %s", __FUNCTION__,
		this->family_name);

	/* Wait for a response (blocking call)
	 * The callback will be called if a valid response is received, which
	 * will in turn call the user callback.
	 */
	error = nl_recvmsgs(this->sock, this->nl_cb);
	if (error < 0)
	{
		DBG2(DBG_KNL, "%s(%s): unable to receive messages: error %d",
			__FUNCTION__, this->family_name, error);
		status = FAILED;
	}

	return status;
}


METHOD(fsm_netlink_sock_t, destroy, void, private_fsm_netlink_sock_t *this)
{
	DBG2(DBG_KNL, "Entering %s in fsm_netlink_sock", __FUNCTION__);

	if (this == NULL)
	{
		return;
	}

	this->resp_cb_fn = NULL;
	this->err_cb_fn = NULL;
	this->ack_cb_fn = NULL;
	this->cb_data = NULL;

	if (this->nl_cb)
	{
		nl_cb_put(this->nl_cb);
	}

	if (this->sock)
	{
		nl_socket_free(this->sock);
	}

	if (this->family_name)
	{
		free(this->family_name);
	}

	free(this);
}

fsm_netlink_sock_t *
fsm_netlink_sock_create(char *family_name, fsm_netlink_sock_resp_cb_t resp_cb,
	fsm_netlink_sock_cb_t ack_cb, fsm_netlink_sock_cb_t err_cb, void *data)
{
	private_fsm_netlink_sock_t *this = NULL;

	if (!resp_cb || !family_name || !data)
	{
		return NULL;
	}

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_sock family %s", __FUNCTION__,
		family_name);

	INIT(this,
		.public =
		{
			.send_msg = _send_msg,
			.recv_msgs = _recv_msgs,
			.destroy = _destroy,
		},
		.resp_cb_fn = resp_cb,
		.ack_cb_fn = ack_cb,
		.err_cb_fn = err_cb,
		.cb_data = data,
		.family_name = strdup(family_name),
		);

	if (!this)
	{
		DBG1(DBG_KNL, "%s: Failed to allocate fsm_netlink_sock object",
			__FUNCTION__);
		return NULL;
	}

	if (this->family_name == NULL)
	{
		DBG2(DBG_KNL, "%s: strdup of family_name failed", __FUNCTION__);
		goto destroythis;
	}

	/* Create netlink socket */
	this->sock = nl_socket_alloc();
	if (this->sock == NULL)
	{
		DBG2(DBG_KNL, "%s: nl_socket_alloc failed", __FUNCTION__);
		goto destroythis;
	}

	/* Connect the socket with the netlink bus*/
	if (genl_connect(this->sock) != 0)
	{
		DBG2(DBG_KNL, "%s: unable to connect socket with netlink bus",
			__FUNCTION__);
		goto destroythis;
	}

	/* resolve the family */
	this->family_id = genl_ctrl_resolve(this->sock, family_name);
	if (this->family_id <= 0)
	{
		DBG2(DBG_KNL, "%s: Unable to resolve the family name: '%s'",
			__FUNCTION__, family_name);
		goto destroythis;
	}

	/* Create callback */
	this->nl_cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (this->nl_cb == NULL)
	{
		DBG2(DBG_KNL, "%s: error in creating custom callback handler",
			__FUNCTION__);
		goto destroythis;
	}

	if (nl_cb_set(this->nl_cb, NL_CB_VALID, NL_CB_CUSTOM,
				  (nl_recvmsg_msg_cb_t)sock_resp_cb, &this->public) != 0)
	{
		DBG2(DBG_KNL, "%s: nl_cb_set failed", __FUNCTION__);
		goto destroythis;
	}

	if (nl_cb_set(this->nl_cb, NL_CB_ACK, NL_CB_CUSTOM,
		(nl_recvmsg_msg_cb_t)sock_ack_cb, &this->public) != 0)
	{
		DBG2(DBG_KNL, "%s: nl_cb_set failed", __FUNCTION__);
		goto destroythis;
	}

	if (nl_cb_set(this->nl_cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM,
		(nl_recvmsg_msg_cb_t)sock_noop_cb, &this->public) != 0)
	{
		DBG2(DBG_KNL, "%s: nl_cb_set failed", __FUNCTION__);
		goto destroythis;
	}

	if (nl_cb_err(this->nl_cb, NL_CB_CUSTOM, (nl_recvmsg_err_cb_t)sock_err_cb,
		&this->public) != 0)
	{
		DBG2(DBG_KNL, "%s: nl_cb_err failed", __FUNCTION__);
		goto destroythis;
	}

	return (fsm_netlink_sock_t *)this;

destroythis:
	if (this)
	{
		this->public.destroy(&this->public);
	}

	return NULL;
}

fsm_netlink_sock_t *
fsm_netlink_sock_mcast_create(char *family_name, char *group_name,
	fsm_netlink_sock_resp_cb_t resp_cb, fsm_netlink_sock_cb_t ack_cb,
	fsm_netlink_sock_cb_t err_cb, void *data)
{
	private_fsm_netlink_sock_t *this;

	if (!resp_cb || !family_name || !data || !group_name)
	{
		return NULL;
	}

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_sock family %s", __FUNCTION__,
		family_name);

	this = (private_fsm_netlink_sock_t *)fsm_netlink_sock_create(family_name,
		resp_cb, ack_cb, err_cb, data);
	if (!this)
	{
		return NULL;
	}

	/* resolve the group */
	this->group_id = genl_ctrl_resolve_grp(this->sock, family_name, group_name);
	if (this->group_id <= 0)
	{
		DBG2(DBG_KNL, "%s: Unable to resolve the group name: '%s'",
			__FUNCTION__, group_name);
		goto destroy_this;
	}

	/* Add group membership */
	if (nl_socket_add_membership(this->sock, this->group_id) != 0)
	{
		DBG2(DBG_KNL, "%s: nl_socket_add_membership failed for group %d",
			__FUNCTION__, this->group_id);
		goto destroy_this;
	}
	return &this->public;

destroy_this:
	destroy(this);

	return NULL;
}

