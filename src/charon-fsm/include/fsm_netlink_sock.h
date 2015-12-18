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

#ifndef __FSM_NETLINK_SOCK_H
#define __FSM_NETLINK_SOCK_H

#include <netlink/types.h>
#include <nss_def.h>
#include <nss_nlcmn_if.h>
#include <nss_nl_if.h>

typedef struct fsm_netlink_sock_t fsm_netlink_sock_t;
struct fsm_netlink_sock_t
{
	/**
	 * Send a netlink message
	 *
	 * @param  this		FSM netlink socket instance
	 * @param  cm		Pointer to populated NSS common header fields
	 * @param  data		Pointer to message data
	 * @return status_t
	 */
	status_t (*send_msg)(fsm_netlink_sock_t *this, struct nss_nlcmn *cm,
		void *data);

	/**
	 * Receive netlink messages response (will call user callback)
	 *
	 * @param  this		FSM netlink socket instance
	 * @param  cm		Pointer to populated NSS common header fields
	 * @param  data		Pointer to message data
	 * @return status_t
	 */
	status_t (*recv_msgs)(fsm_netlink_sock_t *this);

	/**
	 * Destroy FSM netlink socket instance
	 *
	 * @param  this		FSM netlink socket instance
	 * @return void
	 */
	void (*destroy)(fsm_netlink_sock_t *this);
};

/**
 * @brief socket response callback
 */
typedef void (*fsm_netlink_sock_resp_cb_t)(void *this, struct nss_nlcmn *cm,
	void *data);

/**
 * @brief generic socket callback
 */
typedef void (*fsm_netlink_sock_cb_t)(void *this, void *msg);

/**
 * @brief fsm_netlink_sock_create - Create netlink socket
 * @param family_name - Netlink socket family name
 * @param resp_cb - Callback for socket responses
 * @param ack_cb - Callback for socket ACKs
 * @param err_cb - Callback for socket errors
 * @param data - Callback context for caller
 * @return fsm_netlink_sock_t * or NULL
 */
fsm_netlink_sock_t *fsm_netlink_sock_create(char *family_name,
	fsm_netlink_sock_resp_cb_t resp_cb, fsm_netlink_sock_cb_t ack_cb,
	fsm_netlink_sock_cb_t err_cb, void *data);

/**
 * @brief fsm_netlink_sock_mcast_create - Create netlink multicast socket
 * @param family_name - Netlink socket family name
 * @param group_name - Netlink socket group name
 * @param resp_cb - Callback for socket responses
 * @param ack_cb - Callback for socket ACKs
 * @param err_cb - Callback for socket errors
 * @param data - Callback context for caller
 * @return fsm_netlink_sock_t * or NULL
 */
fsm_netlink_sock_t *
fsm_netlink_sock_mcast_create(char *family_name, char *group_name,
	fsm_netlink_sock_resp_cb_t resp_cb, fsm_netlink_sock_cb_t ack_cb,
	fsm_netlink_sock_cb_t err_cb, void *data);

#endif /* __FSM_NETLINK_SOCK_H */
