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

#ifndef __FSM_NETLINK_IP_H
#define __FSM_NETLINK_IP_H
#include <utils/utils.h>

typedef struct fsm_netlink_ip_t fsm_netlink_ip_t;

struct fsm_netlink_ip_t
{
	/**
	 * Add an ip flow
	 *
	 * @param  this			FSM netlink ip instance
	 * @param  src			Pointer to source IP
	 * @param  src_port		Source port number
	 * @param  dst			Pointer to destination IP
	 * @param  dst_port		Destination port number
	 * @param  proto		IP protocol
	 * @param  src_ifname	Source interface name (typically tunnel name)
	 * @param  dst_ifname	Destination interface name (actual device ifname)
	 * @return status_t
	 */
	status_t (*add_flow)(fsm_netlink_ip_t *this, u_int32_t *src,
		u_int32_t src_port, u_int32_t *dst, u_int32_t dst_port,
		u_int8_t proto, char src_ifname[IFNAMSIZ],
		char dst_ifname[IFNAMSIZ]);

	/**
	 * Delete an ip flow
	 *
	 * @param  this		FSM netlink ip instance
	 * @param  src		Pointer to source IP
	 * @param  src_port	Source port number
	 * @param  dst		Pointer to destination IP
	 * @param  dst_port	Destination port number
	 * @param  proto	IP protocol
	 * @return status_t
	 */
	status_t (*del_flow)(fsm_netlink_ip_t *this, u_int32_t *src,
		u_int32_t src_port, u_int32_t *dst, u_int32_t dst_port,
		u_int8_t proto);

	/**
	 * Destroy FSM netlink ip instance
	 *
	 * @param  this		FSM netlink ip instance
	 * @return status_t
	 */
	void (*destroy)(fsm_netlink_ip_t *this);
};

/**
 * Create an FSM netlink ip instance
 *
 * @param  family	IP family (AF_INET or AF_INET6)
 * @return fsm_netlink_ip_t * or NULL
 */
fsm_netlink_ip_t *fsm_netlink_ip_create(u_int32_t family);

#endif /* __FSM_NETLINK_IP_H*/
