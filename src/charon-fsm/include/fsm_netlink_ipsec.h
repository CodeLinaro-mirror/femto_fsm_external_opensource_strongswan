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

#ifndef __FSM_NETLINK_IPSEC_H
#define __FSM_NETLINK_IPSEC_H
#include <utils/utils.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <ifaddrs.h>

typedef struct fsm_netlink_ipsec_t fsm_netlink_ipsec_t;

struct fsm_netlink_ipsec_t
{
	/**
	 * Create an ipsec tunnel
	 *
	 * @param  this		FSM netlink ipsec instance
	 * @param  ifname	Tunnel interface name
	 * @return status_t
	 */
	status_t (*create_tunnel)(fsm_netlink_ipsec_t *this,
		char ifname[IFNAMSIZ]);

	/**
	 * Delete an existing ipsec tunnel (previously added with create_tunnel)
	 *
	 * @param  this		FSM netlink ipsec instance
	 * @param  ifname	Tunnel interface name
	 * @return status_t
	 */
	status_t (*destroy_tunnel)(fsm_netlink_ipsec_t *this,
		char ifname[IFNAMSIZ]);

	/**
	 * Add an encapsulation flow for distinct hosts (tunnel
	 * must exist)
	 *
	 * @param  this			FSM netlink ipsec instance
	 * @param  ifname		Tunnel interface name
	 * @param  inner_src	Pointer to inner Source IP
	 * @param  inner_dst	Pointer to inner Destination IP
	 * @param  inner_family	Inner IP family (AF_INET or AF_INET6)
	 * @param  protocol_nh	IP protocol (IPv4) or Next Header (IPv6)
	 * @param  outer_src	Pointer to outer Source IP
	 * @param  outer_dst	Pointer to outer Destination IP
	 * @param  outer_family	Outer IP family (AF_INET or AF_INET6)
	 * @param  spi			Security Parameter Index for the SA
	 * @param  ttl_hl		Time to Live (IPv4) or Hop Limit (IPv6)
	 * @param  crypto_index	Crypto Index for this SA
	 * @param  icv_len		Hash length
	 * @param  replay_win	Anti-replay window (packets)
	 * @param  nat			TRUE if NAT_T required
	 * @param  seq_skip		TRUE to skip ESP sequence
	 * @param  trailer_skip	TRUE to skip ESP trailer
	 * @param  use_pattern	TRUE to use random pattern in hash calculation
	 * @param  mark			DSCP mark
	 * @return status_t
	 */
	status_t (*add_encap_flow)(fsm_netlink_ipsec_t *this,
		char ifname[IFNAMSIZ], u_int32_t *inner_src, u_int32_t *inner_dst,
		u_int32_t inner_family, u_int32_t protocol_nh, u_int32_t *outer_src,
		u_int32_t *outer_dst, u_int32_t outer_family, u_int32_t spi,
		u_int32_t ttl_hl, u_int32_t crypto_index, u_int16_t icv_len,
		u_int16_t replay_win, bool nat, bool seq_skip, bool trailer_skip,
		bool use_pattern, u_int32_t mark);

	/**
	 * Add an encapsulation rule for destination subnet (tunnel must exist)
	 *
	 * @param  this				FSM netlink ipsec instance
	 * @param  ifname			Tunnel interface name
	 * @param  subnet			Pointer to destination subnet
	 * @param  mask				Pointer to destination subnet mask
	 * @param  subnet_family	Subnet IP family (AF_INET or AF_INET6)
	 * @param  protocol_nh		IP protocol (IPv4) or Next Header (IPv6)
	 * @param  outer_src		Pointer to outer Source IP
	 * @param  outer_dst		Pointer to outer Destination IP
	 * @param  outer_family		Pointer to outer IP family (AF_INET or AF_INET6)
	 * @param  spi				Security Parameter Index for the SA
	 * @param  ttl_hl			Time to Live (IPv4) or Hop Limit (IPv6)
	 * @param  crypto_index		Crypto Index for this SA
	 * @param  icv_len			Hash length
	 * @param  replay_win		Anti-replay window (packets)
	 * @param  nat				TRUE if NAT_T required
	 * @param  seq_skip			TRUE to skip ESP sequence
	 * @param  trailer_skip		TRUE to skip ESP trailer
	 * @param  use_pattern		TRUE to use random pattern in hash calculation
	 * @param  mark				DSCP mark
	 * @return status_t
	 */
	status_t (*add_encap_subnet)(fsm_netlink_ipsec_t *this,
		char ifname[IFNAMSIZ], u_int32_t *subnet, u_int32_t *mask,
		u_int32_t subnet_family, u_int32_t protocol_nh, u_int32_t *outer_src,
		u_int32_t *outer_dst, u_int32_t outer_family, u_int32_t spi,
		u_int32_t ttl_hl, u_int32_t crypto_index, u_int16_t icv_len,
		u_int16_t replay_win, bool nat, bool seq_skip, bool trailer_skip,
		bool use_pattern, u_int32_t mark);

	/**
	 * Delete an encapsulation flow for explicit hosts (tunnel and flow and must
	 * exist)
	 *
	 * @param  this			FSM netlink ipsec instance
	 * @param  ifname		Tunnel interface name
	 * @param  inner_src	Pointer to inner Source IP
	 * @param  inner_dst	Pointer to inner Destination IP
	 * @param  inner_family	Inner IP family (AF_INET or AF_INET6)
	 * @param  protocol_nh	IP protocol (IPv4) or Next Header (IPv6)
	 * @param  outer_src	Pointer to outer Source IP
	 * @param  outer_dst	Pointer to outer Destination IP
	 * @param  outer_family	Outer IP family (AF_INET or AF_INET6)
	 * @param  spi			Security Parameter Index for the SA
	 * @param  ttl_hl		Time to Live (IPv4) or Hop Limit (IPv6)
	 * @return status_t
	 */
	status_t (*del_encap_flow)(fsm_netlink_ipsec_t *this, char ifname[IFNAMSIZ],
		u_int32_t *inner_src, u_int32_t *inner_dst, u_int32_t inner_family,
		u_int32_t protocol_nh, u_int32_t *outer_src, u_int32_t *outer_dst,
		u_int32_t outer_family, u_int32_t spi, u_int32_t ttl_hl);

	/**
	 * Delete an encapsulation rule for destination subnet (tunnel and rule must
	 * exist)
	 *
	 * @param  this				FSM netlink ipsec instance
	 * @param  ifname			Tunnel interface name
	 * @param  subnet			Pointer to destination subnet
	 * @param  mask				Pointer to destination subnet mask
	 * @param  subnet_family	Subnet IP family (AF_INET or AF_INET6)
	 * @param  protocol_nh		IP protocol (IPv4) or Next Header (IPv6)
	 * @param  outer_src		Pointer to outer Source IP
	 * @param  outer_dst		Pointer to outer Destination IP
	 * @param  outer_family		Pointer to outer IP family (AF_INET or AF_INET6)
	 * @param  spi				Security Parameter Index for the SA
	 * @param  ttl_hl			Time to Live (IPv4) or Hop Limit (IPv6)
	 * @return status_t
	 */
	status_t (*del_encap_subnet)(fsm_netlink_ipsec_t *this,
		char ifname[IFNAMSIZ], u_int32_t *subnet, u_int32_t *mask,
		u_int32_t subnet_family, u_int32_t protocol_nh, u_int32_t *outer_src,
		u_int32_t *outer_dst, u_int32_t outer_family, u_int32_t spi,
		u_int32_t ttl_hl);

	/**
	 * Delete all encapsulation rules for this SA
	 *
	 * @param  this			FSM netlink ipsec instance
	 * @param  ifname		Tunnel interface name
	 * @param  outer_src	Pointer to outer Source IP
	 * @param  outer_dst	Pointer to outer Destination IP
	 * @param  outer_family	Pointer to outer IP family (AF_INET or AF_INET6)
	 * @param  spi			Security Parameter Index for the SA
	 * @param  ttl_hl		Time to Live (IPv4) or Hop Limit (IPv6)
	 * @return status_t
	 */
	status_t (*del_encap_sa)(fsm_netlink_ipsec_t *this, char ifname[IFNAMSIZ],
		u_int32_t *outer_src, u_int32_t *outer_dst, u_int32_t outer_family,
		u_int32_t spi, u_int32_t ttl_hl);

	/**
	 * Add a decapsulation SA (tunnel must exist)
	 *
	 * @param  this			FSM netlink ipsec instance
	 * @param  ifname		Tunnel interface name
	 * @param  outer_src	Pointer to outer Source IP
	 * @param  outer_dst	Pointer to outer Destination IP
	 * @param  outer_family	Outer IP family (AF_INET or AF_INET6)
	 * @param  spi			Security Parameter Index for the SA
	 * @param  ttl_hl		Time to Live (IPv4) or Hop Limit (IPv6)
	 * @param  crypto_index	Crypto Index for this SA
	 * @param  icv_len		Hash length
	 * @param  replay_win	Anti-replay window (packets)
	 * @param  nat			TRUE if NAT_T required
	 * @param  seq_skip		TRUE to skip ESP sequence
	 * @param  trailer_skip	TRUE to skip ESP trailer
	 * @param  use_pattern	TRUE to use random pattern in hash calculation
	 * @return status_t
	 */
	status_t (*add_decap_sa)(fsm_netlink_ipsec_t *this, char ifname[IFNAMSIZ],
		u_int32_t *outer_src, u_int32_t *outer_dst, u_int32_t outer_family,
		u_int32_t spi, u_int32_t ttl_hl, u_int32_t crypto_index,
		u_int16_t icv_len, u_int16_t replay_win, bool nat, bool seq_skip,
		bool trailer_skip, bool use_pattern);

	/**
	 * Delete a decapsulation SA (tunnel and SA and must exist)
	 *
	 * @param  this			FSM netlink ipsec instance
	 * @param  ifname		Tunnel interface name
	 * @param  outer_src	Pointer to outer Source IP
	 * @param  outer_dst	Pointer to outer Destination IP
	 * @param  outer_family	Outer IP family (AF_INET or AF_INET6)
	 * @param  spi			Security Parameter Index for the SA
	 * @param  ttl_hl		Time to Live (IPv4) or Hop Limit (IPv6)
	 * @return status_t
	 */
	status_t (*del_decap_sa)(fsm_netlink_ipsec_t *this, char ifname[IFNAMSIZ],
		u_int32_t *outer_src, u_int32_t *outer_dst, u_int32_t outer_family,
		u_int32_t spi, u_int32_t ttl_hl);

	/**
	 * Retrieve stats for the SA with the given SPI
	 *
	 * @param  this		FSM netlink ipsec instance
	 * @param  spi		SPI to use as key to retrieve data
	 * @param  bytes	Location to store number of bytes processed
	 * @param  count	Location to store number of packets processed
	 * @param  time		Location to store last use time
	 * @return status_t
	 */
	status_t (*get_stats)(fsm_netlink_ipsec_t *this, u_int32_t spi,
		u_int64_t *bytes, u_int64_t *count, time_t *time);

	/**
	 * Destroy FSM netlink ipsec instance
	 *
	 * @param  this		FSM netlink ipsec instance
	 * @return status_t
	 */
	void (*destroy)(fsm_netlink_ipsec_t *this);
};

/**
 * Create an FSM netlink ipsec instance
 *
 *
 * @return fsm_netlink_ipsec_t * or NULL
 */
fsm_netlink_ipsec_t *fsm_netlink_ipsec_create(void);
#endif /* __FSM_NETLINK_IPSEC_H*/
