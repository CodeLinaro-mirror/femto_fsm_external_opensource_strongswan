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

#ifndef __FSM_NETLINK_CRYPTO_H
#define __FSM_NETLINK_CRYPTO_H

#include <net/if.h>
#include <utils/utils.h>
#include <utils/chunk.h>

typedef struct fsm_netlink_crypto_t fsm_netlink_crypto_t;

/**
 * FSM netlink crypto interface
 */
struct fsm_netlink_crypto_t
{
	/**
	 * Add a crypto session
	 *
	 * @param  this			FSM netlink crypto instance
	 * @param  enc_alg		Encryption algorithm
	 * @param  enc_key		Chunk containing encryption key and length
	 * @param  int_alg		Integrity algorithm
	 * @param  int_key		Chunk containing integrity key and length
	 * @param  family		IP family (AF_INET or AF_INET6)
	 * @param  nat			TRUE if NAT_T is required
	 * @param  decap		TRUE if this is a decap SA
	 * @param  sess_idx_ptr	[out] location to store session index
	 * @return status_t
	 */
	status_t (*add_session)(fsm_netlink_crypto_t *this, u_int16_t enc_alg,
		chunk_t enc_key, u_int16_t int_alg, chunk_t int_key, u_int32_t family,
		bool nat, bool decap, u_int32_t *sess_idx_ptr);

	/**
	 * Delete an existing crypto session (previously added with add_session)
	 *
	 * @param  this		FSM netlink crypto instance
	 * @param  sess_idx	Crypto session index returned from add_session
	 * @return status_t
	 */
	status_t (*del_session)(fsm_netlink_crypto_t *this, u_int32_t sess_idx);

	/**
	 * Destroy FSM netlink crypto instance
	 *
	 * @param  this		FSM netlink crypto instance
	 * @return status_t
	 */
	void (*destroy)(fsm_netlink_crypto_t *this);
};

/**
 * Create an FSM netlink crypto instance
 *
 *
 * @return fsm_netlink_crypto_t * or NULL
 */
fsm_netlink_crypto_t *fsm_netlink_crypto_create(void);
#endif /* __FSM_NETLINK_CRYPTO_H*/
