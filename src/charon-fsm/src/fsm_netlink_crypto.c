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
#include <netlink/msg.h>
#include <threading/mutex.h>
#include <threading/semaphore.h>
#include <threading/thread.h>
#include <utils/utils/object.h>
#include <utils/utils.h>
#include <utils/debug.h>
#include <utils/chunk.h>
#include <crypto/transform.h>
#include <crypto/crypters/crypter.h>
#include <crypto/signers/signer.h>
#include <nss_def.h>
#include <nss_nl_if.h>
#include <nss_nlcmn_if.h>
#include <nss_cmn.h>
#include <nss_crypto.h>
#include <nss_crypto_if.h>
#include <nss_nlcrypto_if.h>
#include "fsm_netlink_sock.h"
#include "fsm_netlink_crypto.h"

typedef struct private_fsm_netlink_crypto_t private_fsm_netlink_crypto_t;

/**
 * Private data for FSM netlink crypto object
 *
 */
struct private_fsm_netlink_crypto_t
{
	/**
	 * Public part of FSM netlink crypto object
	 */
	fsm_netlink_crypto_t public;

	/**
	 * FSM netlink socket context (crypto family)
	 */
	fsm_netlink_sock_t *nl_sock;

	/**
	 * Mutex to lock access to socket context
	 */
	mutex_t *mutex;

	/**
	 * Last created session index
	 */
	uint32_t last_sess_idx;

	/**
	 * Last update info
	 */
	struct nss_nlcrypto_info_session last_update_info;

	/**
	 * Semaphore used to synchronize messages sent with expected
	 * responses.
	 */
	semaphore_t *sem;

	/**
	 * Semaphore used to indicate errors were received.
	 */
	semaphore_t *err_sem;

	/**
	 * Thread for receiving messages on the socket
	 */
	thread_t *thread;
};

#define CRYPTO_DEFAULT_TIMEOUT 1000
#define CRYPTO_DEFAULT_ERR_TIMEOUT 200

typedef struct algorithm_t algorithm_t;
/**
 * Mapping of IKEv2 kernel identifier to NSS crypto API names
 */
struct algorithm_t
{
	/**
	 * Identifier specified in IKEv2
	 */
	u_int16_t ikev2;

	/**
	 * NSS algorithm ID
	 */
	u_int32_t nss;

	/**
	 * encap skip value
	 */
	u_int32_t encap_skip;

	/**
	 * decap skip value
	 */
	u_int32_t decap_skip;

	/**
	 * NAT_T encap skip value
	 */
	u_int32_t nat_encap_skip;

	/**
	 * NAT_T decap skip value
	 */
	u_int32_t nat_decap_skip;
};

/**
 * Algorithms for encryption
 */
static algorithm_t enc_algs[] =
{
	{ ENCR_DES, NSS_CRYPTO_CIPHER_DES, 36, 16, 44, 16 },
	{ ENCR_3DES, NSS_CRYPTO_CIPHER_DES, 36, 16, 44, 16 },
	{ ENCR_NULL, NSS_CRYPTO_CIPHER_NULL, 0, 0, 0, 0 },
	{ ENCR_AES_CBC, NSS_CRYPTO_CIPHER_AES, 44, 24, 52, 24 },
};

/**
 * Algorithms for integrity protection (auth)
 */
static algorithm_t int_algs[] =
{
	{ AUTH_HMAC_SHA1_96, NSS_CRYPTO_AUTH_SHA1_HMAC, 20, 0, 28, 0 },
	{ AUTH_HMAC_SHA1_160, NSS_CRYPTO_AUTH_SHA1_HMAC, 20, 0, 28, 0 },
	{ AUTH_HMAC_SHA2_256_96, NSS_CRYPTO_AUTH_SHA256_HMAC, 20, 0, 28, 0 },
	{ AUTH_HMAC_SHA2_256_128, NSS_CRYPTO_AUTH_SHA256_HMAC, 20, 0, 28, 0 },
};

/**
 * Look up a crypto algorithm name and key size
 */
static bool crypto_alg_lookup(transform_type_t type, u_int16_t ikev2,
	algorithm_t **alg_ptr)
{
	bool found = FALSE;
	algorithm_t *list = NULL;
	u_int32_t i = 0;
	u_int32_t count = 0;

	if (!alg_ptr)
	{
		return FALSE;
	}

	switch (type)
	{
		case ENCRYPTION_ALGORITHM:
			list = enc_algs;
			count = countof(enc_algs);
			break;
		case INTEGRITY_ALGORITHM:
			list = int_algs;
			count = countof(int_algs);
			break;
		default:
			break;
	}

	if (!list)
	{
		return FALSE;
	}

	for (i = 0; i < count; i++)
	{
		if (list[i].ikev2 == ikev2)
		{
			*alg_ptr = &list[i];
			found = TRUE;
			break;
		}
	}

	return found;
}

CALLBACK(crypto_receiver, void *, private_fsm_netlink_crypto_t *this)
{
	status_t status = FAILED;
	thread_cancelability(TRUE);

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_crypto thread %u", __FUNCTION__,
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
	DBG2(DBG_KNL, "Exiting %s in fsm_netlink_crypto thread %u", __FUNCTION__,
		thread_current_id());

	return NULL;
}

static status_t crypto_send_msg(private_fsm_netlink_crypto_t *this,
	struct nss_nlcrypto_rule *rule_ptr, uint16_t cmd)
{
	status_t status = SUCCESS;

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_crypto", __FUNCTION__);

	if (!this || !rule_ptr)
	{
		return INVALID_ARG;
	}

	if (!this->nl_sock || !this->err_sem)
	{
		return INVALID_ARG;
	}

	/* Init the message structure*/
	nss_nlcrypto_rule_init(rule_ptr, (enum nss_nlcrypto_cmd)cmd);

	/* send message */
	this->mutex->lock(this->mutex);
	status = this->nl_sock->send_msg(this->nl_sock, &rule_ptr->cm,
		rule_ptr);
	this->mutex->unlock(this->mutex);

	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: failed to send message", __FUNCTION__);
		return status;
	}

	DBG2(DBG_KNL, "%s: message sent cmd: %u", __FUNCTION__, cmd);

	/* See if there is an error. */
	if (!this->err_sem->timed_wait(this->err_sem, CRYPTO_DEFAULT_ERR_TIMEOUT))
	{
		DBG2(DBG_KNL, "%s: Error message received.", __FUNCTION__);
		return FAILED;
	}

	return status;
}

/**
 * Callback function invoked when error is received from socket.
 */
CALLBACK(crypto_err, void, private_fsm_netlink_crypto_t *this, void *msg)
{
	struct nlmsgerr *nlerr = (struct nlmsgerr *)msg;
	DBG2(DBG_KNL, "Entering %s in fsm_netlink_crypto", __FUNCTION__);

	if (!msg || !this)
	{
		DBG2(DBG_KNL, "%s: invalid input", __FUNCTION__);
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

/**
 * Callback function invoked when ACK is received from socket.
 */
CALLBACK(crypto_ack, void, private_fsm_netlink_crypto_t *this, void *msg)
{
	DBG2(DBG_KNL, "Entering %s in fsm_netlink_crypto", __FUNCTION__);
}

/**
 * Callback function invoked when response is received from socket.
 */
CALLBACK(crypto_resp, void, private_fsm_netlink_crypto_t *this,
	struct nss_nlcmn *cm, void *data)
{

	struct nss_nlcrypto_rule *rule_ptr;
	struct nss_nlcrypto_info_session *info_ptr;
	uint8_t cmd;
	size_t info_len = sizeof(struct nss_nlcrypto_info_session);

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_crypto", __FUNCTION__);

	if (!data || !cm || !this)
	{
		DBG2(DBG_KNL, "%s: invalid input", __FUNCTION__);
		return;
	}

	rule_ptr = (struct nss_nlcrypto_rule *)data;
	info_ptr = &rule_ptr->msg.info;

	/* handle diffent types of responses */
	cmd =  nss_nlcmn_get_cmd(cm);
	switch (cmd)
	{
		case NSS_NLCRYPTO_CMD_INFO_SESSION:
			DBG2(DBG_KNL,
				"%s: cmd %u: idx %u cipher alg %u len %u auth alg %u len %u",
				__FUNCTION__, cmd, info_ptr->session_idx, info_ptr->cipher.algo,
				info_ptr->cipher.key_len, info_ptr->auth.algo,
				info_ptr->auth.key_len);

			this->mutex->lock(this->mutex);
			memcpy(&this->last_update_info, info_ptr, info_len);
			this->last_sess_idx = info_ptr->session_idx;
			this->mutex->unlock(this->mutex);

			this->sem->post(this->sem);
			break;

		default:
			DBG2(DBG_KNL, "%s: Unexpected response for cmd %u",
				__FUNCTION__, cmd);
			break;
	}
}

METHOD(fsm_netlink_crypto_t, del_session, status_t,
	private_fsm_netlink_crypto_t *this, u_int32_t sess_idx)
{
	struct nss_nlcrypto_rule rule = { { 0 } };
	status_t status = SUCCESS;

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_crypto", __FUNCTION__);

	if (!this)
	{
		return INVALID_ARG;
	}

	/* Copy the session info to the rule */
	rule.msg.destroy.session_idx = sess_idx;

	status = crypto_send_msg(this, &rule, NSS_NLCRYPTO_CMD_DESTROY_SESSION);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: failed to send message", __FUNCTION__);
		return status;
	}

	return status;
}

METHOD(fsm_netlink_crypto_t, add_session, status_t,
	private_fsm_netlink_crypto_t *this, u_int16_t enc_alg, chunk_t enc_key,
	u_int16_t int_alg, chunk_t int_key, bool nat, bool decap,
	u_int32_t *sess_idx_ptr)
{
	struct nss_nlcrypto_rule rule = { { 0 } };
	struct nss_nlcrypto_create_session *crypto_create = &rule.msg.create;
	struct nss_nlcrypto_update_session *crypto_update = &rule.msg.update;
	status_t status = SUCCESS;
	bool found = FALSE;
	algorithm_t *cipher_alg = NULL;
	algorithm_t *auth_alg = NULL;

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_crypto", __FUNCTION__);

	/* Sanity checks */
	if (!this || !sess_idx_ptr)
	{
		DBG2(DBG_KNL, "%s: Invalid arguments", __FUNCTION__);
		return INVALID_ARG;
	}

	/* Validate the encryption algorithm */
	found = crypto_alg_lookup(ENCRYPTION_ALGORITHM, enc_alg, &cipher_alg);
	if (!found || !cipher_alg)
	{
		DBG2(DBG_KNL, "%s: encryption algorithm %N not supported",
			__FUNCTION__, encryption_algorithm_names, enc_alg);
		return FAILED;
	}
	crypto_create->cipher.algo = cipher_alg->nss;

	/* Validate the integrity algorithm */
	found = crypto_alg_lookup(INTEGRITY_ALGORITHM, int_alg, &auth_alg);
	if (!found || !auth_alg)
	{
		DBG2(DBG_KNL, "%s: integrity algorithm %N not supported", __FUNCTION__,
			integrity_algorithm_names, int_alg);
		return FAILED;
	}
	crypto_create->auth.algo = auth_alg->nss;

	/* Validate key lengths */
	if (enc_key.len > NSS_NLCRYPTO_MAX_KEYLEN ||
		int_key.len > NSS_NLCRYPTO_MAX_KEYLEN)
	{
		DBG2(DBG_KNL, "%s: Invalid key length(s)", __FUNCTION__);
		return FAILED;
	}

	/* Set the keys only if not using NULL encryption */
	if ((enc_key.len != 0) && (enc_key.ptr != NULL))
	{
		crypto_create->cipher.key_len = enc_key.len;
		memcpy(&crypto_create->cipher_key[0], enc_key.ptr, enc_key.len);
	}

	if ((int_key.len != 0) && (int_key.ptr != NULL))
	{
		crypto_create->auth.key_len = int_key.len;
		memcpy(&crypto_create->auth_key[0], int_key.ptr, int_key.len);
	}

	DBG2(DBG_KNL, "%s: crypto cipher %N len %u auth %N len %u", __FUNCTION__,
		encryption_algorithm_names, enc_alg, enc_key.len,
		integrity_algorithm_names, int_alg, int_key.len);

	/* Send the message */
	status = crypto_send_msg(this, &rule, NSS_NLCRYPTO_CMD_CREATE_SESSION);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: failed to send message", __FUNCTION__);
		return status;
	}

	/* Wait for response. */
	if (!this->sem->timed_wait(this->sem, CRYPTO_DEFAULT_TIMEOUT))
	{
		this->mutex->lock(this->mutex);
		*sess_idx_ptr = this->last_sess_idx;
		this->mutex->unlock(this->mutex);
	} else
	{
		DBG2(DBG_KNL, "%s: Timed out waiting for response", __FUNCTION__);
		return FAILED;
	}

	memset(&rule, 0, sizeof(rule));
	crypto_update->session_idx = *sess_idx_ptr;

	if (nat)
	{
		/* Set the correct auth/cipher skip values for NAT_T */
		crypto_update->param.auth_skip = (decap) ? auth_alg->nat_decap_skip :
			auth_alg->nat_encap_skip;
		crypto_update->param.cipher_skip =
			(decap) ? cipher_alg->nat_decap_skip : cipher_alg->nat_encap_skip;
	}
	else
	{
		crypto_update->param.auth_skip = (decap) ? auth_alg->decap_skip :
			auth_alg->encap_skip;
		crypto_update->param.cipher_skip = (decap) ? cipher_alg->decap_skip :
			cipher_alg->encap_skip;
	}

	crypto_update->param.req_type = (uint16_t)NSS_CRYPTO_REQ_TYPE_AUTH;
	crypto_update->param.req_type |=
		(decap) ? (uint16_t)NSS_CRYPTO_REQ_TYPE_DECRYPT
		: (uint16_t)NSS_CRYPTO_REQ_TYPE_ENCRYPT;

	DBG2(DBG_KNL, "%s: update crypto %u auth skip %u cipher skip %u req %u",
		__FUNCTION__, crypto_update->session_idx,
		crypto_update->param.auth_skip, crypto_update->param.cipher_skip,
		crypto_update->param.req_type);

	status = crypto_send_msg(this, &rule, NSS_NLCRYPTO_CMD_UPDATE_SESSION);
	if (status != SUCCESS)
	{
		DBG2(DBG_KNL, "%s: failed to send message", __FUNCTION__);
		del_session(this, *sess_idx_ptr);
		return status;
	}

	return status;
}

METHOD(fsm_netlink_crypto_t, destroy, void, private_fsm_netlink_crypto_t *this)
{
	DBG2(DBG_KNL, "Entering %s in fsm_netlink_crypto", __FUNCTION__);

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
	DESTROY_IF(this->sem);
	DESTROY_IF(this->err_sem);
	free(this);
}

/*
 * Described in header.
 */
fsm_netlink_crypto_t *fsm_netlink_crypto_create(void)
{
	private_fsm_netlink_crypto_t *this;

	DBG2(DBG_KNL, "Entering %s in fsm_netlink_crypto", __FUNCTION__);

	INIT(this,
		.public =
		{
			.add_session = _add_session,
			.del_session = _del_session,
			.destroy = _destroy,
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
		.sem = semaphore_create(0),
		.err_sem = semaphore_create(0),
		);

	this->nl_sock = fsm_netlink_sock_create(NSS_NLCRYPTO_FAMILY,
		crypto_resp, crypto_ack, crypto_err, (void *)this);

	if (this->nl_sock == NULL)
	{
		goto exitout;
	}

	/* Spawn thread to listen to mcast socket */
	this->thread = thread_create((thread_main_t)crypto_receiver, this);
	if (this->thread == NULL)
	{
		goto exitout;
	}

	return &this->public;

exitout:
	destroy(this);
	return NULL;
}
