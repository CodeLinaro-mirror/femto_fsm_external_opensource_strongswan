/*
 * Copyright (c) 2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2013 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
 *
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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

#include "fsm_aead.h"

#include <utils/debug.h>
#include "qsecure_ike_sa_api.h"

typedef struct private_fsm_aead_t private_fsm_aead_t;
typedef struct encr_alg_t encr_alg_t;
typedef struct int_alg_t int_alg_t;

/**
 * Private data of an fsm_aead_t object.
 */
struct private_fsm_aead_t
{

	/**
	 * Public fsm_aead_t interface.
	 */
	fsm_aead_t public;

	/**
	 * IKE SA id
	 */
	uint8_t ike_sa_id;

	/**
	 * IV generator
	 */
	iv_gen_t *iv_gen;

	/**
	 * initiator
	 */
	bool initiator;

	/**
	 * Encryption algorithm
	 */
	enc_alg_t enc_alg;

	/**
	 * Encryption algorithm size
	 */
	uint8_t enc_size;

	/**
	 * Integrity algorithm
	 */
	integ_alg_t int_alg;

	/**
	 * Size of the truncated signature
	 */
	size_t enc_block_size;

	/**
	 * Size of the keymat
	 */
	size_t keymat_size;

	/**
	 * Size of initialization vector
	 */
	size_t iv_size;

	/**
	 * Size of the truncated signature
	 */
	size_t int_block_size;

	/**
	 * Default integrity key size
	 */
	size_t int_key_size;
};


struct encr_alg_t
{
	encryption_algorithm_t id;
	size_t block_size;
	/* key size of the algorithm */
	size_t key_size;
	/* size of the keying material */
	size_t keymat_size;
	size_t iv_size;
};

static encr_alg_t enc_algs[] =
{
	{ ENCR_3DES, 8, 24, 24, 8 },
	{ ENCR_AES_CBC, 16, 16, 16, 16 },
	{ ENCR_AES_CBC, 16, 24, 24, 16 },
	{ ENCR_AES_CBC, 16, 32, 32, 16 },
	{ ENCR_AES_CTR, 1, 16, 20, 8 },
	{ ENCR_AES_CTR, 1, 24, 28, 8 },
	{ ENCR_AES_CTR, 1, 32, 36, 8 },
};

struct int_alg_t
{
	integrity_algorithm_t id;
	size_t block_size;
	size_t key_size;
};

static int_alg_t int_algs[] =
{
	{ AUTH_HMAC_SHA1_96, 12, 20 },
	{ AUTH_HMAC_SHA2_256_128, 16, 32 },
};


static size_t lookup_enc_alg(encryption_algorithm_t algo, size_t key_size,
	size_t *keymat_size, size_t *iv_size)
{
	size_t i;

	for (i = 0; i < countof(enc_algs); i++)
	{
		if (enc_algs[i].id == algo &&
			(key_size == 0 || enc_algs[i].key_size == key_size))
		{
			*keymat_size = enc_algs[i].keymat_size;
			*iv_size = enc_algs[i].iv_size;
			return enc_algs[i].block_size;
		}
	}
	return 0;
}

static size_t lookup_int_alg(integrity_algorithm_t algo, size_t *key_size)
{
	size_t i;

	for (i = 0; i < countof(int_algs); i++)
	{
		if (int_algs[i].id == algo)
		{
			*key_size = int_algs[i].key_size;
			return int_algs[i].block_size;
		}
	}
	return 0;
}

METHOD(aead_t, encrypt, bool, private_fsm_aead_t *this, chunk_t plain,
	chunk_t assoc, chunk_t iv, chunk_t *encrypted)
{
	int32_t result = 0;
	ike_sa_enc_payload_req_t req;
	ike_sa_enc_payload_rsp_t rsp;

	DBG2(DBG_IKE, "Entering %s in fsm_aead", __FUNCTION__);

	if (!this || !plain.ptr || !plain.len || !assoc.ptr || !assoc.len ||
		!iv.ptr || !iv.len)
	{
		DBG1(DBG_IKE, "%s: Error: Invalid Arguments!", __FUNCTION__);
		return FALSE;
	}

	/* No garbage */
	memset(&req, 0, sizeof(req));
	memset(&rsp, 0, sizeof(rsp));

	req.ike_sa_id = this->ike_sa_id;
	req.enc_alg = this->enc_alg;
	req.enc_alg_key_sz = this->enc_size;
	req.integ_alg = this->int_alg;
	req.payload_size = (uint32_t)plain.len;
	req.assoc_data_size = (uint32_t)assoc.len;

	/* Copy plain to payload */
	if (plain.len <= MAX_PAYLOAD_SZ)
	{
		memcpy(&req.payload[0], plain.ptr, plain.len);
	}
	else
	{
		DBG1(DBG_IKE, "%s: Error: Payload of size %u larger than max %u",
			 __FUNCTION__, plain.len, MAX_PAYLOAD_SZ);
		return FALSE;
	}

	/* Copy associated data */
	if (assoc.len <= MAX_ASSOC_DATA_SZ)
	{
		memcpy(&req.assoc_data[0], assoc.ptr, assoc.len);
	}
	else
	{
		DBG1(DBG_IKE, "%s: Error: Associated data of size %u larger than max %u",
			 __FUNCTION__, assoc.len, MAX_ASSOC_DATA_SZ);
		return FALSE;
	}

	DBG3(DBG_ENC, "%s: ike_sa_enc_payload req %b", __FUNCTION__, &req,
		sizeof(req));
	result = ike_sa_enc_payload(&req, &rsp);
	DBG3(DBG_ENC, "%s: ike_sa_enc_payload rsp %b", __FUNCTION__, &rsp,
		sizeof(rsp));
	if ((result != 0) || (rsp.result != 0))
	{
		DBG1(DBG_IKE, "%s: ike_sa_enc_payload failed with error: %d!",
			__FUNCTION__, rsp.result);
		return FALSE;
	}

	if (rsp.enc_payload_size == 0)
	{
		DBG1(DBG_IKE, "%s: Error: payload size is 0!", __FUNCTION__);
		return FALSE;
	}

	if (iv.len >= rsp.enc_payload_size)
	{
		DBG1(DBG_IKE, "%s: Error: IV length %u longer than payload size %u!",
			__FUNCTION__, iv.len, rsp.enc_payload_size);
		return FALSE;
	}

	/* The response includes the IV plus the encrypted payload */
	memcpy(iv.ptr, &rsp.enc_payload[0], iv.len);
	DBG3(DBG_ENC, "%s: IV %B", __FUNCTION__, &iv);

	if (encrypted)
	{
		*encrypted = chunk_alloc(rsp.enc_payload_size);
		if (encrypted->ptr)
		{
			memcpy(encrypted->ptr, &rsp.enc_payload[iv.len],
				rsp.enc_payload_size - iv.len);

			DBG3(DBG_ENC, "%s: encrypted %B", __FUNCTION__, encrypted);
		}
		else
		{
			DBG1(DBG_IKE, "%s: Error: Failed to allocate memory for payload!",
				__FUNCTION__);
			return FALSE;
		}
	}
	else
	{
		memcpy(plain.ptr, &rsp.enc_payload[iv.len],
			rsp.enc_payload_size - iv.len);
		DBG3(DBG_ENC, "%s: encrypted %B", __FUNCTION__, &plain);
	}

	return TRUE;
}

METHOD(aead_t, decrypt, bool, private_fsm_aead_t *this, chunk_t encrypted,
	chunk_t assoc, chunk_t iv, chunk_t *plain)
{
	int32_t result = 0;
	ike_sa_dec_payload_req_t req;
	ike_sa_dec_payload_rsp_t rsp;

	DBG2(DBG_IKE, "Entering %s in fsm_aead", __FUNCTION__);

	if (!this || !encrypted.ptr || !encrypted.len || !assoc.ptr || !assoc.len ||
		!iv.ptr || !iv.len)
	{
		DBG1(DBG_IKE, "%s: Error: Invalid Arguments!", __FUNCTION__);
		return FALSE;
	}

	/* No garbage */
	memset(&req, 0, sizeof(req));
	memset(&rsp, 0, sizeof(rsp));

	req.ike_sa_id = this->ike_sa_id;
	req.enc_alg = this->enc_alg;
	req.enc_alg_key_sz = this->enc_size;
	req.integ_alg = this->int_alg;
	req.enc_payload_size = (uint32_t)(encrypted.len + iv.len);
	req.assoc_data_size = (uint32_t)assoc.len;

	/* Copy encrypted data to payload */
	if (encrypted.len + iv.len <= MAX_ENC_PAYLOAD_SZ)
	{
		memcpy(&req.enc_payload[0], iv.ptr, iv.len);
		memcpy(&req.enc_payload[iv.len], encrypted.ptr, encrypted.len);
		DBG3(DBG_ENC, "%s: enc_payload %b", __FUNCTION__, &req.enc_payload[0],
			req.enc_payload_size);
	}
	else
	{
		DBG1(DBG_IKE, "%s: Error: Payload of size %u larger than max %u",
			__FUNCTION__, encrypted.len + iv.len, MAX_ENC_PAYLOAD_SZ);
		return FALSE;
	}

	/* Copy associated data */
	if (assoc.len <= MAX_ASSOC_DATA_SZ)
	{
		memcpy(&req.assoc_data[0], assoc.ptr, assoc.len);
	}
	else
	{
		DBG1(DBG_IKE,
			"%s: Error: Associated data of size %u larger than max %u",
			__FUNCTION__, assoc.len, MAX_ASSOC_DATA_SZ);
		return FALSE;
	}

	DBG3(DBG_ENC, "%s: ike_sa_dec_payload req %b", __FUNCTION__, &req,
		sizeof(req));
	result = ike_sa_dec_payload(&req, &rsp);
	DBG3(DBG_ENC, "%s: ike_sa_dec_payload rsp %b", __FUNCTION__, &rsp,
		sizeof(rsp));
	if ((result != 0) || (rsp.result != 0))
	{
		DBG1(DBG_IKE, "%s: ike_sa_dec_payload failed with error: %d!",
			__FUNCTION__, rsp.result);
		return FALSE;
	}

	if (rsp.payload_size == 0)
	{
		DBG1(DBG_IKE, "%s: Error: payload size is 0!", __FUNCTION__);
		return FALSE;
	}

	if (plain)
	{
		*plain = chunk_alloc(rsp.payload_size);
		if (plain->ptr)
		{
			memcpy(plain->ptr, &rsp.payload[0], rsp.payload_size);
		}
		else
		{
			DBG1(DBG_IKE, "%s: Error: Failed to allocate memory for payload!",
				__FUNCTION__);
			return FALSE;
		}
	}
	else
	{
		memcpy(encrypted.ptr, &rsp.payload[0], rsp.payload_size);
	}

	return TRUE;
}

METHOD(aead_t, get_block_size, size_t, private_fsm_aead_t *this)
{
	DBG2(DBG_IKE, "Entering %s in fsm_aead", __FUNCTION__);

	if (this)
	{
		DBG2(DBG_IKE, "%s: %u", __FUNCTION__, this->enc_block_size);
		return this->enc_block_size;
	}

	return 0;
}

METHOD(aead_t, get_icv_size, size_t, private_fsm_aead_t *this)
{
	DBG2(DBG_IKE, "Entering %s in fsm_aead", __FUNCTION__);

	if (this)
	{
		DBG2(DBG_IKE, "%s: %u", __FUNCTION__, this->int_block_size);
		return this->int_block_size;
	}

	return 0;
}

METHOD(aead_t, get_iv_size, size_t, private_fsm_aead_t *this)
{
	DBG2(DBG_IKE, "Entering %s in fsm_aead", __FUNCTION__);

	if (this)
	{
		DBG2(DBG_IKE, "%s: %u", __FUNCTION__, this->iv_size);
		return this->iv_size;
	}

	return 0;
}

METHOD(aead_t, get_iv_gen, iv_gen_t *, private_fsm_aead_t *this)
{
	DBG2(DBG_IKE, "Entering %s in fsm_aead", __FUNCTION__);

	/* The IV is generated securely, so this is just for compatibility. */
	if (this)
	{
		return this->iv_gen;
	}

	return NULL;
}

METHOD(aead_t, get_key_size, size_t, private_fsm_aead_t *this)
{
	DBG2(DBG_IKE, "Entering %s in fsm_aead", __FUNCTION__);

	if (this)
	{
		DBG2(DBG_IKE, "%s: %u", __FUNCTION__,
			(this->keymat_size + this->int_key_size));

		return this->keymat_size + this->int_key_size;
	}

	return 0;
}

METHOD(aead_t, set_key, bool, private_fsm_aead_t *this, chunk_t key)
{
	DBG2(DBG_IKE, "Entering %s in fsm_aead, not supported", __FUNCTION__);

	/* This is to avoid compiler warnings about unused parameters */
	(void)this;
	(void)key;

	/* Not supported */
	return FALSE;
}

METHOD(aead_t, destroy, void, private_fsm_aead_t *this)
{
	DBG2(DBG_IKE, "Entering %s in fsm_aead", __FUNCTION__);

	if (this)
	{
		DESTROY_IF(this->iv_gen);
		free(this);
	}
}

/**
 * See header
 */
fsm_aead_t *fsm_aead_create(uint8_t ike_sa_id, encryption_algorithm_t enc_alg,
	size_t enc_size, integrity_algorithm_t int_alg, bool initiator)
{
	private_fsm_aead_t *this = NULL;
	size_t enc_block_size = 0;
	size_t keymat_size = 0;
	size_t iv_size = 0;
	size_t int_block_size = 0;
	size_t int_key_size = 0;

	DBG2(DBG_IKE, "Entering %s in fsm_aead, IKE SA id %u", __FUNCTION__,
		 ike_sa_id);

	/* Ensure algorithms are supported */
	enc_block_size = lookup_enc_alg(enc_alg, enc_size, &keymat_size, &iv_size);
	if (!enc_block_size)
	{
		DBG1(DBG_IKE, "%s: Error: Encryption algorithm %N not supported",
			__FUNCTION__, encryption_algorithm_names, enc_alg);
		return NULL;
	}

	int_block_size = lookup_int_alg(int_alg, &int_key_size);
	if (!int_block_size)
	{
		DBG1(DBG_IKE, "%s: Error: Integrity algorithm %N not supported",
			__FUNCTION__, integrity_algorithm_names, int_alg);
		return NULL;
	}

	INIT(this,
		.public =
		{
			.aead =
			{
				.encrypt = _encrypt,
				.decrypt = _decrypt,
				.get_block_size = _get_block_size,
				.get_icv_size = _get_icv_size,
				.get_iv_size = _get_iv_size,
				.get_iv_gen = _get_iv_gen,
				.get_key_size = _get_key_size,
				.set_key = _set_key,
				.destroy = _destroy,
			}
		},
		.iv_gen = NULL,
		.ike_sa_id = ike_sa_id,
		.initiator = initiator,
		.enc_alg = enc_alg,
		.enc_size = enc_size,
		.enc_block_size = enc_block_size,
		.keymat_size = keymat_size,
		.iv_size = iv_size,
		.int_alg = int_alg,
		.int_block_size = int_block_size,
		.int_key_size = int_key_size,
		);

	if (!this)
	{
		DBG1(DBG_IKE, "%s: Error: Failed to allocate memory!", __FUNCTION__);
		return NULL;
	}

	/* The IV is generated securely, so this is just for compatibility. */
	this->iv_gen = iv_gen_create_for_alg(enc_alg);
	if (!this->iv_gen)
	{
		DBG1(DBG_IKE, "%s: Error: Failed to create iv gen!", __FUNCTION__);
		this->public.aead.destroy(&this->public.aead);
		return NULL;
	}

	return (fsm_aead_t *)this;
}
