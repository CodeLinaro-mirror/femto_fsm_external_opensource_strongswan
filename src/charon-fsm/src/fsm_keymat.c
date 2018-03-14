/*
 * Copyright (c) 2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2015 Tobias Brunner
 * Copyrigth (C) 2012 Reto Buerki
 * Copyright (C) 2012 Adrian-Ken Rueegsegger
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

#include <daemon.h>
#include <crypto/hashers/hash_algorithm_set.h>
#include <utils/utils.h>
#include <utils/debug.h>
#include <threading/mutex.h>
#include <collections/linked_list.h>

#include "fsm_keymat.h"
#include "fsm_aead.h"
#include "fsm_diffie_hellman.h"
#include "qsecure_ike_sa_api.h"

typedef struct private_fsm_keymat_t private_fsm_keymat_t;
typedef struct child_id_t child_id_t;

/**
 * Private data of a keymat_t object.
 */
struct private_fsm_keymat_t
{
	/**
	 * Public fsm_keymat_t interface.
	 */
	fsm_keymat_t public;

	/**
	 * IKE_SA Role, initiator or responder
	 */
	bool initiator;

	/**
	 * Set of hash algorithms supported by peer for signature authentication
	 */
	hash_algorithm_set_t *hash_algorithms;

	/**
	 * inbound AEAD
	 */
	fsm_aead_t *aead_in;

	/**
	 * outbound AEAD
	 */
	fsm_aead_t *aead_out;

	/**
	 * General purpose PRF
	 */
	prf_t *prf;

	/**
	 * Negotiated PRF algorithm
	 */
	pseudo_random_function_t prf_alg;

	/**
	 * IKE ID valid
	 */
	bool valid;

	/**
	 * IKE ID
	 */
	uint8_t ike_id;

	/**
	 * List of child IDs
	 */
	linked_list_t *child_ids;

	/**
	 * Mutex for list of child IDs
	 */
	mutex_t *child_ids_mutex;
};

struct child_id_t
{
	/**
	 * IPsec SA reference count
	 */
	refcount_t ref;

	/**
	 * child ID
	 */
	uint8_t child_id;
};

static bool match_entry_by_id(child_id_t *child_id, uint8_t *child_sa_id)
{
	if (!child_id || !child_sa_id)
	{
		return FALSE;
	}
	return (child_id->child_id == *child_sa_id);
}

static void delete_ike_sa(private_fsm_keymat_t *this)
{
	DBG2(DBG_IKE, "Entering %s in fsm_keymat", __FUNCTION__);

	if (!this)
	{
		DBG1(DBG_IKE, "%s: Error: this is NULL!", __FUNCTION__);
		return;
	}

	if (this->valid)
	{
		int32_t result = 0;
		ike_sa_del_req_t req;
		ike_sa_del_rsp_t rsp;

		/* No junk */
		memset(&rsp, 0, sizeof(rsp));
		memset(&req, 0, sizeof(req));

		req.ike_sa_id = this->ike_id;

		DBG3(DBG_ENC, "%s: ike_sa_del req %b", __FUNCTION__, &req,
			sizeof(req));
		result = ike_sa_del(&req, &rsp);
		DBG3(DBG_ENC, "%s: ike_sa_del rsp %b", __FUNCTION__, &rsp,
			sizeof(rsp));
		if ((result != 0) || (rsp.result != 0))
		{
			DBG1(DBG_IKE, "%s: ike_sa_del(%u) failed with error: %d",
				__FUNCTION__, req.ike_sa_id, rsp.result);
			return;
		}
		this->valid = FALSE;
	}
}

static bool delete_child_sa(child_id_t *child_id, private_fsm_keymat_t *this,
	bool ignore)
{
	ike_sa_del_child_sa_req_t req;
	ike_sa_del_child_sa_rsp_t rsp;
	int32_t result = 0;

	/* Decrement the refcount */
	if (!ref_put(&child_id->ref) && !ignore)
	{
		/* Exit, since we're not ignoring refcount and it's > 0 */
		return TRUE;
	}

	/* The refcount is zero, remove the child SA id from the list and free */
	this->child_ids->remove(this->child_ids, child_id, NULL);

	/* No junk */
	memset(&req, 0, sizeof(req));
	memset(&rsp, 0, sizeof(rsp));

	req.child_sa_id = child_id->child_id;
	req.ike_sa_id = this->ike_id;

	free(child_id);
	child_id = NULL;

	DBG3(DBG_ENC, "%s: ike_sa_del_child_sa req %b", __FUNCTION__, &req,
		sizeof(req));

	/* Delete from secure world */
	result = ike_sa_del_child_sa(&req, &rsp);
	DBG3(DBG_ENC, "%s: ike_sa_del_child_sa rsp %b", __FUNCTION__, &rsp,
		sizeof(rsp));
	if ((result != 0) || (rsp.result != 0))
	{
		DBG1(DBG_IKE, "%s: ike_sa_del_child_sa(%u-%u) failed with error: %d!",
			__FUNCTION__, req.ike_sa_id, req.child_sa_id, rsp.result);
		return FALSE;
	}

	return TRUE;
}

METHOD(fsm_keymat_t, del_child_sa, bool, private_fsm_keymat_t *this,
	uint8_t child_sa_id)
{
	bool retval = TRUE;
	status_t status = FAILED;
	child_id_t *chd_id = NULL;

	DBG2(DBG_IKE, "Entering %s in fsm_keymat", __FUNCTION__);

	if (!this)
	{
		DBG1(DBG_IKE, "%s: Error: this is NULL!", __FUNCTION__);
		return FALSE;
	}

	/* Search for the child SA id in the list */
	this->child_ids_mutex->lock(this->child_ids_mutex);
	status = this->child_ids->find_first(this->child_ids,
		(linked_list_match_t)match_entry_by_id,
		(void **)&chd_id, &child_sa_id);
	if ((status != SUCCESS) || !chd_id)
	{
		DBG2(DBG_IKE, "%s: Warning: child id %u is not in the list",
			__FUNCTION__, child_sa_id);
		retval = FALSE;
		goto exitfunc;
	}

	retval = delete_child_sa(chd_id, this, FALSE);

exitfunc:
	this->child_ids_mutex->unlock(this->child_ids_mutex);
	return retval;
}

METHOD(keymat_t, get_version, ike_version_t, private_fsm_keymat_t *this)
{
	/* This is to avoid compiler warnings about unused parameters. */
	(void)this;

	return IKEV2;
}

METHOD(keymat_t, create_dh, diffie_hellman_t *, private_fsm_keymat_t *this,
	diffie_hellman_group_t group)
{
	DBG2(DBG_IKE, "Entering %s in fsm_keymat", __FUNCTION__);
	fsm_diffie_hellman_t *fsm_dh;

	/* This is to avoid compiler warnings about unused parameters. */
	(void)this;

	fsm_dh = fsm_diffie_hellman_create(group);

	if (fsm_dh)
	{
		return &fsm_dh->dh;
	}

	return NULL;
}

METHOD(keymat_t, create_nonce_gen, nonce_gen_t *, private_fsm_keymat_t *this)
{
	DBG2(DBG_IKE, "Entering %s in fsm_keymat", __FUNCTION__);

	/* This is to avoid compiler warnings about unused parameters. */
	(void)this;

	return lib->crypto->create_nonce_gen(lib->crypto);
}

static bool set_params(diffie_hellman_t *dh, chunk_t nonce_i, chunk_t nonce_r,
	ike_sa_id_t *id, u_int16_t enc_alg, size_t key_size_bytes,
	u_int16_t int_alg, pseudo_random_function_t prf_alg,
	ike_sa_params_t *params)
{
	fsm_diffie_hellman_t *fsm_dh = (fsm_diffie_hellman_t *)dh;
	chunk_t value = chunk_empty;

	params->dh_type = dh ? dh->get_dh_group(dh) : 0;
	params->enc_alg = (enc_alg_t)enc_alg;
	params->enc_alg_key_sz = (uint8_t)key_size_bytes;
	params->integ_alg = (integ_alg_t)int_alg;

	/* Set prf */
	params->prf = (prf_alg_t)prf_alg;

	/* Validate initiator nonce length */
	if (nonce_i.len > NONCE_BUF_SZ)
	{
		DBG1(DBG_IKE, "%s: Error: initiator nonce size %u invalid!",
			__FUNCTION__, nonce_i.len);
		goto failure;
	}
	memcpy(&params->initiator_nonce[0], nonce_i.ptr, nonce_i.len);

	/* Validate responder nonce length */
	if (nonce_r.len > NONCE_BUF_SZ)
	{
		DBG1(DBG_IKE, "%s: Error: responder nonce size %u invalid!",
			__FUNCTION__, nonce_r.len);
		goto failure;
	}
	memcpy(&params->responder_nonce[0], nonce_r.ptr, nonce_r.len);

	if (id)
	{
		u_int64_t *spi = (u_int64_t *)&params->initiator_spi[0];
		/* Set SPI values */
		*spi = id->get_initiator_spi(id);
		spi = (u_int64_t *)&params->responder_spi[0];
		*spi = id->get_responder_spi(id);
	}

	if (fsm_dh)
	{
		/* Retrieve other public value */
		if (!fsm_dh->get_other_public_value(fsm_dh, &value))
		{
			DBG1(DBG_IKE,
				"%s: Error: failed to retrieve other DH public value!",
				__FUNCTION__);
			goto failure;
		}

		/* Validate other DH public value */
		if (!value.ptr)
		{
			DBG1(DBG_IKE, "%s: Error: invalid other DH public value!",
				__FUNCTION__);
			goto failure;
		}

		/* Validate length */
		if ((value.len > DH_BUF_SZ) || !value.len)
		{
			DBG1(DBG_IKE, "%s: Error: invalid other DH public value length %u!",
				__FUNCTION__, value.len);
			goto failure;
		}

		/* Set the responder public key and length */
		params->responder_pub_key.dh_key_len = (uint32_t)value.len;
		memcpy(&params->responder_pub_key.dh_key, value.ptr, value.len);

		chunk_free(&value);
	}

	return TRUE;

failure:
	if (value.ptr)
	{
		chunk_free(&value);
	}

	return FALSE;
}

METHOD(keymat_v2_t, derive_ike_keys, bool, private_fsm_keymat_t *this,
	proposal_t *proposal, diffie_hellman_t *dh, chunk_t nonce_i,
	chunk_t nonce_r, ike_sa_id_t *id, pseudo_random_function_t rekey_function,
	chunk_t rekey_skd)
{
	u_int16_t enc_alg = 0;
	size_t key_size = 0;
	u_int16_t int_alg = 0;
	int32_t result = 0;
	size_t key_size_bytes = 0;
	fsm_diffie_hellman_t *fsm_dh = NULL;
	u_int32_t dh_key_id = 0;
	u_int16_t alg = 0;

	/* This is to avoid compiler warnings about unused parameters. */
	(void)rekey_skd;

	DBG2(DBG_IKE, "Entering %s in fsm_keymat", __FUNCTION__);

	if (!this || !proposal || !dh || !id || !nonce_i.ptr || !nonce_i.len ||
		!nonce_r.ptr || !nonce_r.len)
	{
		DBG1(DBG_IKE, "%s: Error: Invalid arguments", __FUNCTION__);
		return FALSE;
	}

	/* Create SAs general purpose PRF first, we may use it here */
	if (!proposal->get_algorithm(proposal, PSEUDO_RANDOM_FUNCTION, &alg, NULL))
	{
		DBG1(DBG_IKE, "%s: Error: no %N selected", __FUNCTION__,
			 transform_type_names, PSEUDO_RANDOM_FUNCTION);
		return FALSE;
	}

	/* Validate PRF alg */
	this->prf_alg = (pseudo_random_function_t)alg;

	if (this->prf_alg != PRF_HMAC_SHA1 && this->prf_alg != PRF_HMAC_SHA2_256)
	{
		DBG1(DBG_IKE, "%s: Error: %N %N not supported!", __FUNCTION__,
			 transform_type_names, PSEUDO_RANDOM_FUNCTION,
			 pseudo_random_function_names, alg);
		return FALSE;
	}

	this->prf = lib->crypto->create_prf(lib->crypto, this->prf_alg);
	if (this->prf == NULL)
	{
		DBG1(DBG_IKE, "%s: Error: %N %N not supported!", __FUNCTION__,
			 transform_type_names, PSEUDO_RANDOM_FUNCTION,
			 pseudo_random_function_names, alg);
		return FALSE;
	}

	/* Retrieve encryption algorithm and key size */
	if (!proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM, &enc_alg,
		(u_int16_t *)&key_size))
	{
		DBG1(DBG_IKE, "%s: Error: no %N selected", __FUNCTION__,
			transform_type_names, ENCRYPTION_ALGORITHM);
		return FALSE;
	}

	/* Retrieve integrity algorithm */
	if (!proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM, &int_alg, NULL))
	{
		DBG1(DBG_IKE, "%s: Error: no %N selected", __FUNCTION__,
			transform_type_names, INTEGRITY_ALGORITHM);
		return FALSE;
	}

	key_size_bytes = key_size / 8;

	fsm_dh = (fsm_diffie_hellman_t *)dh;

	if (!fsm_dh->get_unique_id(fsm_dh, &dh_key_id))
	{
		DBG1(DBG_IKE, "%s: Error: failed to retrieve DH unique ID!",
			__FUNCTION__);
		return FALSE;
	}

	if (rekey_function != PRF_UNDEFINED)
	{
		ike_sa_re_key_req_t req;
		ike_sa_re_key_rsp_t rsp;

		/* No junk */
		memset(&req, 0, sizeof(req));
		memset(&rsp, 0, sizeof(rsp));

		/* Initialize rekey parameters */
		req.dh_key_id = dh_key_id;
		req.ike_sa_id = this->ike_id;
		req.old_prf = (prf_alg_t)rekey_function;

		if (!set_params(dh, nonce_i, nonce_r, id, enc_alg, key_size_bytes,
			int_alg, this->prf_alg, &req.new_params))
		{
			DBG1(DBG_IKE, "%s: Error: failed to initialize params!",
				__FUNCTION__);
			return FALSE;
		}

		DBG3(DBG_ENC, "%s: ike_sa_rekey req %b", __FUNCTION__, &req,
			sizeof(req));
		/* Initiate IKE SA rekey */
		result = ike_sa_re_key(&req, &rsp);
		DBG3(DBG_ENC, "%s: ike_sa_rekey rsp %b", __FUNCTION__, &rsp,
			sizeof(rsp));
		if ((result != 0) || (rsp.result != 0))
		{
			DBG1(DBG_IKE, "%s: ike_sa_rekey failed with error: %d!",
				__FUNCTION__, rsp.result);
			return FALSE;
		}
	}
	else
	{
		ike_sa_init_req_t req;
		ike_sa_init_rsp_t rsp;

		/* No junk */
		memset(&req, 0, sizeof(req));
		memset(&rsp, 0, sizeof(rsp));

		/* Initialize parameters */
		req.dh_key_id = dh_key_id;

		if (!set_params(dh, nonce_i, nonce_r, id, enc_alg, key_size_bytes,
			int_alg, this->prf_alg, &req.init_params))
		{
			DBG1(DBG_IKE, "%s: Error: failed to initialize params!",
				__FUNCTION__);
			return FALSE;
		}

		DBG3(DBG_ENC, "%s: ike_sa_init req %b", __FUNCTION__, &req,
			sizeof(req));
		/* Initialize new IKE SA */
		result = ike_sa_init(&req, &rsp);
		DBG3(DBG_ENC, "%s: ike_sa_init rsp %b", __FUNCTION__, &rsp,
			sizeof(rsp));
		if ((result != 0) || (rsp.result != 0))
		{
			DBG1(DBG_IKE, "%s: ike_sa_init failed with error: %d!",
				__FUNCTION__, rsp.result);
			return FALSE;
		}

		/* Save the ID */
		this->valid = TRUE;
		this->ike_id = rsp.ike_sa_id;
		DBG2(DBG_IKE, "%s: ike_sa_init created IKE SA ID %u!", __FUNCTION__,
			rsp.ike_sa_id);
	}

	this->aead_out = fsm_aead_create(this->ike_id, enc_alg, key_size_bytes,
		int_alg, TRUE);
	if (!this->aead_out)
	{
		DBG1(DBG_IKE, "%s: Error: fsm_aead_create failed for aead_out!",
			__FUNCTION__);
		return FALSE;
	}

	this->aead_in = fsm_aead_create(this->ike_id, enc_alg, key_size_bytes,
		int_alg, FALSE);
	if (!this->aead_in)
	{
		DBG1(DBG_IKE, "%s: Error: fsm_aead_create failed for aead_in!",
			__FUNCTION__);
		return FALSE;
	}

	return TRUE;
}

METHOD(keymat_v2_t, derive_child_keys, bool, private_fsm_keymat_t *this,
	proposal_t *proposal, diffie_hellman_t *dh, chunk_t nonce_i,
	chunk_t nonce_r, chunk_t *encr_i, chunk_t *integ_i, chunk_t *encr_r,
	chunk_t *integ_r)
{
	fsm_diffie_hellman_t *fsm_dh = (fsm_diffie_hellman_t *)dh;
	fsm_keymat_key_t *encr_key_i = NULL;
	fsm_keymat_key_t *integ_key_i = NULL;
	fsm_keymat_key_t *encr_key_r = NULL;
	fsm_keymat_key_t *integ_key_r = NULL;
	u_int16_t enc_alg = 0;
	u_int16_t int_alg = 0;
	u_int16_t enc_size = 0;
	u_int16_t int_size = 0;
	ike_sa_new_child_sa_req_t req;
	ike_sa_new_child_sa_rsp_t rsp;
	int32_t result = 0;
	child_id_t *child_id = NULL;

	DBG2(DBG_CHD, "Entering %s in fsm_keymat", __FUNCTION__);

	if (!this || !proposal || !nonce_i.ptr || !nonce_i.len ||
		!nonce_r.ptr || !nonce_r.len || !encr_i || !integ_i || !encr_r ||
		!integ_r)
	{
		DBG1(DBG_CHD, "%s: Error: Invalid arguments", __FUNCTION__);
		goto failure;
	}

	if (proposal->get_algorithm(proposal, ENCRYPTION_ALGORITHM, &enc_alg,
		&enc_size))
	{
		DBG2(DBG_CHD, "%s: using %N for encryption", __FUNCTION__,
			encryption_algorithm_names, enc_alg);

		if (!enc_size)
		{
			enc_size = keymat_get_keylen_encr(enc_alg);
		}

		if (enc_alg != ENCR_NULL && !enc_size)
		{
			DBG1(DBG_CHD, "%s:Error: no keylength defined for %N", __FUNCTION__,
				encryption_algorithm_names, enc_alg);
			return FALSE;
		}

		/* to bytes */
		enc_size /= 8;

		/* CCM/GCM/CTR/GMAC needs additional bytes */
		switch (enc_alg)
		{
			case ENCR_AES_CCM_ICV8:
			case ENCR_AES_CCM_ICV12:
			case ENCR_AES_CCM_ICV16:
			case ENCR_CAMELLIA_CCM_ICV8:
			case ENCR_CAMELLIA_CCM_ICV12:
			case ENCR_CAMELLIA_CCM_ICV16:
				enc_size += 3;
				break;
			case ENCR_AES_GCM_ICV8:
			case ENCR_AES_GCM_ICV12:
			case ENCR_AES_GCM_ICV16:
			case ENCR_AES_CTR:
			case ENCR_CAMELLIA_CTR:
			case ENCR_NULL_AUTH_AES_GMAC:
			case ENCR_CHACHA20_POLY1305:
				enc_size += 4;
				break;
			default:
				break;
		}
	}

	if (proposal->get_algorithm(proposal, INTEGRITY_ALGORITHM, &int_alg,
		&int_size))
	{
		DBG2(DBG_CHD, "%s: using %N for integrity", __FUNCTION__,
			integrity_algorithm_names, int_alg);

		if (!int_size)
		{
			int_size = keymat_get_keylen_integ(int_alg);
		}
		if (!int_size)
		{
			DBG1(DBG_CHD, "%s: Error: no keylength defined for %N",
				__FUNCTION__, integrity_algorithm_names, int_alg);
			return FALSE;
		}
		/* to bytes */
		int_size /= 8;
	}

	/* No junk */
	memset(&req, 0, sizeof(req));
	memset(&rsp, 0, sizeof(rsp));

	if (dh)
	{
		req.dh_param = DH_PARAM_NEW;

		/* Retrieve DH unique ID */
		if (!fsm_dh->get_unique_id(fsm_dh, &req.dh_key_id))
		{
			DBG1(DBG_CHD, "%s: Error: failed to retrive DH unique id!",
				__FUNCTION__);
			goto failure;
		}
	}
	else
	{
		req.dh_param = DH_PARAM_NO_CHANGE;
	}

	req.ike_sa_id = this->ike_id;
	if (!set_params(dh, nonce_i, nonce_r, NULL, enc_alg, enc_size, int_alg,
		this->prf_alg, &req.params))
	{
		DBG1(DBG_CHD, "%s: Error: failed to set params!", __FUNCTION__);
		goto failure;
	}

	/* Add a new child id to the list */
	INIT(child_id,
		 .ref = 1,
		 .child_id = 0,
		);

	if (!child_id)
	{
		DBG1(DBG_CHD, "%s: Error: failed to allocate child ID!", __FUNCTION__);
		goto failure;
	}

	/* Add to the linked list */
	this->child_ids_mutex->lock(this->child_ids_mutex);
	this->child_ids->insert_last(this->child_ids, child_id);

	DBG3(DBG_ENC, "%s: ike_sa_init_child_sa req %b", __FUNCTION__, &req,
		sizeof(req));
	result = ike_sa_init_child_sa(&req, &rsp);
	DBG3(DBG_ENC, "%s: ike_sa_init_child_sa rsp %b", __FUNCTION__, &rsp,
		sizeof(rsp));
	if ((result != 0) || (rsp.result != 0))
	{
		DBG1(DBG_CHD, "%s: ike_sa_init_child_sa failed with error: %d!",
			__FUNCTION__, rsp.result);
		this->child_ids_mutex->unlock(this->child_ids_mutex);
		goto failure;
	}

	child_id->child_id = rsp.child_sa_id;
	this->child_ids_mutex->unlock(this->child_ids_mutex);

	*encr_i = chunk_alloc(sizeof(fsm_keymat_key_t));
	*encr_r = chunk_alloc(sizeof(fsm_keymat_key_t));
	*integ_i = chunk_alloc(sizeof(fsm_keymat_key_t));
	*integ_r = chunk_alloc(sizeof(fsm_keymat_key_t));

	if (!encr_i->ptr || !encr_i->len || !encr_r->ptr || !encr_r->len ||
		!integ_i->ptr || !integ_i->len || !integ_r->ptr || !integ_r->len)
	{
		DBG1(DBG_CHD, "%s: Error: Failed to allocate memory for keys!",
			__FUNCTION__);
		goto failure;
	}

	encr_key_i = (fsm_keymat_key_t *)encr_i->ptr;
	encr_key_r = (fsm_keymat_key_t *)encr_r->ptr;
	integ_key_i = (fsm_keymat_key_t *)integ_i->ptr;
	integ_key_r = (fsm_keymat_key_t *)integ_r->ptr;

	/* Save encryption and integrity key lengths */
	encr_key_i->len = (size_t)enc_size;
	integ_key_i->len = (size_t)int_size;
	encr_key_r->len = (size_t)enc_size;
	integ_key_r->len = (size_t)int_size;

	/* Save CHILD SA id and offsets */
	encr_key_i->index = rsp.enc_key_imem;
	encr_key_r->index = rsp.integ_key_imem;
	integ_key_i->index = rsp.enc_key_imem;
	integ_key_r->index = rsp.integ_key_imem;

	encr_key_i->child_sa_id = rsp.child_sa_id;
	encr_key_r->child_sa_id = rsp.child_sa_id;
	integ_key_i->child_sa_id = rsp.child_sa_id;
	integ_key_r->child_sa_id = rsp.child_sa_id;

	return TRUE;

failure:
	if (child_id)
	{
		this->public.del_child_sa(&this->public, child_id->child_id);
	}
	return FALSE;
}

METHOD(keymat_t, get_aead, aead_t *, private_fsm_keymat_t *this, bool in)
{
	DBG2(DBG_IKE, "Entering %s in fsm_keymat", __FUNCTION__);

	if (this && this->aead_in && this->aead_out)
	{
		return in ? &this->aead_in->aead : &this->aead_out->aead;
	}

	return NULL;
}

METHOD(keymat_v2_t, get_auth_octets, bool, private_fsm_keymat_t *this,
	bool verify, chunk_t ike_sa_init, chunk_t nonce, identification_t *id,
	char reserved[3], chunk_t *octets)
{
	int32_t result = 0;
	ike_sa_gen_payload_req_t req;
	ike_sa_gen_payload_rsp_t rsp;
	chunk_t chunk = chunk_empty;
	chunk_t idx = chunk_empty;
	size_t prf_block_size = 0;

	DBG2(DBG_IKE, "Entering %s in fsm_keymat", __FUNCTION__);

	if (!this || !ike_sa_init.ptr || !ike_sa_init.len || !nonce.ptr ||
		!nonce.len || !id || !octets)
	{
		DBG2(DBG_IKE, "%s: Error: Invalid arguments!", __FUNCTION__);
		return FALSE;
	}

	if (!this->prf)
	{
		DBG2(DBG_IKE, "%s: Error: prf is NULL!", __FUNCTION__);
		return FALSE;
	}

	/* No junk */
	memset(&req, 0, sizeof(req));
	memset(&rsp, 0, sizeof(rsp));

	chunk = chunk_alloca(4);
	chunk.ptr[0] = id->get_type(id);
	memcpy(chunk.ptr + 1, reserved, 3);
	idx = chunk_cata("cc", chunk, id->get_encoding(id));

	DBG3(DBG_IKE, "%s: IDx' %B", __FUNCTION__, &idx);

	req.ike_sa_id = this->ike_id;
	req.prf = (prf_alg_t)this->prf_alg;
	req.dir = verify ? IKE_SA_RESPONDER : IKE_SA_INITIATOR;
	req.msg_size = idx.len;

	/* Copy idx to message */
	if (idx.len <= IKE_SA_MAX_DATA_SIZE_BYTES)
	{
		memcpy(&req.msg[0], idx.ptr, idx.len);
	}
	else
	{
		DBG1(DBG_IKE, "%s: Error: idx of size %u larger than max %u",
			 __FUNCTION__, idx.len, IKE_SA_MAX_DATA_SIZE_BYTES);
		return FALSE;
	}

	DBG3(DBG_ENC, "%s: ike_sa_gen_auth_payload req %b", __FUNCTION__, &req,
		sizeof(req));
	result = ike_sa_gen_auth_payload(&req, &rsp);
	DBG3(DBG_ENC, "%s: ike_sa_gen_auth_payload rsp %b", __FUNCTION__, &rsp,
		sizeof(rsp));
	if ((result != 0) || (rsp.result != 0))
	{
		DBG1(DBG_IKE, "%s: ike_sa_gen_auth_payload failed with error: %d!",
			__FUNCTION__, rsp.result);
		return FALSE;
	}

	/* Get PRF block size to know how much data should come back */
	prf_block_size = this->prf->get_block_size(this->prf);

	if (rsp.payload_size == prf_block_size)
	{
		chunk = chunk_alloca(prf_block_size);
		memcpy(chunk.ptr, &rsp.payload_buf[0], rsp.payload_size);
		*octets = chunk_cat("ccm", ike_sa_init, nonce, chunk);
		DBG3(DBG_IKE, "%s: octets = message + nonce + prf(Sk_px, IDx') %B",
			 __FUNCTION__, octets);
	}
	else
	{
		DBG1(DBG_IKE, "%s: Error: Payload size mismatch, expected %u got %u!",
			 __FUNCTION__, chunk.len, rsp.payload_size);
		return FALSE;
	}

	return TRUE;
}

METHOD(keymat_v2_t, get_skd, pseudo_random_function_t,
	private_fsm_keymat_t *this, chunk_t *skd)
{
	DBG2(DBG_IKE, "Entering %s in fsm_keymat", __FUNCTION__);

	if (!this || !skd)
	{
		return PRF_UNDEFINED;
	}

	*skd = chunk_empty;

	return this->prf_alg;
}

METHOD(keymat_v2_t, get_psk_sig, bool, private_fsm_keymat_t *this, bool verify,
	chunk_t ike_sa_init, chunk_t nonce, chunk_t secret, identification_t *id,
	char reserved[3], chunk_t *sig)
{
	DBG2(DBG_IKE, "Entering %s in fsm_keymat", __FUNCTION__);

	if (!this || !id || !sig || !nonce.ptr || !nonce.len || !secret.ptr ||
		!secret.len || !ike_sa_init.ptr || !ike_sa_init.len)
	{
		DBG2(DBG_IKE, "%s: Error: Invalid arguments!", __FUNCTION__);
		return FALSE;
	}

	/* This is to avoid compiler warnings about unused parameters. */
	(void)verify;
	(void)reserved;

	/* JLZ TODO: Add qsecurefsm API call */
	DBG1(DBG_IKE, "%s: Error: Not implemented!", __FUNCTION__);

	return FALSE;
}

METHOD(keymat_v2_t, hash_algorithm_supported, bool, private_fsm_keymat_t *this,
	hash_algorithm_t hash)
{
	DBG2(DBG_IKE, "Entering %s in fsm_keymat", __FUNCTION__);

	if (!this || !this->hash_algorithms)
	{
		return FALSE;
	}

	return this->hash_algorithms->contains(this->hash_algorithms, hash);
}

METHOD(keymat_v2_t, add_hash_algorithm, void, private_fsm_keymat_t *this,
	hash_algorithm_t hash)
{
	DBG2(DBG_IKE, "Entering %s in fsm_keymat", __FUNCTION__);

	if (this)
	{
		if (!this->hash_algorithms)
		{
			this->hash_algorithms = hash_algorithm_set_create();
		}

		if (this->hash_algorithms)
		{
			this->hash_algorithms->add(this->hash_algorithms, hash);
		}
	}
}

METHOD(keymat_t, destroy, void, private_fsm_keymat_t *this)
{
	DBG2(DBG_IKE, "Entering %s in fsm_keymat %p", __FUNCTION__, this);

	if (!this)
	{
		return;
	}

	delete_ike_sa(this);

	DESTROY_IF(this->hash_algorithms);
	this->hash_algorithms = NULL;

	if (this->aead_in)
	{
		this->aead_in->aead.destroy(&this->aead_in->aead);
		this->aead_in = NULL;
	}

	if (this->aead_out)
	{
		this->aead_out->aead.destroy(&this->aead_out->aead);
		this->aead_out = NULL;
	}

	DESTROY_IF(this->child_ids);
	this->child_ids = NULL;
	DESTROY_IF(this->child_ids_mutex);
	this->child_ids_mutex = NULL;
	DESTROY_IF(this->prf);
	this->prf = NULL;

	free(this);
	this = NULL;
}

/**
 * See header.
 */
fsm_keymat_t *fsm_keymat_create(bool initiator)
{
	private_fsm_keymat_t *this = NULL;

	DBG2(DBG_IKE, "Entering %s in fsm_keymat", __FUNCTION__);

	INIT(this,
		.public =
		{
			.keymat_v2 =
			{
				.keymat =
				{
					.get_version = _get_version,
					.create_dh = _create_dh,
					.create_nonce_gen = _create_nonce_gen,
					.get_aead = _get_aead,
					.destroy = _destroy,
				},
				.derive_ike_keys = _derive_ike_keys,
				.derive_child_keys = _derive_child_keys,
				.get_skd = _get_skd,
				.get_auth_octets = _get_auth_octets,
				.get_psk_sig = _get_psk_sig,
				.add_hash_algorithm = _add_hash_algorithm,
				.hash_algorithm_supported = _hash_algorithm_supported,
			},
			.del_child_sa = _del_child_sa,
		},
		.initiator = initiator,
		.hash_algorithms = NULL,
		.aead_in = NULL,
		.aead_out = NULL,
		.prf = NULL,
		.prf_alg = PRF_UNDEFINED,
		.child_ids = linked_list_create(),
		.child_ids_mutex = mutex_create(MUTEX_TYPE_RECURSIVE),
		.valid = FALSE,
		.ike_id = 0,
		);

	if (!this)
	{
		DBG1(DBG_IKE, "%s: Error: Failed to create this!", __FUNCTION__);
		return NULL;
	}

	if (!this->child_ids || !this->child_ids_mutex)
	{
		DBG1(DBG_IKE, "%s: Error: Failed to allocate objects!", __FUNCTION__);
		this->public.keymat_v2.keymat.destroy(&this->public.keymat_v2.keymat);
		return NULL;
	}

	DBG2(DBG_IKE, "%s: Created %p", __FUNCTION__, this);

	return (fsm_keymat_t *)this;
}
