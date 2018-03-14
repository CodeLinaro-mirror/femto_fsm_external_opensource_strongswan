/*
 * Copyright (c) 2016, 2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2012-2013 Reto Buerki
 * Copyright (C) 2012-2013 Adrian-Ken Rueegsegger
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
#include <string.h>
#include <utils/debug.h>

#include "fsm_private_key.h"
#include "qsecure_ike_api.h"

typedef struct private_fsm_private_key_t private_fsm_private_key_t;

/**
 * Private data of a fsm_private_key_t object.
 */
struct private_fsm_private_key_t
{

	/**
	 * Public interface for this signer.
	 */
	fsm_private_key_t public;

	/**
	 * Key ID.
	 */
	identification_t *id;

	/**
	 * Key type.
	 */
	key_type_t key_type;

	/**
	 * Reference count.
	 */
	refcount_t ref;

};

METHOD(private_key_t, get_type, key_type_t, private_fsm_private_key_t *this)
{
	DBG2(DBG_IKE, "Entering %s in fsm_private_key", __FUNCTION__);
	return this->key_type;
}

METHOD(private_key_t, sign, bool, private_fsm_private_key_t *this,
	signature_scheme_t scheme, chunk_t data, chunk_t *signature)
{
	int ret;
	tre_ike_sign_cmd_t req;
	tre_ike_rsp_sign_cmd_t rsp;
	bool result = FALSE;

	DBG2(DBG_IKE, "Entering %s in fsm_private_key", __FUNCTION__);

	/* This is to avoid compiler warnings about unused parameters */
	(void)this;

	if (!signature || !data.ptr)
	{
		DBG2(DBG_IKE, "%s: Error: Invalid arguments!", __FUNCTION__);
		return FALSE;
	}

	if (scheme != SIGN_RSA_EMSA_PKCS1_SHA256)
	{
		DBG2(DBG_IKE, "%s: Error: scheme %N not supported!",
			__FUNCTION__, signature_scheme_names, scheme);
		return FALSE;
	}

	if (sizeof(req.buf) < data.len)
	{
		DBG2(DBG_IKE, "%s: Error: request buffer size %u < data len %u",
			__FUNCTION__, sizeof(req.buf), data.len);
		return FALSE;
	}

	/* No junk */
	memset(&req, 0, sizeof(req));
	memset(&rsp, 0, sizeof(rsp));

	req.rsa_pad = CE_RSA_PAD_PKCS1_V1_5_SIG;
	req.saltlen = 0;
	req.buflen = data.len;

	memcpy(req.buf, data.ptr, data.len);

	DBG3(DBG_IKE, "%s: tre_ike_rsa_sign req %b", __FUNCTION__, &req,
		sizeof(req));
	ret = tre_ike_rsa_sign(&req, &rsp);
	DBG3(DBG_IKE, "%s: tre_ike_rsa_sign rsp %b", __FUNCTION__, &rsp,
		sizeof(rsp));

	if (!ret && !rsp.result)
	{
		*signature = chunk_alloc(rsp.siglen);
		if (!signature->ptr)
		{
			DBG2(DBG_IKE, "%s: Error: Failed to allocate %u bytes for signature",
				__FUNCTION__, rsp.siglen);
		}
		else
		{
			memcpy(signature->ptr, rsp.buf, rsp.siglen);
			result = TRUE;
		}
	}

	return result;
}

METHOD(private_key_t, decrypt, bool, private_fsm_private_key_t *this,
	encryption_scheme_t scheme, chunk_t crypto, chunk_t *plain)
{
	/* This is to avoid compiler warnings about unused parameters */
	(void)this;
	(void)scheme;
	(void)crypto;
	(void)plain;

	DBG2(DBG_IKE, "%s: Not supported for fsm_private_key", __FUNCTION__);
	return FALSE;
}

METHOD(private_key_t, get_keysize, int, private_fsm_private_key_t *this)
{
	/* This is to avoid compiler warnings about unused parameters */
	(void)this;

	DBG2(DBG_IKE, "%s: Not supported for fsm_private_key", __FUNCTION__);
	return 0;
}

METHOD(private_key_t, get_public_key, public_key_t *,
	private_fsm_private_key_t *this)
{
	/* This is to avoid compiler warnings about unused parameters */
	(void)this;

	DBG2(DBG_IKE, "%s: Not supported for fsm_private_key", __FUNCTION__);
	return NULL;
}

METHOD(private_key_t, get_encoding, bool, private_fsm_private_key_t *this,
	cred_encoding_type_t type, chunk_t *encoding)
{
	/* This is to avoid compiler warnings about unused parameters */
	(void)this;
	(void)type;
	(void)encoding;

	DBG2(DBG_IKE, "%s: Not supported for fsm_private_key", __FUNCTION__);
	return FALSE;
}

METHOD(private_key_t, get_fingerprint, bool, private_fsm_private_key_t *this,
	cred_encoding_type_t type, chunk_t *fp)
{
	/* This is to avoid compiler warnings about unused parameters */
	(void)type;

	DBG2(DBG_IKE, "Entering %s in fsm_private_key", __FUNCTION__);
	*fp = this->id->get_encoding(this->id);
	return TRUE;
}

METHOD(private_key_t, get_ref, private_key_t *, private_fsm_private_key_t *this)
{
	DBG2(DBG_IKE, "Entering %s in fsm_private_key", __FUNCTION__);

	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(private_key_t, destroy, void, private_fsm_private_key_t *this)
{
	DBG2(DBG_IKE, "Entering %s in fsm_private_key", __FUNCTION__);

	if (ref_put(&this->ref))
	{
		this->id->destroy(this->id);
		free(this);
	}
}

/**
 * See header.
 */
fsm_private_key_t *fsm_private_key_init(identification_t *const id)
{
	private_fsm_private_key_t *this = NULL;

	DBG2(DBG_IKE, "Entering %s in fsm_private_key", __FUNCTION__);

	INIT(this,
		.public =
		{
			.key =
			{
				.get_type = _get_type,
				.sign = _sign,
				.decrypt = _decrypt,
				.get_keysize = _get_keysize,
				.get_public_key = _get_public_key,
				.equals = private_key_equals,
				.belongs_to = private_key_belongs_to,
				.get_fingerprint = _get_fingerprint,
				.has_fingerprint = private_key_has_fingerprint,
				.get_encoding = _get_encoding,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.ref = 1,
		.id = id->clone(id),
		.key_type = KEY_RSA,
		);

	return &this->public;
}
