/*
 * Copyright (c) 2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2008-2010 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
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

#include <crypto/diffie_hellman.h>
#include <utils/debug.h>
#include <utils/utils.h>

#include "fsm_diffie_hellman.h"
#include "qsecure_ike_sa_api.h"

typedef struct private_fsm_diffie_hellman_t private_fsm_diffie_hellman_t;

/**
 * Private data of an fsm_diffie_hellman_t object.
 */
struct private_fsm_diffie_hellman_t
{
	/**
	 * Public fsm_diffie_hellman_t interface
	 */
	fsm_diffie_hellman_t public;

	/**
	 * Diffie Hellman group number
	 */
	diffie_hellman_group_t group;

	/**
	 * Our Diffie Hellman public value
	 */
	chunk_t my_public_value;

	/**
	 * Peer Diffie Hellman public value
	 */
	chunk_t other_public_value;

	/**
	 * Tracking ID from secure world
	 */
	u_int8_t my_id;
};

METHOD(fsm_diffie_hellman_t, get_unique_id, bool,
	private_fsm_diffie_hellman_t *this, u_int32_t *value)
{
	DBG2(DBG_IKE, "Entering %s in fsm_diffie_hellman", __FUNCTION__);

	if (!this || !value)
	{
		DBG1(DBG_IKE, "%s: Error: Invalid arguments!", __FUNCTION__);
		return FALSE;
	}

	*value = (u_int32_t)this->my_id;

	return TRUE;
}

METHOD(fsm_diffie_hellman_t, get_other_public_value, bool,
	private_fsm_diffie_hellman_t *this, chunk_t *value)
{
	DBG2(DBG_IKE, "Entering %s in fsm_diffie_hellman", __FUNCTION__);

	if (!this || !value)
	{
		DBG1(DBG_IKE, "%s: Error: Invalid arguments!", __FUNCTION__);
		return FALSE;
	}

	*value = chunk_clone(this->other_public_value);
	if (!value->ptr)
	{
		DBG1(DBG_IKE, "%s: Error retrieving public value!", __FUNCTION__);
		return FALSE;
	}

	return TRUE;
}

METHOD(diffie_hellman_t, get_my_public_value, bool,
	private_fsm_diffie_hellman_t *this, chunk_t *value)
{
	DBG2(DBG_IKE, "Entering %s in fsm_diffie_hellman", __FUNCTION__);

	if (!this || !value)
	{
		DBG1(DBG_IKE, "%s: Error: Invalid arguments!", __FUNCTION__);
		return FALSE;
	}

	*value = chunk_clone(this->my_public_value);
	if (!value->ptr)
	{
		DBG1(DBG_IKE, "%s: Error retrieving public value!", __FUNCTION__);
		return FALSE;
	}

	return TRUE;
}

METHOD(diffie_hellman_t, get_shared_secret, bool,
	private_fsm_diffie_hellman_t *this, chunk_t *secret)
{
	DBG2(DBG_IKE, "Entering %s in fsm_diffie_hellman, not supported",
		__FUNCTION__);

	/* This is to avoid compiler warnings about unused parameters */
	(void)this;
	(void)secret;

	/* Not supported */
	return FALSE;
}

METHOD(diffie_hellman_t, set_other_public_value, bool,
	private_fsm_diffie_hellman_t *this, chunk_t value)
{
	DBG2(DBG_IKE, "Entering %s in fsm_diffie_hellman", __FUNCTION__);

	if (!this || !value.ptr || !value.len)
	{
		DBG1(DBG_IKE, "%s: Error: Invalid arguments!", __FUNCTION__);
		return FALSE;
	}

	if (!diffie_hellman_verify_value(this->group, value))
	{
		DBG1(DBG_IKE, "%s: Error: Invalid DH public value!", __FUNCTION__);
		return FALSE;
	}

	/* Store the peer's public value */
	this->other_public_value = chunk_clone(value);
	if (!this->other_public_value.ptr)
	{
		DBG1(DBG_IKE, "%s: Error saving DH public value!", __FUNCTION__);
		return FALSE;
	}

	return TRUE;
}

METHOD(diffie_hellman_t, set_private_value, bool,
	private_fsm_diffie_hellman_t *this, chunk_t value)
{
	DBG2(DBG_IKE, "Entering %s in fsm_diffie_hellman, not supported",
		__FUNCTION__);

	/* This is to avoid compiler warnings about unused parameters */
	(void)this;
	(void)value;

	return FALSE;
}

METHOD(diffie_hellman_t, get_dh_group, diffie_hellman_group_t,
	private_fsm_diffie_hellman_t *this)
{
	DBG2(DBG_IKE, "Entering %s in fsm_diffie_hellman", __FUNCTION__);

	if (this)
	{
		return this->group;
	}

	return MODP_NONE;
}

METHOD(diffie_hellman_t, destroy, void, private_fsm_diffie_hellman_t *this)
{
	DBG2(DBG_IKE, "Entering %s in fsm_diffie_hellman", __FUNCTION__);
	ike_sa_del_dh_key_rsp_t rsp;
	ike_sa_del_dh_key_req_t req;
	int32_t result = 0;

	if (this)
	{
		if (this->other_public_value.ptr)
		{
			chunk_free(&this->other_public_value);
		}

		if (this->my_public_value.ptr)
		{
			/* Free the DH instance in secure world */
			memset(&rsp, 0, sizeof(rsp));
			memset(&req, 0, sizeof(req));

			req.dh_key_id = this->my_id;

			DBG3(DBG_ENC, "%s: ike_sa_del_dh_key req %b", __FUNCTION__, &req,
				sizeof(req));
			result = ike_sa_del_dh_key(&req, &rsp);
			DBG3(DBG_ENC, "%s: ike_sa_del_dh_key rsp %b", __FUNCTION__, &rsp,
				sizeof(rsp));
			if ((result != 0) || (rsp.result != 0))
			{
				DBG2(DBG_IKE,
					"%s: ike_sa_del_dh_key(%u) failed with error: %d!",
					__FUNCTION__, this->my_id, rsp.result);
			}
			chunk_free(&this->my_public_value);
		}
		free(this);
	}
}

static const diffie_hellman_group_t dh_group_supported[] =
{
	MODP_1024_BIT,
	MODP_2048_BIT,
};

static bool is_dh_group_supported(diffie_hellman_group_t group)
{
	bool found = FALSE;
	u_int32_t i;

	/* Loop through the list of supported groups looking for a match */
	for (i = 0; i < countof(dh_group_supported); i++)
	{
		if (dh_group_supported[i] == group)
		{
			found = TRUE;
			break;
		}
	}

	return found;
}

/*
 * Described in header.
 */
fsm_diffie_hellman_t *fsm_diffie_hellman_create(diffie_hellman_group_t group)
{
	private_fsm_diffie_hellman_t *this = NULL;
	int32_t result = 0;
	ike_sa_gen_dh_key_req_t req;
	ike_sa_gen_dh_key_rsp_t rsp;

	DBG2(DBG_IKE, "Entering %s in fsm_diffie_hellman", __FUNCTION__);

	if (!is_dh_group_supported(group))
	{
		DBG1(DBG_IKE, "%s: Error: DH group %N not supported!", __FUNCTION__,
			diffie_hellman_group_names, group);
		return NULL;
	}

	INIT(this,
		.public =
		{
			.dh =
			{
				.get_shared_secret = _get_shared_secret,
				.set_other_public_value = _set_other_public_value,
				.get_my_public_value = _get_my_public_value,
				.set_private_value = _set_private_value,
				.get_dh_group = _get_dh_group,
				.destroy = _destroy,
			},
			.get_other_public_value = _get_other_public_value,
			.get_unique_id = _get_unique_id,
		},
		.group = group,
		.other_public_value = chunk_empty,
		.my_id = 0,
		);

	if (!this)
	{
		DBG1(DBG_IKE, "%s: Error allocating this!", __FUNCTION__);
		return NULL;
	}

	/* No junk */
	memset(&req, 0, sizeof(req));
	memset(&rsp, 0, sizeof(rsp));

	/* Initialize the request to generate DH key */
	req.dh_type = (dh_grp_t)group;

	DBG3(DBG_ENC, "%s: ike_sa_gen_dh_key req %b", __FUNCTION__, &req,
		sizeof(req));
	result = ike_sa_gen_dh_key(&req, &rsp);
	DBG3(DBG_ENC, "%s: ike_sa_gen_dh_key rsp %b", __FUNCTION__, &rsp,
		sizeof(rsp));
	if ((result != 0) || (rsp.result != 0))
	{
		DBG1(DBG_IKE, "%s: ike_sa_gen_dh_key failed with error: %d!",
			__FUNCTION__, rsp.result);
		goto failure;
	}

	/* Validate the public key length */
	if (!rsp.pub_dh_key.dh_key_len)
	{
		DBG1(DBG_IKE, "%s: Error: Invalid DH public key!", __FUNCTION__);
		goto failure;
	}

	/* Allocate a chunk to hold the public key */
	this->my_public_value = chunk_alloc(rsp.pub_dh_key.dh_key_len);
	if (!this->my_public_value.ptr)
	{
		DBG1(DBG_IKE, "%s: Error: Failed to create DH public value!",
			__FUNCTION__);
		goto failure;
	}

	/* Save the public key */
	memcpy(this->my_public_value.ptr, &rsp.pub_dh_key.dh_key[0],
		rsp.pub_dh_key.dh_key_len);

	/* Save unique ID */
	this->my_id = rsp.dh_key_id;

	return (fsm_diffie_hellman_t *)this;

failure:
	this->public.dh.destroy(&this->public.dh);
	this = NULL;

	return NULL;
}
