/*
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
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
#include <utils/chunk.h>
#include <asn1/oid.h>
#include <asn1/asn1.h>
#include <asn1/asn1_parser.h>
#include <credentials/keys/public_key.h>

#include "fsm_public_key.h"
#include "fsm_utils.h"
#include "qsecure_ike_api.h"

typedef struct private_fsm_public_key_t private_fsm_public_key_t;

/**
 * Private data of fsm_public_key_t object.
 */
struct private_fsm_public_key_t
{

	/**
	 * Public interface for this signer.
	 */
	fsm_public_key_t public;

	/**
	 * ASN.1 blob of pubkey.
	 */
	chunk_t asn_blob;

	/**
	 * RSA modulus
	 */
	chunk_t n;

	/**
	 * RSA exponent
	 */
	chunk_t e;

	/**
	 * key length (bits)
	 */
	int key_len;

	/**
	 * Reference count.
	 */
	refcount_t ref;
};

METHOD(public_key_t, get_type, key_type_t, private_fsm_public_key_t *this)
{
	/* This is to avoid compiler warnings about unused parameters */
	(void)this;

	DBG2(DBG_IKE, "Entering %s in fsm_public_key", __FUNCTION__);

	return KEY_RSA;
}

struct schemes_t
{
	signature_scheme_t scheme;
	ce_hash_idx_t hash;
};

static struct schemes_t schemes[] =
{
	{ .scheme = SIGN_RSA_EMSA_PKCS1_SHA1, .hash = CE_HASH_IDX_SHA1 },
	{ .scheme = SIGN_RSA_EMSA_PKCS1_SHA256, .hash = CE_HASH_IDX_SHA256 },
};
#define NUM_SCHEMES (sizeof(schemes)/sizeof(struct schemes_t))

static bool scheme_supported(signature_scheme_t scheme)
{
	uint32_t index = 0;
	bool result = FALSE;

	for (index = 0; index < NUM_SCHEMES; index++)
	{
		if (schemes[index].scheme == scheme)
		{
			result = TRUE;
			break;
		}
	}

	return result;
}

static status_t get_hash_idx_from_scheme(signature_scheme_t scheme,
	ce_hash_idx_t *hash)
{
	ce_hash_idx_t result;
	uint32_t index = 0;
	bool found = FALSE;

	if (!hash)
	{
		return FAILED;
	}

	for (index = 0; index < NUM_SCHEMES; index++)
	{
		if (schemes[index].scheme == scheme)
		{
			result = schemes[index].hash;
			found = TRUE;
			break;
		}
	}

	if (!found)
	{
		return FAILED;
	}

	*hash = result;
	return SUCCESS;
}

METHOD(public_key_t, verify, bool, private_fsm_public_key_t *this,
	signature_scheme_t scheme, chunk_t data, chunk_t signature)
{
	tre_ike_verify_sign_cmd_t ike_verify_req;
	tre_ike_rsp_verify_sign_cmd_t ike_verify_rsp;
	int32_t result = -1;
	bool success = FALSE;
	size_t len = 0;
	u_int32_t idx = 0;
	status_t status = FAILED;

	DBG2(DBG_IKE, "Entering %s in fsm_public_key", __FUNCTION__);

	/* Sanity checks */
	if (!this || !data.ptr || !data.len || !signature.ptr || !signature.len)
	{
		DBG2(DBG_IKE, "%s: Invalid arguments!", __FUNCTION__);
		return FALSE;
	}

	if (!scheme_supported(scheme))
	{
		DBG2(DBG_IKE, "%s: Invalid scheme %N",
			__FUNCTION__, signature_scheme_names, scheme);
		return FALSE;
	}

	if ((data.len > MAX_DATA_SIZE_BYTES) || (signature.len > SIG_SZ))
	{
		DBG2(DBG_IKE, "%s: data.len=%u, signature.len=%u",
			__FUNCTION__, data.len, signature.len);
		return FALSE;
	}

	/* No junk */
	memset(&ike_verify_req, 0, sizeof(tre_ike_verify_sign_cmd_t));
	memset(&ike_verify_rsp, 0, sizeof(tre_ike_rsp_verify_sign_cmd_t));

	status = get_hash_idx_from_scheme(scheme, &ike_verify_req.hashidx);
	if (status != SUCCESS)
	{
		DBG2(DBG_IKE, "%s: Could not get hash index for scheme %N",
			__FUNCTION__, signature_scheme_names, scheme);
		return FALSE;
	}
	DBG2(DBG_IKE, "%s: hashidx %u", __FUNCTION__, ike_verify_req.hashidx);

	ike_verify_req.padding_info.padType = CE_RSA_PAD_PKCS1_V1_5_SIG;
	ike_verify_req.padding_info.labelLen = 0;
	ike_verify_req.data_len = data.len;
	ike_verify_req.signature_len = signature.len;

	memcpy(&ike_verify_req.data, data.ptr, data.len);
	DBG3(DBG_IKE, "%s data: %b", __FUNCTION__, data.ptr, data.len);

	memcpy(&ike_verify_req.signature, signature.ptr, signature.len);
	DBG3(DBG_IKE, "%s signature: %b",
		__FUNCTION__, signature.ptr, signature.len);

	/* There may be an extra sign byte at the beginning of each field, we need
	 * to discard those.
	 */
	len = this->n.len;
	if (has_sign_byte(this->n))
	{
		idx = 1;
		len -= 1;
		DBG2(DBG_IKE, "%s: skipped sign byte of n", __FUNCTION__);
	}

	/* Sanity check */
	if (len > MOD_SZ)
	{
		DBG2(DBG_IKE, "%s: modulus size %u greater than max size %u",
			__FUNCTION__, len, MOD_SZ);
		result = -1;
		goto end;
	}

	/* Set up the modulus */
	ike_verify_req.public_key.nbits = len * 8;
	memcpy(ike_verify_req.public_key.n, &this->n.ptr[idx], len);
	DBG4(DBG_IKE, "n: %#b", ike_verify_req.public_key.n, MOD_SZ);

	len = this->e.len;
	idx = 0;
	if (has_sign_byte(this->e))
	{
		idx = 1;
		len -= 1;
		DBG2(DBG_IKE, "%s: skipped sign byte of e", __FUNCTION__);
	}

	/* Sanity check */
	if (len > PUB_EXP_SZ)
	{
		DBG2(DBG_IKE, "%s: public exponent size %u greater than max size %u",
			__FUNCTION__, len, PUB_EXP_SZ);
		goto end;
	}

	/* Set up the public exponent */
	ike_verify_req.pubkey_len = len;
	memcpy(ike_verify_req.public_key.e, &this->e.ptr[idx], len);
	DBG4(DBG_IKE, "e: %#b", ike_verify_req.public_key.e, PUB_EXP_SZ);

	result = tre_ike_verify_rsa_signature(&ike_verify_req, &ike_verify_rsp);

	if (!result && !ike_verify_rsp.result)
	{
		success = TRUE;
	}

end:
	return success;
}

METHOD(public_key_t, encrypt, bool, private_fsm_public_key_t *this,
	encryption_scheme_t scheme, chunk_t plain, chunk_t *crypto)
{
	/* This is to avoid compiler warnings about unused parameters */
	(void)this;
	(void)scheme;
	(void)plain;
	(void)crypto;

	DBG2(DBG_IKE, "%s: Not supported in fsm_public_key", __FUNCTION__);
	return FALSE;
}

METHOD(public_key_t, get_keysize, int, private_fsm_public_key_t *this)
{
	/* This is to avoid compiler warnings about unused parameters */
	(void)this;

	DBG2(DBG_IKE, "Entering %s in fsm_public_key", __FUNCTION__);
	return this->key_len;
}

METHOD(public_key_t, get_encoding, bool, private_fsm_public_key_t *this,
	cred_encoding_type_t type, chunk_t *encoding)
{
	bool result;

	DBG2(DBG_IKE, "Entering %s in fsm_public_key", __FUNCTION__);

	result = lib->encoding->encode(lib->encoding, type, NULL, encoding,
		CRED_PART_RSA_MODULUS, this->n, CRED_PART_RSA_PUB_EXP, this->e,
		CRED_PART_END);

	return result;
}

METHOD(public_key_t, get_fingerprint, bool, private_fsm_public_key_t *this,
	cred_encoding_type_t type, chunk_t *fp)
{
	bool valid = FALSE;
	DBG2(DBG_IKE, "Entering %s in fsm_public_key type %u", __FUNCTION__,
		(u_int32_t)type);

	valid = lib->encoding->encode(lib->encoding, type, NULL, fp,
		CRED_PART_RSA_MODULUS, this->n, CRED_PART_RSA_PUB_EXP, this->e,
		CRED_PART_END);

	if (valid && fp)
	{
		DBG3(DBG_IKE, "%s: encode succeeded %b", __FUNCTION__, fp->ptr,
			fp->len);
	}
	return (valid && fp);
}

METHOD(public_key_t, get_ref, public_key_t *, private_fsm_public_key_t *this)
{
	DBG2(DBG_IKE, "Entering %s in fsm_public_key", __FUNCTION__);
	ref_get(&this->ref);
	return &this->public.key;
}

METHOD(public_key_t, destroy, void, private_fsm_public_key_t *this)
{
	DBG2(DBG_IKE, "Entering %s in fsm_public_key", __FUNCTION__);

	if (NULL == this)
	{
		return;
	}

	if (ref_put(&this->ref))
	{
		DBG2(DBG_IKE, "%s: destroying public key", __FUNCTION__);
		if (NULL != this->asn_blob.ptr)
		{
			chunk_free(&this->asn_blob);
		}
		free(this);
	}
	DBG2(DBG_IKE, "Exiting %s in fsm_public_key", __FUNCTION__);
}

/**
 * ASN.1 definition of RSApublicKey
 */
static const asn1Object_t pub_key_objs[] = {
	{ 0, (u_char *)"RSAPublicKey",		ASN1_SEQUENCE,	ASN1_OBJ  }, /*  0 */
	{ 1, (u_char *)"modulus",			ASN1_INTEGER,	ASN1_BODY }, /*  1 */
	{ 1, (u_char *)"publicExponent",	ASN1_INTEGER,	ASN1_BODY }, /*  2 */
	{ 0, (u_char *)"exit",				ASN1_EOC,		ASN1_EXIT }
};
#define PUB_KEY_RSA_PUBLIC_KEY		0
#define PUB_KEY_MODULUS				1
#define PUB_KEY_EXPONENT			2

static bool parse_rsa_public_key(private_fsm_public_key_t * this)
{
	asn1_parser_t *parser;
	chunk_t object;
	int obj_id;
	bool success = FALSE;

	parser = asn1_parser_create(pub_key_objs, this->asn_blob);

	while (parser->iterate(parser, &obj_id, &object))
	{
		switch (obj_id)
		{
			case PUB_KEY_MODULUS:
				this->n = object;
				break;
			case PUB_KEY_EXPONENT:
				this->e = object;
				break;
		}
	}
	success = parser->success(parser);
	parser->destroy(parser);

	if (success)
	{
		this->key_len = this->n.len * 8;
	}

	return success;
}

/**
 * See header.
 */
fsm_public_key_t *fsm_public_key_load(key_type_t type, va_list args)
{
	private_fsm_public_key_t *this;
	chunk_t blob = chunk_empty;

	DBG2(DBG_IKE, "Entering %s in fsm_private_key", __FUNCTION__);

	if (type != KEY_RSA)
	{
		DBG2(DBG_IKE, "%s: Key type %N not supported", __FUNCTION__,
			key_type_names, type);
		return NULL;
	}

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_BLOB_ASN1_DER:
				blob = va_arg(args, chunk_t);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}

	if (!blob.ptr || !blob.len)
	{
		return NULL;
	}

	INIT(this,
		.public =
		{
			.key =
			{
				.get_type = _get_type,
				.verify = _verify,
				.encrypt = _encrypt,
				.equals = public_key_equals,
				.get_keysize = _get_keysize,
				.get_fingerprint = _get_fingerprint,
				.has_fingerprint = public_key_has_fingerprint,
				.get_encoding = _get_encoding,
				.get_ref = _get_ref,
				.destroy = _destroy,
			},
		},
		.ref = 1,
		.asn_blob = chunk_clone(blob),
		.n = chunk_empty,
		.e = chunk_empty,
		.key_len = 0,
		);

	if (!this)
	{
		goto errexit;
	}

	if (!this->asn_blob.ptr)
	{
		goto errexit;
	}

	/* Parse the public key to determine n, e and key_len values */
	if (!parse_rsa_public_key(this))
	{
		goto errexit;
	}

	return (fsm_public_key_t *)this;

errexit:
	if (this)
	{
		this->public.key.destroy(&this->public.key);
	}
	return NULL;
}
