/*
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
 * Copyright (C) 2008-2009 Martin Willi
 * Copyright (C) 2008 Tobias Brunner
 * Copyright (C) 2000-2008 Andreas Steffen
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
#include <asn1/asn1.h>
#include <asn1/oid.h>
#include <asn1/asn1_parser.h>
#include <errno.h>
#include <utils/debug.h>

#include "fsm_command.h"
#include "fsm_utils.h"
#include "qsecure_ike_api.h"

/**
 * ASN.1 definition of a PKCS#1 RSA private key
 */
static const asn1Object_t priv_key_objs[] = {
	{ 0, (u_char *)"RSAPrivateKey",		ASN1_SEQUENCE,     ASN1_NONE }, /*  0 */
	{ 1, (u_char *)"version",			ASN1_INTEGER,      ASN1_BODY }, /*  1 */
	{ 1, (u_char *)"modulus",			ASN1_INTEGER,      ASN1_BODY }, /*  2 */
	{ 1, (u_char *)"publicExponent",	ASN1_INTEGER,      ASN1_BODY }, /*  3 */
	{ 1, (u_char *)"privateExponent",	ASN1_INTEGER,      ASN1_BODY }, /*  4 */
	{ 1, (u_char *)"prime1",			ASN1_INTEGER,      ASN1_BODY }, /*  5 */
	{ 1, (u_char *)"prime2",			ASN1_INTEGER,      ASN1_BODY }, /*  6 */
	{ 1, (u_char *)"exponent1",			ASN1_INTEGER,      ASN1_BODY }, /*  7 */
	{ 1, (u_char *)"exponent2",			ASN1_INTEGER,      ASN1_BODY }, /*  8 */
	{ 1, (u_char *)"coefficient",		ASN1_INTEGER,      ASN1_BODY }, /*  9 */
	{ 1, (u_char *)"otherPrimeInfos",	ASN1_SEQUENCE,     ASN1_OPT |
		ASN1_LOOP }, /* 10 */
	{ 2,   (u_char *)"otherPrimeInfo",	ASN1_SEQUENCE,     ASN1_NONE }, /* 11 */
	{ 3,       (u_char *)"prime",			ASN1_INTEGER,  ASN1_BODY }, /* 12 */
	{ 3,       (u_char *)"exponent",		ASN1_INTEGER,  ASN1_BODY }, /* 13 */
	{ 3,       (u_char *)"coefficient",	ASN1_INTEGER,      ASN1_BODY }, /* 14 */
	{ 1,   (u_char *)"end opt or loop",	ASN1_EOC,          ASN1_END  }, /* 15 */
	{ 0, (u_char *)"exit",				ASN1_EOC,          ASN1_EXIT }
};
#define PRIV_KEY_VERSION		 1
#define PRIV_KEY_MODULUS		 2
#define PRIV_KEY_PUB_EXP		 3
#define PRIV_KEY_PRIV_EXP		 4
#define PRIV_KEY_PRIME1			 5
#define PRIV_KEY_PRIME2			 6
#define PRIV_KEY_EXP1			 7
#define PRIV_KEY_EXP2			 8
#define PRIV_KEY_COEFF			 9


/**
 * Load a RSA private key from a ASN1 encoded blob.
 */
static int prov_key(chunk_t *blob)
{
	tre_ike_encrypt_key_cmd_t encr_key_req;
	tre_ike_rsp_encrypt_key_cmd_t encr_key_rsp;
	tre_ike_prov_key_cmd_t prov_key_req;
	tre_ike_rsp_prov_key_cmd_t prov_key_rsp;
	chunk_t n = chunk_empty;
	chunk_t e = chunk_empty;
	chunk_t d = chunk_empty;
	chunk_t p = chunk_empty;
	chunk_t q = chunk_empty;
	chunk_t exp1 = chunk_empty;
	chunk_t exp2 = chunk_empty;
	chunk_t coeff = chunk_empty;
	asn1_parser_t *parser = NULL;
	chunk_t object = chunk_empty;
	int obj_id = -1;
	bool success = FALSE;
	int result = 0;
	size_t len = 0;
	u_int32_t idx = 0;

	parser = asn1_parser_create(priv_key_objs, *blob);
	parser->set_flags(parser, FALSE, TRUE);

	while (parser->iterate(parser, &obj_id, &object))
	{
		switch (obj_id)
		{
			case PRIV_KEY_VERSION:
				if (object.len > 0 && *object.ptr != 0)
				{
					DBG1(DBG_APP, "%s: Invalid private key version %#b!",
						__FUNCTION__, object.ptr, object.len);
					goto end;
				}
				break;
			case PRIV_KEY_MODULUS:
				n = object;
				DBG4(DBG_APP, "n %#b", n.ptr, n.len);
				break;
			case PRIV_KEY_PUB_EXP:
				e = object;
				DBG4(DBG_APP, "e: %#b", e.ptr, e.len);
				break;
			case PRIV_KEY_PRIV_EXP:
				d = object;
				DBG4(DBG_APP, "d: %#b", d.ptr, d.len);
				break;
			case PRIV_KEY_PRIME1:
				p = object;
				DBG4(DBG_APP, "p.len=%u\n%#b", p.len, p.ptr, p.len);
				break;
			case PRIV_KEY_PRIME2:
				q = object;
				DBG4(DBG_APP, "q.len=%u\n%#b", q.len, q.ptr, q.len);
				break;
			case PRIV_KEY_EXP1:
				exp1 = object;
				DBG4(DBG_APP, "exp1.len=%u\n%#b", exp1.len, exp1.ptr, exp1.len);
				break;
			case PRIV_KEY_EXP2:
				exp2 = object;
				DBG4(DBG_APP, "exp2.len=%u\n%#b", exp2.len, exp2.ptr, exp2.len);
				break;
			case PRIV_KEY_COEFF:
				coeff = object;
				DBG4(DBG_APP, "coeff.len=%u\n%#b",
					coeff.len, coeff.ptr, coeff.len);
				break;
			default:
				break;
		}
	}
	success = parser->success(parser);
	parser->destroy(parser);
	if (!success)
	{
		DBG1(DBG_APP, "%s: parser failed!", __FUNCTION__);
		result = -1;
		goto end;
	}

	if (!chunk_compare(n, chunk_empty) || !chunk_compare(e, chunk_empty) ||
		!chunk_compare(d, chunk_empty))
	{
		DBG1(DBG_APP, "%s: Invalid private key!", __FUNCTION__);
		result = -1;
		goto end;
	}

	/* No junk */
	memset(&encr_key_req, 0, sizeof(tre_ike_encrypt_key_cmd_t));
	memset(&encr_key_rsp, 0, sizeof(tre_ike_rsp_encrypt_key_cmd_t));
	memset(&prov_key_req, 0, sizeof(tre_ike_prov_key_cmd_t));
	memset(&prov_key_rsp, 0, sizeof(tre_ike_rsp_prov_key_cmd_t));

	/* There may be an extra sign byte at the beginning of each field, we need
	 * to discard those.
	 */
	len = n.len;
	if (has_sign_byte(n))
	{
		idx = 1;
		len -= 1;
		DBG2(DBG_APP, "%s: skipped sign byte of n", __FUNCTION__);
	}

	/* Sanity check */
	if (len > MOD_SZ)
	{
		DBG1(DBG_APP, "%s: modulus size %u greater than max size %u",
			__FUNCTION__, len, MOD_SZ);
		result = -1;
		goto end;
	}

	/* Set up the modulus */
	encr_key_req.keybuf.nbits = len * 8;
	memcpy(encr_key_req.keybuf.n, &n.ptr[idx], len);
	DBG4(DBG_APP, "hex str n: %#b", encr_key_req.keybuf.n, MOD_SZ);

	len = e.len;
	idx = 0;
	if (has_sign_byte(e))
	{
		idx = 1;
		len -= 1;
		DBG2(DBG_APP, "%s: skipped sign byte of e", __FUNCTION__);
	}

	/* Sanity check */
	if (len > PUB_EXP_SZ)
	{
		DBG1(DBG_APP, "%s: public exponent size %u greater than max size %u",
			__FUNCTION__, len, PUB_EXP_SZ);
		result = -1;
		goto end;
	}

	/* Set up the public exponent */
	memcpy(encr_key_req.keybuf.e, &e.ptr[idx], len);
	DBG4(DBG_APP, "hex str e: %#b", encr_key_req.keybuf.e, PUB_EXP_SZ);

	len = d.len;
	idx = 0;
	if (has_sign_byte(d))
	{
		idx = 1;
		len -= 1;
		DBG2(DBG_APP, "%s: skipped sign byte of d", __FUNCTION__);
	}

	/* Sanity check */
	if (len > PRIV_EXP_SZ)
	{
		DBG1(DBG_APP, "%s: private exponent size %u greater than max size %u",
			__FUNCTION__, len, PRIV_EXP_SZ);
		result = -1;
		goto end;
	}

	/* Set up the private exponent */
	memcpy(encr_key_req.keybuf.d, &d.ptr[idx], len);
	DBG4(DBG_APP, "hex str d: %#b", encr_key_req.keybuf.d, PRIV_EXP_SZ);

	/* First, we need to encrypt the private key */
	result = tre_ike_encrypt_rsa_key(&encr_key_req, &encr_key_rsp);

	if (result || encr_key_rsp.result)
	{
		DBG1(DBG_APP,
			"%s: tre_ike_encrypt_rsa_key failed returned %d result %d",
			__FUNCTION__, result, encr_key_rsp.result);
		result = -1;
		goto end;
	}

	DBG4(DBG_APP, "encrypted key: %#b", encr_key_rsp.enc_keybuf, ENC_KEY_SZ);

	/* Then, we need to provision the private key into TZ */
	memcpy((void *)&prov_key_req.keybuf[0], (void *)&encr_key_rsp.enc_keybuf[0],
		ENC_KEY_SZ);

	result = tre_ike_prov_rsa_key(&prov_key_req, &prov_key_rsp);

	if (result || prov_key_rsp.result)
	{
		DBG1(DBG_APP, "%s: tre_ike_prov_rsa_key failed returned %d result %d",
			__FUNCTION__, result, prov_key_rsp.result);
		result = -1;
	}

end:
	return result;
}


/**
 * Provision private key to TZ
 */
static int provision(void)
{
	char *arg, *file = NULL;
	int result = 0;
	chunk_t *chunk_ptr = NULL;

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				return command_usage(NULL);
			case 'i':
				file = arg;
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --print option");
		}
		break;
	}

	if (!file)
	{
		return command_usage("-i required option!");
	}

	chunk_ptr = chunk_map(file, FALSE);
	if (!chunk_ptr)
	{
		DBG1(DBG_APP, "chunk_map failed: %s\n", strerror(errno));
		return -1;
	}

	/* send private key to TZ*/
	if (prov_key(chunk_ptr))
	{
		result = -1;
		DBG1(DBG_APP, "Could not provision %s", file);
	}
	else
	{
		DBG1(DBG_APP, "%s successfully provisioned!", file);
	}

	chunk_unmap(chunk_ptr);

	return result;
}

/**
 * Register the command.
 */
static void __attribute__((constructor)) reg(void)
{
	command_register((command_t)
	{
		provision, 'p', "provision", "Provision private key into TZ",
		{ "[--in file]" },
		{
			{ "help",	'h', 0, "show usage information" },
			{ "in",		'i', 1, "private key in DER format" },
		}
	});
}
