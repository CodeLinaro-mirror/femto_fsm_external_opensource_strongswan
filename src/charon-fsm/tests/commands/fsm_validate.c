/*
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
 * Copyright (C) 2014 Martin Willi
 * Copyright (C) 2014 revosec AG
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
#include <errno.h>
#include <utils/debug.h>
#include <utils/identification.h>
#include <credentials/keys/public_key.h>

#include "fsm_command.h"

static bool verify(chunk_t *data, char *pub_path, chunk_t *sig)
{
	bool result = FALSE;
	public_key_t *pub_key = NULL;
	chunk_t encoding = chunk_empty;
	chunk_t fingerprint = chunk_empty;

	if (!data || !pub_path || !sig)
	{
		return FALSE;
	}

	/* Build a public key */
	pub_key = lib->creds->create(lib->creds, CRED_PUBLIC_KEY, KEY_ANY,
		BUILD_FROM_FILE, pub_path, BUILD_END);

	if (!pub_key)
	{
		DBG1(DBG_APP, "%s: Could not create public key!", __FUNCTION__);
		return FALSE;
	}

	DBG2(DBG_APP, "%s: Created public key type %N",
		__FUNCTION__, key_type_names, pub_key->get_type(pub_key));

	result = pub_key->get_encoding(pub_key, PUBKEY_ASN1_DER, &encoding);
	if (result)
	{
		DBG3(DBG_APP, "encoding: %#b", encoding.ptr, encoding.len);
	}

	result = pub_key->get_fingerprint(pub_key, KEYID_PUBKEY_SHA1, &fingerprint);
	if (result)
	{
		DBG3(DBG_APP, "fingerprint: %b", fingerprint.ptr, fingerprint.len);
	}

	DBG3(DBG_APP, "data: %b", data->ptr, data->len);
	DBG3(DBG_APP, "sig: %b", sig->ptr, sig->len);

	/* Verify signature */
	result = pub_key->verify(pub_key, SIGN_RSA_EMSA_PKCS1_SHA256, *data, *sig);
	return result;
}

/**
 * Validate signature
 */
static int validate(void)
{
	char *arg = NULL;
	char *data_path = NULL;
	char *pub_path = NULL;
	char *sig_path = NULL;
	int result = 0;
	chunk_t *data = NULL;
	chunk_t *sig = NULL;

	while (TRUE)
	{
		switch (command_getopt(&arg))
		{
			case 'h':
				return command_usage(NULL);
			case 'd':
				data_path = arg;
				continue;
			case 'k':
				pub_path = arg;
				continue;
			case 's':
				sig_path = arg;
				continue;
			case EOF:
				break;
			default:
				return command_usage("invalid --print option");
		}
		break;
	}

	if (!data_path)
	{
		return command_usage("-d required!");
	}

	if (!pub_path)
	{
		return command_usage("-p required!");
	}

	if (!sig_path)
	{
		return command_usage("-S required!");
	}

	data = chunk_map(data_path, FALSE);
	if (!data)
	{
		DBG1(DBG_APP, "chunk_map failed for %s: %s\n",
			data_path, strerror(errno));
		result = -1;
		goto endvalidate;
	}

	sig = chunk_map(sig_path, FALSE);
	if (!sig)
	{
		DBG1(DBG_APP, "chunk_map failed for %s: %s\n",
			sig_path, strerror(errno));
		result = -1;
		goto endvalidate;
	}

	/* Verify signature */
	if (!verify(data, pub_path, sig))
	{
		DBG1(DBG_APP, "Invalid signature!");
		result = -1;
		goto endvalidate;
	}

	DBG1(DBG_APP, "Signature is valid!");

endvalidate:
	if (data)
	{
		chunk_unmap(data);
	}

	if (sig)
	{
		chunk_unmap(sig);
	}

	return result;
}

/**
 * Register the command.
 */
static void __attribute__((constructor)) reg(void)
{
	command_register((command_t)
	{
		validate, 'V', "validate", "Validate the given signature",
		{ "[--data file] [--key keyfile] [--sig sigfile]" },
		{
			{ "help", 'h', 0, "show usage information" },
			{ "data", 'd', 1, "data that was signed" },
			{ "key", 'k', 1, "public key in DER format" },
			{ "sig", 's', 1, "signature file to validate" },
		}
	});
}
