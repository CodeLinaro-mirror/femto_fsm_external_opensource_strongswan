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
#include <string.h>
#include <errno.h>
#include <utils/debug.h>
#include <utils/identification.h>
#include <credentials/keys/private_key.h>

#include "fsm_command.h"

static int signature(chunk_t *chunk_ptr, char *sig_path)
{
	int ret = 0;
	bool result = FALSE;
	private_key_t *priv_key = NULL;
	identification_t *id = NULL;
	chunk_t data = chunk_empty;
	chunk_t signature = chunk_empty;

	if (!chunk_ptr || !sig_path)
	{
		return -1;
	}

	data = *chunk_ptr;

	/* Create an id */
	id = identification_create_from_string("keyid:fsm");

	if (!id)
	{
		DBG1(DBG_APP, "%s: could not create id!", __FUNCTION__);
		ret = -1;
		goto exitout;
	}

	DBG2(DBG_APP, "%s: id %Y has type %N",
		__FUNCTION__, id, id_type_names, id->get_type(id));

	/* Get a private key object */
	priv_key = lib->credmgr->get_private(lib->credmgr, KEY_RSA, id, NULL);

	if (!priv_key)
	{
		DBG1(DBG_APP, "%s: Could not get private key!", __FUNCTION__);
		ret = -1;
		goto exitout;
	}

	DBG1(DBG_APP, "%s: Created private key type %N for id %Y",
		__FUNCTION__, key_type_names, priv_key->get_type(priv_key),
		id);

	/* Sign data with private key */
	result = priv_key->sign(priv_key, SIGN_RSA_EMSA_PKCS1_SHA256,
		data, &signature);

	if (!result)
	{
		DBG1(DBG_APP, "%s: Private key signing failed!", __FUNCTION__);
		ret = -1;
		goto exitout;
	}

	result = chunk_write(signature, sig_path, 0022, TRUE);
	if (!result)
	{
		DBG1(DBG_APP, "Could not write signature to %s", sig_path);
		ret = -1;
		goto exitout;
	}
	DBG1(DBG_APP, "Signature written to %s", sig_path);

exitout:
	if (signature.ptr)
	{
		chunk_free(&signature);
	}

	if (id)
	{
		id->destroy(id);
	}

	if (priv_key)
	{
		priv_key->destroy(priv_key);
	}

	return ret;
}


/**
 * Sign data using private key provisioned in TZ
 */
static int sign(void)
{
	char *arg = NULL;
	char *file = NULL;
	char *outfile = NULL;
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
			case 'o':
				outfile = arg;
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
		return command_usage("-i required!");
	}

	if (!outfile)
	{
		return command_usage("-o required!");
	}

	chunk_ptr = chunk_map(file, FALSE);
	if (!chunk_ptr)
	{
		DBG1(DBG_APP, "chunk_map failed: %s\n", strerror(errno));

		result = -1;
		goto endsign;
	}

	/* Sign data */
	if (!signature(chunk_ptr, outfile))
	{
		result = -1;
	}

	chunk_unmap(chunk_ptr);

endsign:

	return result;
}

/**
 * Register the command.
 */
static void __attribute__((constructor)) reg(void)
{
	command_register((command_t)
	{
		sign, 's', "sign",
		"Sign the given data with the private key already provisioned in TZ",
		{ "[--in file] [--out outfile]" },
		{
			{ "help", 'h', 0, "Show usage information" },
			{ "in", 'i', 1, "Input data to sign" },
			{ "out", 'o', 1, "Output file for signature" },
		}
	});
}
