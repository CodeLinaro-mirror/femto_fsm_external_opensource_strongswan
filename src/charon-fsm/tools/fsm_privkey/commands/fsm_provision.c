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
 * Provision a private key to TrE either from an encrypted file or from fuses.
 */
static int prov_key(chunk_t *blob)
{
	tre_ike_prov_key_cmd_t prov_key_req;
	tre_ike_rsp_prov_key_cmd_t prov_key_rsp;
	int result = 0;

	prov_key_req.key_in_fuse = (blob) ? FALSE : TRUE;

	if (blob)
	{
		if (!blob->ptr || !blob->len)
		{
			DBG1(DBG_APP, "%s: Invalid blob!", __FUNCTION__);
			return -1;
		}

		if (blob->len != sizeof(prov_key_req.keybuf))
		{
			DBG1(DBG_APP, "%s: Invalid key size %u, expected %u", __FUNCTION__,
				blob->len, sizeof(prov_key_req.keybuf));
			return -1;
		}

		/* Copy the encrypted private key to the request buffer */
		memcpy((void *)&prov_key_req.keybuf[0], blob->ptr,
			blob->len);
	}
	else
	{
		/* Zero out the key buffer */
		memset(prov_key_req.keybuf, 0, sizeof(prov_key_req.keybuf));
	}

	result = tre_ike_prov_rsa_key(&prov_key_req, &prov_key_rsp);

	if (result || prov_key_rsp.result)
	{
		DBG1(DBG_APP, "%s: tre_ike_prov_rsa_key failed returned %d result %d",
			__FUNCTION__, result, prov_key_rsp.result);
		result = -1;
	}

	return result;
}


/**
 * Provision private key to TrE
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

	if (file)
	{
		chunk_ptr = chunk_map(file, FALSE);
		if (!chunk_ptr)
		{
			DBG1(DBG_APP, "chunk_map failed: %s\n", strerror(errno));
			return -1;
		}
	}

	/* Provision private key to TrE */
	if (prov_key(chunk_ptr))
	{
		result = -1;
		DBG1(DBG_APP, "Could not provision key from %s", ((file) ?: "fuse"));
	}
	else
	{
		DBG1(DBG_APP, "Key from %s successfully provisioned!",
			((file) ?: "fuse"));
	}

	if (chunk_ptr)
	{
		chunk_unmap(chunk_ptr);
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
		provision, 'p', "provision", "Provision private key into TrE. "
			"If no file is given, fused key is provisioned.",
		{ "[--in file]" },
		{
			{ "help",	'h', 0, "Show usage information" },
			{ "in",		'i', 1, "Encrypted private key file (optional)" },
		}
	});
}
