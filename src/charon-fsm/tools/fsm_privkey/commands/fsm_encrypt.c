/*
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
 * Copyright (C) 2013 Tobias Brunner
 * Copyright (C) 2009 Martin Willi
 * Copyright (C) 2001-2008 Andreas Steffen
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
#include <utils/lexparser.h>

#include "fsm_command.h"
#include "fsm_utils.h"
#include "qsecure_ike_api.h"

/* PEM related functions came from pem_builder.c and ASN.1 parsing code came
 * from pkcs1_builder.c.
 */

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

/**
 * check the presence of a pattern in a character string, skip if found
 */
static bool present(char* pattern, chunk_t* ch)
{
	u_int len = strlen(pattern);

	if (ch->len >= len && strneq(ch->ptr, pattern, len))
	{
		*ch = chunk_skip(*ch, len);
		return TRUE;
	}
	return FALSE;
}

/**
 * find a boundary of the form -----tag name-----
 */
static bool find_boundary(char* tag, chunk_t *line)
{
	chunk_t name = chunk_empty;

	if (!present("-----", line) ||
		!present(tag, line) ||
		*line->ptr != ' ')
	{
		return FALSE;
	}
	*line = chunk_skip(*line, 1);

	/* extract name */
	name.ptr = line->ptr;
	while (line->len > 0)
	{
		if (present("-----", line))
		{
			DBG2(DBG_ASN, "  -----%s %.*s-----", tag, (int)name.len, name.ptr);
			return TRUE;
		}
		line->ptr++;  line->len--;  name.len++;
	}
	return FALSE;
}

/**
 * Converts a PEM encoded file into its binary form (RFC 1421, RFC 934)
 */
static status_t pem_to_bin(chunk_t *blob, bool *pgp)
{
	typedef enum {
		PEM_PRE    = 0,
		PEM_MSG    = 1,
		PEM_HEADER = 2,
		PEM_BODY   = 3,
		PEM_POST   = 4,
		PEM_ABORT  = 5
	} state_t;

	bool encrypted = FALSE;
	state_t state  = PEM_PRE;
	chunk_t src    = *blob;
	chunk_t dst    = *blob;
	chunk_t line   = chunk_empty;

	dst.len = 0;

	while (fetchline(&src, &line))
	{
		if (state == PEM_PRE)
		{
			if (find_boundary("BEGIN", &line))
			{
				state = PEM_MSG;
			}
			continue;
		}
		else
		{
			if (find_boundary("END", &line))
			{
				state = PEM_POST;
				break;
			}
			if (state == PEM_MSG)
			{
				state = PEM_HEADER;
				if (memchr(line.ptr, ':', line.len) == NULL)
				{
					state = PEM_BODY;
				}
			}
			if (state == PEM_HEADER)
			{
				err_t ugh = NULL;
				chunk_t name  = chunk_empty;
				chunk_t value = chunk_empty;

				/* an empty line separates HEADER and BODY */
				if (line.len == 0)
				{
					state = PEM_BODY;
					continue;
				}

				/* we are looking for a parameter: value pair */
				DBG2(DBG_ASN, "  %.*s", (int)line.len, line.ptr);
				ugh = extract_parameter_value(&name, &value, &line);
				if (ugh != NULL)
				{
					continue;
				}
				if (match("Proc-Type", &name) && *value.ptr == '4')
				{
					encrypted = TRUE;
				}
			}
			else /* state is PEM_BODY */
			{
				chunk_t data;

				/* remove any trailing whitespace */
				if (!extract_token(&data ,' ', &line))
				{
					data = line;
				}

				/* check for PGP armor checksum */
				if (*data.ptr == '=')
				{
					*pgp = TRUE;
					data.ptr++;
					data.len--;
					DBG2(DBG_ASN, "  armor checksum: %.*s", (int)data.len,
						 data.ptr);
					continue;
				}

				if (blob->len - dst.len < data.len / 4 * 3)
				{
					state = PEM_ABORT;
				}
				data = chunk_from_base64(data, dst.ptr);

				dst.ptr += data.len;
				dst.len += data.len;
			}
		}
	}
	/* set length to size of binary blob */
	blob->len = dst.len;

	if (state != PEM_POST)
	{
		DBG1(DBG_LIB, "  file coded in unknown format, discarded");
		return PARSE_ERROR;
	}

	if (!encrypted)
	{
		return SUCCESS;
	}
	else
	{
		return FAILED;
	}
}

/**
 * Check if a blob looks like an ASN1 SEQUENCE or SET with BER indefinite length
 */
static bool is_ber_indefinite_length(chunk_t blob)
{
	if (blob.len >= 4)
	{
		switch (blob.ptr[0])
		{
			case ASN1_SEQUENCE:
			case ASN1_SET:
				/* BER indefinite length uses 0x80, and is terminated with
				 * end-of-content using 0x00,0x00 */
				return blob.ptr[1] == 0x80 &&
					   blob.ptr[blob.len - 2] == 0 &&
					   blob.ptr[blob.len - 1] == 0;
			default:
				break;
		}
	}
	return FALSE;
}

/**
 * Encrypt an RSA private key from a ASN1 encoded blob.
 */
static int encrypt_key(chunk_t *blob, char *key_path)
{
	tre_ike_encrypt_key_cmd_t encr_key_req;
	tre_ike_rsp_encrypt_key_cmd_t encr_key_rsp;
	chunk_t n = chunk_empty;
	chunk_t e = chunk_empty;
	chunk_t d = chunk_empty;
	asn1_parser_t *parser = NULL;
	chunk_t object = chunk_empty;
	int obj_id = -1;
	bool success = FALSE;
	bool pgp = FALSE;
	bool pem = FALSE;
	int result = 0;
	size_t len = 0;
	u_int32_t idx = 0;
	chunk_t key = chunk_empty;
	chunk_t binkey = chunk_empty;

	if (!blob)
	{
		DBG1(DBG_APP, "%s: Invalid private key", __FUNCTION__);
		goto end;
	}

	binkey = *blob;
	if (!is_ber_indefinite_length(binkey) && !is_asn1(binkey))
	{
		binkey = chunk_clone(*blob);
		pem = TRUE;
		if (pem_to_bin(&binkey, &pgp) != SUCCESS)
		{
			DBG1(DBG_APP, "%s: Could not convert PEM to binary", __FUNCTION__);
			result = -1;
			goto end;
		}

		if (pgp)
		{
			DBG1(DBG_APP, "%s: pgp is not supported", __FUNCTION__);
			result = -1;
			goto end;
		}
	}

	parser = asn1_parser_create(priv_key_objs, binkey);
	if (!parser)
	{
		DBG1(DBG_APP, "%s: Failed to create parser", __FUNCTION__);
		result = -1;
		goto end;
	}

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
					parser->destroy(parser);
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
			default:
				break;
		}
	}
	success = parser->success(parser);
	parser->destroy(parser);
	if (!success)
	{
		DBG1(DBG_APP, "%s: Could not parse private key!", __FUNCTION__);
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

	/* Encrypt the private key */
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

	key.ptr = &encr_key_rsp.enc_keybuf[0];
	key.len = ENC_KEY_SZ;

	success = chunk_write(key, key_path, 0022, TRUE);
	if (!success)
	{
		DBG1(DBG_APP, "Could not write encrypted key to %s", key_path);
		result = -1;
		goto end;
	}
	DBG1(DBG_APP, "Encrypted key written to %s", key_path);

end:
	if (pem)
	{
		chunk_clear(&binkey);
	}
	return result;
}


/**
 * Encrypt a DER or PEM encoded private key by sending it to the TrE.
 */
static int encrypt(void)
{
	char *arg = NULL;
	char *file = NULL;
	int result = 0;
	chunk_t *chunk_ptr = NULL;
	char *outfile = NULL;

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
		return command_usage("-i required option!");
	}

	if (!outfile)
	{
		return command_usage("-o required!");
	}

	chunk_ptr = chunk_map(file, FALSE);
	if (!chunk_ptr)
	{
		DBG1(DBG_APP, "chunk_map failed: %s\n", strerror(errno));
		return -1;
	}

	/* encrypt private key */
	if (encrypt_key(chunk_ptr, outfile))
	{
		result = -1;
		DBG1(DBG_APP, "Could not encrypt %s", file);
	}
	else
	{
		DBG1(DBG_APP, "%s successfully encrypted!", file);
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
		encrypt, 'e', "encrypt", "Encrypt PEM or DER encoded private key",
		{ "[--in file] [--out outfile]" },
		{
			{ "help",	'h', 0, "Show usage information" },
			{ "in",		'i', 1, "DER or PEM encoded private key file" },
			{ "out",	'o', 1, "File to store encrypted key" },
		}
	});
}
