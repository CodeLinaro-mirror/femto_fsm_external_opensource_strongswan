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
#include <library.h>
#include <hydra.h>
#include <daemon.h>
#include <utils/debug.h>

#include "fsm_command.h"
#include "fsm_cred.h"
#include "fsm_public_key.h"

/**
 * Log levels as defined via command line arguments
 */
static level_t levels[DBG_MAX];

int main(int argc, char *argv[])
{
	fsm_cred_t *creds;
	int group;

	/* initialize library */
	atexit(library_deinit);
	if (!library_init(NULL, "fsm-tests"))
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}

	atexit(libhydra_deinit);
	if (!libhydra_init())
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}

	atexit(libcharon_deinit);
	if (!libcharon_init())
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}

	/* use CTRL loglevel for default */
	for (group = 0; group < DBG_MAX; group++)
	{
		levels[group] = LEVEL_CTRL;
	}

	charon->load_loggers(charon, levels, TRUE);

	/* Register fsm specific plugins */
	static plugin_feature_t features[] = {
		PLUGIN_REGISTER(PUBKEY, fsm_public_key_load, TRUE),
			PLUGIN_PROVIDE(PUBKEY, KEY_RSA),
			PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_RSA_EMSA_PKCS1_SHA1),
			PLUGIN_PROVIDE(PUBKEY_VERIFY, SIGN_RSA_EMSA_PKCS1_SHA256),
	};
	lib->plugins->add_static_features(lib->plugins, "fsm", features,
		countof(features), TRUE, NULL, NULL);
	creds = fsm_cred_create();
	lib->credmgr->add_set(lib->credmgr, (credential_set_t *)creds);

	if (!lib->plugins->load(lib->plugins,
		lib->settings->get_str(lib->settings, "fsm-tests.load", PLUGINS)))
	{
		exit(SS_RC_INITIALIZATION_FAILED);
	}
	lib->plugins->status(lib->plugins, LEVEL_CTRL);

	return command_dispatch(argc, argv);
}
