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

/**
 * Log levels as defined via command line arguments
 */
static level_t levels[DBG_MAX];

int main(int argc, char *argv[])
{
	int group;

	/* initialize library */
	atexit(library_deinit);
	if (!library_init(NULL, "fsm-privkey"))
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

	return command_dispatch(argc, argv);
}
