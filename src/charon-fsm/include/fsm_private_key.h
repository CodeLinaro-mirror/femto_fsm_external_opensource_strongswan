/*
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
 * Copyright (C) 2012 Reto Buerki
 * Copyright (C) 2012 Adrian-Ken Rueegsegger
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
#ifndef FSM_PRIVATE_KEY_H_
#define FSM_PRIVATE_KEY_H_

#include <credentials/keys/private_key.h>

typedef struct fsm_private_key_t fsm_private_key_t;

/**
 * FSM private_key_t implementation.
 */
struct fsm_private_key_t
{
	/**
	 * Implements private_key_t interface
	 */
	private_key_t key;
};

/**
 * Initialize FSM private key with given key ID.
 */
fsm_private_key_t *fsm_private_key_init(identification_t *const id);

#endif /** FSM_PRIVATE_KEY_H_ @}*/
