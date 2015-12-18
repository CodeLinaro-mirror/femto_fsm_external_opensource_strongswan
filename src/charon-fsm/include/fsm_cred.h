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
#ifndef FSM_CRED_H_
#define FSM_CRED_H_

typedef struct fsm_cred_t fsm_cred_t;

#include <credentials/credential_set.h>

/**
 * FSM in-memory credential set.
 */
struct fsm_cred_t
{
	/**
	 * Implements credential_set_t.
	 */
	credential_set_t set;

	/**
	 * Destroy a fsm_cred_t.
	 */
	void (*destroy)(fsm_cred_t *this);

};

/**
 * Create a fsm_cred instance.
 */
fsm_cred_t *fsm_cred_create(void);

#endif /** FSM_CRED_H_ @}*/
