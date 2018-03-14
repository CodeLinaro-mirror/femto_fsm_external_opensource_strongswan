/*
 * Copyright (c) 2018, The Linux Foundation. All rights reserved.
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

/**
 * @defgroup fsm-keymat keymat
 * @{ @ingroup fsm
 */

#ifndef FSM_KEYMAT_H_
#define FSM_KEYMAT_H_

#include <sa/ikev2/keymat_v2.h>

typedef struct fsm_keymat_t fsm_keymat_t;
typedef struct fsm_keymat_key_t fsm_keymat_key_t;

/**
 * Derivation and management of sensitive keying material, FSM variant.
 */
struct fsm_keymat_t
{
	/**
	 * Implements keymat_v2_t.
	 */
	keymat_v2_t keymat_v2;

	/**
	 * Deletes a CHILD SA from the list
	 *
	 * @param	Child SA ID
	 * @return	TRUE on success
	 */
	bool (*del_child_sa)(fsm_keymat_t *this, uint8_t child_sa_id);
};

/**
 * FSM keymat key format
 */
struct fsm_keymat_key_t
{
	/**
	 * Key index in memory
	 */
	u_int32_t index;

	/**
	 * Key length in bytes
	 */
	size_t len;

	/**
	 * CHILD SA id
	 */
	u_int32_t child_sa_id;
};

/**
 * Create FSM keymat instance.
 *
 * @param initiator			TRUE if we are the initiator
 * @return					keymat instance
 */
fsm_keymat_t *fsm_keymat_create(bool initiator);

#endif /** KEYMAT_FSM_H_ @}*/
