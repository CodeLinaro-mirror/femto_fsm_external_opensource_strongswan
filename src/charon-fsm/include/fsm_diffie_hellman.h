/*
 * Copyright (c) 2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2008 Tobias Brunner
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
 * @defgroup fsm_diffie_hellman fsm_diffie_hellman
 * @{ @ingroup fsm_p
 */

#ifndef FSM_DIFFIE_HELLMAN_H_
#define FSM_DIFFIE_HELLMAN_H_

#include <library.h>

typedef struct fsm_diffie_hellman_t fsm_diffie_hellman_t;

/**
 * Implementation of the Diffie-Hellman algorithm using OpenSSL.
 */
struct fsm_diffie_hellman_t
{
	/**
	 * Implements diffie_hellman_t interface.
	 */
	diffie_hellman_t dh;

	/**
	 * Returns the unique id for this Diffie Hellman instance.
	 *
	 * @param value		unique id will be written into this
	 * @return			TRUE if other public value saved successfully
	 */
	bool (*get_unique_id)(fsm_diffie_hellman_t *this, uint32_t *value)
		__attribute__((warn_unused_result));

	/**
	 * Returns the peer's public value for this Diffie Hellman instance.
	 *
	 * Space for returned public value is allocated and must be freed by caller.
	 *
	 * @param value		other public value will be written into this chunk
	 * @return			TRUE if other public value saved successfully
	 */
	bool (*get_other_public_value)(fsm_diffie_hellman_t *this, chunk_t *value)
		__attribute__((warn_unused_result));
};

/**
 * Creates a new fsm_diffie_hellman_t object.
 *
 * @param group			Diffie Hellman group number to use
 * @return				fsm_diffie_hellman_t object, NULL if not supported
 */
fsm_diffie_hellman_t *fsm_diffie_hellman_create(diffie_hellman_group_t group);

#endif /** FSM_DIFFIE_HELLMAN_H_ @}*/
