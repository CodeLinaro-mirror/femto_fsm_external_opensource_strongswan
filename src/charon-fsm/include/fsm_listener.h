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
#ifndef FSM_LISTENER_H_
#define FSM_LISTENER_H_

#include <bus/listeners/listener.h>
#include "fsm_kernel_ipsec.h"

typedef struct fsm_listener_t fsm_listener_t;

/**
 * FSM bus listener.
 */
struct fsm_listener_t
{
	/**
	 * Implements listener_t interface.
	 */
	listener_t listener;

	/**
	 * Destroy a fsm_listener_t.
	 */
	void (*destroy)(fsm_listener_t *this);
};

/**
 * Create a fsm_listener instance.
 *
 * @param  ipsec	Pointer to FSM ipsec instance
 * @return listener instance
 */
fsm_listener_t *fsm_listener_create(fsm_kernel_ipsec_t *ipsec);

#endif /** FSM_LISTENER_H_ @}*/
