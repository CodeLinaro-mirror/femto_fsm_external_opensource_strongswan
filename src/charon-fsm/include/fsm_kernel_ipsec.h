/*
 * Copyright (c) 2016, 2018, The Linux Foundation. All rights reserved.
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
#ifndef FSM_KERNEL_IPSEC_H_
#define FSM_KERNEL_IPSEC_H_

#include <kernel/kernel_ipsec.h>
#include <sa/ike_sa.h>

typedef struct fsm_kernel_ipsec_t fsm_kernel_ipsec_t;

/**
 * Implementation of the kernel ipsec interface using Netlink.
 */
struct fsm_kernel_ipsec_t
{
	/**
	 * Implements kernel_ipsec_t interface
	 */
	kernel_ipsec_t interface;

	/**
	 * Create a tunnel and associate it with an IKE SA
	 */
	status_t (*create_tunnel)(fsm_kernel_ipsec_t *this, ike_sa_t *ike_sa);

	/**
	 * Migrate an existing tunnel and associate it with a new IKE SA
	 */
	status_t (*migrate_tunnel)(fsm_kernel_ipsec_t *this,
		u_int32_t old_ike_sa_id, u_int32_t new_ike_sa_id);

	/**
	 * Delete a tunnel associated with the given IKE SA
	 */
	status_t (*delete_tunnel)(fsm_kernel_ipsec_t *this, u_int32_t ike_sa_id);

	/**
	 * Get the tunnel interface associated with the given IKE SA
	 */
	status_t (*get_tunnel_iface)(fsm_kernel_ipsec_t *this, u_int32_t ike_sa_id,
		char **iface);

	/**
	 * Get the child SA ID for the SA with the given SPI
	 */
	status_t (*get_child_sa_id)(fsm_kernel_ipsec_t *this, u_int32_t spi,
		bool inbound, u_int8_t *child_sa_id);
};

/**
 * Create a netlink kernel ipsec interface instance.
 *
 * @return			fsm_kernel_ipsec_t instance or NULL
 */
fsm_kernel_ipsec_t *fsm_kernel_ipsec_create(void);

/**
 * Create a netlink kernel ipsec interface instance in secure
 * mode.
 *
 * @return			fsm_kernel_ipsec_t instance or NULL
 */
fsm_kernel_ipsec_t *fsm_kernel_ipsec_create_secure(void);

#endif /** FSM_KERNEL_IPSEC_H_ @}*/
