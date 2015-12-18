/*
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
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
#ifndef FSM_KERNEL_NET_H_
#define FSM_KERNEL_NET_H_

#include <net/if.h>
#include <kernel/kernel_net.h>

typedef struct fsm_kernel_net_t fsm_kernel_net_t;

/**
 * Implementation of the kernel network interface using Netlink.
 */
struct fsm_kernel_net_t
{
	/**
	 * Implements kernel_net_t interface
	 */
	kernel_net_t interface;

	/**
	 * Activate given interface
	 * @param this		FSM kernel net object
	 * @param ifname	Name of the interface to activate
	 * @return status_t	SUCCESS if successful, or an error code if
	 *  	   otherwise.
	 */
	status_t (*activate_iface)(fsm_kernel_net_t *this, char ifname[IFNAMSIZ]);
};

/**
 * Get the single kernel net instance
 *
 * @return			fsm_kernel_net_t instance
 */
fsm_kernel_net_t *fsm_kernel_net_get_instance(void);

/**
 * Create a netlink kernel network interface instance.
 *
 * @return			fsm_kernel_net_t instance
 */
fsm_kernel_net_t *fsm_kernel_net_create(void);

#endif /** FSM_KERNEL_NET_H_ @}*/
