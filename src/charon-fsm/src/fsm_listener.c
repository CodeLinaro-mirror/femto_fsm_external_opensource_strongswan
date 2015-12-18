/*
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
 * Copyrigth (C) 2012 Reto Buerki
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
#include <stdarg.h>

#include <daemon.h>
#include <encoding/payloads/auth_payload.h>
#include <utils/utils.h>
#include <utils/debug.h>
#include <utils/chunk.h>

#include "fsm_listener.h"
#include "fsm_kernel_ipsec.h"

typedef struct private_fsm_listener_t private_fsm_listener_t;

/**
 * Private data of a fsm_listener_t object.
 */
struct private_fsm_listener_t
{
	/**
	 * Public fsm_listener_t interface.
	 */
	fsm_listener_t public;

	/**
	 * FSM kernel ipsec instance.
	 */
	fsm_kernel_ipsec_t *ipsec;
};


METHOD(listener_t, authorize, bool, private_fsm_listener_t *this,
	ike_sa_t *ike_sa, bool final, bool *success)
{
	bool result = TRUE;

	DBG2(DBG_IKE, "Entering %s in fsm_listener", __FUNCTION__);

	if (!final)
	{
		return TRUE;
	}

	DBG2(DBG_IKE, "%s: Received final auth hook", __FUNCTION__);

	/* TODO: Add additional validation here */

	*success = result;

	return TRUE;
}

METHOD(listener_t, handle_vips, bool, private_fsm_listener_t *this,
	ike_sa_t *ike_sa, bool handle)
{
	status_t status = FAILED;
	u_int32_t ike_sa_id = 0;

	DBG2(DBG_IKE, "Entering %s in fsm_listener", __FUNCTION__);

	if (!ike_sa || !this || !this->ipsec)
	{
		/* NOTE: TRUE does not indicate success here. Rather, it indicates that
		 * this handler should remain registered to be called again at a future
		 * point.
		 */
		return TRUE;
	}

	ike_sa_id = ike_sa->get_unique_id(ike_sa);
	DBG2(DBG_IKE, "%s: Received Virtual IP %s for IKE SA %u", __FUNCTION__,
		(handle ? "handle" : "release"), ike_sa_id);

	/* handle is TRUE if the virtual IP is being assigned, FALSE if it is
	 * being removed.
	 */
	if (handle)
	{
		/* Create a tunnel for this SA. */
		status = this->ipsec->create_tunnel(this->ipsec, ike_sa);
		if (status != SUCCESS)
		{
			DBG2(DBG_IKE, "%s: Could not create tunnel", __FUNCTION__);
		}
	}
	else
	{
		/* Try to tear down the tunnel. If SAs are still using the tunnel,
		 * this will only serve to decrement the tunnel reference count.
		 * The tunnel will be destroyed when the last SA is deleted.
		 */
		status = this->ipsec->delete_tunnel(this->ipsec, ike_sa_id);
		if (status != SUCCESS)
		{
			DBG2(DBG_IKE, "%s: Could not delete tunnel", __FUNCTION__);
		}
	}

	/* NOTE: TRUE does not indicate success here. Rather, it indicates that
	 * this handler should remain registered to be called again at a future
	 * point.
	 */
	return TRUE;
}

METHOD(listener_t, ike_rekey, bool, private_fsm_listener_t *this,
	ike_sa_t *old_sa, ike_sa_t *new_sa)
{
	status_t status = FAILED;
	u_int32_t old_ike_sa_id = 0;
	u_int32_t new_ike_sa_id = 0;

	DBG2(DBG_IKE, "Entering %s in fsm_listener", __FUNCTION__);

	if (!old_sa || !this || !this->ipsec || !new_sa)
	{
		/* NOTE: TRUE does not indicate success here. Rather, it indicates that
		 * this handler should remain registered to be called again at a future
		 * point.
		 */
		return TRUE;
	}

	old_ike_sa_id = old_sa->get_unique_id(old_sa);
	new_ike_sa_id = new_sa->get_unique_id(new_sa);
	DBG2(DBG_IKE, "%s: Rekeying IKE SA %u to IKE SA %u", __FUNCTION__,
		old_ike_sa_id, new_ike_sa_id);

	/* We need to know about the IKE SA rekeys so that the associated tunnel
	 * object can be updated to reflect the new SA id. This will prevent the
	 * tunnel from being accidentally deleted when the virtual IP is removed
	 * from the old SA.
	 */
	status = this->ipsec->migrate_tunnel(this->ipsec, old_ike_sa_id,
		new_ike_sa_id);
	if (status != SUCCESS)
	{
		DBG2(DBG_IKE, "%s: Failed to migrate tunnel for IKE SA %u to %u",
			__FUNCTION__, old_ike_sa_id, new_ike_sa_id);
	}

	/* NOTE: TRUE does not indicate success here. Rather, it indicates that
	 * this handler should remain registered to be called again at a future
	 * point.
	 */
	return TRUE;
}

METHOD(listener_t, ike_reestablish_pre, bool, private_fsm_listener_t *this,
	ike_sa_t *old_sa, ike_sa_t *new_sa)
{
	status_t status = FAILED;
	u_int32_t old_ike_sa_id = 0;
	u_int32_t new_ike_sa_id = 0;

	DBG2(DBG_IKE, "Entering %s in fsm_listener", __FUNCTION__);

	if (!old_sa || !this || !this->ipsec || !new_sa)
	{
		/* NOTE: TRUE does not indicate success here. Rather, it indicates that
		 * this handler should remain registered to be called again at a future
		 * point.
		 */
		return TRUE;
	}

	old_ike_sa_id = old_sa->get_unique_id(old_sa);
	new_ike_sa_id = new_sa->get_unique_id(new_sa);
	DBG2(DBG_IKE, "%s: Reestablishing IKE SA %u as IKE SA %u", __FUNCTION__,
		old_ike_sa_id, new_ike_sa_id);

	/* We need to know about the IKE SA reauths so that the associated tunnel
	 * object can be updated to reflect the new SA id. This will prevent the
	 * tunnel from being accidentally deleted when the virtual IP is removed
	 * from the old SA. It will also prevent an unnecessary new tunnel from
	 * being created.
	 */
	status = this->ipsec->migrate_tunnel(this->ipsec, old_ike_sa_id,
		new_ike_sa_id);
	if (status != SUCCESS)
	{
		DBG2(DBG_IKE, "%s: Failed to migrate tunnel for IKE SA %u to %u",
			__FUNCTION__, old_ike_sa_id, new_ike_sa_id);
	}

	/* NOTE: TRUE does not indicate success here. Rather, it indicates that
	 * this handler should remain registered to be called again at a future
	 * point.
	 */
	return TRUE;
}

METHOD(fsm_listener_t, destroy, void, private_fsm_listener_t *this)
{
	DBG2(DBG_IKE, "Entering %s in fsm_listener", __FUNCTION__);

	if (!this)
	{
		return;
	}

	free(this);
}

/**
 * See header
 */
fsm_listener_t *fsm_listener_create(fsm_kernel_ipsec_t *ipsec)
{
	private_fsm_listener_t *this = NULL;

	DBG2(DBG_IKE, "Entering %s in fsm_listener", __FUNCTION__);

	if (!ipsec)
	{
		return NULL;
	}

	INIT(this,
		.public =
		{
			.listener =
			{
				.authorize = _authorize,
				.handle_vips = _handle_vips,
				.ike_rekey = _ike_rekey,
				.ike_reestablish_pre = _ike_reestablish_pre,
			},
			.destroy = _destroy,
		},
		.ipsec = ipsec,
		);

	if (!this)
	{
		return NULL;
	}

	return &this->public;
}
