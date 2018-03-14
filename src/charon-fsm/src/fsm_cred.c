/*
 * Copyright (c) 2016, 2018, The Linux Foundation. All rights reserved.
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

#include <credentials/sets/mem_cred.h>
#include <collections/hashtable.h>
#include <threading/rwlock.h>
#include <utils/debug.h>

#include "fsm_private_key.h"
#include "fsm_cred.h"

typedef struct private_fsm_cred_t private_fsm_cred_t;

/**
 * Private data of a fsm_cred_t object.
 */
struct private_fsm_cred_t
{

	/**
	 * Public fsm_cred_t interface.
	 */
	fsm_cred_t public;

	/**
	 * In-memory credential set.
	 */
	mem_cred_t *creds;

	/**
	 * Key-id hashtable.
	 */
	hashtable_t *known_keys;

	/**
	 * rwlock for hashtable.
	 */
	rwlock_t *lock;

};

METHOD(credential_set_t, create_private_enumerator, enumerator_t *,
	private_fsm_cred_t *this, key_type_t type, identification_t *id)
{
	identification_t *entry;

	DBG2(DBG_IKE, "Entering %s in fsm_cred", __FUNCTION__);

	if (!this)
	{
		DBG1(DBG_IKE, "%s: Error: Invalid arguments!", __FUNCTION__);
		return NULL;
	}

	if (!this->known_keys || !this->creds || !this->lock)
	{
		DBG1(DBG_IKE, "%s: Error: Invalid arguments!", __FUNCTION__);
		return NULL;
	}

	if (!id)
	{
		return this->known_keys->create_enumerator(this->known_keys);
	}

	this->lock->write_lock(this->lock);
	entry = this->known_keys->get(this->known_keys, id);

	if (!entry)
	{
		identification_t *clone = id->clone(id);
		fsm_private_key_t *key = fsm_private_key_init(id);

		DBG2(DBG_IKE, "%s: adding private key for id '%Y'",
			__FUNCTION__, clone);
		if (!key)
		{
			DBG2(DBG_IKE, "%s: Error: unable to create private key for id '%Y'",
				__FUNCTION__, clone);
			this->lock->unlock(this->lock);
			return NULL;
		}
		this->creds->add_key(this->creds, (private_key_t *)key);
		entry = this->known_keys->put(this->known_keys, clone, clone);
	}
	this->lock->unlock(this->lock);

	return this->creds->set.create_private_enumerator(&this->creds->set,
		type, id);
}

METHOD(fsm_cred_t, destroy, void, private_fsm_cred_t *this)
{
	enumerator_t *enumerator;
	identification_t *entry = NULL;

	if (!this)
	{
		DBG1(DBG_IKE, "%s: Error: Invalid arguments!", __FUNCTION__);
		return;
	}

	if (this->known_keys != NULL)
	{
		enumerator = this->known_keys->create_enumerator(this->known_keys);
		if (enumerator)
		{
			while (enumerator->enumerate(enumerator, NULL, &entry))
			{
				DESTROY_IF(entry);
			}
			enumerator->destroy(enumerator);
		}
		this->known_keys->destroy(this->known_keys);
	}

	DESTROY_IF(this->creds);
	DESTROY_IF(this->lock);
	free(this);
}

/**
 * Hashtable hash function.
 */
static u_int hash(identification_t *id)
{
	return chunk_hash(id->get_encoding(id));
}

/**
 * Hashtable equals function.
 */
static bool equals(identification_t *a, identification_t *b)
{
	return a->equals(a, b);
}

/**
 * See header
 */
fsm_cred_t *fsm_cred_create(void)
{
	private_fsm_cred_t *this = NULL;

	INIT(this,
		.public =
		{
			.set =
			{
				.create_shared_enumerator = (void*)return_null,
				.create_private_enumerator = _create_private_enumerator,
				.create_cert_enumerator = (void*)return_null,
				.create_cdp_enumerator = (void*)return_null,
				.cache_cert = (void*)nop,
			},
			.destroy = _destroy,
		},
		.creds = mem_cred_create(),
		.lock = rwlock_create(RWLOCK_TYPE_DEFAULT),
		.known_keys = hashtable_create((hashtable_hash_t)hash,
			(hashtable_equals_t)equals, 4),
		);

	if (!this)
	{
		DBG1(DBG_IKE, "%s: Error: Failed to create this!", __FUNCTION__);
		return NULL;
	}

	if (!this->creds || !this->lock || !this->known_keys)
	{
		DBG1(DBG_IKE, "%s: Error: Failed to allocate objects!", __FUNCTION__);
		return NULL;
	}

	return &this->public;
}
