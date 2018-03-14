/*
 * Copyright (c) 2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2013 Tobias Brunner
 * Hochschule fuer Technik Rapperswil
 *
 * Copyright (C) 2010 Martin Willi
 * Copyright (C) 2010 revosec AG
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
 * @defgroup fsm_aead fsm_aead
 * @{ @ingroup crypto
 */

#ifndef FSM_AEAD_H_
#define FSM_AEAD_H_

#include <stddef.h>
#include <utils/utils/types.h>
#include <library.h>
#include <crypto/aead.h>
#include <crypto/crypters/crypter.h>
#include <crypto/signers/signer.h>

typedef struct fsm_aead_t fsm_aead_t;

/**
 * Authenticated encryption / authentication decryption interface.
 */
struct fsm_aead_t
{
	aead_t aead;
};

/**
 * Create a fsm_aead instance.
 *
 * @param ike_sa_id		IKE SA id
 * @param enc_alg		encryption algorithm
 * @param enc_size		encryption size
 * @param int_alg		integrity algorithm
 * @param initiator		whether this is the initiator or responder
 * @return				fsm_aead_t
 */
fsm_aead_t *fsm_aead_create(uint8_t ike_sa_id, encryption_algorithm_t enc_alg,
	size_t enc_size, integrity_algorithm_t int_alg, bool initiator);

#endif /** FSM_AEAD_H_ @}*/
