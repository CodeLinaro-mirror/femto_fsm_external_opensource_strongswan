/*
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials provided
 *       with the distribution.
 *     * Neither the name of The Linux Foundation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <net/if.h>
#include <utils/debug.h>
#include <utils/utils.h>
#include <utils/chunk.h>

#include "fsm_utils.h"

bool has_sign_byte(chunk_t chunk)
{
	bool result = FALSE;

	if ((chunk.len % 2) && (chunk.len > 1))
	{
		if (!(chunk.ptr[0]) && (chunk.ptr[1] & 0x80))
		{
			result = TRUE;
		}
	}

	return result;
}

status_t copy_ifname(char *dst_ifname, char *src_ifname)
{
	status_t status = SUCCESS;
	size_t ifname_len = 0;

	if (!dst_ifname || !src_ifname)
	{
		return INVALID_ARG;
	}

	ifname_len = strlen(src_ifname);
	if (ifname_len > IFNAMSIZ)
	{
		ifname_len = IFNAMSIZ;
	}
	memcpy(dst_ifname, src_ifname, ifname_len);

	/* Terminate the ifname properly */
	if (ifname_len == IFNAMSIZ)
	{
		dst_ifname[IFNAMSIZ - 1] = '\0';
	}
	else
	{
		dst_ifname[ifname_len] = '\0';
	}

	return status;
}
