/*
 * Copyright (c) 2016, The Linux Foundation. All rights reserved.
 * Copyright (C) 2013 Tobias Brunner
 * Copyright (C) 2008 Martin Willi
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

#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <utils/process.h>
#include <hydra.h>
#include <daemon.h>
#include <config/child_cfg.h>
#include <library.h>
#include <encoding/payloads/auth_payload.h>
#include <utils/utils.h>
#include <utils/debug.h>
#include <utils/chunk.h>

#include "fsm_listener.h"
#include "fsm_kernel_ipsec.h"
#include "fsm_updown_handler.h"

typedef struct private_fsm_listener_t private_fsm_listener_t;
typedef struct cache_entry_t cache_entry_t;

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

	/**
	 * List of cached interface names
	 */
	linked_list_t *iface_cache;

	/**
	 * DNS attribute handler
	 */
	fsm_updown_handler_t *handler;
};

/**
 * Cache line in the interface name cache.
 */
struct cache_entry_t
{
	/** requid of the CHILD_SA */
	u_int32_t reqid;

	/** cached interface name */
	char *iface;
};


/**
 * Allocate and push a format string to the environment
 */
static bool push_env(char *envp[], u_int count, char *fmt, ...)
{
	uint32_t i = 0;
	char *str;
	va_list args;

	while (envp[i])
	{
		if (++i + 1 >= count)
		{
			return FALSE;
		}
	}
	va_start(args, fmt);
	if (vasprintf(&str, fmt, args) >= 0)
	{
		envp[i] = str;
	}
	va_end(args);
	return envp[i] != NULL;
}

/**
 * Free all allocated environment strings
 */
static void free_env(char *envp[])
{
	int i;

	for (i = 0; envp[i]; i++)
	{
		free(envp[i]);
	}
}

/**
 * Push variables for handled DNS attributes
 */
static void push_dns_env(private_fsm_listener_t *this, ike_sa_t *ike_sa,
	char *envp[], u_int count)
{
	enumerator_t *enumerator;
	host_t *host;
	int v4 = 0, v6 = 0;

	if (this->handler)
	{
		enumerator = this->handler->create_dns_enumerator(this->handler,
			ike_sa->get_unique_id(ike_sa));
		while (enumerator->enumerate(enumerator, &host))
		{
			switch (host->get_family(host))
			{
				case AF_INET:
					push_env(envp, count, "PLUTO_DNS4_%d=%H", ++v4, host);
					break;
				case AF_INET6:
					push_env(envp, count, "PLUTO_DNS6_%d=%H", ++v6, host);
					break;
				default:
					continue;
			}
		}
		enumerator->destroy(enumerator);
	}
}

/**
 * Push variables for local/remote virtual IPs
 */
static void push_vip_env(private_fsm_listener_t *this, ike_sa_t *ike_sa,
	char *envp[], u_int count, bool local)
{
	enumerator_t *enumerator;
	host_t *host;
	int v4 = 0, v6 = 0;
	bool first = TRUE;

	/* This is to avoid compiler warnings about unused parameters */
	(void)this;

	enumerator = ike_sa->create_virtual_ip_enumerator(ike_sa, local);
	while (enumerator->enumerate(enumerator, &host))
	{
		if (first)
		{	/* legacy variable for first VIP */
			first = FALSE;
			push_env(envp, count, "PLUTO_%s_SOURCEIP=%H",
					 local ? "MY" : "PEER", host);
		}
		switch (host->get_family(host))
		{
			case AF_INET:
				push_env(envp, count, "PLUTO_%s_SOURCEIP4_%d=%H",
						 local ? "MY" : "PEER", ++v4, host);
				break;
			case AF_INET6:
				push_env(envp, count, "PLUTO_%s_SOURCEIP6_%d=%H",
						 local ? "MY" : "PEER", ++v6, host);
				break;
			default:
				continue;
		}
	}
	enumerator->destroy(enumerator);
}

/**
 * Determine proper values for port env variable
 */
static u_int16_t get_port(traffic_selector_t *me, traffic_selector_t *other,
	bool local)
{
	switch (max(me->get_protocol(me), other->get_protocol(other)))
	{
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
		{
			u_int16_t port = me->get_from_port(me);

			port = max(port, other->get_from_port(other));
			return local ? traffic_selector_icmp_type(port)
						 : traffic_selector_icmp_code(port);
		}
	}
	return local ? me->get_from_port(me) : other->get_from_port(other);
}

/**
 * Insert an interface name to the cache
 */
static void cache_iface(private_fsm_listener_t *this, u_int32_t reqid,
	char *iface)
{
	cache_entry_t *entry = NULL;

	if (!this || !this->iface_cache)
	{
		return;
	}

	entry = malloc_thing(cache_entry_t);
	if (entry)
	{
		entry->reqid = reqid;
		entry->iface = strdup(iface);

		this->iface_cache->insert_first(this->iface_cache, entry);
	}
}

/**
 * Remove a cached interface name and return it.
 */
static char *uncache_iface(private_fsm_listener_t *this, u_int32_t reqid)
{
	enumerator_t *enumerator;
	cache_entry_t *entry;
	char *iface = NULL;

	if (!this || !this->iface_cache)
	{
		return NULL;
	}

	enumerator = this->iface_cache->create_enumerator(this->iface_cache);
	if (enumerator)
	{
		while (enumerator->enumerate(enumerator, &entry))
		{
			if (entry->reqid == reqid)
			{
				this->iface_cache->remove_at(this->iface_cache, enumerator);
				iface = entry->iface;
				free(entry);
				break;
			}
		}
		enumerator->destroy(enumerator);
	}

	return iface;
}

/**
 * Invoke the updown script once for given traffic selectors
 */
static void invoke_once(private_fsm_listener_t *this, ike_sa_t *ike_sa,
	child_sa_t *child_sa, child_cfg_t *config, bool up,
	traffic_selector_t *my_ts, traffic_selector_t *other_ts, char *iface)
{
	host_t *me, *other, *host;
	u_int8_t mask;
	mark_t mark;
	bool is_host, is_ipv6;
	int out;
	FILE *shell;
	process_t *process;
	char *envp[128] = {};

	me = ike_sa->get_my_host(ike_sa);
	other = ike_sa->get_other_host(ike_sa);

	push_env(envp, countof(envp), "PATH=%s", getenv("PATH"));
	push_env(envp, countof(envp), "PLUTO_VERSION=1.1");
	is_host = my_ts->is_host(my_ts, me);
	if (is_host)
	{
		is_ipv6 = me->get_family(me) == AF_INET6;
	}
	else
	{
		is_ipv6 = my_ts->get_type(my_ts) == TS_IPV6_ADDR_RANGE;
	}
	push_env(envp, countof(envp), "PLUTO_VERB=%s%s%s",
			 up ? "up" : "down",
			 is_host ? "-host" : "-client",
			 is_ipv6 ? "-v6" : "");
	push_env(envp, countof(envp), "PLUTO_CONNECTION=%s",
			 config->get_name(config));

	if (up)
	{
		if (iface)
		{
			cache_iface(this, child_sa->get_reqid(child_sa), iface);
		}
	}
	else
	{
		iface = uncache_iface(this, child_sa->get_reqid(child_sa));
	}

	push_env(envp, countof(envp), "PLUTO_INTERFACE=%s",
			 iface ? iface : "unknown");

	if (!up && iface)
	{
		/* Free the previously cached iface */
		free(iface);
	}

	push_env(envp, countof(envp), "PLUTO_REQID=%u",
			 child_sa->get_reqid(child_sa));
	push_env(envp, countof(envp), "PLUTO_PROTO=%s",
			 child_sa->get_protocol(child_sa) == PROTO_ESP ? "esp" : "ah");
	push_env(envp, countof(envp), "PLUTO_UNIQUEID=%u",
			 ike_sa->get_unique_id(ike_sa));
	push_env(envp, countof(envp), "PLUTO_ME=%H", me);
	push_env(envp, countof(envp), "PLUTO_MY_ID=%Y", ike_sa->get_my_id(ike_sa));
	if (my_ts->to_subnet(my_ts, &host, &mask))
	{
		push_env(envp, countof(envp), "PLUTO_MY_CLIENT=%+H/%u", host, mask);
		host->destroy(host);
	}

	push_env(envp, countof(envp), "PLUTO_MY_PORT=%u",
			 get_port(my_ts, other_ts, TRUE));
	push_env(envp, countof(envp), "PLUTO_MY_PROTOCOL=%u",
			 my_ts->get_protocol(my_ts));
	push_env(envp, countof(envp), "PLUTO_PEER=%H", other);
	push_env(envp, countof(envp), "PLUTO_PEER_ID=%Y",
			 ike_sa->get_other_id(ike_sa));
	if (other_ts->to_subnet(other_ts, &host, &mask))
	{
		push_env(envp, countof(envp), "PLUTO_PEER_CLIENT=%+H/%u", host, mask);
		host->destroy(host);
	}

	push_env(envp, countof(envp), "PLUTO_PEER_PORT=%u",
			 get_port(my_ts, other_ts, FALSE));
	push_env(envp, countof(envp), "PLUTO_PEER_PROTOCOL=%u",
			 other_ts->get_protocol(other_ts));
	if (ike_sa->has_condition(ike_sa, COND_EAP_AUTHENTICATED) ||
		ike_sa->has_condition(ike_sa, COND_XAUTH_AUTHENTICATED))
	{
		push_env(envp, countof(envp), "PLUTO_XAUTH_ID=%Y",
				 ike_sa->get_other_eap_id(ike_sa));
	}

	push_vip_env(this, ike_sa, envp, countof(envp), TRUE);
	push_vip_env(this, ike_sa, envp, countof(envp), FALSE);
	mark = config->get_mark(config, TRUE);
	if (mark.value)
	{
		push_env(envp, countof(envp), "PLUTO_MARK_IN=%u/0x%08x",
				 mark.value, mark.mask);
	}

	mark = config->get_mark(config, FALSE);
	if (mark.value)
	{
		push_env(envp, countof(envp), "PLUTO_MARK_OUT=%u/0x%08x",
				 mark.value, mark.mask);
	}

	if (ike_sa->has_condition(ike_sa, COND_NAT_ANY))
	{
		push_env(envp, countof(envp), "PLUTO_UDP_ENC=%u",
				 other->get_port(other));
	}

	if (child_sa->get_ipcomp(child_sa) != IPCOMP_NONE)
	{
		push_env(envp, countof(envp), "PLUTO_IPCOMP=1");
	}

	push_dns_env(this, ike_sa, envp, countof(envp));
	if (config->get_hostaccess(config))
	{
		push_env(envp, countof(envp), "PLUTO_HOST_ACCESS=1");
	}

	process = process_start_shell(envp, NULL, &out, NULL, "2>&1 %s",
		config->get_updown(config));
	if (process)
	{
		shell = fdopen(out, "r");
		if (shell)
		{
			while (TRUE)
			{
				char resp[128];

				if (fgets(resp, sizeof(resp), shell) == NULL)
				{
					if (ferror(shell))
					{
						DBG1(DBG_CHD,
							"fsm_updown: error reading from updown script");
					}
					break;
				}
				else
				{
					char *e = resp + strlen(resp);
					if (e > resp && e[-1] == '\n')
					{
						e[-1] = '\0';
					}
					DBG1(DBG_CHD, "fsm_updown: %s", resp);
				}
			}
			fclose(shell);
		}
		else
		{
			close(out);
		}
		process->wait(process, NULL);
	}
	free_env(envp);
}

METHOD(listener_t, child_updown, bool, private_fsm_listener_t *this,
	ike_sa_t *ike_sa, child_sa_t *child_sa, bool up)
{
	status_t status = SUCCESS;
	traffic_selector_t *my_ts, *other_ts;
	enumerator_t *enumerator;
	child_cfg_t *config;
	char *iface = NULL;

	if (!this || !ike_sa || !child_sa)
	{
		/* NOTE: TRUE does not indicate success here. Rather, it indicates that
		 * this handler should remain registered to be called again at a future
		 * point.
		 */
		return TRUE;
	}

	DBG2(DBG_IKE, "Entering %s in fsm_listener: IKE_SA %u CHILD_SA %u %s",
		__FUNCTION__, ike_sa->get_unique_id(ike_sa),
		child_sa->get_unique_id(child_sa), ((up) ? "up" : "down"));

	/* Retrieve the tunnel interface for the given IKE SA, if available */
	status = this->ipsec->get_tunnel_iface(this->ipsec,
		ike_sa->get_unique_id(ike_sa), &iface);
	if (status != SUCCESS)
	{
		iface = NULL;
	}

	config = child_sa->get_config(child_sa);
	if (config->get_updown(config))
	{
		enumerator = child_sa->create_policy_enumerator(child_sa);
		while (enumerator->enumerate(enumerator, &my_ts, &other_ts))
		{
			invoke_once(this, ike_sa, child_sa, config, up, my_ts, other_ts,
				iface);
		}
		enumerator->destroy(enumerator);
	}

	/* NOTE: TRUE does not indicate success here. Rather, it indicates that
	 * this handler should remain registered to be called again at a future
	 * point.
	 */
	return TRUE;
}

METHOD(listener_t, authorize, bool, private_fsm_listener_t *this,
	ike_sa_t *ike_sa, bool final, bool *success)
{
	bool result = TRUE;

	/* This is to avoid compiler warnings about unused parameters */
	(void)this;
	(void)ike_sa;

	DBG2(DBG_IKE, "Entering %s in fsm_listener", __FUNCTION__);

	if (!final)
	{
		/* NOTE: TRUE does not indicate success here. Rather, it indicates that
		 * this handler should remain registered to be called again at a future
		 * point.
		 */
		return TRUE;
	}

	DBG2(DBG_IKE, "%s: Received final auth hook", __FUNCTION__);

	/* TODO: Add additional validation here */

	*success = result;

	/* NOTE: TRUE does not indicate success here. Rather, it indicates that
	 * this handler should remain registered to be called again at a future
	 * point.
	 */
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

	if (this->handler)
	{
		charon->attributes->remove_handler(charon->attributes,
			&this->handler->handler);
		DESTROY_IF(this->handler);
	}

	DESTROY_IF(this->iface_cache);
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
				.child_updown = _child_updown,
			},
			.destroy = _destroy,
		},
		.ipsec = ipsec,
		.handler = NULL,
		.iface_cache = linked_list_create(),
		);

	if (!this || !this->iface_cache)
	{
		return NULL;
	}

	if (lib->settings->get_bool(lib->settings,
		"%s.plugins.updown.dns_handler", FALSE, lib->ns))
	{
		this->handler = fsm_updown_handler_create();
		if (this->handler)
		{
			charon->attributes->add_handler(charon->attributes,
				&this->handler->handler);
		}
	}

	return &this->public;
}
