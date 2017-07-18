ipsec_PROGRAMS = charon-fsm
ipsec_SCRIPTS = scripts/fsm_updown

charon_fsm_SOURCES = \
	src/charon-fsm.c \
	src/fsm_utils.c \
	src/fsm_cred.c \
	src/fsm_listener.c \
	src/fsm_private_key.c \
	src/fsm_public_key.c \
	src/fsm_kernel_shared.c \
	src/fsm_kernel_net.c \
	src/fsm_kernel_ipsec.c \
	src/fsm_netlink_sock.c \
	src/fsm_netlink_crypto.c \
	src/fsm_netlink_ip.c \
	src/fsm_netlink_ipsec.c \
	src/fsm_updown_handler.c

charon-fsm.o :	$(top_builddir)/config.status

AM_CPPFLAGS = \
	$(QCT_CPPFLAGS) -Wextra -MMD -MP \
	-I$(SYSROOT)/usr/include/libnl3 \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon \
	-I$(top_srcdir)/src/charon-fsm/include \
	-DIPSEC_DIR=\"${ipsecdir}\" \
	-DIPSEC_PIDDIR=\"${piddir}\" \
	-DPLUGINS=\""${charon_plugins}\"" \
	-DROUTING_TABLE=${routing_table} \
	-DROUTING_TABLE_PRIO=${routing_table_prio}

AM_CFLAGS = \
	$(QCT_CFLAGS) \
	$(PLUGIN_CFLAGS) \
	-Wno-strict-prototypes -Wno-missing-declarations

AM_LDFLAGS = $(QCT_LDFLAGS)

charon_fsm_LDADD = \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	$(top_builddir)/src/libhydra/libhydra.la \
	$(top_builddir)/src/libcharon/libcharon.la \
	-lm -lQsecureFsmApi -lQsecureIkeApi -lnl-3 -lnl-genl-3 \
	$(PTHREADLIB) $(DLLIB) $(QCT_LIBDIRS)

SUBDIRS = .
SUBDIRS += tests tools/fsm_privkey
