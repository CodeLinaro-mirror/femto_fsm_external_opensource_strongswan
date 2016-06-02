ipsec_PROGRAMS = fsm_privkey

fsm_privkey_SOURCES = \
	fsm_privkey.c \
	../../src/fsm_command.c \
	../../src/fsm_utils.c \
	commands/fsm_provision.c \
	commands/fsm_encrypt.c

fsm_privkey.o : $(top_builddir)/config.status

fsm_privkey_CFLAGS = \
	-Wall -Werror -MD -MP \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon \
	-I$(top_srcdir)/src/charon-fsm/include \
	-DIPSEC_DIR=\"${ipsecdir}\" \
	-DIPSEC_PIDDIR=\"${piddir}\"

fsm_privkey_LDFLAGS = $(QCT_LDFLAGS)

fsm_privkey_LDADD = \
	$(top_builddir)/src/libcharon/libcharon.la \
	$(top_builddir)/src/libhydra/libhydra.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	-lm -lQsecureFsmApi -lQsecureIkeApi \
	$(PTHREADLIB) $(DLLIB)
