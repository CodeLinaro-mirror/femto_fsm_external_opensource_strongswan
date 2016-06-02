ipsec_PROGRAMS = fsm_tests

fsm_tests_SOURCES = \
	fsm_tests.c \
	../src/fsm_command.c \
	commands/fsm_sign.c \
	commands/fsm_validate.c \
	../src/fsm_utils.c \
	../src/fsm_cred.c \
	../src/fsm_private_key.c \
	../src/fsm_public_key.c

fsm_tests.o : $(top_builddir)/config.status

fsm_tests_CFLAGS = \
	-Wall -Werror -MD -MP \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libhydra \
	-I$(top_srcdir)/src/libcharon \
	-I$(top_srcdir)/src/charon-fsm/include \
	-DIPSEC_DIR=\"${ipsecdir}\" \
	-DIPSEC_PIDDIR=\"${piddir}\" \
	-DPLUGINS=\""${charon_plugins}\""

fsm_tests_LDFLAGS = $(QCT_LDFLAGS)

fsm_tests_LDADD = \
	$(top_builddir)/src/libcharon/libcharon.la \
	$(top_builddir)/src/libhydra/libhydra.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la \
	-lm -lQsecureFsmApi -lQsecureIkeApi \
	$(PTHREADLIB) $(DLLIB)
