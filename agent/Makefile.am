#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

include $(top_srcdir)/common.mk
include $(top_srcdir)/common-modified/gst-glib-gen.mak

libagentincludedir = $(includedir)/agent

public_headers = agent.h \
	address.h \
	candidate.h \
	component.h \
	stream.h

glib_enum_headers=$(public_headers)
glib_enum_define=AGENT
glib_gen_prefix=_agent
glib_gen_basename=agent

AM_CFLAGS = \
	-DG_LOG_DOMAIN=\"libnice\" \
	$(ERROR_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GUPNP_CFLAGS) \
	-I $(top_srcdir) \
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/socket \
	-I $(top_srcdir)/stun

if WINDOWS
  AM_CFLAGS += -DWINVER=0x0501 # _WIN32_WINNT_WINXP
endif

noinst_LTLIBRARIES = libagent.la

nodist_libagentinclude_HEADERS = \
		agent-enumtypes.h

nodist_libagent_la_SOURCES = \
	agent-enumtypes.c

BUILT_SOURCES = \
	$(nodist_libagentinclude_HEADERS)

CLEANFILES += $(BUILT_SOURCES)

libagent_la_SOURCES = \
	address.h \
	address.c \
	debug.h \
	debug.c \
	candidate.h \
	candidate.c \
	component.h \
	component.c \
	agent.h \
	agent-priv.h \
	agent.c \
	stream.h \
	stream.c \
	conncheck.c \
	conncheck.h \
	discovery.c \
	discovery.h \
	interfaces.c \
	interfaces.h \
	$(BUILT_SOURCES)

libagent_la_LIBADD = \
	$(top_builddir)/random/libnice-random.la \
	$(top_builddir)/socket/libsocket.la \
	$(top_builddir)/stun/libstun.la
libagent_la_DEPENDENCIES = \
	$(top_builddir)/random/libnice-random.la \
	$(top_builddir)/socket/libsocket.la \
	$(top_builddir)/stun/libstun.la

pkginclude_HEADERS = \
	agent.h \
	candidate.h \
	debug.h \
	address.h \
	interfaces.h

if WINDOWS
  libagent_la_LIBADD += -liphlpapi -lws2_32
endif
