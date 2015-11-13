#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.

include $(top_srcdir)/common.mk

lib_LTLIBRARIES = libnice.la

libnice_la_SOURCES =
libnice_la_DEPENDENCIES = \
	$(top_builddir)/agent/libagent.la \
	libnice.sym

libnice_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GUPNP_LIBS) \
	$(top_builddir)/agent/libagent.la

libnice_la_LDFLAGS = \
	-export-symbols $(srcdir)/libnice.sym \
	$(LIBNICE_LT_LDFLAGS)


AM_CFLAGS = \
	$(ERROR_CFLAGS) \
	$(GLIB_CFLAGS) \
	-I $(top_srcdir) \
	-I $(top_srcdir)/agent \
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/socket \
	-I $(top_srcdir)/stun

test-symbols.sh::
	chmod +x $(srcdir)/$@

libnice-symbols-test.c: libnice.sym
	rm -f $@
	while read s; do echo "void $$s(void) { }" ; done < $? > $@

libnice-symbols-test.o: libnice-symbols-test.c
	$(CC) $(CFLAGS) -c -o $@ $?

libnice.symbols: libnice-symbols-test.o
	rm -f $@
	$(top_srcdir)/scripts/make-symbol-list.sh $? > $@

CLEANFILES += libnice.symbols libnice-symbols-test.c libnice-symbols-test.o

check_SCRIPTS = test-symbols.sh
check_DATA = libnice.symbols

TESTS = $(check_SCRIPTS)

EXTRA_DIST = $(check_SCRIPTS) libnice.sym libnice.ver

pkginclude_HEADERS = nice.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = nice.pc

#
# GObject introspection
#
# We need --accept-unprefixed because of PseudoTcp and TurnServer.
#
-include $(INTROSPECTION_MAKEFILE)
INTROSPECTION_GIRS =
INTROSPECTION_SCANNER_ARGS = --add-include-path=$(srcdir) --warn-all --accept-unprefixed
INTROSPECTION_COMPILER_ARGS = --includedir=$(srcdir)

gir_headers = \
	$(top_srcdir)/agent/address.h \
	$(top_srcdir)/agent/agent.h \
	$(top_srcdir)/agent/candidate.h \
	$(top_srcdir)/agent/debug.h \
	$(top_srcdir)/agent/interfaces.h

gir_sources = \
	$(top_srcdir)/agent/address.c \
	$(top_srcdir)/agent/agent.c \
	$(top_srcdir)/agent/candidate.c \
	$(top_srcdir)/agent/debug.c \
	$(top_srcdir)/agent/interfaces.c

if HAVE_INTROSPECTION
introspection_sources = $(gir_headers) $(gir_sources)

Nice-0.1.gir: libnice.la
Nice_0_1_gir_INCLUDES = GObject-2.0 Gio-2.0
Nice_0_1_gir_EXPORT_PACKAGES = nice
Nice_0_1_gir_CFLAGS = $(AM_CFLAGS)
Nice_0_1_gir_LIBS = libnice.la
Nice_0_1_gir_FILES = $(introspection_sources)
INTROSPECTION_GIRS += Nice-0.1.gir

girdir = $(datadir)/gir-1.0
gir_DATA = $(INTROSPECTION_GIRS)

typelibdir = $(libdir)/girepository-1.0
typelib_DATA = $(INTROSPECTION_GIRS:.gir=.typelib)

CLEANFILES += $(gir_DATA) $(typelib_DATA)
endif
