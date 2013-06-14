#
# Makefile.am for the Nice Glib ICE library
#
# (C) 2006, 2007 Collabora Ltd.
# (C) 2006, 2007 Nokia Corporation. All rights reserved.
#
# Licensed under MPL 1.1/LGPL 2.1. See file COPYING.
#

include $(top_srcdir)/common.mk
include $(top_srcdir)/common-modified/gst-glib-gen.mak
AM_CFLAGS = -std=gnu99 $(ERROR_CFLAGS) $(GLIB_CFLAGS)
AM_CPPFLAGS = -I$(top_srcdir) 

bin_PROGRAMS = stunbdc stund

check_PROGRAMS = stund

stund_SOURCES = stund.c stund.h
stund_LDADD = $(top_builddir)/stun/libstun.la $(GLIB_LIBS)

stunbdc_SOURCES = stunbdc.c 

stunbdc_LDADD = $(top_builddir)/stun/libstun.la $(GLIB_LIBS)


if WINDOWS
  AM_CFLAGS += -DWINVER=0x0501 # _WIN32_WINNT_WINXP
  stunbdc_LDADD += -lws2_32
endif
