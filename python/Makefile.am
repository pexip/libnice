PYDEFS=`pkg-config --variable=defsdir pygobject-2.0`
GSTPYDEFS=`pkg-config --variable=defsdir gst-python-0.10`
PYOBJECT_CFLAGS=`pkg-config --cflags pygobject-2.0`

AM_CFLAGS = \
	-I.						\
	-I$(top_srcdir)/gst-libs/			\
	-DG_LOG_DOMAIN=\"libnice\" \
	$(ERROR_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GUPNP_CFLAGS) \
	$(PYTHON_INCLUDES)				\
	$(PYOBJECT_CFLAGS) \
	-I $(top_srcdir) \
	-I $(top_srcdir)/random \
	-I $(top_srcdir)/socket \
	-I $(top_srcdir)/stun	\
	-I $(top_srcdir)/agent

BUILT_SOURCES =						\
	pylibnice.c					 

pylibnicedir = $(pyexecdir)
pylibnice_LTLIBRARIES = libnice.la

libnice_la_SOURCES =					\
	pylibnicemodule.c

nodist_libnice_la_SOURCES = pylibnice.c

libnice_la_LIBADD =					\
	$(PYLIBNICE_LIBS)				\
	$(top_builddir)/nice/libnice.la

libnice_la_LDFLAGS = -module -avoid-version

pylibnice.c: pylibnice.override pylibnice.defs
	$(PYCODEGEN)						\
		--prefix libnice				\
		--register $(GSTPYDEFS)/gst-types.defs		\
		--override $(srcdir)/pylibnice.override	\
		$(srcdir)/pylibnice.defs > $@ 

EXTRA_DIST =			\
	pylibnice.override	\
	pylibnice.defs		\
	pylibnice-filter.defs  \
	rebuild-defs.sh

CLEANFILES = $(BUILT_SOURCES)
