
ERROR_CFLAGS = \
	$(LIBNICE_CFLAGS) \
	-fno-strict-aliasing \
	-Wextra \
	-Wundef \
	-Wnested-externs \
	-Wwrite-strings \
	-Wpointer-arith \
	-Wmissing-declarations \
	-Wmissing-prototypes \
	-Wstrict-prototypes \
	-Wredundant-decls \
	-Wno-unused-parameter \
	-Wno-missing-field-initializers \
	-Werror 
# -Wold-style-definition -Winline -Wunreachable-code

CLEANFILES = *.gcno *.gcda

pkgincludedir = $(includedir)/nice


check-valgrind:
	$(MAKE) TESTS_ENVIRONMENT="sh $$(cd "$(top_srcdir)" && pwd)/scripts/valgrind.sh" check

.PHONY: check-valgrind
