#!/bin/sh
set -e

test -d m4 || mkdir m4
gtkdocize || exit 1

autoreconf -fi

run_configure=true
for arg in $*; do
    case $arg in
        --no-configure)
            run_configure=false
            ;;
        *)
            ;;
    esac
done

test -n "$NOCONFIGURE" && {
  echo "skipping configure stage for package libnice, as requested."
  echo "autogen.sh done."
  exit 0
}

if test $run_configure = true; then
    ./configure "$@"
fi
