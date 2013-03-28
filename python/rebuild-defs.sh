#!/bin/sh

HEADERS=" \
    agent.h \
    candidate.h \
    "

srcdir=../agent/

output=pylibnice.defs
filter=pylibnice-filter.defs

cat ${filter} > ${output}

H2DEF="$(pkg-config --variable=codegendir pygobject-2.0)/h2def.py"
[ -z "${H2DEF}" ] && H2DEF="$(pkg-config --variable=codegendir pygtk-2.0)/h2def.py"
[ -z "${H2DEF}" -a -f /usr/share/pygtk/2.0/codegen/h2def.py ] && H2DEF=/usr/share/pygtk/2.0/codegen/h2def.py

for h in $HEADERS; do
    python ${H2DEF} --defsfilter=${filter} ${srcdir}/$h >> $output
done

