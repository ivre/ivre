#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2021 Pierre LALET <pierre@droids-corp.org>
#
# IVRE is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# IVRE is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with IVRE. If not, see <http://www.gnu.org/licenses/>.

"""This sub-module is responsible for generating Nmap agents."""


from ivre import nmapopt


AGENT_TEMPLATE = """#! /bin/sh

# This file is part of IVRE.
# Copyright 2011 - 2021 Pierre LALET <pierre@droids-corp.org>
#
# IVRE is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# IVRE is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with IVRE. If not, see <http://www.gnu.org/licenses/>.

SLEEP="sleep 2"
THREADS=10
STOREDOWN="true"

INDIR=./input/
CURDIR=./cur/
OUTDIR=./output/
ERRORDIR=./error/
DATADIR=./data/

filter () {
    %(filter)s
}

scan () {
    %(scan)s -iL - -oX -
}

_get_screenshots () {
    fname="$1"
    bzgrep -o 'output=\"Saved to [^\"]*\"' "$fname" | \\
        sed 's#^output="Saved to ##;s#"$##'
}

post_scan () {
    fname="$1"

    if [ "$STOREDOWN" = "true" ] || bzgrep -qF '<status state="up"' \\
             "$CURDIR/$fname.xml.bz2"; then
        # find screenshots
        OIFS="$IFS"
        IFS=$'\n'
        set -- `_get_screenshots "$CURDIR/$fname.xml.bz2"`
        IFS="$OIFS"
        tar cf "$DATADIR/$fname.tar" "$@" 2>/dev/null
        rm -f -- "$@"
        mv "$CURDIR/$fname.xml.bz2" "$OUTDIR"
    else
        rm -f "$CURDIR/$fname.xml.bz2"
    fi
    rm -f "$CURDIR/$fname"
}

someone_alive () {
    pids=$1
    for pid in $pids; do
        # Is $pid alive?
        kill -0 $pid 2> /dev/null && return 0
    done

    # Everyone is dead
    return 1
}

mkdir -p "$INDIR" "$CURDIR" "$OUTDIR" "$ERRORDIR" "$DATADIR"

# master
if [ -z "$IVRE_WORKER" ]; then
    master_prompt="[master     ] "

    # clean children on exit
    trap "trap - TERM INT EXIT; echo '${master_prompt}shutting down' >&2;\\
          pkill -g 0; exit" TERM INT EXIT

    echo "${master_prompt}spawning $THREADS workers" >&2
    export IVRE_WORKER=1
    worker_pids=""
    for i in `seq 1 $THREADS`; do
        worker_prompt="[worker `printf %%-4d $i`] "
        ("$0" "$@" 2>&1 | sed -u "s/^/$worker_prompt/") &
        worker_pids="$! $worker_pids"
    done
    unset IVRE_WORKER

    # handle wait interruptions (any non terminating signal)
    while someone_alive $worker_pids; do
        wait
    done

    exit 0
fi

# worker
echo "worker ready" >&2

while true; do
    [ -f "want_down" ] && break
    fname=`ls -rt "$INDIR" | head -1`
    if [ -z "$fname" ]; then
        $SLEEP
        continue
    fi
    if ! mv "$INDIR/$fname" "$CURDIR/" 2> /dev/null; then
        continue
    fi
    echo "scan $fname" >&2

    if ! (filter < "$CURDIR/$fname" | scan | bzip2 > "$CURDIR/$fname.xml.bz2");
    then
        mv "$CURDIR/$fname.xml.bz2" "$ERRORDIR/$fname-`date +%%s`.xml.bz2"
        cp "$CURDIR/$fname" "$ERRORDIR/$fname-`date +%%s`"
        mv "$CURDIR/$fname" "$INDIR/"
        $SLEEP
        echo "error with $fname" >&2
    else
        post_scan "$fname"
        echo "done $fname" >&2
    fi
done
"""


FILTERS = {
    # This basic filter strips out comments, but one can add here more
    # sophisticaed filters (including network probes). This can be
    # useful to avoid time-consuming honeypots.
    "none": "sed 's/ *#.*//'",
}


def build_agent(filtername: str = "none", template: str = "default") -> str:
    """Build an agent shell script (returned as  a string)."""
    return AGENT_TEMPLATE % {
        "filter": FILTERS[filtername],
        "scan": nmapopt.build_nmap_commandline(template=template),
    }
