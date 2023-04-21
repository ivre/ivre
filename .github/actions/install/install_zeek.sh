#! /bin/bash

# This file is part of IVRE.
# Copyright 2011 - 2022 Pierre LALET <pierre@droids-corp.org>
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

zeek_v[0]="3.0.6"
zeek_v[1]="3.1.3"
zeek_v[2]="3.2.4"
zeek_v[3]="4.0.3"
ZEEK_VERSION="${zeek_v[ $RANDOM % 4 ]}"
unset zeek_v
echo "ZEEK_VERSION: ${ZEEK_VERSION}"

if [ "${ZEEK_VERSION:0:2}" = "4." ]; then
    cat tests/samples/results_zeek_v4 >> tests/samples/results
fi

UBUNTU_VERSION="$(awk -F = '/^DISTRIB_RELEASE=/ {print $2}' /etc/lsb-release)"
echo "UBUNTU_VERSION: ${UBUNTU_VERSION}"

# shellcheck disable=SC2066
for archive in "zeek-${ZEEK_VERSION}_ubuntu-${UBUNTU_VERSION}"; do
    wget -q --no-check-certificate "https://ivre.rocks/data/tests/${archive}.tar.bz2" -O - | tar jxf -
done

# shellcheck disable=SC2066
for path_val in "$(pwd)/usr/local/zeek/bin"; do
    echo "$path_val" >> "$GITHUB_PATH"
    export PATH="$path_val:$PATH"
done

for env_val in "ZEEKPATH=.:$(pwd)/usr/local/zeek/share/zeek:$(pwd)/usr/local/zeek/share/zeek/policy:$(pwd)/usr/local/zeek/share/zeek/site" "ZEEKSAMPLES=$(pwd)/usr/local/zeek/testing"; do
    echo "$env_val" >> "$GITHUB_ENV"
    export "${env_val?}"
done

LD_LIBRARY_PATH="$(pwd)/usr/local/zeek/lib" zeek --version
