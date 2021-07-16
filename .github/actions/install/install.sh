#! /bin/bash

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

sudo apt-get -qy install tesseract-ocr tesseract-ocr-osd tesseract-ocr-eng phantomjs
pip install coverage codecov
pip install .
mv ivre ivre_bak
cat .travis/ivre.conf >> ~/.ivre.conf
echo "NMAP_SHARE_PATH = '`pwd`/usr/local/nmap/share/nmap'" >> ~/.ivre.conf
echo "WIRESHARK_SHARE_PATH = '`pwd`/usr/local/wireshark/share/wireshark'" >> ~/.ivre.conf
mkdir -p usr/local/wireshark/share/wireshark
wget -q https://raw.githubusercontent.com/wireshark/wireshark/master/manuf -O usr/local/wireshark/share/wireshark/manuf
wget -q -O - https://github.com/ivre/ivre-test-samples/archive/0951ba6fc0eee158546e04fbce84c560950023d6.tar.gz | tar --transform='s#^ivre-test-samples-[^/]*/*#./#' -zxf -

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

UBUNTU_VERSION="`awk -F = '/^DISTRIB_RELEASE=/ {print $2}' /etc/lsb-release`"
echo "UBUNTU_VERSION: ${UBUNTU_VERSION}"

for archive in tools-travis-ivre zeek-${ZEEK_VERSION}_ubuntu-${UBUNTU_VERSION} nmap-7.91_ubuntu-${UBUNTU_VERSION} nfdump-1.6.17; do
    wget -q --no-check-certificate https://ivre.rocks/data/tests/${archive}.tar.bz2 -O - | tar jxf -
done

mv tests/geoip/GeoLite2-{ASN,City,Country,RegisteredCountry}.dump-IPv4.csv.bz2 `python -c 'from ivre import config; print(config.GEOIP_PATH)'`; bunzip2 "/`python -c 'from ivre import config; print(config.GEOIP_PATH)'`/"GeoLite2-{ASN,City,Country,RegisteredCountry}.dump-IPv4.csv.bz2

for path_val in "`pwd`/usr/local/zeek/bin" "`pwd`/usr/local/nmap/bin" "`pwd`/usr/local/nfdump/bin"; do
    echo "$path_val" >> $GITHUB_PATH
    export PATH="$path_val:$PATH"
done

for env_val in "LD_LIBRARY_PATH=`pwd`/usr/local/zeek/lib:`pwd`/usr/local/nfdump/lib" "ZEEKPATH=.:`pwd`/usr/local/zeek/share/zeek:`pwd`/usr/local/zeek/share/zeek/policy:`pwd`/usr/local/zeek/share/zeek/site" "ZEEKSAMPLES=`pwd`/usr/local/zeek/testing"; do
    echo "$env_val" >> $GITHUB_ENV
    export "$env_val"
done

cp `python -c "import ivre.config; print(ivre.config.guess_prefix('nmap_scripts'))"`/*.nse `pwd`/usr/local/nmap/share/nmap/scripts/
for patch in `python -c "import ivre.config; print(ivre.config.guess_prefix('nmap_scripts'))"`/patches/*; do (cd `pwd`/usr/local/nmap/share/nmap && patch -p0 < $patch); done
nmap --script-updatedb

ivre --version && zeek --version && nmap --version
