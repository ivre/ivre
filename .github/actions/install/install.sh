#! /bin/bash

# This file is part of IVRE.
# Copyright 2011 - 2023 Pierre LALET <pierre@droids-corp.org>
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

sudo apt-get -q update
sudo apt-get -qy install tesseract-ocr tesseract-ocr-osd tesseract-ocr-eng phantomjs p0f
pip install .
mv ivre ivre_bak
{
    cat .github/workflows/files/ivre.conf
    echo "NMAP_SHARE_PATH = '$(pwd)/usr/local/nmap/share/nmap'"
} >> ~/.ivre.conf
wget -q -O - https://github.com/ivre/ivre-test-samples/archive/c7f4f992e4f55c14f396efb6043adb617aa4ffc8.tar.gz | tar --transform='s#^ivre-test-samples-[^/]*/*#./#' -zxf -

USE_PYOPENSSL="$((RANDOM % 2))"
echo "USE_PYOPENSSL: ${USE_PYOPENSSL}"
if [ "${USE_PYOPENSSL}" = "0" ]; then
    pip uninstall -y pyOpenSSL
fi

UBUNTU_VERSION="$(awk -F = '/^DISTRIB_RELEASE=/ {print $2}' /etc/lsb-release)"
echo "UBUNTU_VERSION: ${UBUNTU_VERSION}"

for archive in tools-travis-ivre "nmap-7.91_ubuntu-${UBUNTU_VERSION}" nfdump-1.6.17; do
    wget -q --no-check-certificate "https://ivre.rocks/data/tests/${archive}.tar.bz2" -O - | tar jxf -
done

mv tests/geoip/GeoLite2-{ASN,City,Country,RegisteredCountry}.dump-IPv4.csv.bz2 "$(python -c 'from ivre import config; print(config.GEOIP_PATH)')"; bunzip2 "/$(python -c 'from ivre import config; print(config.GEOIP_PATH)')/GeoLite2-"{ASN,City,Country,RegisteredCountry}.dump-IPv4.csv.bz2

# This particular files often fail
wget -q --no-check-certificate "https://ivre.rocks/data/tests/share_data.tar.bz2" -O - | (cd "$(python -c "import ivre.config; print(ivre.config.guess_prefix('data'))")" && tar jxf -)

for path_val in "$(pwd)/usr/local/nmap/bin" "$(pwd)/usr/local/nfdump/bin"; do
    echo "$path_val" >> "$GITHUB_PATH"
    export PATH="$path_val:$PATH"
done

# shellcheck disable=SC2066
for env_val in "LD_LIBRARY_PATH=$(pwd)/usr/local/zeek/lib:$(pwd)/usr/local/nfdump/lib"; do
    echo "$env_val" >> "$GITHUB_ENV"
    export "${env_val?}"
done

cp "$(python -c "import ivre.config; print(ivre.config.guess_prefix('patches'))")/nmap/scripts/"*.nse "$(pwd)/usr/local/nmap/share/nmap/scripts/"
for patch in "$(python -c "import ivre.config; print(ivre.config.guess_prefix('patches'))")/nmap/"*.patch; do (cd "$(pwd)/usr/local/nmap/share/nmap" && patch -p0 < "$patch"); done
nmap --script-updatedb

sudo patch /etc/p0f/p0f.fp "$(python -c "import ivre.config; print(ivre.config.guess_prefix('patches'))")/p0f/p0f.fp.patch"

ivre --version && nmap --version
