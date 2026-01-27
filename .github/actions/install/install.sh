#! /bin/bash

# This file is part of IVRE.
# Copyright 2011 - 2025 Pierre LALET <pierre@droids-corp.org>
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
sudo apt-get -qy install tesseract-ocr tesseract-ocr-osd tesseract-ocr-eng p0f nfdump
pip install .
mv ivre ivre_bak
cp .github/workflows/files/ivre.conf ~/.ivre.conf
wget -q -O - https://github.com/ivre/ivre-test-samples/archive/c7f4f992e4f55c14f396efb6043adb617aa4ffc8.tar.gz | tar --transform='s#^ivre-test-samples-[^/]*/*#./#' -zxf -

USE_PYOPENSSL="$((RANDOM % 2))"
echo "USE_PYOPENSSL: ${USE_PYOPENSSL}"
if [ "${USE_PYOPENSSL}" = "0" ]; then
    pip uninstall -y pyOpenSSL
fi

# 404 from GitHub runners...
# wget -q https://bitbucket.org/ariya/phantomjs/downloads/phantomjs-2.1.1-linux-x86_64.tar.bz2 -O - | tar jxf - phantomjs-2.1.1-linux-x86_64/bin/phantomjs
wget -q https://ivre.rocks/data/tests/phantomjs-2.1.1-linux-x86_64.tar.bz2 -O - | tar jxf - phantomjs-2.1.1-linux-x86_64/bin/phantomjs
sudo mv phantomjs-2.1.1-linux-x86_64/bin/phantomjs /usr/local/bin/phantomjs
rm -rf phantomjs-2.1.1-linux-x86_64

wget -q https://nmap.org/dist/nmap-7.95-3.x86_64.rpm -O nmap.rpm
sudo apt-get -q update && \
    sudo apt-get -qy --no-install-recommends install alien && \
    sudo alien ./nmap.rpm && \
    sudo dpkg -i ./nmap*.deb && \
    rm -f ./nmap.rpm ./nmap*.deb

mv tests/geoip/GeoLite2-{ASN,City,Country,RegisteredCountry}.dump-IPv4.csv.bz2 "$(python -c 'from ivre import config; print(config.GEOIP_PATH)')"; bunzip2 "/$(python -c 'from ivre import config; print(config.GEOIP_PATH)')/GeoLite2-"{ASN,City,Country,RegisteredCountry}.dump-IPv4.csv.bz2

# This particular files often fail
wget -q --no-check-certificate "https://ivre.rocks/data/tests/share_data.tar.bz2" -O - | (cd "$(python -c "import ivre.config; print(ivre.config.guess_prefix('data'))")" && tar jxf -)

sudo cp "$(python -c "import ivre.config; print(ivre.config.guess_prefix('patches'))")/nmap/scripts/"*.nse "/usr/share/nmap/scripts/"
# shellcheck disable=SC2024
for patch in "$(python -c "import ivre.config; print(ivre.config.guess_prefix('patches'))")/nmap/"*.patch; do (cd "/usr/share/nmap" && sudo patch -p0 < "$patch"); done
sudo nmap --script-updatedb

sudo patch /etc/p0f/p0f.fp "$(python -c "import ivre.config; print(ivre.config.guess_prefix('patches'))")/p0f/p0f.fp.patch"

ivre --version && nmap --version
