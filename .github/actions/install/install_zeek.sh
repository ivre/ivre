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

echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | sudo tee /etc/apt/sources.list.d/zeek.list > /dev/null
wget -qO - https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt-get -q update
sudo apt-get -qy --no-install-recommends install zeek

echo "/opt/zeek/bin" >> "$GITHUB_PATH"
export PATH="/opt/zeek/bin:$PATH"

# for env_val in "ZEEKPATH=.:/opt/zeek/share/zeek:/opt/zeek/share/zeek/policy:/opt/zeek/share/zeek/site"; do
#     echo "$env_val" >> "$GITHUB_ENV"
#     export "${env_val?}"
# done

zeek --version
