# This file is part of IVRE.
# Copyright 2011 - 2018 Pierre LALET <pierre.lalet@cea.fr>
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

# Run zeek with the following option to log TCP banners:
#
# -e 'redef tcp_content_deliver_all_resp = T; redef tcp_content_deliver_all_orig = T;'
#
# Use the following option to extract all the files:
#
# -e '@load policy/frameworks/files/extract-all-files'

@load base/frameworks/software
@load base/utils/directions-and-hosts

@load policy/frameworks/software/windows-version-detection

@load policy/protocols/dhcp/software
@load policy/protocols/ftp/software
@load policy/protocols/http/detect-webapps
@load policy/protocols/http/software
@load policy/protocols/http/software-browser-plugins
@load policy/protocols/mysql/software
@load policy/protocols/smtp/software
@load policy/protocols/ssh/software

@load policy/protocols/modbus/track-memmap
@load policy/protocols/modbus/known-masters-slaves

# Not sure about these ones
@load policy/frameworks/dpd/detect-protocols
@load policy/frameworks/intel/do_notice
@load policy/frameworks/intel/seen
@load policy/frameworks/software/windows-version-detection
@load policy/protocols/ftp/detect

export {
    redef Software::asset_tracking = ALL_HOSTS;
}

@load ./passiverecon
@load ./arp
