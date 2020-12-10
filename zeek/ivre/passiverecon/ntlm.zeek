# This file is part of IVRE.
#
# Copyright 2018, salesforce.com, inc. 
# Copyright 2020 Pierre LALET <pierre@droids-corp.org>
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

@load base/protocols/ntlm

module PassiveRecon;

# Get the exact version of the protocol using NTLM
# For now, only handles SMB
function _get_protocol_version(c: connection): string {
    if (c?$smb_state) {
        return "Protocol:" + encode_base64(c$smb_state$current_cmd$version);
    }
    return "";
}

# Returns a string made from the list of protocols detected by Zeek
function _get_source(c: connection): string {
    local protocols = vector();
    for (p in c$service) {
        protocols += p;
    }
    if (|protocols| == 0) {
        protocols += "NTLM";
    }
    return join_string_vec(sort(protocols, strcmp), "-");
}
