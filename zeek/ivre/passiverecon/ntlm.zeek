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

const IvreNTLMVersion: string = "1.0";

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
    return fmt("%s-v%s", join_string_vec(sort(protocols, strcmp), "-"),
               IvreNTLMVersion);
}

# Returns a hex string corresponding to the fingerprint of the Negotiate Flags
function _get_hex_flags(flags: NTLM::NegotiateFlags): string {
    # Some flags are not present in the NegotiateFlags structure, we consider
    # them all as unset as the most recent NTLM documentation for each of those
    # flags specifies 'This bit is unused and MUST be zero.'
    # (except for the NT Only flag which SHOULD be zero)
    # https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-NLMP/%5bMS-NLMP%5d.pdf
    # p32-35
    local v = vector(flags$negotiate_unicode, flags$negotiate_oem,
                     flags$request_target, F, flags$negotiate_sign,
                     flags$negotiate_seal, flags$negotiate_datagram,
                     flags$negotiate_lm_key, F, flags$negotiate_ntlm,
                     F, flags$negotiate_anonymous_connection,  # Negotiate NT Only = F
                     flags$negotiate_oem_domain_supplied,
                     flags$negotiate_oem_workstation_supplied, F,
                     flags$negotiate_always_sign, flags$target_type_domain,
                     flags$target_type_server, F,
                     flags$negotiate_extended_sessionsecurity,
                     flags$negotiate_identify, F,
                     flags$request_non_nt_session_key,
                     flags$negotiate_target_info, F, flags$negotiate_version,
                     F, F, F, flags$negotiate_128, flags$negotiate_key_exch,
                     flags$negotiate_56);
    local carry = 1;
    local hex_flags = 0;
    for (i in v) {
        if (v[i] == T) {
            hex_flags = hex_flags + carry;
        }
        carry = carry * 2;
    }
    return fmt("ntlm-fingerprint:%s", fmt("0x%08x", hex_flags));
}
