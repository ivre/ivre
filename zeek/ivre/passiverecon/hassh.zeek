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
#
# This file is based on the original JA3 module
# (<https://github.com/salesforce/hassh>), reworked and integrated to
# the passiverecon module.

@load base/protocols/ssh

module PassiveRecon;


################################################
##
## Data stores
##
################################################

# The following names have been chosen to avoid name collisions with
# the original HASSH package itself, and with other packages

# This version number must be the same than for the original project
const IvreHASSHVersion: string = "1.1";

redef record SSH::Info += {
    ivrehasshv: string &log &optional;
    ivrehasshc: string &log &optional;
    ivrehasshs: string &log &optional;
};

# priority=10 to make sure we are executed before the event from ./__load__.zeek
event ssh_capabilities(c: connection, cookie: string, capabilities: SSH::Capabilities) &priority=10 {
    if (!c?$ssh) {
        return;
    }
    c$ssh$ivrehasshv = IvreHASSHVersion;
    if (capabilities$is_server) {
        c$ssh$ivrehasshs = fmt(
            "%s;%s;%s;%s",
            join_string_vec(capabilities$kex_algorithms,","),
            join_string_vec(capabilities$encryption_algorithms$server_to_client,","),
            join_string_vec(capabilities$mac_algorithms$server_to_client,","),
            join_string_vec(capabilities$compression_algorithms$server_to_client,",")
        );
    }
    else {
        c$ssh$ivrehasshc = fmt(
            "%s;%s;%s;%s",
            join_string_vec(capabilities$kex_algorithms,","),
            join_string_vec(capabilities$encryption_algorithms$client_to_server,","),
            join_string_vec(capabilities$mac_algorithms$client_to_server,","),
            join_string_vec(capabilities$compression_algorithms$client_to_server,",")
        );
    }
}
