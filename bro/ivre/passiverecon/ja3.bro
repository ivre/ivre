# This file is part of IVRE.
#
# Copyright 2017 salesforce.com, inc.
# Copyright 2018 Pierre LALET <pierre.lalet@cea.fr>
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
# (<https://github.com/salesforce/ja3>), reworked and integrated to
# the passiverecon module.

@load base/misc/version
@load base/protocols/ssl

module PassiveRecon;


################################################
##
## Data stores
##
################################################

# The following names have been chosen to avoid name collisions with
# the original JA3 package itself, and with other packages (see for
# example
# <https://github.com/salesforce/ja3/issues/13#issuecomment-419256795>)

type IvreJA3CStore: record {
    extensions:   vector of string &default=vector() &log;
    e_curves:     vector of string &default=vector() &log;
    ec_point_fmt: vector of string &default=vector() &log;
};

type IvreJA3SStore: record {
    extensions: vector of string &default=vector() &log;
};

redef record connection += {
    ivreja3c: IvreJA3CStore &optional;
    ivreja3s: IvreJA3SStore &optional;
};

redef record SSL::Info += {
    ivreja3c: string &optional &log;
    ivreja3s: string &optional &log;
};


################################################
##
## SSL extensions
##
################################################

# Google. https://tools.ietf.org/html/draft-davidben-tls-grease-01
const grease: set[int] = {
    2570,
    6682,
    10794,
    14906,
    19018,
    23130,
    27242,
    31354,
    35466,
    39578,
    43690,
    47802,
    51914,
    56026,
    60138,
    64250
};

event ssl_extension(c: connection, is_orig: bool, code: count, val: string) {
    if (is_orig) {
        if (! c?$ivreja3c) {
            c$ivreja3c = IvreJA3CStore();
        }
        if (code in grease) {
            next;
        }
        c$ivreja3c$extensions[|c$ivreja3c$extensions|] = cat(code);
    }
    else {
        if (! c?$ivreja3s) {
            c$ivreja3s = IvreJA3SStore();
        }
        c$ivreja3s$extensions[|c$ivreja3s$extensions|] = cat(code);
    }
}

event ssl_extension_ec_point_formats(c: connection, is_orig: bool, point_formats: index_vec) {
    if (is_orig) {
        if (! c?$ivreja3c) {
            c$ivreja3c = IvreJA3CStore();
        }
        for (i in point_formats) {
            local point_format = point_formats[i];
            if (point_format in grease) {
                next;
            }
            c$ivreja3c$ec_point_fmt[|c$ivreja3c$ec_point_fmt|] = cat(point_format);
        }
    }
}

event ssl_extension_elliptic_curves(c: connection, is_orig: bool, curves: index_vec)
{
    if (is_orig) {
        if (! c?$ivreja3c) {
            c$ivreja3c = IvreJA3CStore();
        }
        for (i in curves) {
            local curve = curves[i];
            if (curve in grease) {
                next;
            }
            c$ivreja3c$e_curves[|c$ivreja3c$e_curves|] = cat(curve);
        }
    }
}

@if(Version::number >= 20600 || (Version::number == 20500 && Version::info$commit >= 944))
event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) &priority=1
@else
event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec) &priority=1
@endif
{
    if (! c?$ivreja3c) {
        c$ivreja3c = IvreJA3CStore();
    }

    local ciphers_string = vector();
    for (i in ciphers) {
        local cipher = ciphers[i];
        if (cipher in grease) {
            next;
        }
        ciphers_string[|ciphers_string|] = cat(cipher);
    }

    c$ssl$ivreja3c = fmt(
        "%d,%s,%s,%s,%s",
        version, join_string_vec(ciphers_string, "-"),
        join_string_vec(c$ivreja3c$extensions, "-"),
        join_string_vec(c$ivreja3c$e_curves, "-"),
        join_string_vec(c$ivreja3c$ec_point_fmt, "-")
    );
}

@if(Version::number >= 20600 || (Version::number == 20500 && Version::info$commit >= 944))
event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) &priority=1
@else
event ssl_server_hello(c: connection, version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) &priority=1
@endif
{
    if (! c?$ivreja3s) {
        c$ivreja3s = IvreJA3SStore();
    }

    c$ssl$ivreja3s = fmt(
        "%d,%d,%s", version, cipher,
        join_string_vec(c$ivreja3s$extensions, "-")
    );
}
