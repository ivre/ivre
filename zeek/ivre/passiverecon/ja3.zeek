# This file is part of IVRE.
#
# Copyright 2017 salesforce.com, inc.
# Copyright 2018 - 2024 Pierre LALET <pierre@droids-corp.org>
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
# the passiverecon module. JA4 fingerprint has also been added.

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
    sni:          string &default="i" &log;
    alpn:         string &default="00" &log;
    version:      count &default=0 &log;
    signatures:   vector of string &default=vector() &log;
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
    ivreja3c_raw: string &optional;
    ivreja3s: string &optional &log;
    ivreja3s_raw: string &optional;
    ivreja4c: string &optional &log;
    ivreja4c_raw: string &optional;
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

const ja4_ignore_ext: set[string] = {
    "0",
    "16"
};

const ja4_tls_versions: table[count] of string = {
    [0x0002] = "s2",
    [0x0300] = "s3",
    [0x0301] = "10",
    [0x0302] = "11",
    [0x0303] = "12",
    [0x0304] = "13",
    [0xfeff] = "d1",
    [0xfefd] = "d2",
    [0xfefc] = "d3"
};

event ssl_extension(c: connection, is_orig: bool, code: count, val: string) {
    if (is_orig) {
        if (code in grease) {
            return;
        }
        if (! c?$ivreja3c) {
            c$ivreja3c = IvreJA3CStore();
        }
        c$ivreja3c$extensions += cat(code);
    }
    else {
        if (! c?$ivreja3s) {
            c$ivreja3s = IvreJA3SStore();
        }
        c$ivreja3s$extensions += cat(code);
    }
}

event ssl_extension_server_name(c: connection, is_orig: bool, names: string_vec) {
    if (is_orig && |names| > 0) {
        if (! c?$ivreja3c) {
            c$ivreja3c = IvreJA3CStore();
        }
        if (!is_valid_ip(names[0])) {
            c$ivreja3c$sni = "d";
        }
    }
}

event ssl_extension_application_layer_protocol_negotiation(c: connection, is_orig: bool, protocols: string_vec) {
    if (is_orig && |protocols| > 0) {
        if (! c?$ivreja3c) {
            c$ivreja3c = IvreJA3CStore();
        }
        # Only use the first instance of the extension
        if (c$ivreja3c$alpn == "00") {
            c$ivreja3c$alpn = protocols[0][0] + protocols[0][-1];
            if (!is_ascii(c$ivreja3c$alpn)) {
                c$ivreja3c$alpn = "99";
            }
        }
    }
}

event ssl_extension_signature_algorithm(c: connection, is_orig: bool, signature_algorithms: signature_and_hashalgorithm_vec) {
    if (is_orig && |signature_algorithms| > 0) {
        if (! c?$ivreja3c) {
            c$ivreja3c = IvreJA3CStore();
        }
        for (i in signature_algorithms) {
            local val = signature_algorithms[i];
            local value = val$HashAlgorithm * 256 + val$SignatureAlgorithm;
            if (value !in grease) {
                c$ivreja3c$signatures += fmt("%04x", value);
            }
        }
    }
}

event ssl_extension_supported_versions(c: connection, is_orig: bool, versions: index_vec) {
    if (is_orig && |versions| > 0) {
        if (! c?$ivreja3c) {
            c$ivreja3c = IvreJA3CStore();
        }
        c$ivreja3c$version = versions[0];
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
            c$ivreja3c$ec_point_fmt += cat(point_format);
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
            c$ivreja3c$e_curves += cat(curve);
        }
    }
}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) &priority=1
{
    if (! c?$ivreja3c) {
        c$ivreja3c = IvreJA3CStore();
    }

    local ciphers_string: vector of string = vector();
    for (i in ciphers) {
        local cipher = ciphers[i];
        if (cipher in grease) {
            next;
        }
        ciphers_string += cat(cipher);
    }

    c$ssl$ivreja3c_raw = fmt(
        "%d,%s,%s,%s,%s",
        version, join_string_vec(ciphers_string, "-"),
        join_string_vec(c$ivreja3c$extensions, "-"),
        join_string_vec(c$ivreja3c$e_curves, "-"),
        join_string_vec(c$ivreja3c$ec_point_fmt, "-")
    );
    c$ssl$ivreja3c = md5_hash(c$ssl$ivreja3c_raw);

    local ja4_a: vector of string = vector();
    # the first byte is the protocol:
    # - "t" for TCP
    # - "q" for QUIC
    # - "?" otherwise (*not standard*)
    local proto: transport_proto = get_port_transport_proto(c$id$resp_p);
    if (proto == tcp){
        ja4_a += "t";
    }
    else if (proto == udp) {
        if ("QUIC" in c$service) {
            ja4_a += "q";
        }
        else {
            # other UDP: unknown
            ja4_a += "?";
        }
    }
    else {
        # other protocol: unknown
        ja4_a += "?";
    }
    local real_version: count = c$ivreja3c$version == 0 ? version : c$ivreja3c$version;
    if (real_version in ja4_tls_versions) {
        ja4_a += ja4_tls_versions[real_version];
    }
    else {
        ja4_a += "??";
    }
    # SNI, collected in ssl_extension_server_name()
    ja4_a += c$ivreja3c$sni;
    # ciphers count (use ciphers_string to remove grease)
    if (|ciphers_string| >= 100) {
        ja4_a += "99";
    }
    else {
        ja4_a += fmt("%02d", |ciphers_string|);
    }
    # extensions count
    if (|c$ivreja3c$extensions| >= 100) {
        ja4_a += "99";
    }
    else {
        ja4_a += fmt("%02d", |c$ivreja3c$extensions|);
    }
    # ALPN, collected in ssl_extension_application_layer_protocol_negotiation()
    ja4_a += c$ivreja3c$alpn;
    local ja4_a_s = join_string_vec(ja4_a, "");

    local ciphers_sorted: vector of string = vector();
    for (i in ciphers_string) {
        ciphers_sorted += fmt("%04x", to_count(ciphers_string[i]));
    }
    sort(ciphers_sorted, strcmp);

    local ja4_b_s = join_string_vec(ciphers_sorted, ",");

    local ext_sorted: vector of string = vector();
    for (i in c$ivreja3c$extensions) {
        if (c$ivreja3c$extensions[i] !in ja4_ignore_ext) {
            ext_sorted += fmt("%04x", to_count(c$ivreja3c$extensions[i]));
        }
    }
    sort(ext_sorted, strcmp);

    local ja4_c: vector of string = vector();
    ja4_c += join_string_vec(ext_sorted, ",");
    if (|c$ivreja3c$signatures| > 0) {
        ja4_c += join_string_vec(c$ivreja3c$signatures, ",");
    }
    local ja4_c_s = join_string_vec(ja4_c, "_");

    c$ssl$ivreja4c_raw = fmt("%s_%s_%s", ja4_a_s, ja4_b_s, ja4_c_s);
    c$ssl$ivreja4c = fmt("%s_%s_%s", ja4_a_s, sha256_hash(ja4_b_s)[:12], sha256_hash(ja4_c_s)[:12]);
}

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) &priority=1
{
    if (! c?$ivreja3s) {
        c$ivreja3s = IvreJA3SStore();
    }

    c$ssl$ivreja3s_raw = fmt(
        "%d,%d,%s", version, cipher,
        join_string_vec(c$ivreja3s$extensions, "-")
    );
    c$ssl$ivreja3s = md5_hash(c$ssl$ivreja3s_raw);
}
