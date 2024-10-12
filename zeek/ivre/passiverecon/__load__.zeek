# This file is part of IVRE.
# Copyright 2011 - 2024 Pierre LALET <pierre@droids-corp.org>
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

@load base/frameworks/notice
@load base/misc/version
@load base/protocols/http
@if(Version::number >= 60100)
@load base/protocols/quic
@endif
@load base/protocols/ssh
@load base/protocols/ssl
@load base/protocols/dns
@load base/protocols/ftp
@load base/protocols/pop3
@load base/protocols/ntlm
@load base/protocols/smb
@load base/protocols/dce-rpc

@load ./hassh
@load ./ja3
@load ./ntlm

module PassiveRecon;

export {
    redef enum Log::ID += { LOG };

    redef enum Notice::Type += {
        PassiveRecon,
    };

    type Type: enum {
        UNKNOWN,
        HTTP_CLIENT_HEADER,
        HTTP_SERVER_HEADER,
        HTTP_CLIENT_HEADER_SERVER,
        HTTP_HONEYPOT_REQUEST,
        SSH_CLIENT,
        SSH_SERVER,
        SSH_CLIENT_ALGOS,
        SSH_SERVER_ALGOS,
        SSH_SERVER_HOSTKEY,
        SSH_CLIENT_HASSH,
        SSH_SERVER_HASSH,
        SSL_CLIENT,
        SSL_SERVER,
        DNS_ANSWER,
        DNS_HONEYPOT_QUERY,
        FTP_CLIENT,
        FTP_SERVER,
        POP_CLIENT,
        POP_SERVER,
        TCP_CLIENT_BANNER,
        TCP_SERVER_BANNER,
        TCP_HONEYPOT_HIT,
        UDP_HONEYPOT_HIT,
        OPEN_PORT,
        MAC_ADDRESS,
        NTLM_NEGOTIATE,
        NTLM_CHALLENGE,
        NTLM_AUTHENTICATE,
        NTLM_SERVER_FLAGS,
        NTLM_CLIENT_FLAGS,
        SMB,
        STUN_HONEYPOT_REQUEST,
    };

    type Info: record {
        ## The time at which the software was detected.
        ts: time &log;
        ## The connection uid
        uid: string &log &optional;
        ## The IP address detected running the software.
        host: addr &log &optional;
        ## The service port
        srvport: port &log &optional;
        ## The type of software detected
        recon_type: Type &log &default=UNKNOWN;
        ## The source (e.g., header) name
        source: string &log &optional;
        ## The value
        value: string &log;
        ## The second value (e.g., for CNAME DNS records)
        targetval: string &log &optional;
    };

    const HTTP_CLIENT_HEADERS: set[string] = {
        "USER-AGENT",
        "X-FLASH-VERSION",
        "ACCEPT-LANGUAGE",
        "AUTHORIZATION",
        "PROXY-AUTHORIZATION",
        "X-FORWARDED-FOR",
        "VIA",
    };

    # Headers sent by the client that give information about the
    # server (some headers end up logged twice, but that's what I
    # want)
    const HTTP_CLIENT_HEADER_SERVERS: set[string] = {
        "HOST",
        "AUTHORIZATION",
        "PROXY-AUTHORIZATION",
        # "COOKIE",
    };

    const HTTP_SERVER_HEADERS: set[string] = {
        "SERVER",
        "X-SERVER",
        "X-POWERED-BY",
        "VIA",
        "X-GENERATOR",
        # "SET-COOKIE",
        "WWW-AUTHENTICATE",
        "PROXY-AUTHENTICATE",
        "MICROSOFTSHAREPOINTTEAMSERVICES",
    };

    const FTP_COMMANDS: set[string] = {
        "USER",
        "PASS",
    };

    const POP_COMMANDS: set[string] = {
        "USER",
        "PASS",
    };

    # We want to ignore banners when we have missed the beginning
    # of the connection
    const TCP_BANNER_HISTORY = /Sh[aA]*[dD]/;

    # Ignore SSL/TLS client hello messages (from
    # scripts/base/protocols/ssl/dpd.sig), HTTP requests (from
    # scripts/base/protocols/http/dpd.sig) and SSH banners (from
    # scripts/base/protocols/ssh/dpd.sig). "." must be replaced by
    # "[\x00-\xFF]" since the 's' flag does not seem to be supported.
    const TCP_CLIENT_BANNER_IGNORE: pattern = /^(\x16\x03[\x00\x01\x02\x03][\x00-\xFF][\x00-\xFF]\x01[\x00-\xFF][\x00-\xFF][\x00-\xFF]\x03[\x00\x01\x02\x03]|[\x00-\xFF][\x00-\xFF][\x00-\xFF]?\x01[\x00\x03][\x00\x01\x02\x03\x04]|\x16\xfe[\xff\xfd]\x00\x00\x00\x00\x00\x00\x00[\x00-\xFF][\x00-\xFF][\x00-\xFF]\x01[\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF][\x00-\xFF]\xfe[\xff\xfd]|[[:space:]]*(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|VERSION-CONTROL|REPORT|CHECKOUT|CHECKIN|UNCHECKOUT|MKWORKSPACE|UPDATE|LABEL|MERGE|BASELINE-CONTROL|MKACTIVITY|ORDERPATCH|ACL|PATCH|SEARCH|BCOPY|BDELETE|BMOVE|BPROPFIND|BPROPPATCH|NOTIFY|POLL|SUBSCRIBE|UNSUBSCRIBE|X-MS-ENUMATTS|RPC_OUT_DATA|RPC_IN_DATA)[[:space:]]*|[sS][sS][hH]-[12]\.)/;

    # Ignore HTTP server responses (from scripts/base/protocols/http/dpd.sig)
    # Ignore thttpd UNKNOWN timeout answer
    # Ignore SSH banners (from scripts/base/protocols/ssh/dpd.sig)
    const TCP_SERVER_BANNER_IGNORE: pattern = /^(HTTP\/[0-9]|UNKNOWN 408|[sS][sS][hH]-[12]\.)/;

    const STUN_CLIENT_REQUEST: pattern = /^\x00\x01..\x21\x12\xa4\x42/;
    const STUN_CLIENT_REQUEST_RELAXED: pattern = /^\x00\x01\x00\x08.{16}\x00\x03\x00\x04\x00\x00\x00/;

    option HONEYPOTS: set[addr] = {};
}

event zeek_init() {
    Log::create_stream(LOG, [$columns=Info]);
}

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (is_orig) {
        if (name in HTTP_CLIENT_HEADERS)
            Log::write(LOG, [$ts=c$start_time,
                             $uid=c$uid,
                             $host=c$id$orig_h,
                             $recon_type=HTTP_CLIENT_HEADER,
                             $source=name,
                             $value=value]);
        if (c$id$resp_h in HONEYPOTS) {
            return;
        }
        if (name in HTTP_CLIENT_HEADER_SERVERS) {
            # While this is a header sent by the client,
            # it gives information about the server
            # if (name == "COOKIE")
            #     value = split1(value, /=/)[1];
            Log::write(LOG, [$ts=c$start_time,
                             $uid=c$uid,
                             $host=c$id$resp_h,
                             $srvport=c$id$resp_p,
                             $recon_type=HTTP_CLIENT_HEADER_SERVER,
                             $source=name,
                             $value=value]);
        }
    }
    else {
        if (c$id$resp_h in HONEYPOTS) {
            return;
        }
        if (name in HTTP_SERVER_HEADERS) {
            # if (name == "SET-COOKIE")
            #     value = split1(value, /=/)[1];
            Log::write(LOG, [$ts=c$start_time,
                             $uid=c$uid,
                             $host=c$id$resp_h,
                             $srvport=c$id$resp_p,
                             $recon_type=HTTP_SERVER_HEADER,
                             $source=name,
                             $value=value]);
            }
        }
    }

event ssh_client_version(c: connection, version: string) {
    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $host=c$id$orig_h,
                     $recon_type=SSH_CLIENT,
                     $value=version]);
}

event ssh_server_version(c: connection, version: string) {
    if (c$id$resp_h in HONEYPOTS) {
        return;
    }
    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $host=c$id$resp_h,
                     $srvport=c$id$resp_p,
                     $recon_type=SSH_SERVER,
                     $value=version]);
}

# API change, see https://docs.zeek.org/en/master/scripts/base/bif/plugins/Zeek_SSH.events.bif.zeek.html#id-ssh1_server_host_key
@if(Version::number >= 40000)
event ssh1_server_host_key(c: connection, modulus: string, exponent: string) {
    if (c$id$resp_h in HONEYPOTS) {
        return;
    }
    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $host=c$id$resp_h,
                     $srvport=c$id$resp_p,
                     $recon_type=SSH_SERVER_HOSTKEY,
                     $source="SSHv1",
                     $value=fmt("%s %s", exponent, modulus)]);
}
@else
event ssh1_server_host_key(c: connection, p: string, e: string) {
    if (c$id$resp_h in HONEYPOTS) {
        return;
    }
    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $host=c$id$resp_h,
                     $srvport=c$id$resp_p,
                     $recon_type=SSH_SERVER_HOSTKEY,
                     $source="SSHv1",
                     $value=fmt("%s %s", p, e)]);
}
@endif

event ssh2_server_host_key(c: connection, key: string) {
    if (c$id$resp_h in HONEYPOTS) {
        return;
    }
    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $host=c$id$resp_h,
                     $srvport=c$id$resp_p,
                     $recon_type=SSH_SERVER_HOSTKEY,
                     $source="SSHv2",
                     $value=key]);
}

event ssh_capabilities(c: connection, cookie: string, capabilities: SSH::Capabilities) {
    if (capabilities$is_server) {
        if (c$id$resp_h in HONEYPOTS) {
            return;
        }
        Log::write(LOG, [
            $ts=c$start_time,
            $uid=c$uid,
            $host=c$id$resp_h,
            $srvport=c$id$resp_p,
            $recon_type=SSH_SERVER_ALGOS,
            $source="kex_algorithms",
            $value=join_string_vec(capabilities$kex_algorithms, " ")
        ]);
        Log::write(LOG, [
            $ts=c$start_time,
            $uid=c$uid,
            $host=c$id$resp_h,
            $srvport=c$id$resp_p,
            $recon_type=SSH_SERVER_ALGOS,
            $source="kex_algorithms",
            $value=join_string_vec(capabilities$kex_algorithms, " ")
        ]);
        Log::write(LOG, [
            $ts=c$start_time,
            $uid=c$uid,
            $host=c$id$resp_h,
            $srvport=c$id$resp_p,
            $recon_type=SSH_SERVER_ALGOS,
            $source="server_host_key_algorithms",
            $value=join_string_vec(capabilities$server_host_key_algorithms, " ")
        ]);
        Log::write(LOG, [
            $ts=c$start_time,
            $uid=c$uid,
            $host=c$id$resp_h,
            $srvport=c$id$resp_p,
            $recon_type=SSH_SERVER_ALGOS,
            $source="encryption_algorithms",
            $value=join_string_vec(capabilities$encryption_algorithms$server_to_client, " ")
        ]);
        Log::write(LOG, [
            $ts=c$start_time,
            $uid=c$uid,
            $host=c$id$resp_h,
            $srvport=c$id$resp_p,
            $recon_type=SSH_SERVER_ALGOS,
            $source="mac_algorithms",
            $value=join_string_vec(capabilities$mac_algorithms$server_to_client, " ")
        ]);
        Log::write(LOG, [
            $ts=c$start_time,
            $uid=c$uid,
            $host=c$id$resp_h,
            $srvport=c$id$resp_p,
            $recon_type=SSH_SERVER_ALGOS,
            $source="compression_algorithms",
            $value=join_string_vec(capabilities$compression_algorithms$server_to_client, " ")
        ]);
        if (c$ssh?$ivrehasshs) {
            Log::write(LOG, [$ts=c$start_time,
                             $uid=c$uid,
                             $host=c$id$resp_h,
                             $srvport=c$id$resp_p,
                             $recon_type=SSH_SERVER_HASSH,
                             $source=fmt("hassh-v%s", c$ssh$ivrehasshv),
                             $value=c$ssh$ivrehasshs]);
        }
    }
    else {
        Log::write(LOG, [
            $ts=c$start_time,
            $uid=c$uid,
            $host=c$id$orig_h,
            $recon_type=SSH_CLIENT_ALGOS,
            $source="kex_algorithms",
            $value=join_string_vec(capabilities$kex_algorithms, " ")
        ]);
        Log::write(LOG, [
            $ts=c$start_time,
            $uid=c$uid,
            $host=c$id$orig_h,
            $recon_type=SSH_CLIENT_ALGOS,
            $source="server_host_key_algorithms",
            $value=join_string_vec(capabilities$server_host_key_algorithms, " ")
        ]);
        Log::write(LOG, [
            $ts=c$start_time,
            $uid=c$uid,
            $host=c$id$orig_h,
            $recon_type=SSH_CLIENT_ALGOS,
            $source="encryption_algorithms",
            $value=join_string_vec(capabilities$encryption_algorithms$client_to_server, " ")
        ]);
        Log::write(LOG, [
            $ts=c$start_time,
            $uid=c$uid,
            $host=c$id$orig_h,
            $recon_type=SSH_CLIENT_ALGOS,
            $source="mac_algorithms",
            $value=join_string_vec(capabilities$mac_algorithms$client_to_server, " ")
        ]);
        Log::write(LOG, [
            $ts=c$start_time,
            $uid=c$uid,
            $host=c$id$orig_h,
            $recon_type=SSH_CLIENT_ALGOS,
            $source="compression_algorithms",
            $value=join_string_vec(capabilities$compression_algorithms$client_to_server, " ")
        ]);
        if (c$ssh?$ivrehasshc) {
            Log::write(LOG, [$ts=c$start_time,
                             $uid=c$uid,
                             $host=c$id$orig_h,
                             $recon_type=SSH_CLIENT_HASSH,
                             $source=fmt("hassh-v%s", c$ssh$ivrehasshv),
                             $value=c$ssh$ivrehasshc]);
        }
    }
}

event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec, comp_methods: index_vec) {
    if (c$ssl?$ivreja3c) {
        Log::write(LOG, [$ts=c$start_time,
                         $uid=c$uid,
                         $host=c$id$orig_h,
                         $recon_type=SSL_CLIENT,
                         $source="ja3",
                         $value=c$ssl$ivreja3c_raw]);
        Log::write(LOG, [$ts=c$start_time,
                         $uid=c$uid,
                         $host=c$id$orig_h,
                         $recon_type=SSL_CLIENT,
                         $source="ja4",
                         $value=c$ssl$ivreja4c_raw]);
    }
}

event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count) {
    if (c$ssl?$ivreja3s) {
        local ja3c_raw = "UNKNOWN";
        if (c$ssl?$ivreja3c_raw) {
            ja3c_raw = c$ssl$ivreja3c_raw;
        }
        Log::write(LOG, [$ts=c$start_time,
                         $uid=c$uid,
                         $host=c$id$resp_h,
                         $srvport=c$id$resp_p,
                         $recon_type=SSL_SERVER,
                         $source=fmt("ja3-%s", ja3c_raw),
                         $value=c$ssl$ivreja3s_raw]);
    }
}

event ssl_established(c: connection) {
    local cacert: bool;
    if (c$ssl?$client_cert_chain) {
        cacert = F;
        for (i in c$ssl$client_cert_chain) {
            Log::write(LOG, [
                $ts=c$start_time,
                $uid=c$uid,
                $host=c$id$orig_h,
                $recon_type=SSL_CLIENT,
                $source=cacert ? "cacert" : "cert",
                $value=encode_base64(x509_get_certificate_string(c$ssl$client_cert_chain[i]$x509$handle))
            ]);
            cacert = T;
        }
    }
    if (c$id$resp_h in HONEYPOTS) {
        return;
    }
    if (c$ssl?$cert_chain) {
        cacert = F;
        for (i in c$ssl$cert_chain) {
            Log::write(LOG, [
                $ts=c$start_time,
                $uid=c$uid,
                $host=c$id$resp_h,
                $srvport=c$id$resp_p,
                $recon_type=SSL_SERVER,
                $source=cacert ? "cacert" : "cert",
                $value=encode_base64(x509_get_certificate_string(c$ssl$cert_chain[i]$x509$handle))
            ]);
            cacert = T;
        }
    }
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    if (c$id$resp_h in HONEYPOTS) {
        Log::write(LOG, [$ts=c$start_time,
                         $uid=c$uid,
                         $host=c$id$orig_h,
                         $recon_type=DNS_HONEYPOT_QUERY,
                         $source=fmt("%s/%d-%s-%s", get_port_transport_proto(c$id$resp_p), c$id$resp_p, DNS::query_types[qtype], DNS::classes[qclass]),
                         $value=query]);
    }
}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) {
    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $host=a,
                     $recon_type=DNS_ANSWER,
                     $source=fmt("A-%s-%d", c$id$resp_h, c$id$resp_p),
                     $value=ans$query]);
}

event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) {
    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $host=a,
                     $recon_type=DNS_ANSWER,
                     $source=fmt("AAAA-%s-%d", c$id$resp_h, c$id$resp_p),
                     $value=ans$query]);
}

event dns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) {
@if(Version::number >= 40000)
    if (! ends_with(ans$query, ".arpa")) {
        return;
    }
@endif
    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $host=ptr_name_to_addr(ans$query),
                     $recon_type=DNS_ANSWER,
                     $source=fmt("PTR-%s-%d", c$id$resp_h, c$id$resp_p),
                     $value=name]);
}

event dns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) {
    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $targetval=name,
                     $recon_type=DNS_ANSWER,
                     $source=fmt("CNAME-%s-%d", c$id$resp_h, c$id$resp_p),
                     $value=ans$query]);
}

event dns_NS_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) {
    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $targetval=name,
                     $recon_type=DNS_ANSWER,
                     $source=fmt("NS-%s-%d", c$id$resp_h, c$id$resp_p),
                     $value=ans$query]);
}

event dns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string,
           preference: count) {
    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $targetval=name,
                     $recon_type=DNS_ANSWER,
                     $source=fmt("MX-%s-%d", c$id$resp_h, c$id$resp_p),
                     $value=ans$query]);
}

event ftp_request(c: connection, command: string, arg: string) {
    if (command in FTP_COMMANDS) {
        Log::write(LOG, [$ts=c$start_time,
                         $uid=c$uid,
                         $host=c$id$orig_h,
                         $recon_type=FTP_CLIENT,
                         $source=command,
                         $value=arg]);
        if (c$id$resp_h in HONEYPOTS) {
            return;
        }
        Log::write(LOG, [$ts=c$start_time,
                         $uid=c$uid,
                         $host=c$id$resp_h,
                         $srvport=c$id$resp_p,
                         $recon_type=FTP_SERVER,
                         $source=command,
                         $value=arg]);
    }
}

event pop3_request(c: connection, is_orig: bool, command: string, arg: string) {
    if (command in POP_COMMANDS) {
        Log::write(LOG, [$ts=c$start_time,
                         $uid=c$uid,
                         $host=c$id$orig_h,
                         $recon_type=POP_CLIENT,
                         $source=command,
                         $value=arg]);
        if (c$id$resp_h in HONEYPOTS) {
            return;
        }
        Log::write(LOG, [$ts=c$start_time,
                         $uid=c$uid,
                         $host=c$id$resp_h,
                         $srvport=c$id$resp_p,
                         $recon_type=POP_SERVER,
                         $source=command,
                         $value=arg]);
    }
}

event tcp_contents(c: connection, is_orig: bool, seq: count, contents: string) {
    if (seq == 1 && "ftp-data" !in c$service && "gridftp-data" !in c$service &&
        "irc-dcc-data" !in c$service) {
        if (is_orig) {
            if (c$resp$size == 0 && c$history == TCP_BANNER_HISTORY) {
                if (c$id$resp_h in HONEYPOTS) {
                    Log::write(LOG, [$ts=c$start_time,
                                     $uid=c$uid,
                                     $host=c$id$orig_h,
                                     $recon_type=TCP_HONEYPOT_HIT,
                                     $source=fmt("tcp/%d", c$id$resp_p),
                                     $value=contents]);
                }
                else if (! (TCP_CLIENT_BANNER_IGNORE in contents)) {
                    Log::write(LOG, [$ts=c$start_time,
                                     $uid=c$uid,
                                     $host=c$id$orig_h,
                                     $recon_type=TCP_CLIENT_BANNER,
                                     $source=fmt("tcp/%d", c$id$resp_p),
                                     $value=contents]);
                }
            }
        }
        else if (c$orig$size == 0 && c$history == TCP_BANNER_HISTORY &&
                 ! (TCP_SERVER_BANNER_IGNORE in contents) &&
                 ! (c$id$resp_h in HONEYPOTS))
            Log::write(LOG, [$ts=c$start_time,
                             $uid=c$uid,
                             $host=c$id$resp_h,
                             $srvport=c$id$resp_p,
                             $recon_type=TCP_SERVER_BANNER,
                             $value=contents]);
    }
}

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string) {
    Log::write(LOG, [$ts=network_time(),
                     $host=SPA,
                     $recon_type=MAC_ADDRESS,
                     $source="ARP_REQUEST_SRC",
                     $value=SHA]);
    if (THA != "00:00:00:00:00:00" && THA != "ff:ff:ff:ff:ff:ff") {
        Log::write(LOG, [$ts=network_time(),
                         $host=TPA,
                         $recon_type=MAC_ADDRESS,
                         $source="ARP_REQUEST_DST",
                         $value=THA]);
    }
}

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string) {
    Log::write(LOG, [$ts=network_time(),
                     $host=SPA,
                     $recon_type=MAC_ADDRESS,
                     $source="ARP_REPLY_SRC",
                     $value=SHA]);
    if (THA != "ff:ff:ff:ff:ff:ff") {
        Log::write(LOG, [$ts=network_time(),
                         $host=TPA,
                         $recon_type=MAC_ADDRESS,
                         $source="ARP_REPLY_DST",
                         $value=THA]);
    }
}

event connection_established(c: connection) {
    if (c$id$resp_h in HONEYPOTS) {
        Log::write(LOG, [$ts=c$start_time,
                         $uid=c$uid,
                         $host=c$id$orig_h,
                         $recon_type=TCP_HONEYPOT_HIT,
                         $source=fmt("tcp/%d", c$id$resp_p),
                         $value=""]);
    }
    else if ("ftp-data" !in c$service && "gridftp-data" !in c$service &&
        "irc-dcc-data" !in c$service) {
        Log::write(LOG, [$ts=c$start_time,
                         $host=c$id$resp_h,
                         $recon_type=OPEN_PORT,
                         $source="TCP",
                         $srvport=c$id$resp_p,
                         $value=fmt("tcp/%d", c$id$resp_p),
                         $uid=c$uid]);
    }
}

event connection_attempt(c: connection) {
    if (c$id$resp_h in HONEYPOTS) {
        Log::write(LOG, [$ts=c$start_time,
                         $uid=c$uid,
                         $host=c$id$orig_h,
                         $recon_type=TCP_HONEYPOT_HIT,
                         $source=fmt("tcp/%d", c$id$resp_p),
                         $value=""]);
    }
}

# Note: this will only be called for UDP packets on ports specified by
# udp_content_delivery_ports_orig or udp_content_delivery_ports_resp
# (see https://docs.zeek.org/en/master/scripts/base/bif/plugins/Zeek_UDP.events.bif.zeek.html#id-udp_contents)
# For inspection of all UDP packets (no matter the port):
# redef udp_content_deliver_all_orig = T;
event udp_contents(u: connection, is_orig: bool, contents: string) {
    if (is_orig && u$id$resp_h in HONEYPOTS) {
        if (is_orig && (STUN_CLIENT_REQUEST in contents || STUN_CLIENT_REQUEST_RELAXED in contents)) {
            Log::write(LOG, [$ts=u$start_time,
                             $uid=u$uid,
                             $host=u$id$orig_h,
                             $recon_type=STUN_HONEYPOT_REQUEST,
                             $source=fmt("udp/%d", u$id$resp_p),
                             $value=contents]);
        } else {
            Log::write(LOG, [$ts=u$start_time,
                             $uid=u$uid,
                             $host=u$id$orig_h,
                             $recon_type=UDP_HONEYPOT_HIT,
                             $source=fmt("udp/%d", u$id$resp_p),
                             $value=contents]);
        }
    }
}

event http_request (c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    if (c$id$resp_h in HONEYPOTS && version != "0.9") {
        Log::write(LOG, [$ts=c$start_time,
                         $uid=c$uid,
                         $host=c$id$orig_h,
                         $recon_type=HTTP_HONEYPOT_REQUEST,
                         $source=fmt("%s-%s-tcp/%d", method, version, c$id$resp_p),
                         $value=original_URI]);
    }
}

event ntlm_challenge(c: connection, challenge: NTLM::Challenge){
    # Build a string with all the host information found with NTLM
    # (the resulting string is a list of "field:val" with values encoded in b64)
    local value: vector of string = vector();

    if (challenge?$target_name) {
        value += fmt("Target_Name:%s", encode_base64(challenge$target_name));
    }
    if (challenge?$target_info) {
        value += "NetBIOS_Domain_Name:" +
                 encode_base64(challenge$target_info$nb_domain_name) +
                 ",NetBIOS_Computer_Name:" +
                 encode_base64(challenge$target_info$nb_computer_name);
        if (challenge$target_info?$dns_domain_name) {
            value += "DNS_Domain_Name:" +
                     encode_base64(challenge$target_info$dns_domain_name);
        }
        if (challenge$target_info?$dns_computer_name) {
            value += "DNS_Computer_Name:" +
                     encode_base64(challenge$target_info$dns_computer_name);
        }
        if (challenge$target_info?$dns_tree_name) {
            value += "DNS_Tree_Name:" +
                     encode_base64(challenge$target_info$dns_tree_name);
        }
    }
    if (challenge?$version) {
        value += "Product_Version:" + encode_base64(fmt("%s.%s.%s",
                                                challenge$version$major,
                                                challenge$version$minor,
                                                challenge$version$build));
        value += fmt("NTLM_Version:%d", challenge$version$ntlmssp);
    }
    local proto = _get_protocol_version(c);
    if (proto != "") {
        value += proto;
    }
    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $host=c$id$resp_h,
                     $recon_type=NTLM_CHALLENGE,
                     $source=_get_source(c, c$id$resp_p),
                     $srvport=c$id$resp_p,
                     $value=join_string_vec(value, ",")]);
    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $host=c$id$resp_h,
                     $recon_type=NTLM_SERVER_FLAGS,
                     $source=_get_source(c, c$id$resp_p),
                     $srvport=c$id$resp_p,
                     $value=_get_hex_flags(challenge$flags)]);
}

event ntlm_negotiate(c: connection, negotiate: NTLM::Negotiate){

    local value: vector of string = vector();
    if (negotiate?$domain_name) {
        value += "NetBIOS_Domain_Name:" + encode_base64(negotiate$domain_name);
    }
    if (negotiate?$workstation) {
        value += "Workstation:" + encode_base64(negotiate$workstation);
    }
    if (negotiate?$version) {
        value += "Product_Version:" + encode_base64(fmt("%s.%s.%s",
                                                    negotiate$version$major,
                                                    negotiate$version$minor,
                                                    negotiate$version$build));
        value += fmt("NTLM_Version:%d", negotiate$version$ntlmssp);
    }
    local proto = _get_protocol_version(c);
    if (proto != "") {
        value += proto;
    }
    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $host=c$id$orig_h,
                     $recon_type=NTLM_NEGOTIATE,
                     $source=_get_source(c, c$id$orig_p),
                     $value=join_string_vec(value, ",")]);
    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $host=c$id$orig_h,
                     $recon_type=NTLM_CLIENT_FLAGS,
                     $source=_get_source(c, c$id$orig_p),
                     $value=_get_hex_flags(negotiate$flags)]);
}

event ntlm_authenticate(c: connection, request: NTLM::Authenticate){

    local value: vector of string = vector();
    if (request?$domain_name) {
        value += "NetBIOS_Domain_Name:" + encode_base64(request$domain_name);
    }
    if (request?$user_name) {
        value += "User_Name:" + encode_base64(request$user_name);
    }
    if (request?$workstation) {
        value += "Workstation:" + encode_base64(request$workstation);
    }
    if (request?$version) {
        value += "Product_Version:" + encode_base64(fmt("%s.%s.%s",
                                                    request$version$major,
                                                    request$version$minor,
                                                    request$version$build));
        value += fmt("NTLM_Version:%d", request$version$ntlmssp);
    }
    local proto = _get_protocol_version(c);
    if (proto != "") {
        value += proto;
    }
    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $host=c$id$orig_h,
                     $recon_type=NTLM_AUTHENTICATE,
                     $source=_get_source(c, c$id$orig_p),
                     $value=join_string_vec(value, ",")]);
}

event smb1_session_setup_andx_request(c: connection, hdr: SMB1::Header, request: SMB1::SessionSetupAndXRequest) {
    local value = vector(
        fmt("os:%s", encode_base64(request$native_os)),
        fmt("lanmanager:%s", encode_base64(request$native_lanman)));

    if (request?$primary_domain) {
        value += "domain:" + encode_base64(request$primary_domain);
    }
    if (request?$account_name) {
        value += "account_name:" + encode_base64(request$account_name);
    }
    if (request?$account_password) {
        value += "account_password:" + encode_base64(request$account_password);
    }
    if (request?$case_insensitive_password) {
        value += "account_password:" +
            encode_base64(request$case_insensitive_password);
    }

    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $host=c$id$orig_h,
                     $recon_type=SMB,
                     $source=_get_source(c, c$id$orig_p, "SMB"),
                     $value=join_string_vec(value, ",")]);
}

event smb1_session_setup_andx_response(c: connection, hdr: SMB1::Header, response: SMB1::SessionSetupAndXResponse) {
    local value: vector of string = vector();
    if (response?$native_os) {
        value += "os:" + encode_base64(response$native_os);
    }
    if (response?$native_lanman) {
        value += "lanmanager:" + encode_base64(response$native_lanman);
    }
    if (response?$primary_domain) {
        value += "domain:" + encode_base64(response$primary_domain);
    }
    if (response?$is_guest) {
        if (response$is_guest) {
            value += "is_guest:true";
        }
        else {
            value += "is_guest:false";
        }
    }
    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $host=c$id$resp_h,
                     $srvport=c$id$resp_p,
                     $recon_type=SMB,
                     $source=_get_source(c, c$id$resp_p, "SMB"),
                     $value=join_string_vec(value, ",")]);
}
