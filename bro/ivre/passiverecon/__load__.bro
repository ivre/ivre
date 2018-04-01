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

@load base/frameworks/notice
@load base/protocols/http
@load base/protocols/ssh
@load base/protocols/ssl
@load base/protocols/dns
@load base/protocols/ftp
@load base/protocols/pop3

module PassiveRecon;

export {
    redef enable_syslog = F;

    redef enum Log::ID += { LOG };

    redef enum Notice::Type += {
        PassiveRecon,
    };

    type Type: enum {
        UNKNOWN,
        HTTP_CLIENT_HEADER,
        HTTP_SERVER_HEADER,
        HTTP_CLIENT_HEADER_SERVER,
        SSH_CLIENT,
        SSH_SERVER,
        SSH_CLIENT_ALGOS,
        SSH_SERVER_ALGOS,
        SSH_SERVER_HOSTKEY,
        SSL_SERVER,
        DNS_ANSWER,
        FTP_CLIENT,
        FTP_SERVER,
        POP_CLIENT,
        POP_SERVER,
        TCP_CLIENT_BANNER,
        TCP_SERVER_BANNER,
        P0F,
    };

    type Info: record {
        ## The time at which the software was detected.
        ts: time &log;
        ## The connection uid
        uid: string &log;
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
    # scripts/base/protocols/ssl/dpd.sig) and HTTP requests (from
    # scripts/base/protocols/http/dpd.sig)
    const TCP_CLIENT_BANNER_IGNORE: pattern = /^(\x16\x03[\x00\x01\x02\x03]..\x01...\x03[\x00\x01\x02\x03]|...?\x01[\x00\x03][\x00\x01\x02\x03\x04]|\x16\xfe[\xff\xfd]\x00\x00\x00\x00\x00\x00\x00...\x01...........\xfe[\xff\xfd]|[[:space:]]*(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|VERSION-CONTROL|REPORT|CHECKOUT|CHECKIN|UNCHECKOUT|MKWORKSPACE|UPDATE|LABEL|MERGE|BASELINE-CONTROL|MKACTIVITY|ORDERPATCH|ACL|PATCH|SEARCH|BCOPY|BDELETE|BMOVE|BPROPFIND|BPROPPATCH|NOTIFY|POLL|SUBSCRIBE|UNSUBSCRIBE|X-MS-ENUMATTS|RPC_OUT_DATA|RPC_IN_DATA)[[:space:]]*)/;

    # Ignore HTTP server responses (from scripts/base/protocols/http/dpd.sig)
    const TCP_SERVER_BANNER_IGNORE: pattern = /^HTTP\/[0-9]/;
}

event bro_init() {
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
        if (name in HTTP_CLIENT_HEADER_SERVERS) {
            # While this is a header sent by the client,
            # it gives information about the server
            # if (name == "COOKIE")
            # 	value = split1(value, /=/)[1];
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
    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $host=c$id$resp_h,
                     $srvport=c$id$resp_p,
                     $recon_type=SSH_SERVER,
                     $value=version]);
}

event ssh1_server_host_key(c: connection, p: string, e: string) {
    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $host=c$id$resp_h,
                     $srvport=c$id$resp_p,
                     $recon_type=SSH_SERVER_HOSTKEY,
                     $source="SSHv1",
                     $value=fmt("%s %s", p, e)]);
}

event ssh2_server_host_key(c: connection, key: string) {
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
    }
}

event ssl_established(c: connection) {
    if (! (c$ssl?$cert_chain && |c$ssl$cert_chain| > 0) )
        return;
    Log::write(LOG, [
        $ts=c$start_time,
        $uid=c$uid,
        $host=c$id$resp_h,
        $srvport=c$id$resp_p,
        $recon_type=SSL_SERVER,
        $source="cert",
        $value=encode_base64(x509_get_certificate_string(c$ssl$cert_chain[0]$x509$handle))
    ]);
}

event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) {
    Log::write(LOG, [$ts=c$start_time,
                     $uid=c$uid,
                     $host=a,
                     $recon_type=DNS_ANSWER,
                     $source=fmt("A-%s-%d", c$id$resp_h, c$id$resp_p),
                     $value=ans$query]);
}

event dns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) {
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
    if (seq == 1) {
        if (is_orig && c$resp$size == 0 && c$history == TCP_BANNER_HISTORY &&
            ! (TCP_CLIENT_BANNER_IGNORE in contents))
            Log::write(LOG, [$ts=c$start_time,
                             $uid=c$uid,
                             $host=c$id$orig_h,
                             $recon_type=TCP_CLIENT_BANNER,
                             $value=contents]);
        else if (c$orig$size == 0 && c$history == TCP_BANNER_HISTORY &&
             ! (TCP_SERVER_BANNER_IGNORE in contents))
            Log::write(LOG, [$ts=c$start_time,
                             $uid=c$uid,
                             $host=c$id$resp_h,
                             $srvport=c$id$resp_p,
                             $recon_type=TCP_SERVER_BANNER,
                             $value=contents]);
    }
}

event OS_version_found(c: connection, host: addr, OS: OS_version) {
    if (OS$match_type == direct_inference && OS$genre != "UNKNOWN")
        Log::write(LOG, [$ts=c$start_time,
                         $uid=c$uid,
                         $host=host,
                         $recon_type=P0F,
                         $source=fmt("%d-%s", OS$dist, OS$detail),
                         $value=OS$genre]);
}
