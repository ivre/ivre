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

module ARP;

export {
    ## The weird logging stream identifier.
    redef enum Log::ID += { LOG };

    redef enum Notice::Type += {
        ARP,
    };

    type Op: enum {
        WHO_HAS,
        IS_AT,
    };

    ## The record which is used for representing and logging weirds.
    type Info: record {
        ## The time when the weird occurred.
        ts: time &log;
        op: Op &log;
        mac_src: string &log;
        mac_dst: string &log;
        pkt_src: addr &log;
        pkt_dst: addr &log;
        hwr_src: string &log;
        hwr_dst: string &log;
    };
}

event bro_init() {
    Log::create_stream(LOG, [$columns=Info]);
}

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string) {
    Log::write(LOG, [$ts=network_time(),
                     $op=WHO_HAS,
                     $mac_src=mac_src,
                     $mac_dst=mac_dst,
                     $pkt_src=SPA,
                     $pkt_dst=TPA,
                     $hwr_src=SHA,
                     $hwr_dst=THA]);
}

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string) {
    Log::write(LOG, [$ts=network_time(),
                     $op=IS_AT,
                     $mac_src=mac_src,
                     $mac_dst=mac_dst,
                     $pkt_src=SPA,
                     $pkt_dst=TPA,
                     $hwr_src=SHA,
                     $hwr_dst=THA]);
}

event bad_arp(SPA: addr, SHA: string, TPA: addr, THA: string, explanation: string) {
    event flow_weird(fmt("Bad ARP %s (%s -> %s)", explanation, SHA, THA), SPA, TPA);
}
