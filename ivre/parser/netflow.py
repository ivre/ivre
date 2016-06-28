#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2016 Pierre LALET <pierre.lalet@cea.fr>
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

"""Support for NetFlow files"""

import datetime
from itertools import izip

from ivre import utils
from ivre.parser import CmdParser

class NetFlow(CmdParser):
    """NetFlow log generator"""

    fields = [
        ("start_time", "%ts"),
        ("end_time", "%te"),
        ("proto", "%pr"),
        ("addr1", "%sa"),
        ("addr2", "%da"),
        ("port1", "%sp"),
        ("port2", "%dp"),
        ("pkts1", "%opkt"),
        ("pkts2", "%ipkt"),
        ("bytes1", "%obyt"),
        ("bytes2", "%ibyt"),
        ("flags", "%flg"),
    ]
    field_idx = dict((fld, idx) for idx, (fld, _) in enumerate(fields))
    fmt = 'fmt:' + ','.join(fmt for _, fmt in fields)
    units = {
        'K': 1000,
        'M': 1000000,
        'G': 1000000000,
        'T': 1000000000000,
    }
    timefmt = '%Y-%m-%d %H:%M:%S.%f'

    def __init__(self, fdesc, pcap_filter=None):
        """Creates the NetFlow object.

        fdesc: a file-like object or a filename
        pcap_filter: a PCAP filter to use with nfdump

        """
        cmd = ["nfdump", "-aq", "-o", self.fmt]
        cmdkargs = {}
        if isinstance(fdesc, basestring):
            with open(fdesc) as fde:
                if fde.read(2) not in utils.FileOpener.FILE_OPENERS_MAGIC:
                    cmd.extend(["-r", fdesc])
                else:
                    cmdkargs["stdin"] = utils.open_file(fdesc)
        else:
            cmdkargs["stdin"] = fdesc
        if pcap_filter is not None:
            cmd.append(pcap_filter)
        super(NetFlow, self).__init__(cmd, cmdkargs)

    @classmethod
    def str2int(cls, val):
        try:
            return int(val)
        except ValueError:
            return int(float(val[:-1]) * cls.units[val[-1]])

    @classmethod
    def parse_line(cls, line):
        fields = dict((name[0], val.strip()) for name, val in izip(cls.fields, line.split(",")))
        fields["proto"] = fields["proto"].lower()
        srv_idx = None
        if fields["proto"] == "icmp":
            # Looks like an nfdump anomaly, keeping "0.8" leads to nonsense
            # flows, whereas switching to "8.0" makes it sane again.
            if fields["port2"] == "0.8":
                fields["port2"] = "8.0"
            fields["type"], fields["code"] = [int(x) for x in
                                              fields.pop("port2").split(".")]
            # ICMP 0 is an answer to ICMP 8
            if fields["type"] == 0:
                fields["type"] = 8
                srv_idx = 1
            else:
                srv_idx = 2
            del fields["port1"]
        else:
            for field in ["port1", "port2"]:
                fields[field] = int(fields[field])
        for field in ["start_time", "end_time"]:
            fields[field] = datetime.datetime.strptime(fields[field],
                                                       cls.timefmt)
        if srv_idx is None:
            srv_idx = (
                1 if
                utils.guess_srv_port(fields["port1"], fields["port2"],
                                     proto=fields["proto"]) >= 0
                else 2
            )
        cli_idx = 1 if srv_idx == 2 else 2
        fields["src"] = fields.pop("addr%d" % cli_idx)
        fields["dst"] = fields.pop("addr%d" % srv_idx)
        if "port%s" % cli_idx in fields:
            fields["sport"] = fields.pop("port%d" % cli_idx)
        if "port%s" % srv_idx in fields:
            fields["dport"] = fields.pop("port%d" % srv_idx)
            fields["flow_name"] = "%(proto)s %(dport)s" % fields
        elif "type" in fields:
            fields["flow_name"] = "%(proto)s %(type)s" % fields
        else:
            fields["flow_name"] = fields['proto']
        fields["scbytes"] = cls.str2int(fields.pop("bytes%d" % cli_idx))
        fields["scpkts"] = cls.str2int(fields.pop("pkts%d" % cli_idx))
        fields["csbytes"] = cls.str2int(fields.pop("bytes%d" % srv_idx))
        fields["cspkts"] = cls.str2int(fields.pop("pkts%d" % srv_idx))
        return fields

