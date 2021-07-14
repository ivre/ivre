#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2021 Pierre LALET <pierre@droids-corp.org>
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

"""
This program runs scans and produces output files importable with
ivre scan2db.
"""


import argparse
import atexit
import fcntl
import functools
import multiprocessing
import os
import re
import resource
import select
import shutil
import subprocess
import sys
import termios
import time
from typing import Any, BinaryIO, Dict, List, Optional, Set, Tuple, Type


import ivre.agent
import ivre.geoiputils
import ivre.utils
import ivre.target
from ivre.types import Target
import ivre.nmapopt


STATUS_NEW = 0
STATUS_DONE_UP = 1
STATUS_DONE_DOWN = 2
STATUS_DONE_UNKNOWN = 3

NMAP_LIMITS: Dict[int, Tuple[int, int]] = {}


def setnmaplimits() -> None:
    """Enforces limits from NMAP_LIMITS global variable."""
    for limit, value in NMAP_LIMITS.items():
        resource.setrlimit(limit, value)


class XmlProcess:
    addrrec = re.compile(b'<address\\s+addr="([0-9\\.]+)" addrtype="ipv4"/>')

    # pylint: disable=no-self-use
    def target_status(self, _target: str) -> int:
        return STATUS_NEW

    def process(self, fdesc: BinaryIO) -> bool:
        raise NotImplementedError


class XmlProcessTest(XmlProcess):
    def process(self, fdesc: BinaryIO) -> bool:
        data = fdesc.read()
        if not data:
            return False
        for addr in self.addrrec.finditer(data):
            print("Read address", addr.groups()[0].decode())
        return True


class XmlProcessWritefile(XmlProcess):
    statusline = re.compile(b"<task(begin|end|progress).*/>\n")
    status_up = b'<status state="up"'
    status_down = b'<status state="down"'
    hostbegin = re.compile(b"<host[\\s>]")
    status_paths = {
        "up": STATUS_DONE_UP,
        "down": STATUS_DONE_DOWN,
        "unknown": STATUS_DONE_UNKNOWN,
    }

    def __init__(self, path: str, fulloutput: bool = False) -> None:
        self.path = path
        self.starttime = int(time.time() * 1000000)
        self.data = b""
        self.isstarting = True
        self.startinfo = b""
        ivre.utils.makedirs(self.path)
        # pylint: disable=consider-using-with
        self.scaninfo = open("%sscaninfo.%d" % (self.path, self.starttime), "wb")
        if fulloutput:
            self.has_fulloutput = True
            # pylint: disable=consider-using-with
            self.fulloutput = open(
                "%sfulloutput.%d" % (self.path, self.starttime), "wb"
            )
        else:
            self.has_fulloutput = False

    def process(self, fdesc: BinaryIO) -> bool:
        newdata = fdesc.read()
        # print("READ", len(newdata), "bytes")
        if not newdata:
            self.scaninfo.write(self.data)
            self.scaninfo.close()
            if self.has_fulloutput:
                self.fulloutput.close()
            return False
        if self.has_fulloutput:
            self.fulloutput.write(newdata)
            self.fulloutput.flush()
        self.data += newdata
        while b"</host>" in self.data:
            hostbeginmatch = self.hostbegin.search(self.data)
            assert hostbeginmatch is not None
            hostbeginindex = self.data.index(hostbeginmatch.group())
            self.scaninfo.write(self.data[:hostbeginindex])
            self.scaninfo.flush()
            if self.isstarting:
                self.startinfo += self.statusline.sub(
                    b"",
                    self.data[:hostbeginindex],
                )
                self.isstarting = False
            self.data = self.data[hostbeginindex:]
            hostrec = self.data[: self.data.index(b"</host>") + 7]
            try:
                addrmatch = self.addrrec.search(hostrec)
                assert addrmatch is not None
                addr = addrmatch.groups()[0]
            except Exception:
                ivre.utils.LOGGER.warning(
                    "Exception for record %r", hostrec, exc_info=True
                )
            if self.status_up in hostrec:
                status = "up"
            elif self.status_down in hostrec:
                status = "down"
            else:
                status = "unknown"
            outfile = (
                self.path + status + "/" + addr.decode().replace(".", "/") + ".xml"
            )
            ivre.utils.makedirs(os.path.dirname(outfile))
            with open(outfile, "wb") as out:
                # out.write(b'<scaninfo starttime="%d" />\n' % starttime)
                out.write(self.startinfo)
                out.write(hostrec)
                out.write(b"\n</nmaprun>\n")
            self.data = self.data[self.data.index(b"</host>") + 7 :]
            if self.data.startswith(b"\n"):
                self.data = self.data[1:]
        return True

    def target_status(self, target: str) -> int:
        for status, statuscode in self.status_paths.items():
            try:
                os.stat(
                    os.path.join(self.path, status, target.replace(".", "/") + ".xml")
                )
                return statuscode
            except OSError:
                pass
        return STATUS_NEW


def restore_echo() -> None:
    """Hack for https://stackoverflow.com/questions/6488275 equivalent
    issue with Nmap (from
    http://stackoverflow.com/a/8758047/3223422)

    """
    try:
        fdesc = sys.stdin.fileno()
    except ValueError:
        return
    try:
        attrs = termios.tcgetattr(fdesc)
    except termios.error:
        return
    attrs[3] = attrs[3] | termios.ECHO
    termios.tcsetattr(fdesc, termios.TCSADRAIN, attrs)


def call_nmap(
    options: List[str],
    xmlprocess: XmlProcess,
    targets: Target,
    accept_target_status: Optional[Set[int]] = None,
) -> int:
    if accept_target_status is None:
        accept_target_status = {STATUS_NEW}
    options += ["-oX", "-", "-iL", "-"]
    # pylint: disable=consider-using-with
    proc = subprocess.Popen(
        options, preexec_fn=setnmaplimits, stdin=subprocess.PIPE, stdout=subprocess.PIPE
    )
    assert proc.stdout is not None
    procout = proc.stdout.fileno()
    procoutfl = fcntl.fcntl(procout, fcntl.F_GETFL)
    fcntl.fcntl(procout, fcntl.F_SETFL, procoutfl | os.O_NONBLOCK)
    toread = [proc.stdout]
    towrite = [proc.stdin]
    targiter = iter(targets)
    while toread:
        # print("ENTERING SELECT")
        rlist, wlist = select.select(toread, towrite, [])[:2]
        # print("LEAVING SELECT", rlist, wlist)
        for rfdesc in rlist:
            # print("PROCESSING DATA")
            if not xmlprocess.process(rfdesc):
                print("NO MORE DATA TO PROCESS")
                rfdesc.close()
                toread.remove(rfdesc)
        for wfdesc in wlist:
            try:
                naddr = ivre.utils.int2ip(next(targiter))
                while xmlprocess.target_status(naddr) not in accept_target_status:
                    naddr = ivre.utils.int2ip(next(targiter))
                print("ADDING TARGET", end=" ")
                # TargetIter has a .nextcount attribute
                print(targiter.nextcount, end=" ")  # type: ignore
                if hasattr(targets, "targetscount"):
                    print("/", targets.targetscount, end=" ")
                print(":", naddr)
                wfdesc.write(naddr.encode() + b"\n")
                wfdesc.flush()
            except StopIteration:
                print("WROTE ALL TARGETS")
                wfdesc.close()
                towrite.remove(wfdesc)
            except IOError:
                print("ERROR: NMAP PROCESS IS DEAD")
                return -1
    proc.wait()
    return 0


def _call_nmap_single(
    maincategory: str, options: List[str], accept_target_status: List[int], target: int
) -> None:
    target_str = ivre.utils.int2ip(target)
    outfile = "scans/%s/%%s/%s.xml" % (maincategory, target_str.replace(".", "/"))
    if STATUS_DONE_UP not in accept_target_status:
        try:
            os.stat(outfile % "up")
            return
        except OSError:
            pass
    if STATUS_DONE_DOWN not in accept_target_status:
        try:
            os.stat(outfile % "down")
            return
        except OSError:
            pass
    if STATUS_DONE_UNKNOWN not in accept_target_status:
        try:
            os.stat(outfile % "unknown")
            return
        except OSError:
            pass
    ivre.utils.makedirs(os.path.dirname(outfile % "current"))
    subprocess.call(
        options + ["-oX", outfile % "current", target_str], preexec_fn=setnmaplimits
    )
    with open(outfile % "current", "rb") as fdesc:
        resdata = fdesc.read()
    if b'<status state="up"' in resdata:
        outdir = "up"
    elif b'<status state="down"' in resdata:
        outdir = "down"
    else:
        outdir = "unknown"
    ivre.utils.makedirs(os.path.dirname(outfile % outdir))
    shutil.move(outfile % "current", outfile % outdir)


def main() -> None:
    atexit.register(restore_echo)
    accept_target_status = set([STATUS_NEW])
    parser = argparse.ArgumentParser(
        description="Run massive nmap scans.",
        parents=[ivre.target.ARGPARSER, ivre.nmapopt.ARGPARSER],
    )
    parser.add_argument(
        "--output",
        choices=[
            "XML",
            "XMLFull",
            "XMLFork",
            "Test",
            "Count",
            "List",
            "ListAll",
            "ListAllRand",
            "ListCIDRs",
            "CommandLine",
            "Agent",
        ],
        default="XML",
        help="select output method for scan results",
    )
    parser.add_argument(
        "--processes",
        metavar="COUNT",
        type=int,
        default=30,
        help="run COUNT nmap processes in parallel " "(when --output=XMLFork)",
    )
    parser.add_argument(
        "--nmap-max-cpu",
        metavar="TIME",
        type=int,
        help="maximum amount of CPU time (in seconds) " "per nmap process",
    )
    parser.add_argument(
        "--nmap-max-heap-size",
        metavar="SIZE",
        type=int,
        help="maximum size (in bytes) of each nmap " "process's heap",
    )
    parser.add_argument(
        "--nmap-max-stack-size",
        metavar="SIZE",
        type=int,
        help="maximum size (in bytes) of each nmap " "process's stack",
    )
    parser.add_argument(
        "--again",
        nargs="+",
        choices=["up", "down", "unknown", "all"],
        help="select status of targets to scan again",
    )
    args = parser.parse_args()
    if args.output == "CommandLine":
        print("Command line to run a scan with template " "%s" % args.nmap_template)
        print(
            "    %s"
            % ivre.nmapopt.build_nmap_commandline(
                template=args.nmap_template,
            )
        )
        sys.exit(0)
    if args.output == "Agent":
        sys.stdout.write(ivre.agent.build_agent(template=args.nmap_template))
        sys.exit(0)
    targets = ivre.target.target_from_args(args)
    if args.output in ["Count", "List", "ListAll", "ListCIDRs"]:
        if isinstance(targets, ivre.target.TargetFile):
            parser.error(
                "argument --output: invalid choice: '%s' "
                "(not available with this target selection)" % args.output
            )
        if args.output == "Count":
            count = len(targets)
            print("Target has %d IP address%s" % (count, "es" if count > 1 else ""))
        elif args.output == "List":
            for start_stop in targets.targets.iter_ranges():
                print("%s - %s" % start_stop)
        else:
            for out in {
                "ListAll": targets.targets.iter_addrs,
                "ListCIDRs": targets.targets.iter_nets,
            }[args.output]():
                print(out)
        sys.exit(0)
    if targets is None:
        parser.error(
            "one argument of --country/--region/--city/--asnum/"
            "--range/--network/--routable/--file/--test is required"
        )
    if args.again is not None:
        accept_target_status = set(
            status
            for x in args.again
            for status in {
                "up": [STATUS_DONE_UP],
                "down": [STATUS_DONE_DOWN],
                "unknown": [STATUS_DONE_UNKNOWN],
                "all": [STATUS_DONE_UP, STATUS_DONE_DOWN, STATUS_DONE_UNKNOWN],
            }[x]
        )
        accept_target_status.add(STATUS_NEW)
    if args.zmap_prescan_port is not None:
        args.nmap_ping_types = ["PS%d" % args.zmap_prescan_port]
    elif args.nmap_prescan_ports is not None:
        args.nmap_ping_types = [
            "PS%s" % ",".join(str(p) for p in args.nmap_prescan_ports)
        ]
    options = ivre.nmapopt.build_nmap_options(template=args.nmap_template)
    if args.nmap_max_cpu is not None:
        NMAP_LIMITS[resource.RLIMIT_CPU] = (args.nmap_max_cpu, args.nmap_max_cpu)
    if args.nmap_max_heap_size is not None:
        NMAP_LIMITS[resource.RLIMIT_DATA] = (
            args.nmap_max_heap_size,
            args.nmap_max_heap_size,
        )
    if args.nmap_max_stack_size is not None:
        NMAP_LIMITS[resource.RLIMIT_STACK] = (
            args.nmap_max_stack_size,
            args.nmap_max_stack_size,
        )
    if args.output == "XMLFork":
        with multiprocessing.Pool(processes=args.processes) as pool:
            call_nmap_single = functools.partial(
                _call_nmap_single,
                targets.infos["categories"][0],
                options,
                accept_target_status,
            )
            for _ in pool.imap(call_nmap_single, targets, chunksize=1):
                pass
        sys.exit(0)
    elif args.output == "ListAllRand":
        targiter = iter(targets)
        try:
            for target in targiter:
                print(ivre.utils.int2ip(target))
        except KeyboardInterrupt:
            print(
                'Interrupted.\nUse "--state %s" to resume.'
                # TargetIter has a .getstate method
                % (" ".join(str(elt) for elt in targiter.getstate()))  # type: ignore
            )
        except Exception:
            ivre.utils.LOGGER.critical("Exception", exc_info=True)
            print(
                'Use "--state %s" to resume.'
                # TargetIter has a .getstate method
                % (" ".join(str(elt) for elt in targiter.getstate()))  # type: ignore
            )
        sys.exit(0)
    xmlprocess_choice: Dict[str, Tuple[Type[XmlProcess], List[str], Dict[str, Any]]] = {
        "XML": (
            XmlProcessWritefile,
            ["./scans/%s/" % targets.infos["categories"][0]],
            {},
        ),
        "XMLFull": (
            XmlProcessWritefile,
            ["./scans/%s/" % targets.infos["categories"][0]],
            {"fulloutput": True},
        ),
        "Test": (XmlProcessTest, [], {}),
    }
    xmlprocess = xmlprocess_choice[args.output]
    xmlprocess_call = xmlprocess[0](*xmlprocess[1], **xmlprocess[2])  # type: ignore
    retval = call_nmap(
        options, xmlprocess_call, targets, accept_target_status=accept_target_status
    )
    sys.exit(retval)
