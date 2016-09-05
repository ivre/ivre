#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2015 Pierre LALET <pierre.lalet@cea.fr>
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

import subprocess
import resource
import multiprocessing
import pipes
import shutil
import select
import re
import os
import sys
import fcntl
import time
import termios

import ivre.geoiputils
import ivre.utils
import ivre.target
import ivre.nmapopt

if sys.version_info >= (2, 7):
    import functools
    USE_PARTIAL = True
else:
    # Python version <= 2.6:
    # see http://bugs.python.org/issue5228
    # multiprocessing not compatible with functools.partial
    USE_PARTIAL = False

STATUS_NEW = 0
STATUS_DONE_UP = 1
STATUS_DONE_DOWN = 2
STATUS_DONE_UNKNOWN = 3

NMAP_LIMITS = {}


def setnmaplimits():
    """Enforces limits from NMAP_LIMITS global variable."""
    for limit, value in NMAP_LIMITS.iteritems():
        resource.setrlimit(limit, value)


class XmlProcess(object):
    addrrec = re.compile('<address\\s+addr="([0-9\\.]+)" addrtype="ipv4"/>')

    def target_status(self, _):
        return STATUS_NEW


class XmlProcessTest(XmlProcess):

    def process(self, fdesc):
        data = fdesc.read()
        if data == '':
            return False
        for addr in self.addrrec.finditer(data):
            print "Read adddress", addr.groups()[0]
        return True


class XmlProcessWritefile(XmlProcess):
    statusline = re.compile('<task(begin|end|progress).*/>\n')
    status_up = '<status state="up"'
    status_down = '<status state="down"'
    hostbegin = re.compile('<host[\\s>]')
    status_paths = {
        'up': STATUS_DONE_UP,
        'down': STATUS_DONE_DOWN,
        'unknown': STATUS_DONE_UNKNOWN,
    }

    def __init__(self, path, fulloutput=False):
        self.path = path
        self.starttime = int(time.time() * 1000000)
        self.data = ''
        self.isstarting = True
        self.startinfo = ''
        ivre.utils.makedirs(self.path)
        self.scaninfo = open('%sscaninfo.%d' % (self.path,
                                                self.starttime),
                             'w')
        if fulloutput:
            self.has_fulloutput = True
            self.fulloutput = open('%sfulloutput.%d' % (self.path,
                                                        self.starttime),
                                   'w')
        else:
            self.has_fulloutput = False

    def process(self, fdesc):
        newdata = fdesc.read()
        # print "READ", len(newdata), "bytes"
        if newdata == '':
            self.scaninfo.write(self.data)
            self.scaninfo.close()
            if self.has_fulloutput:
                self.fulloutput.close()
            return False
        if self.has_fulloutput:
            self.fulloutput.write(newdata)
            self.fulloutput.flush()
        self.data += newdata
        while '</host>' in self.data:
            hostbeginindex = self.data.index(
                self.hostbegin.search(self.data).group())
            self.scaninfo.write(self.data[:hostbeginindex])
            self.scaninfo.flush()
            if self.isstarting:
                self.startinfo += self.statusline.sub(
                    '', self.data[:hostbeginindex])
                self.isstarting = False
            self.data = self.data[hostbeginindex:]
            hostrec = self.data[:self.data.index('</host>') + 7]
            try:
                addr = self.addrrec.search(hostrec).groups()[0]
            except Exception as exc:
                print exc
                print hostrec
            if self.status_up in hostrec:
                status = 'up'
            elif self.status_down in hostrec:
                status = 'down'
            else:
                status = 'unknown'
            outfile = self.path + status + \
                '/' + addr.replace('.', '/') + '.xml'
            ivre.utils.makedirs(os.path.dirname(outfile))
            with open(outfile, 'w') as fdesc:
                # fdesc.write('<scaninfo starttime="%d" />\n' % starttime)
                fdesc.write(self.startinfo)
                fdesc.write(hostrec)
                fdesc.write('\n</nmaprun>\n')
            self.data = self.data[self.data.index('</host>') + 7:]
            if self.data.startswith('\n'):
                self.data = self.data[1:]
        return True

    def target_status(self, target):
        for status, statuscode in self.status_paths.iteritems():
            try:
                os.stat(os.path.join(self.path, status,
                                     target.replace('.', '/') + '.xml'))
                return statuscode
            except OSError:
                pass
        return STATUS_NEW


def restore_echo():
    """Hack for https://stackoverflow.com/questions/6488275 equivalent
    issue with Nmap (from
    http://stackoverflow.com/a/8758047/3223422)

    """
    fdesc = sys.stdin.fileno()
    attrs = termios.tcgetattr(fdesc)
    attrs[3] = attrs[3] | termios.ECHO
    termios.tcsetattr(fdesc, termios.TCSADRAIN, attrs)


def call_nmap(options, xmlprocess, targets,
              accept_target_status=None):
    if accept_target_status is None:
        accept_target_status = [STATUS_NEW]
    options += ['-oX', '-', '-iL', '-']
    proc = subprocess.Popen(options, preexec_fn=setnmaplimits,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    procout = proc.stdout.fileno()
    procoutfl = fcntl.fcntl(procout, fcntl.F_GETFL)
    fcntl.fcntl(procout, fcntl.F_SETFL, procoutfl | os.O_NONBLOCK)
    toread = [proc.stdout]
    towrite = [proc.stdin]
    targiter = targets.__iter__()
    while toread:
        # print "ENTERING SELECT"
        rlist, wlist = select.select(toread, towrite, [])[:2]
        # print "LEAVING SELECT", rlist, wlist
        for rfdesc in rlist:
            # print "PROCESSING DATA"
            if not xmlprocess.process(rfdesc):
                print "NO MORE DATA TO PROCSESS"
                rfdesc.close()
                toread.remove(rfdesc)
        for wfdesc in wlist:
            try:
                naddr = ivre.utils.int2ip(targiter.next())
                while xmlprocess.target_status(
                        naddr) not in accept_target_status:
                    naddr = ivre.utils.int2ip(targiter.next())
                print "ADDING TARGET",
                print targiter.nextcount,
                if hasattr(targets, "targetcount"):
                    print '/', targets.targetscount,
                print ":", naddr
                wfdesc.write(naddr + '\n')
                wfdesc.flush()
            except StopIteration:
                print "WROTE ALL TARGETS"
                wfdesc.close()
                towrite.remove(wfdesc)
            except IOError:
                print "ERROR: NMAP PROCESS IS DEAD"
                return -1
    proc.wait()
    return 0


def _call_nmap_single(maincategory, options,
                      accept_target_status, target):
    target = ivre.utils.int2ip(target)
    outfile = 'scans/%s/%%s/%s.xml' % (maincategory, target.replace('.', '/'))
    if STATUS_DONE_UP not in accept_target_status:
        try:
            os.stat(outfile % 'up')
            return
        except OSError:
            pass
    if STATUS_DONE_DOWN not in accept_target_status:
        try:
            os.stat(outfile % 'down')
            return
        except OSError:
            pass
    if STATUS_DONE_UNKNOWN not in accept_target_status:
        try:
            os.stat(outfile % 'unknown')
            return
        except OSError:
            pass
    ivre.utils.makedirs(os.path.dirname(outfile % 'current'))
    subprocess.call(options + ['-oX', outfile % 'current', target],
                    preexec_fn=setnmaplimits)
    resdata = open(outfile % 'current').read()
    if '<status state="up"' in resdata:
        outdir = 'up'
    elif '<status state="down"' in resdata:
        outdir = 'down'
    else:
        outdir = 'unknown'
    ivre.utils.makedirs(os.path.dirname(outfile % outdir))
    shutil.move(outfile % 'current', outfile % outdir)

def main():
    accept_target_status = set([STATUS_NEW])
    try:
        import argparse
        parser = argparse.ArgumentParser(
            description='Run massive nmap scans.',
            parents=[ivre.target.argparser,
                     ivre.nmapopt.argparser])
        USING_ARGPARSE = True
    except ImportError:
        import optparse
        parser = optparse.OptionParser(
            description='Run massive nmap scans.')
        for parent in [ivre.target.argparser, ivre.nmapopt.argparser]:
            for args, kargs in parent.args:
                parser.add_option(*args, **kargs)
        parser.parse_args_orig = parser.parse_args
        parser.parse_args = lambda: parser.parse_args_orig()[0]
        parser.add_argument = parser.add_option
        USING_ARGPARSE = False
    parser.add_argument('--output',
                        choices=['XML', 'XMLFull', 'XMLFork', 'Test',
                                 'Count', 'List', 'ListAll',
                                 'ListAllRand', 'ListCIDRs',
                                 'CommandLine'],
                        default='XML',
                        help='select output method for scan results')
    parser.add_argument('--processes', metavar='COUNT', type=int, default=30,
                        help='run COUNT nmap processes in parallel '
                        '(when --output=XMLFork)')
    parser.add_argument('--nmap-max-cpu', metavar='TIME', type=int,
                        help='maximum amount of CPU time (in seconds) '
                        'per nmap process')
    parser.add_argument('--nmap-max-heap-size', metavar='SIZE', type=int,
                        help="maximum size (in bytes) of each nmap "
                        "process's heap")
    parser.add_argument('--nmap-max-stack-size', metavar='SIZE', type=int,
                        help="maximum size (in bytes) of each nmap "
                        "process's stack")
    if USING_ARGPARSE:
        parser.add_argument('--again', nargs='+',
                            choices=['up', 'down', 'unknown', 'all'],
                            help='select status of targets to scan again')
    else:
        parser.add_argument('--again',
                            choices=['up', 'down', 'unknown', 'all'],
                            help='select status of targets to scan again')
    args = parser.parse_args()
    if args.output == 'CommandLine':
        print "Command line to run a scan with template %s" % args.nmap_template
        print "   ",
        print " ".join(pipes.quote(elt) for elt in
                       ivre.nmapopt.build_nmap_options(args))
        exit(0)
    if args.output == 'Count':
        if args.country is not None:
            print '%s has %d IPs.' % (
                args.country,
                ivre.geoiputils.count_ips_by_country(args.country)
            )
            exit(0)
        if args.region is not None:
            print '%s / %s has %d IPs.' % (
                args.region[0], args.region[1],
                ivre.geoiputils.count_ips_by_region(*args.region),
            )
            exit(0)
        if args.asnum is not None:
            print 'AS%d has %d IPs.' % (
                args.asnum,
                ivre.geoiputils.count_ips_by_asnum(args.asnum)
            )
            exit(0)
        if args.routable:
            print 'We have %d routable IPs.' % (
                ivre.geoiputils.count_routable_ips()
            )
            exit(0)
        parser.error("argument --output: invalid choice: '%s' "
                     "(only available with --country, --asnum, --region "
                     "or --routable)" % args.output)
    if args.output in ['List', 'ListAll', 'ListCIDRs']:
        if args.output == 'List':
            listall = False
            listcidrs = False
        elif args.output == 'ListAll':
            listall = True
            listcidrs = False
        else:  # args.output == 'ListCIDRs'
            listall = False
            listcidrs = True
        if args.country is not None:
            ivre.geoiputils.list_ips_by_country(args.country,
                                                listall=listall,
                                                listcidrs=listcidrs)
            exit(0)
        if args.region is not None:
            ivre.geoiputils.list_ips_by_region(*args.region,
                                               listall=listall,
                                               listcidrs=listcidrs)
            exit(0)
        if args.asnum is not None:
            ivre.geoiputils.list_ips_by_asnum(args.asnum,
                                              listall=listall,
                                              listcidrs=listcidrs)
            exit(0)
        if args.routable:
            ivre.geoiputils.list_routable_ips(listall=listall,
                                              listcidrs=listcidrs)
            exit(0)
        parser.error("argument --output: invalid choice: '%s' "
                     "(only available with --country, --region, --asnum "
                     "or --routable)" % args.output)
    targets = ivre.target.target_from_args(args)
    if targets is None:
        parser.error('one argument of --country/--region/--asnum/--range/'
                     '--network/--routable/--file/--test is required')
    if args.again is not None:
        accept_target_status = set(reduce(
            lambda x, y: x + y, [{
                'up': [STATUS_DONE_UP],
                'down': [STATUS_DONE_DOWN],
                'unknown': [STATUS_DONE_UNKNOWN],
                'all': [STATUS_DONE_UP, STATUS_DONE_DOWN,
                        STATUS_DONE_UNKNOWN]
            }[x] for x in args.again],
            [STATUS_NEW]))
    if args.zmap_prescan_port is not None:
        args.nmap_ping_types = ["PS%d" % args.zmap_prescan_port]
    elif args.nmap_prescan_ports is not None:
        args.nmap_ping_types = [
            "PS%s" % ",".join(str(p) for p in args.nmap_prescan_ports)
        ]
    options = ivre.nmapopt.build_nmap_options(args)
    if args.nmap_max_cpu is not None:
        NMAP_LIMITS[resource.RLIMIT_CPU] = (args.nmap_max_cpu,
                                            args.nmap_max_cpu)
    if args.nmap_max_heap_size is not None:
        NMAP_LIMITS[resource.RLIMIT_DATA] = (args.nmap_max_heap_size,
                                             args.nmap_max_heap_size)
    if args.nmap_max_stack_size is not None:
        NMAP_LIMITS[resource.RLIMIT_STACK] = (args.nmap_max_stack_size,
                                              args.nmap_max_stack_size)
    if args.output == 'XMLFork':
        if USE_PARTIAL:
            call_nmap_single = functools.partial(_call_nmap_single,
                                                 targets.infos[
                                                     'categories'][0],
                                                 options,
                                                 accept_target_status)
        else:
            def call_nmap_single(target):
                return _call_nmap_single(targets.infos['categories'][0],
                                         options,
                                         accept_target_status,
                                         target)
        pool = multiprocessing.Pool(processes=args.processes)
        for _ in pool.imap(call_nmap_single, targets, chunksize=1):
            pass
        restore_echo()
        exit(0)
    elif args.output == 'ListAllRand':
        targiter = targets.__iter__()
        try:
            for t in targiter:
                print ivre.utils.int2ip(t)
        except KeyboardInterrupt:
            print 'Interrupted.\nUse "--state %s" to resume.' % (
                ' '.join(map(str, targiter.getstate())))
        except Exception as e:
            print 'ERROR: %r.' % e
            print 'Use "--state %s" to resume.' % (
                ' '.join(map(str, targiter.getstate())))
        exit(0)
    xmlprocess = {
        'XML': (XmlProcessWritefile,
                ['./scans/%s/' % targets.infos['categories'][0]], {}),
        'XMLFull': (XmlProcessWritefile,
                    ['./scans/%s/' % targets.infos['categories'][0]],
                    {'fulloutput': True}),
        'Test': (XmlProcessTest, [], {}),
    }[args.output]
    xmlprocess = xmlprocess[0](*xmlprocess[1], **xmlprocess[2])
    retval = call_nmap(options, xmlprocess, targets,
                       accept_target_status=accept_target_status)
    restore_echo()
    exit(retval)
