#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2017 Pierre LALET <pierre.lalet@cea.fr>
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


from contextlib import contextmanager
from cStringIO import StringIO
from distutils.spawn import find_executable as which
import errno
import json
import os
import random
import re
import signal
import socket
import subprocess
import sys
import time
import urllib2

if sys.version_info[:2] < (2, 7):
    import unittest2 as unittest
else:
    import unittest

HTTPD_PORT = 18080
try:
    HTTPD_HOSTNAME = socket.gethostbyaddr('127.0.0.1')[0]
except:
    sys.stderr.write('Cannot guess domain name - using localhost')
    HTTPD_HOSTNAME = 'localhost'

# http://schinckel.net/2013/04/15/capture-and-test-sys.stdout-sys.stderr-in-unittest.testcase/
@contextmanager
def capture(function, *args, **kwargs):
    out, sys.stdout = sys.stdout, StringIO()
    err, sys.stderr = sys.stderr, StringIO()
    result = function(*args, **kwargs)
    sys.stdout.seek(0)
    sys.stderr.seek(0)
    yield result, sys.stdout.read(), sys.stderr.read()
    sys.stdout, sys.stderr = out, err

def run_iter(cmd, interp=None, stdin=None, stdout=subprocess.PIPE,
             stderr=subprocess.PIPE):
    if interp is not None:
        cmd = interp + [which(cmd[0])] + cmd[1:]
    return subprocess.Popen(cmd, stdin=stdin, stdout=stdout, stderr=stderr)

def run_cmd(cmd, interp=None, stdin=None):
    proc = run_iter(cmd, interp=interp, stdin=stdin)
    out, err = proc.communicate()
    return proc.returncode, out, err

def python_run(cmd, stdin=None):
    return run_cmd(cmd, interp=[sys.executable], stdin=stdin)

def python_run_iter(cmd, stdin=None, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE):
    return run_iter(cmd, interp=[sys.executable], stdin=stdin, stdout=stdout,
                    stderr=stderr)

def coverage_init():
    cov = coverage.coverage(data_suffix=True)
    cov.erase()

def coverage_run(cmd, stdin=None):
    return run_cmd(cmd, interp=COVERAGE + ["run", "--parallel-mode"], stdin=stdin)

def coverage_run_iter(cmd, stdin=None, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE):
    return run_iter(cmd, interp=COVERAGE + ["run", "--parallel-mode"],
                    stdin=stdin, stdout=stdout, stderr=stderr)

def coverage_report():
    cov = coverage.coverage()
    cov.combine(strict=True)
    cov.save()


class IvreTests(unittest.TestCase):

    def setUp(self):
        try:
            with open(os.path.join(SAMPLES, "results")) as fdesc:
                self.results = dict([l[:l.index(' = ')],
                                     eval(l[l.index(' = ') + 3:-1])]
                                    for l in fdesc if ' = ' in l)
        except IOError as exc:
            if exc.errno != errno.ENOENT:
                raise exc
            self.results = {}
        self.new_results = set()
        self.used_prefixes = set()
        self.unused_results = set(self.results)

    def tearDown(self):
        ivre.utils.cleandir("logs")
        ivre.utils.cleandir(".state")
        if self.new_results:
            with open(os.path.join(SAMPLES, "results"), 'a') as fdesc:
                for valname in self.new_results:
                    fdesc.write("%s = %r\n" % (valname, self.results[valname]))
        for name in self.unused_results:
            if any(name.startswith(prefix) for prefix in self.used_prefixes):
                sys.stderr.write("UNUSED VALUE key %r\n" % name)

    def check_value(self, name, value, check=None):
        if check is None:
            check = self.assertEqual
        try:
            self.unused_results.remove(name)
        except KeyError:
            pass
        self.used_prefixes.add(name.split('_', 1)[0] + '_')
        if name not in self.results:
            self.results[name] = value
            sys.stderr.write("NEW VALUE for key %r: %r\n" % (name, value))
            self.new_results.add(name)
        check(value, self.results[name])

    def check_value_cmd(self, name, cmd, errok=False):
        res, out, err = RUN(cmd)
        self.assertTrue(errok or not err)
        self.assertEqual(res, 0)
        self.check_value(name, out)

    def check_lines_value_cmd(self, name, cmd, errok=False):
        res, out, err = RUN(cmd)
        self.assertTrue(errok or not err)
        self.assertEqual(res, 0)
        self.check_value(name, [line for line in out.split('\n') if line],
                         check=self.assertItemsEqual)

    def check_int_value_cmd(self, name, cmd, errok=False):
        res, out, err = RUN(cmd)
        self.assertTrue(errok or not err)
        self.assertEqual(res, 0)
        self.check_value(name, int(out))

    def start_web_server(self):
        pid = os.fork()
        if pid == -1:
            raise OSError("Cannot fork()")
        if pid:
            self.children.append(pid)
            time.sleep(2)
        else:
            def terminate(signum, stack_frame):
                try:
                    proc.send_signal(signum)
                    proc.wait()
                    signal.signal(signum, signal.SIG_DFL)
                    sys.exit(0)
                except:
                    pass
            for sig in [signal.SIGINT, signal.SIGTERM]:
                signal.signal(sig, terminate)
            proc = RUN_ITER(["ivre", "httpd", "-p", str(HTTPD_PORT)],
                            stdout=open(os.devnull, 'w'),
                            stderr=subprocess.STDOUT)
            proc.wait()
            sys.exit(0)

    @classmethod
    def stop_children(cls):
        for sig in [signal.SIGINT, signal.SIGTERM, signal.SIGKILL]:
            for pid in cls.children[:]:
                try:
                    os.kill(pid, sig)
                except OSError:
                    cls.children.remove(pid)
            time.sleep(2)
        while cls.children:
            os.waitpid(cls.children.pop(), 0)

    def _check_top_value_api(self, name, field, count):
        self.check_value(name, list(ivre.db.db.nmap.topvalues(field,
                                                              topnbr=count)),
                         check=self.assertItemsEqual)

    def _check_top_value_cli(self, name, field, count):
        res, out, err = RUN(["ivre", "scancli", "--top", field, "--limit",
                             str(count)])
        self.assertTrue(not err)
        self.assertEqual(res, 0)
        self.check_value(name, [line for line in out.split('\n') if line],
                         check=self.assertItemsEqual)

    def _check_top_value_cgi(self, name, field, count):
        req = urllib2.Request('http://%s:%d/cgi-bin/'
                              'scanjson.py?action='
                              'topvalues:%s:%d' % (HTTPD_HOSTNAME, HTTPD_PORT,
                                                   field, count))
        req.add_header('Referer',
                       'http://%s:%d/' % (HTTPD_HOSTNAME, HTTPD_PORT))
        self.check_value(name, json.loads(urllib2.urlopen(req).read()),
                         check=self.assertItemsEqual)

    def check_top_value(self, name, field, count=10):
        for method in ['api', 'cli', 'cgi']:
            getattr(self, "_check_top_value_%s" % method)(
                "%s_%s" % (name, method),
                field, count,
            )

    @classmethod
    def setUpClass(cls):
        cls.nmap_files = (
            os.path.join(root, fname)
            for root, _, files in os.walk(SAMPLES)
            for fname in files
            if fname.endswith('.xml') or fname.endswith('.json')
            or fname.endswith('.xml.bz2') or fname.endswith('.json.bz2')
        )
        cls.pcap_files = (
            os.path.join(root, fname)
            for root, _, files in os.walk(SAMPLES)
            for fname in files
            if fname.endswith('.pcap')
        )
        cls.children = []

    @classmethod
    def tearDownClass(cls):
        cls.stop_children()

    def test_nmap(self):

        # Start a Web server to test CGI
        self.start_web_server()

        # Init DB
        self.assertEqual(RUN(["ivre", "scancli", "--count"])[1], "0\n")
        self.assertEqual(RUN(["ivre", "scancli", "--init"],
                              stdin=open(os.devnull))[0], 0)
        self.assertEqual(RUN(["ivre", "scancli", "--count"])[1], "0\n")

        # Insertion / "test" insertion (JSON output)
        host_counter = 0
        scan_counter = 0
        host_counter_test = 0
        scan_warning = 0
        host_stored = re.compile("^DEBUG:ivre:HOST STORED: ", re.M)
        scan_stored = re.compile("^DEBUG:ivre:SCAN STORED: ", re.M)
        def host_stored_test(line):
            try:
                return len(json.loads(line))
            except ValueError:
                return 0
        scan_duplicate = re.compile("^DEBUG:ivre:Scan already present in "
                                    "Database", re.M)
        for fname in self.nmap_files:
            # Insertion in DB
            options = ["ivre", "scan2db", "--port", "-c", "TEST",
                       "-s", "SOURCE"]
            if "-probe-" in fname:
                options.extend(["--masscan-probes", fname.split('-probe-')[1]])
            options.extend(["--", fname])
            res, _, err = RUN(options)
            self.assertEqual(res, 0)
            host_counter += sum(1 for _ in host_stored.finditer(err))
            scan_counter += sum(1 for _ in scan_stored.finditer(err))
            # Insertion test (== parsing only)
            res, out, _ = RUN(["ivre", "scan2db", "--port", "--test",
                               "-c", "TEST", "-s", "SOURCE", fname])
            self.assertEqual(res, 0)
            host_counter_test += sum(host_stored_test(line)
                                     for line in out.splitlines())
            # Duplicate insertion
            res, _, err = RUN(["ivre", "scan2db", "--port",
                               "-c", "TEST", "-s", "SOURCE", fname])
            self.assertEqual(res, 0)
            scan_warning += sum(
                1 for _ in scan_duplicate.finditer(err)
            )

        RUN(["ivre", "scancli", "--update-schema"])
        RUN(["ivre", "scancli", "--update-schema", "--archives"])

        self.assertEqual(host_counter, host_counter_test)
        self.assertEqual(scan_counter, scan_warning)

        res, out, _ = RUN(["ivre", "scancli", "--count"])
        self.assertEqual(res, 0)
        hosts_count = int(out)
        res, out, _ = RUN(["ivre", "scancli", "--count", "--archives"])
        self.assertEqual(res, 0)
        archives_count = int(out)

        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchnonexistent())
        self.assertEqual(count, 0)

        # Is the test case OK?
        self.assertGreater(hosts_count, 0)
        self.check_value("nmap_get_count", hosts_count)
        self.check_value("nmap_get_archives_count",
                         archives_count)
        # Counting results
        self.assertEqual(hosts_count + archives_count,
                         host_counter)

        # Object ID
        res, out, _ = RUN(["ivre", "scancli", "--json", "--limit", "1"])
        self.assertEqual(res, 0)
        oid = str(ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchhost(json.loads(out)['addr']),
            limit=1, fields=["_id"],
        ).next()['_id'])
        res, out, _ = RUN(["ivre", "scancli", "--count", "--id", oid])
        self.assertEqual(res, 0)
        self.assertEqual(int(out), 1)
        res, out, _ = RUN(["ivre", "scancli", "--count", "--no-id", oid])
        self.assertEqual(res, 0)
        self.assertEqual(int(out) + 1, hosts_count)

        res, out, _ = RUN(["ivre", "scancli", "--count",
                           "--countports", "20", "20"])
        self.assertEqual(res, 0)
        portsnb_20 = int(out)
        self.check_value("nmap_20_ports", portsnb_20)

        res, out, _ = RUN(["ivre", "scancli", "--count",
                           "--no-countports", "20", "20"])
        self.assertEqual(res, 0)
        portsnb_not_20 = int(out)

        self.assertEqual(portsnb_20 + portsnb_not_20, host_counter)

        res, out, _ = RUN(["ivre", "scancli", "--count",
                           "--countports", "10", "100"])
        self.assertEqual(res, 0)
        portsnb_10_100 = int(out)
        self.check_value("nmap_10-100_ports", portsnb_10_100)

        res, out, _ = RUN(["ivre", "scancli", "--count",
                           "--no-countports", "10", "100"])
        self.assertEqual(res, 0)
        portsnb_not_10_100 = int(out)
        self.check_int_value_cmd(
            "nmap_extended_eu_count",
            ["ivre", "scancli", "--count", "--country=EU*,CH,NO"],
        )

        self.assertEqual(portsnb_10_100 + portsnb_not_10_100, host_counter)

        # Filters
        addr = ivre.db.db.nmap.get(
            ivre.db.db.nmap.flt_empty, fields=["addr"]
        ).next()['addr']
        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchhost(addr)
        )
        self.assertEqual(count, 1)
        result = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchhost(addr)
        ).next()
        self.assertEqual(result['addr'], addr)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.flt_and(
            ivre.db.db.nmap.searchhost(addr),
            ivre.db.db.nmap.searchhost(addr),
        ))
        self.assertEqual(count, 1)
        # Remove
        result = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchhost(addr)
        ).next()
        ivre.db.db.nmap.remove(result)
        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchhost(addr)
        )
        self.assertEqual(count, 0)
        hosts_count -= 1
        recid = ivre.db.db.nmap.getid(
            ivre.db.db.nmap.get(ivre.db.db.nmap.flt_empty).next()
        )
        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchid(recid)
        )
        self.assertEqual(count, 1)
        self.assertIsNotNone(
            ivre.db.db.nmap.getscan(
                ivre.db.db.nmap.getscanids(
                    ivre.db.db.nmap.get(ivre.db.db.nmap.flt_empty).next()
                )[0]
            )
        )

        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchhost("127.12.34.56")
        )
        self.assertEqual(count, 0)

        generator = ivre.db.db.nmap.get(ivre.db.db.nmap.flt_empty)
        addrrange = sorted((x['addr'] for x in [generator.next(),
                                                generator.next()]),
                           key=lambda x: (ivre.utils.ip2int(x)
                                          if isinstance(x, basestring) else x))
        addr_range_count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchrange(*addrrange)
        )
        self.assertGreaterEqual(addr_range_count, 2)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.flt_and(
            ivre.db.db.nmap.searchcmp("addr", addrrange[0], '>='),
            ivre.db.db.nmap.searchcmp("addr", addrrange[1], '<='),
        ))
        self.assertEqual(count, addr_range_count)
        addrrange2 = [
            ivre.utils.int2ip(ivre.utils.ip2int(addrrange[0]) - 1)
            if isinstance(addrrange[0], basestring) else addrrange[0] - 1,
            ivre.utils.int2ip(ivre.utils.ip2int(addrrange[1]) + 1)
            if isinstance(addrrange[1], basestring) else addrrange[1] + 1,
        ]
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.flt_and(
            ivre.db.db.nmap.searchcmp("addr", addrrange2[0], '>'),
            ivre.db.db.nmap.searchcmp("addr", addrrange2[1], '<'),
        ))
        self.assertEqual(count, addr_range_count)
        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchrange(*addrrange, neg=True)
        )
        self.assertEqual(count + addr_range_count, hosts_count)
        count = sum(
            ivre.db.db.nmap.count(ivre.db.db.nmap.searchnet(net))
            for net in ivre.utils.range2nets(
                    [x if isinstance(x, basestring) else ivre.utils.int2ip(x)
                     for x in addrrange]
            )
        )
        self.assertEqual(count, addr_range_count)

        addrs = set(
            addr if isinstance(addr, basestring) else ivre.utils.int2ip(addr)
            for net in ivre.utils.range2nets(
                [x if isinstance(x, basestring) else ivre.utils.int2ip(x)
                 for x in addrrange]
            )
            for addr in ivre.db.db.nmap.distinct(
                    "addr", flt=ivre.db.db.nmap.searchnet(net),
            )
        )
        self.assertTrue(len(addrs) <= addr_range_count)

        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchhosts(addrrange)
        )
        self.assertEqual(count, 2)
        count_cmpl = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchhosts(addrrange, neg=True)
        )
        self.assertEqual(count + count_cmpl, hosts_count)

        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchtimerange(
                0, ivre.db.db.nmap.get(
                    ivre.db.db.nmap.flt_empty,
                    fields=['endtime'],
                    sort=[['endtime', -1]]
                ).next()['endtime']
            )
        )
        self.assertEqual(count, hosts_count)

        nets = ivre.utils.range2nets(addrrange)
        count = 0
        for net in nets:
            count += ivre.db.db.nmap.count(
                ivre.db.db.nmap.searchnet(net)
            )
            start, stop = map(ivre.utils.ip2int,
                              ivre.utils.net2range(net))
            for addr in ivre.db.db.nmap.distinct(
                    "addr",
                    flt=ivre.db.db.nmap.searchnet(net),
            ):
                self.assertTrue(
                    (ivre.utils.ip2int(start) if isinstance(start, basestring)
                     else start)
                    <= (ivre.utils.ip2int(addr) if isinstance(addr, basestring)
                        else addr)
                    <= (ivre.utils.ip2int(stop) if isinstance(stop, basestring)
                        else stop)
                )
        self.assertEqual(count, addr_range_count)
        # Networks in `nets` are separated sets
        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.flt_and(
                *(ivre.db.db.nmap.searchnet(net) for net in nets)
            ))
        self.assertEqual(count, 0)
        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.flt_or(
                *(ivre.db.db.nmap.searchnet(net) for net in nets)
            )
        )
        self.assertEqual(count, addr_range_count)

        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchscript(name="http-robots.txt")
        )
        # Test case OK?
        self.assertGreater(count, 0)
        self.check_value("nmap_robots.txt_count", count)

        result = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchscript(name="http-robots.txt")
        )
        addr = result.next()['addr']
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.flt_and(
            ivre.db.db.nmap.searchscript(name="http-robots.txt"),
            ivre.db.db.nmap.searchhost(addr),
        ))
        self.assertEqual(count, 1)
        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchscript(
                name="http-robots.txt",
                output=ivre.utils.str2regexp("/cgi-bin"),
            ))
        self.assertGreater(count, 0)
        self.check_value("nmap_robots.txt_cgi_count", count)

        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchftpanon())
        # Test case OK?
        self.assertGreater(count, 0)
        self.check_value("nmap_anonftp_count", count)

        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchhopdomain(re.compile('.'))
        )
        # Test case OK?
        self.assertGreater(count, 0)
        self.check_value("nmap_trace_hostname_count", count)
        result = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchhopdomain(re.compile('.'))
        )
        hop = random.choice([
            hop for hop in
            reduce(lambda x, y: x['hops'] + y['hops'],
                   result.next()['traces'],
                   {'hops': []})
            if 'domains' in hop and hop['domains']
        ])
        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchhop(hop['ipaddr'])
        )
        self.assertGreaterEqual(count, 1)
        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchhopdomain(hop['domains'][0])
        )
        self.assertGreaterEqual(count, 1)

        # Indexes
        addr = ivre.db.db.nmap.get(
            ivre.db.db.nmap.flt_empty
        ).next()['addr']
        if not isinstance(addr, basestring):
            addr = ivre.utils.int2ip(addr)
        queries = [
            ivre.db.db.nmap.searchhost(addr),
            ivre.db.db.nmap.searchnet('.'.join(addr.split('.')[:3]) + '.0/24'),
            ivre.db.db.nmap.searchrange(max(ivre.utils.ip2int(addr) - 256, 0),
                                        min(ivre.utils.ip2int(addr) + 256,
                                            4294967295)),
        ]
        for query in queries:
            result = ivre.db.db.nmap.get(query)
            count = ivre.db.db.nmap.count(query)
            if DATABASE == "mongo":
                nscanned = json.loads(ivre.db.db.nmap.explain(result))
                try:
                    nscanned = nscanned['nscanned']
                except KeyError:
                    nscanned = nscanned['executionStats']['totalDocsExamined']
                self.assertEqual(count, nscanned)
                self.assertEqual(
                    query,
                    ivre.db.db.nmap.str2flt(ivre.db.db.nmap.flt2str(query))
                )
            # FIXME: test PostgreSQL indexes
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchx11())
        self.check_value("nmap_x11_count", count)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchx11access())
        self.check_value("nmap_x11access_count", count)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchnfs())
        self.check_value("nmap_nfs_count", count)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchypserv())
        self.check_value("nmap_nis_count", count)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchphpmyadmin())
        self.check_value("nmap_phpmyadmin_count", count)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchwebfiles())
        self.check_value("nmap_webfiles_count", count)
        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchbanner(re.compile("^SSH-"))
        )
        self.check_value("nmap_ssh_count", count)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchvncauthbypass())
        self.check_value("nmap_vncauthbypass_count", count)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchmssqlemptypwd())
        self.check_value("nmap_mssql_emptypwd_count", count)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchmysqlemptypwd())
        self.check_value("nmap_mysql_emptypwd_count", count)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchxp445())
        self.check_value("nmap_xp445_count", count)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchtorcert())
        self.check_value("nmap_torcert_count", count)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchgeovision())
        self.check_value("nmap_geovision_count", count)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchwebcam())
        self.check_value("nmap_webcam_count", count)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchphonedev())
        self.check_value("nmap_phonedev_count", count)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchnetdev())
        self.check_value("nmap_netdev_count", count)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchdomain("com"))
        # Test case OK?
        self.assertGreater(count, 0)
        self.check_value("nmap_domain_com_count", count)
        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchdomain("com", neg=True)
        )
        self.check_value("nmap_not_domain_com_count", count)
        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchdomain(re.compile("^(com|net)$"),
                                         neg=True)
        )
        self.check_value("nmap_not_domain_com_or_net_count", count)
        name = ivre.db.db.nmap.get(ivre.db.db.nmap.searchdomain(
            'com'
        )).next()['hostnames'][0]['name']
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchhostname(name))
        self.assertGreater(count, 0)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchcategory("TEST"))
        self.assertEqual(count, hosts_count)
        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchcategory("TEST", neg=True)
        )
        self.assertEqual(count, 0)
        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchcategory(re.compile("^TEST$"),
                                           neg=True)
        )
        self.assertEqual(count, 0)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchsource("SOURCE"))
        self.assertEqual(count, hosts_count)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchsource("SOURCE",
                                                                   neg=True))
        self.assertEqual(count, 0)
        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchsource(re.compile("^SOURCE$"),
                                         neg=True)
        )
        self.assertEqual(count, 0)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchport(80))
        self.check_value("nmap_80_count", count)
        neg_count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchport(80,
                                       neg=True)
        )
        self.assertEqual(count + neg_count, hosts_count)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchports([80, 443]))
        self.check_value("nmap_80_443_count", count)
        neg_count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchports([80, 443],
                                        neg=True)
        )
        self.check_value("nmap_not_80_443_count", neg_count)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchopenport())
        self.check_value("nmap_openport_count", count)
        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchhttpauth(newscript=True,
                                           oldscript=True)
        )
        self.check_value("nmap_httpauth_count", count)
        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchwebmin()
        )
        self.check_value("nmap_webmin_count", count)
        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchowa()
        )
        self.check_value("nmap_owa_count", count)
        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchhttptitle(re.compile('.'))
        )
        self.check_value("nmap_http_title_count", count)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchvsftpdbackdoor())
        self.check_value("nmap_vsftpbackdoor_count", count)
        count = ivre.db.db.nmap.count(ivre.db.db.nmap.searchldapanon())
        self.check_value("nmap_ldapanon_count", count)
        self.check_int_value_cmd(
            "nmap_isakmp_count",
            ["ivre", "scancli", "--count", "--service", "isakmp"],
        )
        self.check_value_cmd(
            "nmap_isakmp_top_products",
            ["ivre", "scancli", "--top", "product", "--service", "isakmp"],
        )
        self.check_top_value("nmap_ssh_top_port", "port:ssh")
        self.check_lines_value_cmd(
            "nmap_domains_pttsh_tw",
            ["ivre", "scancli", "--domain", "/^pttsh.*tw$/i",
             "--distinct", "hostnames.name"]
        )
        self.check_value_cmd("nmap_top_filename",
                             ["ivre", "scancli", "--top", "file", "--limit",
                              "1"])
        self.check_value_cmd("nmap_top_filename",
                             ["ivre", "scancli", "--top", "file.filename",
                              "--limit", "1"])
        self.check_value_cmd("nmap_top_anonftp_filename",
                             ["ivre", "scancli", "--top", "file:ftp-anon",
                              "--limit", "1"])
        self.check_value_cmd("nmap_top_anonftp_filename",
                             ["ivre", "scancli", "--top",
                              "file:ftp-anon.filename", "--limit", "1"])
        self.check_value_cmd("nmap_top_uids",
                             ["ivre", "scancli", "--top", "file.uid"])
        self.check_value_cmd("nmap_top_anonftp_uids",
                             ["ivre", "scancli", "--top", "file:ftp-anon.uid"])
        self.check_value_cmd("nmap_top_modbus_deviceids",
                             ["ivre", "scancli", "--top", "modbus.deviceid"])
        self.check_value_cmd("nmap_top_services",
                             ["ivre", "scancli", "--top", "service"])
        self.check_value_cmd("nmap_top_product",
                             ["ivre", "scancli", "--top", "product"])
        self.check_value_cmd("nmap_top_product_http",
                             ["ivre", "scancli", "--top", "product:http"])
        self.check_value_cmd("nmap_top_version",
                             ["ivre", "scancli", "--top", "version"])
        self.check_value_cmd("nmap_top_version_http",
                             ["ivre", "scancli", "--top", "version:http"])
        self.check_value_cmd("nmap_top_version_http_apache",
                             ["ivre", "scancli", "--top", "version:http:Apache httpd"])

        categories = ivre.db.db.nmap.topvalues("category")
        category = categories.next()
        self.assertEqual(category["_id"], "TEST")
        self.assertEqual(category["count"], hosts_count)
        with self.assertRaises(StopIteration):
            categories.next()
        topgen = ivre.db.db.nmap.topvalues("service")
        topval = topgen.next()['_id']
        while topval is None:
            topval = topgen.next()['_id']
        self.check_value("nmap_topsrv", topval)
        topgen = ivre.db.db.nmap.topvalues("service:80")
        topval = topgen.next()['_id']
        while topval is None:
            topval = topgen.next()['_id']
        self.check_value("nmap_topsrv_80", topval)
        topgen = ivre.db.db.nmap.topvalues("product")
        topval = topgen.next()['_id']
        while topval[1] is None:
            topval = list(topgen.next()['_id'])
        self.check_value("nmap_topprod", topval)
        topgen = ivre.db.db.nmap.topvalues("product:80")
        topval = list(topgen.next()['_id'])
        while topval[1] is None:
            topval = list(topgen.next()['_id'])
        self.check_value("nmap_topprod_80", topval)
        topgen = ivre.db.db.nmap.topvalues("devicetype")
        topval = topgen.next()['_id']
        while topval is None:
            topval = topgen.next()['_id']
        self.check_value("nmap_topdevtype", topval)
        topgen = ivre.db.db.nmap.topvalues("devicetype:80")
        topval = topgen.next()['_id']
        while topval is None:
            topval = topgen.next()['_id']
        self.check_value("nmap_topdevtype_80", topval)
        self.check_value(
            "nmap_topdomain",
            ivre.db.db.nmap.topvalues("domains").next()['_id'])
        self.check_value(
            "nmap_topdomains_1",
            ivre.db.db.nmap.topvalues("domains:1").next()['_id'])
        self.check_value(
            "nmap_tophop",
            ivre.db.db.nmap.topvalues("hop").next()['_id'])
        self.check_value(
            "nmap_tophop_10+",
            ivre.db.db.nmap.topvalues("hop>10").next()['_id'])

        if DATABASE != "postgres":
            # FIXME: for some reason, this does not terminate
            self.assertEqual(RUN(["ivre", "scancli", "--init"],
                                 stdin=open(os.devnull))[0], 0)

    def test_passive(self):

        # Init DB
        self.assertEqual(RUN(["ivre", "ipinfo", "--count"])[1], "0\n")
        self.assertEqual(RUN(["ivre", "ipinfo", "--init"],
                             stdin=open(os.devnull))[0], 0)
        self.assertEqual(RUN(["ivre", "ipinfo", "--count"])[1], "0\n")

        # p0f & Bro insertion
        ivre.utils.makedirs("logs")
        broenv = os.environ.copy()
        broenv["LOG_ROTATE"] = "60"
        broenv["LOG_PATH"] = "logs/passiverecon"

        for fname in self.pcap_files:
            for mode in ivre.passive.P0F_MODES.values():
                p0fprocess = subprocess.Popen(
                    ['p0f', '-q', '-l', '-S', '-ttt', '-s',
                     fname] + mode['options'] + [mode['filter']],
                    stdout=subprocess.PIPE, stderr=open(os.devnull, 'w')
                )
                for line in p0fprocess.stdout:
                    timestamp, spec = ivre.passive.parse_p0f_line(
                        line,
                        include_port=(mode['name'] == 'SYN+ACK')
                    )
                    spec['sensor'] = "TEST"
                    spec['recontype'] = 'P0F2-%s' % mode['name']
                    self.assertIsNone(
                        ivre.db.db.passive.insert_or_update(
                            timestamp, spec))
            broprocess = subprocess.Popen(
                ['bro', '-b', '-r', fname,
                 os.path.join(
                     ivre.config.guess_prefix('passiverecon'),
                     'passiverecon.bro')],
                env=broenv)
            broprocess.wait()

        time.sleep(1) # Hack for Travis CI
        for root, _, files in os.walk("logs"):
            for fname in files:
                with open(os.path.join(root, fname)) as fdesc:
                    for line in fdesc:
                        if not line or line.startswith('#'):
                            continue
                        line.rstrip('\n')
                        timestamp, spec = ivre.passive.handle_rec(
                            "TEST", {}, {}, *line.split('\t'))
                        if spec is not None:
                            ivre.db.db.passive.insert_or_update(
                                timestamp, spec,
                                getinfos=ivre.passive.getinfos
                            )

        # Counting
        total_count = ivre.db.db.passive.count(
            ivre.db.db.passive.flt_empty
        )
        self.assertGreater(total_count, 0)
        self.check_value("passive_count", total_count)

        # Filters
        addr = ivre.db.db.passive.get_one(
            ivre.db.db.passive.searchnet('0.0.0.0/0')
        )["addr"]
        result = ivre.db.db.passive.count(
            ivre.db.db.passive.searchhost(addr)
        )
        self.assertGreater(result, 0)
        ret, out, err = RUN([
            "ivre", "ipinfo", "--count",
            addr if isinstance(addr, basestring) else ivre.utils.int2ip(addr),
        ])
        self.assertEqual(ret, 0)
        self.assertTrue(not err)
        self.assertEqual(int(out.strip()), result)
        ret, out, err = RUN([
            "ivre", "ipinfo",
            addr if isinstance(addr, basestring) else ivre.utils.int2ip(addr),
        ])
        self.assertEqual(ret, 0)
        self.assertTrue(not err)
        self.assertGreater(out.count('\n'), result)

        result = ivre.db.db.passive.count(
            ivre.db.db.passive.searchhost("127.12.34.56")
        )
        self.assertEqual(result, 0)

        addrrange = sorted(
            (x for x in ivre.db.db.passive.distinct('addr')
             if isinstance(x, (int, long, basestring)) and x),
            key=lambda x: (ivre.utils.ip2int(x)
                           if isinstance(x, basestring) else x),
        )
        self.assertGreaterEqual(len(addrrange), 2)
        if len(addrrange) < 4:
            addrrange = [addrrange[0], addrrange[-1]]
        else:
            addrrange = [addrrange[1], addrrange[-2]]
        result = ivre.db.db.passive.count(
            ivre.db.db.passive.searchrange(*addrrange)
        )
        self.assertGreaterEqual(result, 2)
        addresses_1 = list(ivre.db.db.passive.distinct(
            'addr',
            flt=ivre.db.db.passive.searchrange(*addrrange),
        ))
        addresses_2 = list(ivre.db.db.passive.distinct(
            'addr',
            flt=ivre.db.db.passive.flt_and(
                ivre.db.db.passive.searchcmp("addr", addrrange[0], '>='),
                ivre.db.db.passive.searchcmp("addr", addrrange[1], '<='),
            ),
        ))
        self.assertItemsEqual(addresses_1, addresses_2)
        addresses_2 = list(ivre.db.db.passive.distinct(
            'addr',
            flt=ivre.db.db.passive.flt_and(
                ivre.db.db.passive.searchcmp(
                    "addr",
                    ivre.utils.int2ip(ivre.utils.ip2int(addrrange[0]) - 1)
                    if isinstance(addrrange[0], basestring) else
                    addrrange[0] - 1,
                    '>',
                ),
                ivre.db.db.passive.searchcmp(
                    "addr",
                    ivre.utils.int2ip(ivre.utils.ip2int(addrrange[1]) + 1)
                    if isinstance(addrrange[1], basestring) else
                    addrrange[1] + 1,
                    '<'),
            ),
        ))
        self.assertItemsEqual(addresses_1, addresses_2)
        addresses_2 = set()
        nets = ivre.utils.range2nets(addrrange)
        for net in nets:
            addresses_2 = addresses_2.union(
                ivre.db.db.passive.distinct(
                    "addr",
                    flt=ivre.db.db.passive.searchnet(net),
                )
            )
        self.assertItemsEqual(addresses_1, addresses_2)
        count = 0
        for net in nets:
            result = ivre.db.db.passive.count(
                ivre.db.db.passive.searchnet(net)
            )
            count += result
            start, stop = map(ivre.utils.ip2int,
                              ivre.utils.net2range(net))
            for addr in ivre.db.db.passive.distinct(
                    "addr",
                    flt=ivre.db.db.passive.searchnet(net),
            ):
                self.assertTrue(
                    start <= (ivre.utils.ip2int(addr)
                              if isinstance(addr, basestring)
                              else addr) <= stop
                )
        result = ivre.db.db.passive.count(
            ivre.db.db.passive.flt_and(
                *(ivre.db.db.passive.searchnet(net) for net in nets)
            ))
        self.assertEqual(result, 0)
        result = ivre.db.db.passive.count(
            ivre.db.db.passive.flt_or(
                *(ivre.db.db.passive.searchnet(net) for net in nets)
            ))
        self.assertEqual(result, count)

        count = ivre.db.db.passive.count(
            ivre.db.db.passive.searchtorcert()
        )
        self.check_value("passive_torcert_count", count)
        count = ivre.db.db.passive.count(
            ivre.db.db.passive.searchcertsubject(
                re.compile('google', re.I)
            )
        )
        self.check_value("passive_cert_google", count)
        count = ivre.db.db.passive.count(
            ivre.db.db.passive.searchcertsubject(
                re.compile('microsoft', re.I)
            )
        )
        self.check_value("passive_cert_microsoft", count)
        count = ivre.db.db.passive.count(
            ivre.db.db.passive.searchjavaua()
        )
        self.check_value("passive_javaua_count", count)

        count = ivre.db.db.passive.count(
            ivre.db.db.passive.searchsensor("TEST")
        )
        self.assertEqual(count, total_count)
        count = ivre.db.db.passive.count(
            ivre.db.db.passive.searchsensor("TEST", neg=True)
        )
        self.assertEqual(count, 0)
        count = ivre.db.db.passive.count(
            ivre.db.db.passive.searchsensor(
                re.compile("^TEST$"), neg=True)
        )
        self.assertEqual(count, 0)

        for auth_type in ["basic", "http", "pop", "ftp"]:
            count = ivre.db.db.passive.count(
                getattr(
                    ivre.db.db.passive, "search%sauth" % auth_type
                )()
            )
            self.check_value("passive_%sauth_count" % auth_type, count)

        # Top values
        for distinct in [True, False]:
            values = ivre.db.db.passive.topvalues(field="addr",
                                                  distinct=distinct,
                                                  topnbr=1).next()
            self.check_value(
                "passive_top_addr_%sdistinct" % ("" if distinct else "not_"),
                ivre.utils.ip2int(values["_id"])
                if isinstance(values["_id"], basestring) else
                values["_id"],
            )
            self.check_value(
                "passive_top_addr_%sdistinct_count" % ("" if distinct
                                                       else "not_"),
                values["count"],
            )

        # Delete
        flt = ivre.db.db.passive.searchcert()
        count = ivre.db.db.passive.count(flt)
        # Test case OK?
        self.assertGreater(count, 0)
        ivre.db.db.passive.remove(flt)
        new_count = ivre.db.db.passive.count(
            ivre.db.db.passive.flt_empty
        )
        self.assertEqual(count + new_count, total_count)

        self.assertEqual(RUN(["ivre", "ipinfo", "--init"],
                              stdin=open(os.devnull))[0], 0)

    def test_utils(self):
        """Functions that have not yet been tested"""

        self.assertIsNotNone(ivre.config.guess_prefix())
        self.assertIsNone(ivre.config.guess_prefix("inexistant"))

        # Version / help
        res, out1, err = RUN(["ivre"])
        self.assertEqual(res, 0)
        self.assertTrue(not err)
        res, out2, err = RUN(["ivre", "help"])
        self.assertEqual(res, 0)
        self.assertTrue(not err)
        self.assertEqual(out1, out2)
        res, _, err = RUN(["ivre", "version"])
        self.assertEqual(res, 0)
        self.assertTrue(not err)
        res, _, _ = RUN(["ivre", "inexistant"])
        self.assertTrue(res)

        # IP addresses manipulation utils
        with self.assertRaises(ValueError):
            ivre.utils.range2nets((2, 1))

        # String utils
        teststr = "TEST STRING -./*'"
        self.assertEqual(ivre.utils.regexp2pattern(teststr),
                         (re.escape(teststr), 0))
        self.assertEqual(
            ivre.utils.regexp2pattern(
                re.compile('^' + re.escape(teststr) + '$')),
            (re.escape(teststr), 0))
        self.assertEqual(
            ivre.utils.regexp2pattern(re.compile(re.escape(teststr))),
            ('.*' + re.escape(teststr) + '.*', 0))
        self.assertEqual(ivre.utils.str2list(teststr), teststr)
        teststr = "1,2|3"
        self.assertItemsEqual(ivre.utils.str2list(teststr),
                              ["1", "2", "3"])
        self.assertTrue(ivre.utils.isfinal(1))
        self.assertTrue(ivre.utils.isfinal("1"))
        self.assertFalse(ivre.utils.isfinal([]))
        self.assertFalse(ivre.utils.isfinal({}))

        # Nmap ports
        ports = [1,3,2,4,6,80,5,5,110,111]
        self.assertEqual(
            set(ports),
            ivre.utils.nmapspec2ports(ivre.utils.ports2nmapspec(ports))
        )
        self.assertEqual(ivre.utils.ports2nmapspec(ports), '1-6,80,110-111')

        # Nmap fingerprints
        ivre.config.NMAP_SHARE_PATH = './share/nmap/'
        ivre.utils.makedirs(ivre.config.NMAP_SHARE_PATH)
        with open(os.path.join(ivre.config.NMAP_SHARE_PATH,
                               'nmap-service-probes'), 'w') as fdesc:
            fdesc.write(
                "Probe TCP NULL q||\n"
                "match test m|^test$|\n"
                "softmatch softtest m|^softtest$|\n"
            )
        ## We need to have at least one "hard" and one soft match
        self.assertTrue(any(
            not fp[1]['soft'] for fp in
            ivre.utils.get_nmap_svc_fp()['fp']
        ))
        self.assertTrue(any(
            fp[1]['soft'] for fp in
            ivre.utils.get_nmap_svc_fp()['fp']
        ))
        ivre.utils.cleandir(ivre.config.NMAP_SHARE_PATH)

        # Math utils
        # http://stackoverflow.com/a/15285588/3223422
        def is_prime(n):
            if n == 2 or n == 3: return True
            if n < 2 or n % 2 == 0: return False
            if n < 9: return True
            if n % 3 == 0: return False
            r = int(n**0.5)
            f = 5
            while f <= r:
                if n % f == 0: return False
                if n % (f + 2) == 0: return False
                f += 6
            return True
        for _ in xrange(3):
            nbr = random.randint(2, 1000)
            factors = list(ivre.mathutils.factors(nbr))
            self.assertTrue(is_prime(nbr) or len(factors) > 1)
            self.assertTrue(all(is_prime(x) for x in factors))
            self.assertEqual(reduce(lambda x, y: x * y, factors), nbr)


def parse_args():
    global SAMPLES, USE_COVERAGE
    try:
        import argparse
        parser = argparse.ArgumentParser(
            description='Run IVRE tests',
        )
    except ImportError:
        import optparse
        parser = optparse.OptionParser(
            description='Run IVRE tests',
        )
        parser.parse_args_orig = parser.parse_args
        parser.parse_args = lambda: parser.parse_args_orig()[0]
        parser.add_argument = parser.add_option
    parser.add_argument('--samples', metavar='DIR',
                        default="./samples/")
    parser.add_argument('--coverage', action="store_true")
    args = parser.parse_args()
    SAMPLES = args.samples
    USE_COVERAGE = args.coverage
    sys.argv = [sys.argv[0]]


DATABASES = {
    # **excluded** tests
    #"mongo": ["flow"],
    #"postgres": ["nmap"],
}


def parse_env():
    global DATABASE
    DATABASE = os.getenv("DB")
    for test in DATABASES.get(DATABASE, []):
        sys.stderr.write("Desactivating test %r for database %r."
                         "\n" % (test, DATABASE))
        delattr(IvreTests, "test_%s" % test)


if __name__ == '__main__':
    SAMPLES = None
    parse_args()
    parse_env()
    import ivre.config
    import ivre.db
    import ivre.utils
    import ivre.mathutils
    import ivre.passive
    if not ivre.config.DEBUG:
        sys.stderr.write("You *must* have the DEBUG config value set to "
                         "True to run the tests.\n")
        sys.exit(-1)
    if USE_COVERAGE:
        import coverage
        COVERAGE = [sys.executable, os.path.dirname(coverage.__file__)]
        RUN = coverage_run
        RUN_ITER = coverage_run_iter
        coverage_init()
        cov = coverage.coverage(data_suffix=True)
        cov.start()
    else:
        RUN = python_run
        RUN_ITER = python_run_iter
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.TestLoader().loadTestsFromTestCase(IvreTests),
    )
    if USE_COVERAGE:
        cov.stop()
        cov.save()
        coverage_report()
    sys.exit(len(result.failures) + len(result.errors))
