#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2014 Pierre LALET <pierre.lalet@cea.fr>
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

import unittest

import json
import re
import subprocess
import os
import sys
import errno
import random
import time
from cStringIO import StringIO
from contextlib import contextmanager
from distutils.spawn import find_executable as which


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

def run_iter(cmd, interp=None, stdin=None):
    if interp is not None:
        cmd = interp + [which(cmd[0])] + cmd[1:]
    return subprocess.Popen(cmd, stdin=stdin,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

def run_cmd(cmd, interp=None, stdin=None):
    proc = run_iter(cmd, interp=interp, stdin=stdin)
    out, err = proc.communicate()
    return proc.returncode, out, err

def python_run(cmd, stdin=None):
    return run_cmd(cmd, interp=[sys.executable], stdin=stdin)

def python_run_iter(cmd, stdin=None):
    return run_iter(cmd, interp=[sys.executable], stdin=stdin)

def coverage_init():
    return run_cmd(COVERAGE + ["erase"])

def coverage_run(cmd, stdin=None):
    return run_cmd(cmd, interp=COVERAGE + ["run", "-a"], stdin=stdin)

def coverage_run_iter(cmd, stdin=None):
    return run_iter(cmd, interp=COVERAGE + ["run", "-a"], stdin=stdin)

def coverage_report():
    cov = coverage.coverage()
    cov.load()
    cov.html_report(omit=['tests*', '/usr/*'])


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

    def tearDown(self):
        ivre.utils.cleandir("logs")
        ivre.utils.cleandir(".state")
        if self.new_results:
            with open(os.path.join(SAMPLES, "results"), 'a') as fdesc:
                for valname in self.new_results:
                    fdesc.write("%s = %r\n" % (valname, self.results[valname]))

    def check_value(self, name, value):
        if name not in self.results:
            self.results[name] = value
            self.new_results.add(name)
        self.assertEqual(value, self.results[name])

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

    def test_nmap(self):

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
        host_stored = re.compile("^HOST STORED: ", re.M)
        scan_stored = re.compile("^SCAN STORED: ", re.M)
        def host_stored_test(line):
            try:
                return len(json.loads(line))
            except ValueError:
                return 0
        scan_duplicate = re.compile("^WARNING: Scan already present in Database", re.M)
        for fname in self.nmap_files:
            # Insertion in DB
            res, _, err = RUN(["ivre", "scan2db", "--port",
                               "-c", "TEST", "-s", "SOURCE", fname])
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
        )[0]['_id'])
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

        self.assertEqual(portsnb_10_100 + portsnb_not_10_100, host_counter)

        if USE_COVERAGE:
            cov = coverage.coverage()
            cov.load()
            cov.start()

        # Filters
        addr = ivre.db.db.nmap.get(
            ivre.db.db.nmap.flt_empty, fields=["addr"])[0].get('addr')
        result = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchhost(addr))
        self.assertEqual(result.count(), 1)
        result = result[0]
        self.assertEqual(result['addr'], addr)
        result = ivre.db.db.nmap.get(ivre.db.db.nmap.flt_and(
            ivre.db.db.nmap.searchhost(addr),
            ivre.db.db.nmap.searchhost(addr),
        ))
        self.assertEqual(result.count(), 1)
        # Remove
        result = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchhost(addr))[0]
        ivre.db.db.nmap.remove(result)
        result = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchhost(addr))
        self.assertEqual(result.count(), 0)
        hosts_count -= 1
        recid = ivre.db.db.nmap.getid(
            ivre.db.db.nmap.get(ivre.db.db.nmap.flt_empty)[0])
        result = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchid(recid))
        self.assertEqual(result.count(), 1)
        self.assertIsNotNone(
            ivre.db.db.nmap.getscan(
                ivre.db.db.nmap.get(
                    ivre.db.db.nmap.flt_empty)[0]['scanid']))

        result = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchhost(-1))
        self.assertEqual(result.count(), 0)

        addrrange = sorted(x.get('addr') for x in
                           ivre.db.db.nmap.get(
                               ivre.db.db.nmap.flt_empty)[:2])
        result = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchrange(*addrrange))
        addr_range_count = result.count()
        self.assertGreaterEqual(addr_range_count, 2)
        result = ivre.db.db.nmap.get(ivre.db.db.nmap.flt_and(
            ivre.db.db.nmap.searchcmp("addr", addrrange[0], '>='),
            ivre.db.db.nmap.searchcmp("addr", addrrange[1], '<='),
        ))
        self.assertEqual(result.count(), addr_range_count)
        result = ivre.db.db.nmap.get(ivre.db.db.nmap.flt_and(
            ivre.db.db.nmap.searchcmp("addr", addrrange[0] - 1, '>'),
            ivre.db.db.nmap.searchcmp("addr", addrrange[1] + 1, '<'),
        ))
        self.assertEqual(result.count(), addr_range_count)
        result = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchrange(*addrrange, neg=True))
        self.assertEqual(result.count() + addr_range_count,
                         hosts_count)
        addrs = set()
        for net in ivre.utils.range2nets(map(ivre.utils.int2ip, addrrange)):
            result = ivre.db.db.nmap.get(
                ivre.db.db.nmap.searchnet(net))
            addrs = addrs.union(
                (ivre.utils.int2ip(addr)
                 for addr in ivre.db.db.nmap.distinct(result, "addr")))

        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchhosts(addrrange)).count()
        self.assertEqual(count, 2)
        result = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchhosts(addrrange, neg=True))
        self.assertEqual(count + result.count(), hosts_count)

        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchtimerange(
                0, ivre.db.db.nmap.get(
                    ivre.db.db.nmap.flt_empty,
                    fields=['endtime'],
                    sort=[['endtime', -1]])[0]['endtime'])).count()
        self.assertEqual(count, hosts_count)

        nets = ivre.utils.range2nets(addrrange)
        count = 0
        for net in nets:
            result = ivre.db.db.nmap.get(
                ivre.db.db.nmap.searchnet(net))
            count += result.count()
            start, stop = map(ivre.utils.ip2int,
                              ivre.utils.net2range(net))
            for addr in ivre.db.db.nmap.distinct(result, "addr"):
                self.assertTrue(start <= addr <= stop)
        self.assertEqual(count, addr_range_count)
        # Networks in `nets` are separated sets
        result = ivre.db.db.nmap.get(
            ivre.db.db.nmap.flt_and(
                *(ivre.db.db.nmap.searchnet(net) for net in nets)
            ))
        self.assertEqual(result.count(), 0)
        result = ivre.db.db.nmap.get(
            ivre.db.db.nmap.flt_or(
                *(ivre.db.db.nmap.searchnet(net) for net in nets)
            ))
        self.assertEqual(result.count(), addr_range_count)

        result = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchscript(name="http-robots.txt"))
        # Test case OK?
        count = result.count()
        self.assertGreater(count, 0)
        self.check_value("nmap_robots.txt_count", count)

        addr = result[0]['addr']
        result = ivre.db.db.nmap.get(ivre.db.db.nmap.flt_and(
            ivre.db.db.nmap.searchscript(name="http-robots.txt"),
            ivre.db.db.nmap.searchhost(addr),
        ))
        self.assertEqual(result.count(), 1)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchscript(
                name="http-robots.txt",
                output=ivre.utils.str2regexp("/cgi-bin"),
            )).count()
        self.assertGreater(count, 0)
        self.check_value("nmap_robots.txt_cgi_count", count)

        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchftpanon()).count()
        # Test case OK?
        self.assertGreater(count, 0)
        self.check_value("nmap_anonftp_count", count)

        result = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchhopdomain(re.compile('.')))
        # Test case OK?
        count = result.count()
        self.assertGreater(count, 0)
        self.check_value("nmap_trace_hostname_count", count)
        hop = random.choice([
            hop for hop in
            reduce(lambda x, y: x['hops'] + y['hops'],
                   result[0]['traces'],
                   {'hops': []})
            if 'domains' in hop
        ])
        result = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchhop(hop['ipaddr'])
        )
        self.assertGreaterEqual(result.count(), 1)
        result = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchhopdomain(hop['domains'][0])
        )
        self.assertGreaterEqual(result.count(), 1)

        # Indexes
        addr = ivre.db.db.nmap.get(
            ivre.db.db.nmap.flt_empty)[0].get('addr')
        queries = [
            ivre.db.db.nmap.searchhost(addr),
            ivre.db.db.nmap.searchnet(
                '.'.join(
                    ivre.utils.int2ip(addr).split('.')[:3]
                )+'.0/24'),
            ivre.db.db.nmap.searchrange(max(addr - 256, 0),
                                        min(addr + 256, 4294967295)),
        ]
        for query in queries:
            result = ivre.db.db.nmap.get(query)
            nscanned = json.loads(
                ivre.db.db.nmap.explain(result))['nscanned']
            self.assertEqual(result.count(), nscanned)
            self.assertEqual(
                query,
                ivre.db.db.nmap.str2flt(ivre.db.db.nmap.flt2str(query))
            )
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchx11()).count()
        self.check_value("nmap_x11_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchx11access()).count()
        self.check_value("nmap_x11access_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchnfs()).count()
        self.check_value("nmap_nfs_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchypserv()).count()
        self.check_value("nmap_nis_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchphpmyadmin()).count()
        self.check_value("nmap_phpmyadmin_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchwebfiles()).count()
        self.check_value("nmap_webfiles_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchbanner(re.compile("^SSH-"))
        ).count()
        self.check_value("nmap_ssh_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchvncauthbypass()).count()
        self.check_value("nmap_vncauthbypass_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchmssqlemptypwd()).count()
        self.check_value("nmap_mssql_emptypwd_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchmysqlemptypwd()).count()
        self.check_value("nmap_mysql_emptypwd_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchxp445()).count()
        self.check_value("nmap_xp445_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchxp445()).count()
        self.check_value("nmap_xp445_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchtorcert()).count()
        self.check_value("nmap_torcert_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchgeovision()).count()
        self.check_value("nmap_geovision_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchwebcam()).count()
        self.check_value("nmap_webcam_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchphonedev()).count()
        self.check_value("nmap_phonedev_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchnetdev()).count()
        self.check_value("nmap_netdev_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchdomain("com")).count()
        # Test case OK?
        self.assertGreater(count, 0)
        self.check_value("nmap_domain_com_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchdomain("com", neg=True)).count()
        self.check_value("nmap_not_domain_com_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchdomain(re.compile("^(com|net)$"),
                                         neg=True)).count()
        self.check_value("nmap_not_domain_com_or_net_count", count)
        name = ivre.db.db.nmap.get(ivre.db.db.nmap.searchdomain(
            'com'))[0]['hostnames'][0]['name']
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchhostname(name)).count()
        self.assertGreater(count, 0)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchcategory("TEST")).count()
        self.assertEqual(count, hosts_count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchcategory("TEST", neg=True)).count()
        self.assertEqual(count, 0)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchcategory(re.compile("^TEST$"),
                                           neg=True)).count()
        self.assertEqual(count, 0)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchsource("SOURCE")).count()
        self.assertEqual(count, hosts_count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchsource("SOURCE", neg=True)).count()
        self.assertEqual(count, 0)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchsource(re.compile("^SOURCE$"),
                                         neg=True)).count()
        self.assertEqual(count, 0)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchport(80)).count()
        self.check_value("nmap_80_count", count)
        neg_count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchport(80,
                                       neg=True)).count()
        self.assertEqual(count + neg_count, hosts_count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchports([80, 443])).count()
        self.check_value("nmap_80_443_count", count)
        neg_count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchports([80, 443],
                                        neg=True)).count()
        self.check_value("nmap_not_80_443_count", neg_count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchopenport()).count()
        self.check_value("nmap_openport_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchhttpauth(newscript=True,
                                           oldscript=True)).count()
        self.check_value("nmap_httpauth_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchwebmin()).count()
        self.check_value("nmap_webmin_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchowa()).count()
        self.check_value("nmap_owa_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchhttptitle(re.compile('.'))).count()
        self.check_value("nmap_http_title_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchvsftpdbackdoor()).count()
        self.check_value("nmap_vsftpbackdoor_count", count)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchldapanon()).count()
        self.check_value("nmap_ldapanon_count", count)

        categories = ivre.db.db.nmap.topvalues("category")
        category = categories.next()
        self.assertEqual(category["_id"], "TEST")
        self.assertEqual(category["count"], hosts_count)
        with self.assertRaises(StopIteration):
            categories.next()
        self.check_value(
            "nmap_topsrv",
            ivre.db.db.nmap.topvalues("service").next()['_id'])
        self.check_value(
            "nmap_topsrv_80",
            ivre.db.db.nmap.topvalues("service:80").next()['_id'])
        self.check_value(
            "nmap_topprod",
            ivre.db.db.nmap.topvalues("product").next()['_id'])
        self.check_value(
            "nmap_topprod_80",
            ivre.db.db.nmap.topvalues("product:80").next()['_id'])
        self.check_value(
            "nmap_topdevtype",
            ivre.db.db.nmap.topvalues("devicetype").next()['_id'])
        self.check_value(
            "nmap_topdevtype_80",
            ivre.db.db.nmap.topvalues("devicetype:80").next()['_id'])
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

        if USE_COVERAGE:
            cov.stop()
            cov.save()

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
                    ['p0f', '-l', '-S', '-ttt', '-s',
                     fname] + mode['options'] + [mode['filter']],
                    stdout=subprocess.PIPE)
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
        total_count = ivre.db.db.passive.get(
            ivre.db.db.passive.flt_empty).count()
        self.assertGreater(total_count, 0)
        self.check_value("passive_count", total_count)

        # Filters
        addr = ivre.db.db.passive.get(
            ivre.db.db.passive.flt_empty)[0].get("addr")
        result = ivre.db.db.passive.get(
            ivre.db.db.passive.searchhost(addr))
        self.assertGreater(result.count(), 0)

        result = ivre.db.db.passive.get(
            ivre.db.db.passive.searchhost(-1))
        self.assertEqual(result.count(), 0)

        addrrange = sorted(
            x for x in ivre.db.db.passive.get(
                ivre.db.db.passive.flt_empty).distinct('addr')
            if type(x) in [int, long] and x != 0
        )
        self.assertGreaterEqual(len(addrrange), 2)
        if len(addrrange) < 4:
            addrrange = [addrrange[0], addrrange[-1]]
        else:
            addrrange = [addrrange[1], addrrange[-2]]
        result = ivre.db.db.passive.get(
            ivre.db.db.passive.searchrange(*addrrange))
        self.assertGreaterEqual(result.count(), 2)
        addresses_1 = result.distinct('addr')
        result = ivre.db.db.passive.get(ivre.db.db.passive.flt_and(
            ivre.db.db.passive.searchcmp("addr", addrrange[0], '>='),
            ivre.db.db.passive.searchcmp("addr", addrrange[1], '<='),
        ))
        addresses_2 = result.distinct('addr')
        self.assertItemsEqual(addresses_1, addresses_2)
        result = ivre.db.db.passive.get(ivre.db.db.passive.flt_and(
            ivre.db.db.passive.searchcmp("addr", addrrange[0] - 1, '>'),
            ivre.db.db.passive.searchcmp("addr", addrrange[1] + 1, '<'),
        ))
        addresses_2 = result.distinct('addr')
        self.assertItemsEqual(addresses_1, addresses_2)
        addresses_2 = set()
        nets = ivre.utils.range2nets(addrrange)
        for net in nets:
            result = ivre.db.db.passive.get(
                ivre.db.db.passive.searchnet(net))
            addresses_2 = addresses_2.union(
                ivre.db.db.passive.distinct(result, "addr"))
        self.assertItemsEqual(addresses_1, addresses_2)
        count = 0
        for net in nets:
            result = ivre.db.db.passive.get(
                ivre.db.db.passive.searchnet(net))
            count += result.count()
            start, stop = map(ivre.utils.ip2int,
                              ivre.utils.net2range(net))
            for addr in ivre.db.db.passive.distinct(result, "addr"):
                self.assertTrue(start <= addr <= stop)
        result = ivre.db.db.passive.get(
            ivre.db.db.passive.flt_and(
                *(ivre.db.db.passive.searchnet(net) for net in nets)
            ))
        self.assertEqual(result.count(), 0)
        result = ivre.db.db.passive.get(
            ivre.db.db.passive.flt_or(
                *(ivre.db.db.passive.searchnet(net) for net in nets)
            ))
        self.assertEqual(result.count(), count)

        count = ivre.db.db.passive.get(
            ivre.db.db.passive.searchtorcert()).count()
        self.check_value("passive_torcert_count", count)
        count = ivre.db.db.passive.get(
            ivre.db.db.passive.searchcertsubject(
                re.compile('google', re.I))).count()
        self.check_value("passive_cert_google", count)
        count = ivre.db.db.passive.get(
            ivre.db.db.passive.searchcertsubject(
                re.compile('microsoft', re.I))).count()
        self.check_value("passive_cert_microsoft", count)
        count = ivre.db.db.passive.get(
            ivre.db.db.passive.searchjavaua()).count()
        self.check_value("passive_javaua_count", count)

        count = ivre.db.db.passive.get(
            ivre.db.db.passive.searchsensor("TEST")).count()
        self.assertEqual(count, total_count)
        count = ivre.db.db.passive.get(
            ivre.db.db.passive.searchsensor("TEST", neg=True)).count()
        self.assertEqual(count, 0)
        count = ivre.db.db.passive.get(
            ivre.db.db.passive.searchsensor(
                re.compile("^TEST$"), neg=True)).count()
        self.assertEqual(count, 0)

        for auth_type in ["basic", "http", "pop", "ftp"]:
            count = ivre.db.db.passive.get(
                getattr(
                    ivre.db.db.passive, "search%sauth" % auth_type
                )()).count()
            self.check_value("passive_%sauth_count" % auth_type, count)

        # Top values
        for distinct in [True, False]:
            values = ivre.db.db.passive.topvalues(field="addr",
                                                  distinct=distinct,
                                                  topnbr=1).next()
            self.check_value(
                "passive_top_addr_%sdistinct" % ("" if distinct else "not_"),
                values["_id"],
            )
            self.check_value(
                "passive_top_addr_%sdistinct_count" % ("" if distinct
                                                       else "not_"),
                values["count"],
            )

        # Delete
        flt = ivre.db.db.passive.searchcert()
        count = ivre.db.db.passive.get(flt).count()
        # Test case OK?
        self.assertGreater(count, 0)
        ivre.db.db.passive.remove(flt)
        new_count = ivre.db.db.passive.get(
            ivre.db.db.passive.flt_empty).count()
        self.assertEqual(count + new_count, total_count)

        self.assertEqual(RUN(["ivre", "ipinfo", "--init"],
                              stdin=open(os.devnull))[0], 0)

    def test_utils(self):
        """Functions that have not yet been tested"""

        self.assertIsNotNone(ivre.config.guess_prefix())
        self.assertIsNone(ivre.config.guess_prefix("inexistant"))

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

        # Math utils
        # http://stackoverflow.com/a/15285588/3223422
        def is_prime(n):
            if n == 2 or n == 3: return True
            if n < 2 or n%2 == 0: return False
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

if __name__ == '__main__':
    SAMPLES = None
    parse_args()
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
    else:
        RUN = python_run
        RUN_ITER = python_run_iter
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.TestLoader().loadTestsFromTestCase(IvreTests),
    )
    if USE_COVERAGE:
        coverage_report()
    sys.exit(len(result.failures) + len(result.errors))
