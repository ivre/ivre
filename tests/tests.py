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
try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO
from contextlib import contextmanager
import coverage
from functools import reduce


def prepare_config():
    """This function, used before importing ivre.db, will make IVRE
    use the same parameters as usual with a different database.

    """
    for param in (x for x in dir(ivre.config) if x.startswith('DB_')):
        delattr(ivre.config, param)
    ivre.config.DB = MONGODB
>>>>>>> Python 2 / 3 compatibility builtins fixes


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
    if interp is None:
        interp = []
    return subprocess.Popen(interp + cmd, stdin=stdin,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE)

def run_cmd(cmd, interp=None, stdin=None):
    proc = run_iter(cmd, interp=interp, stdin=stdin)
    out, err = proc.communicate()
    return proc.returncode, out, err

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

def init_links():
    os.mkdir("bin")
    for binary in ["ipinfo", "nmap2db", "scancli"]:
        os.symlink("../../bin/%s" % binary, "bin/%s.py" % binary)
    os.symlink("../../ivre", "bin/ivre")


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
        cls.nmap_files = [
            os.path.join(root, fname)
            for root, _, files in os.walk(SAMPLES)
            for fname in files
            if fname.endswith('.xml')
        ]
        cls.pcap_files = [
            os.path.join(root, fname)
            for root, _, files in os.walk(SAMPLES)
            for fname in files
            if fname.endswith('.pcap')
        ]

    def test_nmap(self):

        # Init DB
        self.assertEqual(RUN(["./bin/scancli.py", "--count"])[1], "0\n")
        self.assertEqual(RUN(["./bin/scancli.py", "--init"],
                              stdin=open(os.devnull))[0], 0)
        self.assertEqual(RUN(["./bin/scancli.py", "--count"])[1], "0\n")

        # Insertion / "test" insertion (JSON output)
        host_counter = 0
        host_counter_test = 0
        host_stored = re.compile("^HOST STORED: ", re.M)
        host_stored_test = re.compile("^{[0-9]+:", re.M)
        for fname in self.nmap_files:
            res, out, _ = RUN(["./bin/nmap2db.py", "--port",
                               "-c", "TEST", "-s", "SOURCE", fname])
            self.assertEqual(res, 0)
            host_counter += sum(1 for _ in host_stored.finditer(out))
            res, out, _ = RUN(["./bin/nmap2db.py", "--port", "--test",
                               "-c", "TEST", "-s", "SOURCE", fname])
            self.assertEqual(res, 0)
            host_counter_test += sum(
                1 for _ in host_stored_test.finditer(out)
            )
        self.assertEqual(host_counter, host_counter_test)

        cov = coverage.coverage()
        cov.load()
        cov.start()
        # Insertion with scans already in DB
        for fname in self.nmap_files:
            with capture(ivre.db.db.nmap.store_scan, fname,
                         categories=["TEST"],
                         source="SOURCE",
                         needports=True) as (res, _, _):
                self.assertFalse(res)

        hosts_count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.flt_empty).count()
        archives_count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.flt_empty, archive=True).count()
        # Is the test case OK?
        self.assertGreater(hosts_count, 0)
        self.check_value("nmap_get_count", hosts_count)
        self.check_value("nmap_get_archives_count",
                         archives_count)
        # Counting results
        self.assertEqual(hosts_count + archives_count,
                         host_counter)

        # Filters
        addr = ivre.db.db.nmap.get(
            ivre.db.db.nmap.flt_empty)[0].get('addr')
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
            ivre.db.db.nmap.searchscriptid("http-robots.txt"))
        # Test case OK?
        count = result.count()
        self.assertGreater(count, 0)
        self.check_value("nmap_robots.txt_count", count)

        addr = result[0]['addr']
        result = ivre.db.db.nmap.get(ivre.db.db.nmap.flt_and(
            ivre.db.db.nmap.searchscriptid("http-robots.txt"),
            ivre.db.db.nmap.searchhost(addr),
        ))
        self.assertEqual(result.count(), 1)
        count = ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchscriptidout(
                "http-robots.txt",
                ivre.utils.str2regexp("/cgi-bin"))).count()
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

        categories = list(ivre.db.db.nmap.topvalues("category"))
        category = categories[0]
        self.assertEqual(category["_id"], "TEST")
        self.assertEqual(category["count"], hosts_count)
        self.assertEqual(len(categories), 1)
        self.check_value(
            "nmap_topsrv",
            list(ivre.db.db.nmap.topvalues("service"))[0]['_id'])
        self.check_value(
            "nmap_topsrv_80",
            list(ivre.db.db.nmap.topvalues("service:80"))[0]['_id'])
        self.check_value(
            "nmap_topprobedsrv",
            list(ivre.db.db.nmap.topvalues("probedservice"))[0]['_id'])
        self.check_value(
            "nmap_topprobedsrv_80",
            list(ivre.db.db.nmap.topvalues("probedservice:80"))[0]['_id'])
        self.check_value(
            "nmap_topprod",
            list(ivre.db.db.nmap.topvalues("product"))[0]['_id'])
        self.check_value(
            "nmap_topprod_80",
            list(ivre.db.db.nmap.topvalues("product:80"))[0]['_id'])
        self.check_value(
            "nmap_topdevtype",
            list(ivre.db.db.nmap.topvalues("devicetype"))[0]['_id'])
        self.check_value(
            "nmap_topdevtype_80",
            list(ivre.db.db.nmap.topvalues("devicetype:80"))[0]['_id'])
        self.check_value(
            "nmap_topdomain",
            list(ivre.db.db.nmap.topvalues("domains"))[0]['_id'])
        self.check_value(
            "nmap_topdomains_1",
            list(ivre.db.db.nmap.topvalues("domains:1"))[0]['_id'])
        self.check_value(
            "nmap_tophop",
            list(ivre.db.db.nmap.topvalues("hop"))[0]['_id'])
        self.check_value(
            "nmap_tophop_10+",
            list(ivre.db.db.nmap.topvalues("hop>10"))[0]['_id'])

        cov.stop()
        cov.save()
        self.assertEqual(RUN(["./bin/scancli.py", "--init"],
                              stdin=open(os.devnull))[0], 0)

    def test_passive(self):

        # Init DB
        self.assertEqual(RUN(["./bin/ipinfo.py", "--count"])[1], "0\n")
        self.assertEqual(RUN(["./bin/ipinfo.py", "--init"],
                              stdin=open(os.devnull))[0], 0)
        self.assertEqual(RUN(["./bin/ipinfo.py", "--count"])[1], "0\n")

        # p0f insertion
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

        # Bro insertion
        ivre.utils.makedirs("logs")
        for fname in self.pcap_files:
            env = os.environ.copy()
            env["LOG_ROTATE"] = "60"
            env["LOG_PATH"] = "logs/passiverecon"
            broprocess = subprocess.Popen(
                ['bro', '-b', '-r', fname,
                 os.path.join(
                     ivre.utils.guess_prefix('passiverecon'),
                     'passiverecon.bro')],
                env=env)
            broprocess.wait()
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
            x.get('addr') for x in
            ivre.db.db.passive.get(ivre.db.db.passive.flt_empty)[:2]
        )
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

        # Delete
        flt = ivre.db.db.passive.searchcert()
        count = ivre.db.db.passive.get(flt).count()
        # Test case OK?
        self.assertGreater(count, 0)
        ivre.db.db.passive.remove(flt)
        new_count = ivre.db.db.passive.get(
            ivre.db.db.passive.flt_empty).count()
        self.assertEqual(count + new_count, total_count)

        self.assertEqual(RUN(["./bin/ipinfo.py", "--init"],
                              stdin=open(os.devnull))[0], 0)

    def test_utils(self):
        """Functions that have not yet been tested"""

        self.assertIsNotNone(ivre.utils.guess_prefix())
        self.assertIsNone(ivre.utils.guess_prefix("inexistant"))

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
        for _ in range(3):
            nbr = random.randint(2, 1000)
            factors = list(ivre.mathutils.factors(nbr))
            self.assertTrue(all(is_prime(x) for x in factors))
            self.assertEqual(reduce(lambda x, y: x * y, factors), nbr)

def parse_args():
    global SAMPLES
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
    args = parser.parse_args()
    SAMPLES = args.samples
    sys.argv = [sys.argv[0]]

if __name__ == '__main__':
    SAMPLES = None
    COVERAGE = [sys.executable, os.path.dirname(coverage.__file__)]
    RUN = coverage_run
    RUN_ITER = coverage_run_iter
    parse_args()
    coverage_init()
    init_links()
    sys.path = ["bin/"] + sys.path
    import ivre.config
    import ivre.db
    import ivre.utils
    import ivre.mathutils
    import ivre.passive
    if not hasattr(IvreTests, "assertItemsEqual"):
        IvreTests.assertItemsEqual = IvreTests.assertCountEqual
    unittest.TextTestRunner(verbosity=2).run(
        unittest.TestLoader().loadTestsFromTestCase(IvreTests),
    )
    coverage_report()
    ivre.utils.cleandir("bin")
