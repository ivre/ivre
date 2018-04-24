#! /usr/bin/env python

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


from __future__ import print_function


from ast import literal_eval
from contextlib import contextmanager
from distutils.spawn import find_executable as which
import errno
from functools import reduce
from glob import glob
from io import BytesIO
from itertools import chain
import json
import os
import pipes
import random
import re
from select import select
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
try:
    from urllib.request import HTTPError, Request, urlopen
except ImportError:
    from urllib2 import HTTPError, Request, urlopen


from builtins import int, range
from future.utils import viewvalues
from future.builtins import int
from past.builtins import basestring
if sys.version_info[:2] < (2, 7):
    import unittest2 as unittest
else:
    import unittest


import ivre
import ivre.config
import ivre.db
import ivre.mathutils
import ivre.parser.bro
import ivre.parser.iptables
import ivre.passive
import ivre.utils
import ivre.web.utils


HTTPD_PORT = 18080
HTTPD_HOSTNAME = socket.gethostname()


# http://schinckel.net/2013/04/15/capture-and-test-sys.stdout-sys.stderr-in-unittest.testcase/
@contextmanager
def capture(function, *args, **kwargs):
    out, sys.stdout = sys.stdout, BytesIO()
    err, sys.stderr = sys.stderr, BytesIO()
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

def coverage_run(cmd, stdin=None):
    return run_cmd(cmd, interp=COVERAGE + ["run", "--parallel-mode"],
                   stdin=stdin)

def coverage_run_iter(cmd, stdin=None, stdout=subprocess.PIPE,
                      stderr=subprocess.PIPE):
    return run_iter(cmd, interp=COVERAGE + ["run", "--parallel-mode"],
                    stdin=stdin, stdout=stdout, stderr=stderr)


class AgentScanner(object):
    """This builds an agent, runs it in the background, runs a feed
process (also in the background) and provides an object that can be
used to .scan() targets.

Example:

    with AgentScanner(self, nmap_template="http") as agent:
        agent.scan(['--net', '192.168.0.0/24'])

    """

    def __init__(self, test, nmap_template="default"):
        self.test = test
        self.pid_agent = self.pid_feed = None
        self._build_agent(nmap_template)
        self._start_agent()
        self._start_feed()

    def __enter__(self):
        return self

    def __delete__(self):
        self.stop()

    def __exit__(self, *_):
        self.wait()
        self.stop()

    def _build_agent(self, nmap_template):
        res, out, _ = RUN(["ivre", "runscans", "--output", "Agent",
                           "--nmap-template", nmap_template])
        self.test.assertEqual(res, 0)
        with tempfile.NamedTemporaryFile(delete=False) as fdesc:
            fdesc.write(out)
        os.chmod(fdesc.name, 0o0755)
        self.agent = fdesc.name

    def _start_agent(self):
        self.agent_dir = tempfile.mkdtemp()
        self.pid_agent = subprocess.Popen([self.agent],
                                          preexec_fn=os.setsid,
                                          cwd=self.agent_dir).pid

    def _start_feed(self):
        feed_cmd = ["runscansagent", "--sync", self.agent_dir]
        if USE_COVERAGE:
            feed_cmd = COVERAGE + ["run", "--parallel-mode",
                                   which("ivre")] + feed_cmd
        else:
            feed_cmd = ["ivre"] + feed_cmd
        self.pid_feed = subprocess.Popen(feed_cmd).pid

    def stop(self):
        """Kills the process backgrounded processes, moves the results to
"output", and removes the temporary files and directories.

        """
        if self.pid_agent is not None:
            os.kill(self.pid_agent, signal.SIGTERM)
            os.waitpid(self.pid_agent, 0)
            self.pid_agent = None
        if self.pid_feed is not None:
            os.kill(self.pid_feed, signal.SIGTERM)
            os.waitpid(self.pid_feed, 0)
            self.pid_feed = None
        os.rename(os.path.join('agentsdata', 'output'), 'output')
        for dirname in [self.agent_dir, 'agentsdata']:
            if dirname is not None:
                try:
                    shutil.rmtree(dirname)
                except OSError as exc:
                    if exc.errno != errno.ENOENT:
                        raise

    def wait(self):
        """Waits for current and scheduled scans to terminate.

        """
        dirnames = [
            dirname for subdir in ['input', 'remoteinput', 'remotecur',
                                   'remoteoutput', 'remotedata']
            for dirname in glob(os.path.join("agentsdata", "*", subdir))
        ]
        dirnames.extend(os.path.join(self.agent_dir, subdir)
                        for subdir in ['input', 'cur', 'output'])
        while any(walk[2] for dirname in dirnames
                  for walk in os.walk(dirname)):
            print(u"Waiting for runscans sync & agent")
            time.sleep(2)

    def scan(self, target_options):
        """Runs a scan. `target_options` should be a list of arguments to be
passed to `ivre runscansagent --feed`.

        """
        res = RUN(["ivre", "runscansagent", "--feed"] + target_options +
                  [self.agent_dir], stdin=open(os.devnull, 'wb'))[0]
        self.test.assertEqual(res, 0)


class IvreTests(unittest.TestCase):

    maxDiff = None

    def setUp(self):
        try:
            with open(os.path.join(SAMPLES, "results")) as fdesc:
                self.results = dict([l[:l.index(' = ')],
                                     literal_eval(l[l.index(' = ') + 3:-1])]
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
        self.check_value(name, out.decode())

    def check_lines_value_cmd(self, name, cmd, errok=False):
        res, out, err = RUN(cmd)
        self.assertTrue(errok or not err)
        self.assertEqual(res, 0)
        self.check_value(name, [line for line in out.decode().split('\n')
                                if line],
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
            def terminate(signum, _):
                try:
                    proc.send_signal(signum)
                    proc.wait()
                    signal.signal(signum, signal.SIG_DFL)
                    sys.exit(0)
                except:
                    pass
            for sig in [signal.SIGINT, signal.SIGTERM]:
                signal.signal(sig, terminate)
            proc = RUN_ITER(["ivre", "httpd", "-p", str(HTTPD_PORT),
                             "-b", HTTPD_HOSTNAME],
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

    @staticmethod
    def _sort_top_values(listval):
        maxval = None
        values = []
        for elem in listval:
            if not elem['_id'] or elem['_id'] == "None":
                # Hack for Postgresql empty field.
                continue
            if maxval is None:
                maxval = elem['count']
            elif maxval != elem['count']:
                break
            values.append(elem['_id'])
        return sorted(values)

    def _check_top_value_api(self, name, field, count=10):
        values = self._sort_top_values(
            ivre.db.db.nmap.topvalues(field, topnbr=count)
        )
        self.check_value(name, values, check=self.assertItemsEqual)

    def _check_top_value_cli(self, name, field, count=10):
        res, out, err = RUN(["ivre", "scancli", "--top", field, "--limit",
                             str(count)])
        self.assertTrue(not err)
        self.assertEqual(res, 0)
        listval = []
        for line in out.decode().split('\n'):
            if not line:
                continue
            line = line.split(": ", 1)
            listval.append({'_id': line[0], 'count': int(line[1])})
        self.check_value(name, self._sort_top_values(listval),
                         check=self.assertItemsEqual)

    def _check_top_value_cgi(self, name, field, count=10):
        req = Request('http://%s:%d/cgi/scans/top/%s:%d' % (
            HTTPD_HOSTNAME, HTTPD_PORT, field, count
        ))
        req.add_header('Referer',
                       'http://%s:%d/' % (HTTPD_HOSTNAME, HTTPD_PORT))
        listval = []
        for elem in json.loads(urlopen(req).read().decode()):
            listval.append({'_id': elem['label'], 'count': elem['value']})
        self.check_value(name, self._sort_top_values(listval),
                         check=self.assertItemsEqual)

    def check_top_value(self, name, field, count=10):
        for method in ['api', 'cli', 'cgi']:
            getattr(self, "_check_top_value_%s" % method)(
                "%s_%s" % (name, method), field, count=count,
            )

    def check_count_value_api(self, name_or_value, flt):
        if isinstance(flt, tuple):
            flt, archive = flt
        else:
            archive = False
        count = ivre.db.db.nmap.count(flt, archive=archive)
        if name_or_value is None:
            pass
        elif isinstance(name_or_value, str):
            self.check_value(name_or_value, count)
        else:
            self.assertEqual(name_or_value, count)
        return count

    def check_count_value_cli(self, name_or_value, cliflt):
        res, out, _ = RUN(["ivre", "scancli", "--count"] + cliflt)
        self.assertEqual(res, 0)
        count = int(out)
        if name_or_value is None:
            pass
        elif isinstance(name_or_value, str):
            self.check_value(name_or_value, count)
        else:
            self.assertEqual(name_or_value, count)
        return count

    def check_count_value_cgi(self, name_or_value, webflt):
        req = Request('http://%s:%d/cgi/scans/count%s' % (
            HTTPD_HOSTNAME, HTTPD_PORT,
            '' if webflt is None else '?q=%s' % webflt,
        ))
        req.add_header('Referer', 'http://%s:%d/' % (HTTPD_HOSTNAME,
                                                     HTTPD_PORT))
        udesc = urlopen(req)
        self.assertEquals(udesc.getcode(), 200)
        count = json.loads(udesc.read().decode())
        if name_or_value is None:
            pass
        elif isinstance(name_or_value, str):
            self.check_value(name_or_value, count)
        else:
            self.assertEqual(name_or_value, count)
        return count

    def check_count_value(self, name_or_value, flt, cliflt, webflt):
        cnt1 = self.check_count_value_api(name_or_value, flt)
        cnt2 = self.check_count_value_cli(name_or_value, cliflt)
        cnt3 = self.check_count_value_cgi(name_or_value, webflt)
        self.assertEqual(cnt1, cnt2)
        self.assertEqual(cnt1, cnt3)
        return cnt1

    def find_record_cgi(self, predicate, webflt=None):
        """Browse the results from the JSON interface to find a record for
which `predicate()` is True, given `webflt`.

        """
        current = 0
        while True:
            query = [] if webflt is None else [webflt]
            if current:
                query.append('skip%%3A%d' % current)
            query = "?q=%s" % '%20'.join(query) if query else ""
            req = Request('http://%s:%d/cgi/scans%s' % (
                HTTPD_HOSTNAME, HTTPD_PORT, query,
            ))
            req.add_header('Referer', 'http://%s:%d/' % (HTTPD_HOSTNAME,
                                                         HTTPD_PORT))
            udesc = urlopen(req)
            self.assertEquals(udesc.getcode(), 200)
            count = 0
            for record in json.loads(udesc.read().decode()):
                if predicate(record):
                    return True
                count += 1
            if count < ivre.config.WEB_LIMIT:
                return False
            current += count

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

    def init_nmap_db(self):
        self.assertEqual(RUN(["ivre", "scancli", "--count"])[1], b"0\n")
        self.assertEqual(RUN(["ivre", "scancli", "--init"],
                             stdin=open(os.devnull))[0], 0)
        self.assertEqual(RUN(["ivre", "scancli", "--count"])[1], b"0\n")

    def test_nmap(self):

        # Start a Web server
        self.start_web_server()

        #
        # Web server tests
        #

        # Test invalid Referer: header values
        ## no header
        req = Request('http://%s:%d/cgi/config' % (HTTPD_HOSTNAME, HTTPD_PORT))
        with self.assertRaises(HTTPError) as herror:
            udesc = urlopen(req)
        self.assertEquals(herror.exception.getcode(), 400)
        ## invalid value
        req = Request('http://%s:%d/cgi/config' % (HTTPD_HOSTNAME, HTTPD_PORT))
        req.add_header('Referer', 'http://invalid.invalid/invalid')
        with self.assertRaises(HTTPError) as herror:
            udesc = urlopen(req)
        self.assertEquals(herror.exception.getcode(), 400)

        # Get configuration
        req = Request('http://%s:%d/cgi/config' % (HTTPD_HOSTNAME, HTTPD_PORT))
        req.add_header('Referer', 'http://%s:%d/' % (HTTPD_HOSTNAME, HTTPD_PORT))
        udesc = urlopen(req)
        self.assertEquals(udesc.getcode(), 200)
        config_values = {
            "notesbase": ivre.config.WEB_NOTES_BASE,
            "dflt_limit": ivre.config.WEB_LIMIT,
            "warn_dots_count": ivre.config.WEB_WARN_DOTS_COUNT,
            "publicsrv": ivre.config.WEB_PUBLIC_SRV,
            "uploadok": ivre.config.WEB_UPLOAD_OK,
            "flow_time_precision": ivre.config.FLOW_TIME_PRECISION,
            "version": ivre.VERSION,
        }
        for line in udesc:
            self.assertTrue(line.endswith(b';\n'))
            key, value = line[:-2].decode().split(' = ')
            self.assertTrue(key.startswith('config.'))
            key = key[7:]
            self.assertEquals(json.loads(value), config_values[key])

        # Test redirections & static files
        req = Request('http://%s:%d/' % (HTTPD_HOSTNAME, HTTPD_PORT))
        udesc = urlopen(req)
        self.assertEquals(udesc.getcode(), 200)
        self.assertEquals(udesc.url,
                          'http://%s:%d/index.html' % (HTTPD_HOSTNAME,
                                                       HTTPD_PORT))
        result = False
        for line in udesc:
            if b'This file is part of IVRE.' in line:
                result = True
                break
        self.assertTrue(result)

        # Test dokuwiki pages
        req = Request('http://%s:%d/dokuwiki/doc:readme' % (HTTPD_HOSTNAME,
                                                            HTTPD_PORT))
        udesc = urlopen(req)
        self.assertEquals(udesc.getcode(), 200)
        result = False
        for line in udesc:
            if b'is a network recon framework' in line:
                result = True
                break
        self.assertTrue(result)

        #
        # Database tests
        #

        # Init DB
        self.init_nmap_db()

        # Insertion / "test" insertion (JSON output)
        host_counter = 0
        scan_counter = 0
        host_counter_test = 0
        scan_warning = 0
        host_stored = re.compile(b"^DEBUG:ivre:HOST STORED: ", re.M)
        scan_stored = re.compile(b"^DEBUG:ivre:SCAN STORED: ", re.M)
        def host_stored_test(line):
            try:
                return len(json.loads(line.decode()))
            except ValueError:
                return 0
        scan_duplicate = re.compile(b"^DEBUG:ivre:Scan already present in "
                                    b"Database", re.M)
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

        # Specific test cases
        ##
        samples = [
            ## Ignored script with a named table element, followed by
            ## a script with an unamed table element
            b"""<nmaprun scanner="nmap">
<host>
<script id="fcrdns" output="FAIL (No PTR record)">
<table key="&lt;none&gt;">
<elem key="status">fail</elem>
<elem key="reason">No PTR record</elem>
</table>
</script>
<script id="fake" output="Test output for fake script">
<elem>fake</elem>
</script>
</host>
</nmaprun>
""",
            ## Masscan with an HTTP banner
            b"""<nmaprun scanner="masscan">
<host>
<ports>
<port protocol="tcp" portid="80">
<state state="open"/>
<service name="http" banner="HTTP/1.1 403 Forbidden\\x0d\\x0aServer: test/1.0\\x0d\\x0a\\x0d\\x0a">
</service>
</port>
</ports>
</host>
</nmaprun>
""",
        ]
        for sample in samples:
            fdesc = tempfile.NamedTemporaryFile(delete=False)
            fdesc.write(sample)
            fdesc.close()
            res, out, _ = RUN(["ivre", "scan2db", "--test", fdesc.name])
            self.assertEqual(res, 0)
            self.assertEqual(sum(host_stored_test(line)
                                 for line in out.splitlines()), 1)
            os.unlink(fdesc.name)
        ##
        ## Screenshots: this tests the http-screenshot script
        ## (including phantomjs) and IVRE's ability to read
        ## screenshots (including extracting words with tesseract)
        ipaddr = socket.gethostbyname('ivre.rocks')
        with AgentScanner(self, nmap_template="http") as agent:
            agent.scan(['--net', '%s/32' % ipaddr])
        data_files, up_files = (
            glob("%s.%s*" % (os.path.join('output', 'MISC', subdir,
                                         '*', *ipaddr.split('.')), ext))
            for subdir, ext in [('data', 'tar'), ('up', 'xml')]
        )
        self.assertEqual(len(data_files), 1)
        self.assertTrue(os.path.exists(data_files[0]))
        self.assertEqual(len(up_files), 1)
        self.assertTrue(os.path.exists(up_files[0]))
        # TarFile object does not implement __exit__ on Python 2.6,
        # cannot use `with`
        data_archive = tarfile.open(data_files[0])
        data_archive.extractall()
        data_archive.close()
        self.assertTrue(os.path.exists('screenshot-%s-80.jpg' % ipaddr))
        res, out, _ = RUN(["ivre", "scan2db", "--test"] + up_files)
        self.assertEqual(res, 0)
        def _json_loads(data, deflt=None):
            try:
                return json.loads(data.decode())
            except ValueError:
                return deflt
        screenshots_count = sum(bool(port.get('screendata'))
                                for line in out.splitlines()
                                for host in _json_loads(line, [])
                                for port in host.get('ports', []))
        self.assertEqual(screenshots_count, 1)
        screenwords = set(word for line in out.splitlines()
                          for host in _json_loads(line, [])
                          for port in host.get('ports', [])
                          for word in port.get('screenwords', []))
        self.assertTrue('IVRE' in screenwords)
        shutil.rmtree('output')

        RUN(["ivre", "scancli", "--update-schema"])
        RUN(["ivre", "scancli", "--update-schema", "--archives"])

        self.assertEqual(host_counter, host_counter_test)
        self.assertEqual(scan_counter, scan_warning)

        hosts_count = self.check_count_value("nmap_get_count",
                                             ivre.db.db.nmap.flt_empty,
                                             [], None)
        archives_count = self.check_count_value(
            "nmap_get_archives_count",
            (ivre.db.db.nmap.flt_empty, True),
            ["--archives"], "archives",
        )

        self.check_count_value_api(0, ivre.db.db.nmap.searchnonexistent())

        # Is the test case OK?
        self.assertGreater(hosts_count, 0)

        # Counting results
        self.assertEqual(hosts_count + archives_count,
                         host_counter)

        # JSON
        res, out, _ = RUN(['ivre', 'scancli', '--json'])
        self.assertEqual(res, 0)
        self.check_value("nmap_json_count", len(out.splitlines()))
        # Object ID
        res, out, _ = RUN(["ivre", "scancli", "--json", "--limit", "1"])
        self.assertEqual(res, 0)
        oid = str(next(ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchhost(json.loads(out.decode())['addr']),
            limit=1, fields=["_id"],
        ))['_id'])
        res, out, _ = RUN(["ivre", "scancli", "--count", "--id", oid])
        self.assertEqual(res, 0)
        self.assertEqual(int(out), 1)
        res, out, _ = RUN(["ivre", "scancli", "--count", "--no-id", oid])
        self.assertEqual(res, 0)
        self.assertEqual(int(out) + 1, hosts_count)

        portsnb_20 = self.check_count_value(
            "nmap_20_ports",
            ivre.db.db.nmap.searchcountopenports(20, 20),
            ["--countports", "20", "20"], "countports:20",
        )
        self.check_count_value(
            hosts_count - portsnb_20,
            ivre.db.db.nmap.searchcountopenports(20, 20, neg=True),
            ["--no-countports", "20", "20"], "!countports:20",
        )

        portsnb_10_100 = self.check_count_value(
            "nmap_10-100_ports",
            ivre.db.db.nmap.searchcountopenports(10, 100),
            ["--countports", "10", "100"], "countports:10-100",
        )
        self.check_count_value(
            hosts_count - portsnb_10_100,
            ivre.db.db.nmap.searchcountopenports(10, 100, neg=True),
            ["--no-countports", "10", "100"], "-countports:10-100",
        )

        self.check_count_value(
            "nmap_extended_eu_count",
            ivre.db.db.nmap.searchcountry(['EU*', 'CH', 'NO']),
            ["--country=EU*,CH,NO"], "country:EU*,CH,NO"
        )

        # Filters
        addr = next(ivre.db.db.nmap.get(
            ivre.db.db.nmap.flt_empty, fields=["addr"]
        ))['addr']
        self.check_count_value(1, ivre.db.db.nmap.searchhost(addr),
                               ['--host', ivre.utils.force_int2ip(addr)],
                               ivre.utils.force_int2ip(addr))
        result = next(ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchhost(addr)
        ))
        self.assertEqual(result['addr'], addr)
        self.check_count_value_api(1, ivre.db.db.nmap.flt_and(
            ivre.db.db.nmap.searchhost(addr),
            ivre.db.db.nmap.searchhost(addr),
        ))
        recid = ivre.db.db.nmap.getid(
            next(ivre.db.db.nmap.get(ivre.db.db.nmap.flt_empty))
        )
        self.check_count_value_api(1, ivre.db.db.nmap.searchid(recid))
        self.assertIsNotNone(
            ivre.db.db.nmap.getscan(
                ivre.db.db.nmap.getscanids(
                    next(ivre.db.db.nmap.get(ivre.db.db.nmap.flt_empty))
                )[0]
            )
        )

        self.check_count_value(0, ivre.db.db.nmap.searchhost("127.12.34.56"),
                               ["--host", "127.12.34.56"], "127.12.34.56")

        generator = ivre.db.db.nmap.get(ivre.db.db.nmap.flt_empty)
        addrrange = sorted((x['addr'] for x in
                            [next(generator), next(generator)]),
                           key=ivre.utils.force_ip2int)
        addr_range_count = self.check_count_value(
            None, ivre.db.db.nmap.searchrange(*addrrange),
            ["--range"] + [ivre.utils.force_int2ip(x) for x in addrrange],
            "range:%s-%s" % tuple(ivre.utils.force_int2ip(x)
                                  for x in addrrange),
        )
        self.assertGreaterEqual(addr_range_count, 2)
        self.check_count_value_api(addr_range_count, ivre.db.db.nmap.flt_and(
            ivre.db.db.nmap.searchcmp("addr", addrrange[0], '>='),
            ivre.db.db.nmap.searchcmp("addr", addrrange[1], '<='),
        ))
        addrrange2 = [
            ivre.utils.int2ip(ivre.utils.ip2int(addrrange[0]) - 1)
            if isinstance(addrrange[0], basestring) else addrrange[0] - 1,
            ivre.utils.int2ip(ivre.utils.ip2int(addrrange[1]) + 1)
            if isinstance(addrrange[1], basestring) else addrrange[1] + 1,
        ]
        self.check_count_value_api(addr_range_count, ivre.db.db.nmap.flt_and(
            ivre.db.db.nmap.searchcmp("addr", addrrange2[0], '>'),
            ivre.db.db.nmap.searchcmp("addr", addrrange2[1], '<'),
        ))
        self.check_count_value_api(
            hosts_count - addr_range_count,
            ivre.db.db.nmap.searchrange(*addrrange, neg=True),
        )
        self.check_count_value_cgi(hosts_count - addr_range_count,
                                   "-range:%s-%s" % tuple(addrrange))
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
                0, next(ivre.db.db.nmap.get(
                    ivre.db.db.nmap.flt_empty,
                    fields=['endtime'],
                    sort=[['endtime', -1]]
                ))['endtime']
            )
        )
        self.assertEqual(count, hosts_count)

        nets = ivre.utils.range2nets(addrrange)
        count = 0
        for net in nets:
            count += ivre.db.db.nmap.count(
                ivre.db.db.nmap.searchnet(net)
            )
            start, stop = (ivre.utils.ip2int(addr) for addr in
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
        addr = next(result)['addr']
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
                   next(result)['traces'],
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
        addr = next(ivre.db.db.nmap.get(
            ivre.db.db.nmap.flt_empty
        ))['addr']
        addr_i = ivre.utils.force_ip2int(addr)
        addr = ivre.utils.force_int2ip(addr)
        addr_net = '.'.join(addr.split('.')[:3]) + '.0/24'
        queries = [
            ivre.db.db.nmap.searchhost(addr),
            ivre.db.db.nmap.searchnet(addr_net),
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

        # Check Web /scans
        ## In the whole database
        self.find_record_cgi(lambda rec: addr == rec['addr'])
        ## In the /24 network
        self.find_record_cgi(lambda rec: addr == rec['addr'],
                             webflt='net:%s' % addr_net)
        # Check Web functions used for graphs
        ## onlyips / IPs as strings
        req = Request('http://%s:%d/cgi/scans/onlyips?q=net:%s' % (
            HTTPD_HOSTNAME, HTTPD_PORT, addr_net,
        ))
        req.add_header('Referer', 'http://%s:%d/' % (HTTPD_HOSTNAME,
                                                     HTTPD_PORT))
        udesc = urlopen(req)
        self.assertEquals(udesc.getcode(), 200)
        self.assertTrue(addr in json.loads(udesc.read().decode()))
        ## onlyips / IPs as numbers
        req = Request(
            'http://%s:%d/cgi/scans/onlyips?q=net:%s&ipsasnumbers=1' % (
                HTTPD_HOSTNAME, HTTPD_PORT, addr_net,
            )
        )
        req.add_header('Referer', 'http://%s:%d/' % (HTTPD_HOSTNAME,
                                                     HTTPD_PORT))
        udesc = urlopen(req)
        self.assertEquals(udesc.getcode(), 200)
        self.assertTrue(addr_i in json.loads(udesc.read().decode()))
        ## ipsports / IPs as strings
        req = Request('http://%s:%d/cgi/scans/ipsports?q=net:%s' % (
            HTTPD_HOSTNAME, HTTPD_PORT, addr_net,
        ))
        req.add_header('Referer', 'http://%s:%d/' % (HTTPD_HOSTNAME,
                                                     HTTPD_PORT))
        udesc = urlopen(req)
        self.assertEquals(udesc.getcode(), 200)
        self.assertTrue(addr in
                        (x[0] for x in json.loads(udesc.read().decode())))
        ## ipsports / IPs as numbers
        req = Request(
            'http://%s:%d/cgi/scans/ipsports?q=net:%s&ipsasnumbers=1' % (
                HTTPD_HOSTNAME, HTTPD_PORT, addr_net,
            )
        )
        req.add_header('Referer', 'http://%s:%d/' % (HTTPD_HOSTNAME,
                                                     HTTPD_PORT))
        udesc = urlopen(req)
        self.assertEquals(udesc.getcode(), 200)
        self.assertTrue(addr_i in
                        (x[0] for x in json.loads(udesc.read().decode())))
        ## timeline / IPs as strings
        req = Request('http://%s:%d/cgi/scans/timeline?q=net:%s' % (
            HTTPD_HOSTNAME, HTTPD_PORT, addr_net,
        ))
        req.add_header('Referer', 'http://%s:%d/' % (HTTPD_HOSTNAME,
                                                     HTTPD_PORT))
        udesc = urlopen(req)
        self.assertEquals(udesc.getcode(), 200)
        self.assertTrue(addr in
                        (x[1] for x in json.loads(udesc.read().decode())))
        ## timeline / IPs as numbers
        req = Request(
            'http://%s:%d/cgi/scans/timeline?q=net:%s&ipsasnumbers=1' % (
                HTTPD_HOSTNAME, HTTPD_PORT, addr_net,
            )
        )
        req.add_header('Referer', 'http://%s:%d/' % (HTTPD_HOSTNAME,
                                                     HTTPD_PORT))
        udesc = urlopen(req)
        self.assertEquals(udesc.getcode(), 200)
        self.assertTrue(addr_i in
                        (x[1] for x in json.loads(udesc.read().decode())))
        ## timeline - modulo 24h / IPs as strings
        req = Request(
            'http://%s:%d/cgi/scans/timeline?q=net:%s&modulo=86400' % (
                HTTPD_HOSTNAME, HTTPD_PORT, addr_net,
            )
        )
        req.add_header('Referer', 'http://%s:%d/' % (HTTPD_HOSTNAME,
                                                     HTTPD_PORT))
        udesc = urlopen(req)
        self.assertEquals(udesc.getcode(), 200)
        self.assertTrue(addr in
                        (x[1] for x in json.loads(udesc.read().decode())))
        ## timeline - modulo 24h / IPs as numbers
        req = Request(
            'http://%s:%d/cgi/scans/timeline?'
            'q=net:%s&ipsasnumbers=1&modulo=86400' % (
                HTTPD_HOSTNAME, HTTPD_PORT, addr_net,
            )
        )
        req.add_header('Referer', 'http://%s:%d/' % (HTTPD_HOSTNAME,
                                                     HTTPD_PORT))
        udesc = urlopen(req)
        self.assertEquals(udesc.getcode(), 200)
        self.assertTrue(addr_i in
                        (x[1] for x in json.loads(udesc.read().decode())))
        ## countopenports / IPs as strings
        req = Request('http://%s:%d/cgi/scans/countopenports?q=net:%s' % (
            HTTPD_HOSTNAME, HTTPD_PORT, addr_net,
        ))
        req.add_header('Referer', 'http://%s:%d/' % (HTTPD_HOSTNAME,
                                                     HTTPD_PORT))
        udesc = urlopen(req)
        self.assertEquals(udesc.getcode(), 200)
        self.assertTrue(addr in
                        (x[0] for x in json.loads(udesc.read().decode())))
        ## countopenports / IPs as numbers
        req = Request(
            'http://%s:%d/cgi/scans/countopenports?q=net:%s&ipsasnumbers=1' % (
                HTTPD_HOSTNAME, HTTPD_PORT, addr_net,
            )
        )
        req.add_header('Referer', 'http://%s:%d/' % (HTTPD_HOSTNAME,
                                                     HTTPD_PORT))
        udesc = urlopen(req)
        self.assertEquals(udesc.getcode(), 200)
        self.assertTrue(addr_i in
                        (x[0] for x in json.loads(udesc.read().decode())))
        ## coordinates
        result = next(ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchcity(re.compile('.'))
        ))
        addr = ivre.utils.force_int2ip(result['addr'])
        addr_net = '.'.join(addr.split('.')[:3]) + '.0/24'
        coords = result['infos']['loc']['coordinates']
        req = Request('http://%s:%d/cgi/scans/coordinates?q=net:%s' % (
            HTTPD_HOSTNAME, HTTPD_PORT, addr_net,
        ))
        req.add_header('Referer', 'http://%s:%d/' % (HTTPD_HOSTNAME,
                                                     HTTPD_PORT))
        udesc = urlopen(req)
        self.assertEquals(udesc.getcode(), 200)
        self.assertTrue(
            coords in
            (x['coordinates']
             for x in json.loads(udesc.read().decode())['geometries'])
        )
        # Check Web /scans (again, new addresses)
        ## In the whole database
        self.find_record_cgi(lambda rec: addr == rec['addr'])
        ## In the /24 network
        self.find_record_cgi(lambda rec: addr == rec['addr'],
                             webflt='net:%s' % addr_net)

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
        name = next(ivre.db.db.nmap.get(ivre.db.db.nmap.searchdomain(
            'com'
        )))['hostnames'][0]['name']
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
        ### FIXME: add --service option to check_top_value_cli.
        #self._check_value_cli(
        #    "nmap_isakmp_top_products",
        #    ["ivre", "scancli", "--top", "product", "--service", "isakmp"],
        #)
        self.check_top_value("nmap_ssh_top_port", "port:ssh")
        self.check_top_value("nmap_http_top_content_type",
                             "httphdr:content-type")
        self.check_top_value("nmap_http_top_header", "httphdr.name")
        self.check_top_value("nmap_http_top_header_value", "httphdr.value")
        self.check_lines_value_cmd(
            "nmap_domains_pttsh_tw",
            ["ivre", "scancli", "--domain", "/^pttsh.*tw$/i",
             "--distinct", "hostnames.name"]
        )
        self._check_top_value_cli("nmap_top_filename", "file")
        self._check_top_value_cli("nmap_top_filename", "file.filename")
        self._check_top_value_cli("nmap_top_anonftp_filename", "file:ftp-anon")
        self._check_top_value_cli("nmap_top_anonftp_filename", "file:ftp-anon.filename")
        self._check_top_value_cli("nmap_top_uids", "file.uid")
        self._check_top_value_cli("nmap_top_modbus_deviceids", "modbus.deviceid")
        self._check_top_value_cli("nmap_top_services", "service")
        self._check_top_value_cli("nmap_top_product", "product")
        self._check_top_value_cli("nmap_top_product_http", "product:http")
        self._check_top_value_cli("nmap_top_version", "version")
        self._check_top_value_cli("nmap_top_version_http", "version:http")
        self._check_top_value_cli("nmap_top_version_http_apache", "version:http:Apache")
        categories = ivre.db.db.nmap.topvalues("category")
        category = next(categories)
        self.assertEqual(category["_id"], "TEST")
        self.assertEqual(category["count"], hosts_count)
        with self.assertRaises(StopIteration):
            next(categories)
        self._check_top_value_api("nmap_topsrv", "service")
        self._check_top_value_api("nmap_topsrv_80", "service:80")
        self._check_top_value_api("nmap_topprod", "product")
        self._check_top_value_api("nmap_topprod_80", "product:80")
        self._check_top_value_api("nmap_topdevtype", "devicetype")
        self._check_top_value_api("nmap_topdevtype_80", "devicetype:80")
        self._check_top_value_api("nmap_topdomain", "domains")
        self._check_top_value_api("nmap_topdomains_1", "domains:1")
        self._check_top_value_api("nmap_tophop", "hop")
        self._check_top_value_api("nmap_tophop_10+", "hop>10")
        locations = list(ivre.db.db.nmap.getlocations(
            ivre.db.db.nmap.flt_empty
        ))
        self.assertTrue(all(len(elt) == 2 for elt in locations))
        self.assertTrue(all(isinstance(elt['_id'], tuple) for elt in locations))
        self.assertTrue(all(len(elt['_id']) == 2 for elt in locations))
        self.assertTrue(all(all(isinstance(sub, float) for sub in elt['_id'])
                            for elt in locations))
        self.assertTrue(all(isinstance(elt['count'], int) for elt in locations))
        self.check_value('nmap_location_count', len(locations))

        # moduli
        proc = RUN_ITER(["ivre", "getmoduli", "--active-ssl", "--active-ssh"],
                        stderr=None)
        distinct = 0
        maxcount = 0
        for line in proc.stdout:
            distinct += 1
            count = int(line.split()[1])
            if count > maxcount:
                maxcount = count
        self.assertEqual(proc.wait(), 0)
        self.check_value("nmap_distinct_moduli", distinct)
        self.check_value("nmap_max_moduli_reuse", maxcount)
        proc = RUN_ITER(["ivre", "getmoduli", "--active-ssl"],
                        stderr=None)
        distinct = 0
        maxcount = 0
        for line in proc.stdout:
            distinct += 1
            count = int(line.split()[1])
            if count > maxcount:
                maxcount = count
        self.assertEqual(proc.wait(), 0)
        self.check_value("nmap_distinct_ssl_moduli", distinct)
        self.check_value("nmap_max_moduli_ssl_reuse", maxcount)
        proc = RUN_ITER(["ivre", "getmoduli", "--active-ssh"],
                        stderr=None)
        distinct = 0
        maxcount = 0
        for line in proc.stdout:
            distinct += 1
            count = int(line.split()[1])
            if count > maxcount:
                maxcount = count
        self.assertEqual(proc.wait(), 0)
        self.check_value("nmap_distinct_ssh_moduli", distinct)
        self.check_value("nmap_max_moduli_ssh_reuse", maxcount)

        # http headers
        self.check_count_value("nmap_count_httphdr",
                               ivre.db.db.nmap.searchhttphdr(),
                               ["--httphdr", ""], "httphdr")
        self.check_count_value(
            "nmap_count_httphdr_contentype",
            ivre.db.db.nmap.searchhttphdr(name="content-type"),
            ["--httphdr", "content-type"], "httphdr:content-type",
        )
        self.check_count_value(
            "nmap_count_httphdr_contentype_textplain",
            ivre.db.db.nmap.searchhttphdr(name="content-type",
                                          value="text/plain"),
            ["--httphdr", "content-type:text/plain"],
            "httphdr:content-type:text/plain",
        )
        self.check_count_value(
            "nmap_count_httphdr_contentype_plain",
            ivre.db.db.nmap.searchhttphdr(name="content-type",
                                          value=re.compile("plain", re.I)),
            ["--httphdr", "content-type:/plain/i"],
            "httphdr:content-type:/plain/i",
        )

        # Remove
        result = next(ivre.db.db.nmap.get(
            ivre.db.db.nmap.searchhost(addr)
        ))
        ivre.db.db.nmap.remove(result)
        count = ivre.db.db.nmap.count(
            ivre.db.db.nmap.searchhost(addr)
        )
        self.assertEqual(count, 0)
        hosts_count -= 1

        if DATABASE != "postgres":
            # FIXME: for some reason, this does not terminate
            self.assertEqual(RUN(["ivre", "scancli", "--init"],
                                 stdin=open(os.devnull))[0], 0)

    def test_passive(self):

        # Init DB
        self.assertEqual(RUN(["ivre", "ipinfo", "--count"])[1], b"0\n")
        self.assertEqual(RUN(["ivre", "ipinfo", "--init"],
                             stdin=open(os.devnull))[0], 0)
        self.assertEqual(RUN(["ivre", "ipinfo", "--count"])[1], b"0\n")

        # p0f & Bro insertion
        ivre.utils.makedirs("logs")
        broenv = os.environ.copy()
        broenv["LOG_ROTATE"] = "60"
        broenv["LOG_PATH"] = "logs/TEST"

        for fname in self.pcap_files:
            for mode in ivre.passive.P0F_MODES:
                res = RUN(["ivre", "p0f2db", "-s", "TEST", "-m", mode,
                           fname])[0]
                self.assertEqual(res, 0)
            broprocess = subprocess.Popen(
                ['bro', '-C', '-b', '-r', fname,
                 os.path.join(
                     ivre.config.guess_prefix('bro'),
                     'ivre', 'passiverecon', 'bare.bro'),
                 '-e',
                 'redef tcp_content_deliver_all_resp = T; '
                 'redef tcp_content_deliver_all_orig = T;'],
                env=broenv)
            broprocess.wait()

        time.sleep(1) # Hack for Travis CI
        pid = os.fork()
        if pid < 0:
            raise Exception("Cannot fork")
        elif pid:
            # Wait for child process to handle every file in "logs"
            while any(walk[2] for walk in os.walk("logs")):
                print(u"Waiting for passivereconworker")
                time.sleep(2)
            os.kill(pid, signal.SIGINT)
            os.waitpid(pid, 0)
        elif USE_COVERAGE:
            os.execvp(
                sys.executable,
                COVERAGE + [
                    "run", "--parallel-mode", which("ivre"),
                    "passivereconworker", "--directory", "logs",
                    "--progname", " ".join(
                        pipes.quote(elt) for elt in
                        COVERAGE + ["run", "--parallel-mode", which("ivre"),
                                    "passiverecon2db"]
                    ),
                ],
            )
        else:
            os.execlp("ivre", "ivre", "passivereconworker", "--directory",
                      "logs")

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
        self.assertGreater(out.count(b'\n'), result)

        result = ivre.db.db.passive.count(
            ivre.db.db.passive.searchhost("127.12.34.56")
        )
        self.assertEqual(result, 0)

        addrrange = sorted(
            (x for x in ivre.db.db.passive.distinct('addr')
             if isinstance(x, (int, basestring)) and x),
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
            start, stop = (ivre.utils.ip2int(addr) for addr in
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
            values = next(ivre.db.db.passive.topvalues(field="addr",
                                                       distinct=distinct,
                                                       topnbr=1))
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

        # moduli
        proc = RUN_ITER(["ivre", "getmoduli", "--passive-ssl", "--passive-ssh"],
                        stderr=None)
        distinct = 0
        maxcount = 0
        for line in proc.stdout:
            distinct += 1
            count = int(line.split()[1])
            if count > maxcount:
                maxcount = count
        self.assertEqual(proc.wait(), 0)
        self.check_value("passive_distinct_moduli", distinct)
        self.check_value("passive_max_moduli_reuse", maxcount)
        proc = RUN_ITER(["ivre", "getmoduli", "--passive-ssl"],
                        stderr=None)
        distinct = 0
        maxcount = 0
        for line in proc.stdout:
            distinct += 1
            count = int(line.split()[1])
            if count > maxcount:
                maxcount = count
        self.assertEqual(proc.wait(), 0)
        self.check_value("passive_distinct_ssl_moduli", distinct)
        self.check_value("passive_max_moduli_ssl_reuse", maxcount)
        proc = RUN_ITER(["ivre", "getmoduli", "--passive-ssh"],
                        stderr=None)
        distinct = 0
        maxcount = 0
        for line in proc.stdout:
            distinct += 1
            count = int(line.split()[1])
            if count > maxcount:
                maxcount = count
        self.assertEqual(proc.wait(), 0)
        self.check_value("passive_distinct_ssh_moduli", distinct)
        self.check_value("passive_max_moduli_ssh_reuse", maxcount)

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

        ret, out, _ = RUN(["ivre", "ipinfo", "--short"])
        self.assertEqual(ret, 0)
        count = sum(1 for _ in out.splitlines())
        self.check_value("passive_ipinfo_short_count", count)

        ret, out, _ = RUN(["ivre", "iphost", "/./"])
        self.assertEqual(ret, 0)
        count = sum(1 for _ in out.splitlines())
        self.check_value("passive_iphost_count", count)

        ret, out, _ = RUN(["ivre", "iphost", "--sub", "com"])
        self.assertEqual(ret, 0)
        count = sum(1 for _ in out.splitlines())
        self.check_value("passive_iphost_count_com", count)

        for tail in ["tail", "tailnew"]:
            ret, out, _ = RUN(["ivre", "ipinfo", "--%s" % tail, "1"])
            self.assertEqual(sum(1 for line in out.splitlines()
                                 if line[:1] != b"\t"), 1)
            self.assertEqual(ret, 0)

        def alarm_handler(signum, stacktrace):
            assert signum == signal.SIGALRM
            raise Exception("Alarm")

        old_handler = signal.signal(signal.SIGALRM, alarm_handler)

        for tail in ["tailf", "tailfnew"]:
            proc = RUN_ITER(['ivre', 'ipinfo', '--%s' % tail],
                            stderr=None)
            out = []
            old_alarm = signal.alarm(30)
            # "for i, line in enumerate(proc.stdout)" won't work.
            # See https://stackoverflow.com/a/26761671
            for line in iter(proc.stdout.readline, b""):
                if line[:1] == b'\t':
                    # we do not count "info" lines
                    continue
                out.append(line)
                if len(out) == 10:
                    break
            signal.alarm(30)
            self.assertEqual(len(out), 10)
            # When we have read 10 lines, we only want to read "info"
            # lines
            while select([proc.stdout], [], [], 10)[0]:
                line = proc.stdout.readline()
                self.assertTrue(line[:1] == b'\t')
            #proc.send_signal(signal.SIGINT)
            #ret = proc.wait()
            #self.assertEqual(ret, 0)
            # XXX Travis CI seems broken here
            proc.kill()
            proc.wait()
            signal.alarm(old_alarm)
        
        signal.signal(signal.SIGALRM, old_handler)

        if DATABASE == "mongo":
            # Check no None value can actually exist in DB
            self.assertFalse(None in (
                rec['source'] for rec in ivre.db.db.passive.get(
                    ivre.db.db.passive.flt_empty,
                    fields=['source'],
                )
                if 'source' in rec
            ))

        self.assertEqual(RUN(["ivre", "ipinfo", "--init"],
                             stdin=open(os.devnull))[0], 0)
        # Clean
        shutil.rmtree("logs")


    def test_data(self):
        """ipdata (Maxmind, thyme.apnic.net) functions"""

        # Init DB
        res, out, _ = RUN(["ivre", "ipdata", "8.8.8.8"])
        self.assertEqual(res, 0)
        self.assertEqual(out, b"8.8.8.8\n")
        res = RUN(["ivre", "ipdata", "--init"], stdin=open(os.devnull))[0]
        self.assertEqual(res, 0)
        res, out, _ = RUN(["ivre", "ipdata", "8.8.8.8"])
        self.assertEqual(res, 0)
        self.assertEqual(out, b"8.8.8.8\n")

        # Download
        res = RUN(["ivre", "ipdata", "--download"])[0]
        self.assertEqual(res, 0)

        # Insert
        proc = RUN_ITER(["ivre", "ipdata", "--import-all",
                         "--no-update-passive-db"],
                        stdout=sys.stdout, stderr=sys.stderr)
        self.assertEqual(proc.wait(), 0)

        res, out, _ = RUN(["ivre", "ipdata", "8.8.8.8"])
        self.assertEqual(res, 0)
        # The order may differ, depending on the backend.  We need to
        # replace float representations because it differs between
        # Python 2.6 and other supported Python version; see
        # <https://docs.python.org/2/whatsnew/2.7.html#python-3-1-features>.
        out = sorted(
            b'    coordinates (37.751, -97.822)' if
            x == b'    coordinates (37.750999999999998, -97.822000000000003)'
            else x for x in out.splitlines()
        )
        self.assertEqual(out, sorted(b'''8.8.8.8
    as_num 15169
    as_name Google Inc.
    coordinates (37.751, -97.822)
    country_code US
    country_name United States
'''.splitlines()))

        res, out, _ = RUN(["ivre", "runscans", "--output", "Count", "--asnum", "15169"])
        self.assertEqual(res, 0)
        self.assertEqual(out, b'AS15169 has 2685951 IPs.\n')
        res, out, _ = RUN(["ivre", "runscans", "--output", "Count", "--country", "US"])
        self.assertEqual(res, 0)
        self.assertEqual(out, b'US has 1595080627 IPs.\n')
        res, out, _ = RUN(["ivre", "runscans", "--output", "List", "--country", "A2"])
        self.assertEqual(res, 0)
        self.assertEqual(out, b'''5.145.149.142 - 5.145.149.142
57.72.6.0 - 57.72.6.255
62.56.206.0 - 62.56.206.255
62.128.160.0 - 62.128.160.255
62.128.167.0 - 62.128.167.255
62.145.35.0 - 62.145.35.255
77.220.0.0 - 77.220.7.255
78.41.29.0 - 78.41.29.255
78.41.227.0 - 78.41.227.255
80.78.16.152 - 80.78.16.167
80.78.16.192 - 80.78.16.207
80.78.16.224 - 80.78.16.224
80.78.19.57 - 80.78.19.63
80.78.19.233 - 80.78.19.239
80.231.5.0 - 80.231.5.255
82.206.239.0 - 82.206.239.255
83.229.22.0 - 83.229.22.255
84.22.67.0 - 84.22.67.255
86.62.5.0 - 86.62.5.255
86.62.30.0 - 86.62.30.255
87.234.247.0 - 87.234.247.255
93.93.101.96 - 93.93.101.127
93.93.102.96 - 93.93.102.127
111.90.150.0 - 111.90.150.255
185.38.108.0 - 185.38.108.255
196.15.8.0 - 196.15.8.255
196.15.10.0 - 196.15.11.255
196.47.77.0 - 196.47.78.255
196.201.132.0 - 196.201.132.255
196.201.135.0 - 196.201.135.255
196.201.148.0 - 196.201.148.255
199.190.44.0 - 199.190.47.255
213.193.49.0 - 213.193.49.255
216.147.155.0 - 216.147.155.255
217.30.26.0 - 217.30.26.255
217.175.75.0 - 217.175.75.255
''')
        res, out, _ = RUN(["ivre", "runscans", "--output", "ListCIDRs", "--country", "A1"])
        self.assertEqual(res, 0)
        self.assertEqual(out, b'''31.14.133.39/32
37.221.172.0/23
46.19.137.0/24
46.19.143.0/24
50.7.78.88/31
62.73.8.0/23
63.235.155.210/32
64.12.118.23/32
64.12.118.88/32
67.43.156.0/24
69.10.139.0/24
70.232.245.0/24
74.82.9.224/32
80.254.74.0/23
93.115.82.0/23
93.115.84.0/23
96.47.226.20/32
147.203.120.0/24
176.9.75.43/32
185.36.100.145/32
192.238.21.0/24
193.107.17.71/32
193.200.150.0/24
198.144.105.88/32
199.114.223.0/24
199.188.236.0/23
200.200.200.200/32
206.71.162.0/24
206.196.103.0/24
208.43.225.52/32
209.216.198.0/24
213.234.249.115/32
216.151.180.0/24
''')
        # ListAll and ListAllRand use different mechanisms
        res, out1, _ = RUN(["ivre", "runscans", "--output", "ListAll",
                            "--country", "A1"])
        self.assertEqual(res, 0)
        res, out2, _ = RUN(["ivre", "runscans", "--output", "ListAllRand",
                            "--country", "A1"])
        self.assertEqual(res, 0)
        out1, out2 = out1.split(b'\n'), out2.split(b'\n')
        self.assertGreater(len(out1), 0)
        self.assertItemsEqual(out1, out2)
        res, out1, _ = RUN(["ivre", "runscans", "--output", "ListAll",
                            "--region", "GP", "R5"])
        self.assertEqual(res, 0)
        res, out2, _ = RUN(["ivre", "runscans", "--output", "ListAllRand",
                            "--region", "GP", "R5"])
        self.assertEqual(res, 0)
        out1, out2 = out1.split(b'\n'), out2.split(b'\n')
        self.assertGreater(len(out1), 0)
        self.assertItemsEqual(out1, out2)
        res, out1, _ = RUN(["ivre", "runscans", "--output", "ListAll",
                            "--city", "FR", "Carcassonne"])
        self.assertEqual(res, 0)
        res, out2, _ = RUN(["ivre", "runscans", "--output", "ListAllRand",
                            "--city", "FR", "Carcassonne"])
        self.assertEqual(res, 0)
        out1, out2 = out1.split(b'\n'), out2.split(b'\n')
        self.assertGreater(len(out1), 0)
        self.assertItemsEqual(out1, out2)
        res, out1, _ = RUN(["ivre", "runscans", "--output", "ListAll",
                            "--asnum", "12345"])
        self.assertEqual(res, 0)
        res, out2, _ = RUN(["ivre", "runscans", "--output", "ListAllRand",
                            "--asnum", "12345"])
        self.assertEqual(res, 0)
        out1, out2 = out1.split(b'\n'), out2.split(b'\n')
        self.assertGreater(len(out1), 0)
        self.assertItemsEqual(out1, out2)

        # Clean
        res = RUN(["ivre", "ipdata", "--init"], stdin=open(os.devnull))[0]
        self.assertEqual(res, 0)

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
        teststr = b"TEST STRING -./*'"
        self.assertEqual(ivre.utils.regexp2pattern(teststr),
                         (re.escape(teststr), 0))
        self.assertEqual(
            ivre.utils.regexp2pattern(
                re.compile(b'^' + re.escape(teststr) + b'$')),
            (re.escape(teststr), 0))
        self.assertEqual(
            ivre.utils.regexp2pattern(re.compile(re.escape(teststr))),
            (b'.*' + re.escape(teststr) + b'.*', 0))
        self.assertEqual(ivre.utils.str2list(teststr), teststr)
        teststr = "1,2|3"
        self.assertItemsEqual(ivre.utils.str2list(teststr),
                              ["1", "2", "3"])
        self.assertTrue(ivre.utils.isfinal(1))
        self.assertTrue(ivre.utils.isfinal("1"))
        self.assertFalse(ivre.utils.isfinal([]))
        self.assertFalse(ivre.utils.isfinal({}))

        # Nmap ports
        ports = [1, 3, 2, 4, 6, 80, 5, 5, 110, 111]
        self.assertEqual(
            set(ports),
            ivre.utils.nmapspec2ports(ivre.utils.ports2nmapspec(ports))
        )
        self.assertEqual(ivre.utils.ports2nmapspec(ports), '1-6,80,110-111')

        # Nmap fingerprints
        match = ivre.utils.match_nmap_svc_fp(
            b'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u7\r\n'
        )
        self.assertEqual(match['service_name'], 'ssh')
        self.assertEqual(match['service_extrainfo'], 'protocol 2.0')
        self.assertEqual(match['service_ostype'], 'Linux')
        self.assertEqual(match['service_product'], 'OpenSSH')
        self.assertEqual(match['service_version'], '6.0p1 Debian 4+deb7u7')
        match = ivre.utils.match_nmap_svc_fp(
            b'HTTP/1.1 400 Bad Request\r\n'
            b'Date: Sun, 22 Apr 2018 12:21:46 GMT\r\n'
            b'Server: Apache/2.4.10 (Debian)\r\n'
            b'Content-Length: 312\r\n'
            b'Connection: close\r\n'
            b'Content-Type: text/html; charset=iso-8859-1\r\n',
            probe="GetRequest"
        )
        self.assertEqual(match['service_name'], 'http')
        self.assertEqual(match['service_extrainfo'], '(Debian)')
        self.assertEqual(match['service_product'], 'Apache httpd')
        self.assertEqual(match['service_version'], '2.4.10')
        match = ivre.utils.match_nmap_svc_fp(
            b'220 localhost.localdomain ESMTP Server (Microsoft Exchange '
            b'Internet Mail Service 5.5.2653.13) ready\n'
        )
        self.assertEqual(match['service_name'], 'smtp')
        self.assertEqual(match['service_hostname'], 'localhost.localdomain')
        self.assertEqual(match['service_ostype'], 'Windows')
        self.assertEqual(match['service_product'], 'Microsoft Exchange smtpd')
        self.assertEqual(match['service_version'], '5.5.2653.13')

        # Nmap (and Bro) encoding & decoding
        # >>> from random import randint
        # >>> bytes(randint(0, 255) for _ in range(1000))
        raw_data = b'\xc6\x97\x05\xc8\x16\x96\xaei\xe9\xdd\xe8"\x07\x16\x15\x8c\xf5%x\xb0\x00\xb4\xbcv\xb8A\x19\xefj+RbgH}U\xec\xb4\x1bZ\x08\xd4\xfe\xca\x95z\xa0\x0cB\xabWM\xf1\xfd\x95\xb7)\xbb\xe9\xa7\x8a\x08]\x8a\xcab\xb3\x1eI\xc0Q0\xec\xd0\xd4\xd4bt\xf7\xbb1\xc5\x9c\x85\xf8\x87\x8b\xb2\x87\xed\x82R\xf9}+\xfc\xa4\xf2?\xa5}\x17k\xa6\xb6t\xab\x91\x91\x83?\xb4\x01L\x1fO\xff}\x98j\xa5\x9a\t,\xf3\x8b\x1e\xf4\xd3~\x83\x87\x0b\x95\\\xa9\xaa\xfbi5\xfb\xaau\xc6y\xff\xac\xcb\'\xa5\xf4y\x8f\xab\xf2\x04Z\xf1\xd7\x08\x17\xa8\xa5\xe4\x04\xa5R0\xdb\xa3\xe6\xc0\x88\x9a\xee\x93\x8c\x8a\x8b\xa3\x03\xb6\xdf\xbbHp\x1f\x1d{\x92\xb2\xd7B\xc4\x13\xddD\xb29\xbd\x0f\xd8\xed\x94q\xda\x00\x067\xd8T\xb3I\xd3\x88/wE\xd4C\xec!\xf6 <H\xaa\xea\xc1;\x90\x87)\xc5\xb6\xd6\n\x81r\x16\xa1/\xd0Q<\xa4jT\x0f\xe4\xad\x14>0\xf1\xb7\xec\x08\x7f>"\x96P\xd2;\xc4:\xed\xc0\xcb\x85M\x04&{|k\xd0\x06Yc_\x12S\xb0>\xe0=:\xca1\xca\n\xcb.\xf4\xe2\xb1e\x0e\x16\xd6\x8c\xbc!\xbcWd\x19\x0b\xd7\xa0\xed\x1d>$%\xf7\xfb\xc2(\xef\x13\x82\xcc\xa5\xecc\x1fy_\x9f93\xbcPv\xd7\x9b\xbb\x0b]\x9a\xc7\xbd&5\xb2\x85\x95\xfb\xf2j\x11f\xd8\xdb\x03\xc0\xb1\xda\x08aF\x80\xd8\x18\x7f\xf3\x86N\x91\xa6\xd4i\x83\xd4*$_t\x19\xb3\xa2\x187w2 \x0c#\xe5\xca\x03\xb3@H\xb7\xfb,a\xb8\x02\xe4;/\xc11\xb7\xd8\xdd\x9b\xcc\xdcg\xb4\x9f\x81\x10,\x0e\x0c\'_m\xf8$\xa10\xc4\xe9\xc5G_\x14\x10\xf5& \xcf\xa8\x10:\xee\x1aGL\x966\xd7\x1d?\xb0:\xee\x11\x89\xb9\xeb\x8d\xf7\x02\x00\xdb\xd9/\x8a\x01!\xa5wRc?\xfd\x87\x11E\xa9\x8f\x9ed\x0f.\xffM\xd1\xb4\xe9\x19\xb0\xb0"\xac\x84\xff5D\xa9\x12O\xcc1G#\xb5\x16\xba%{:\xde\xf6\t"\xe7\xed\xa0*\xa3\x89\xabl\x08p\x1d\xc1\xae\x14e)\xf3=\x16\x80\xa8\x1b\xe3OSD&V\x16\xf3*\x8416\xdd6\xe6\xbf,R$\x93s>\x87\xbe\x94\x1c\x10\\o,\xc2\x18ig\xa2\xf7\xc9\x9d|\x8c\xc6\x94\\\xee\xb0\'\x01\x1c\x94\xf8\xea\xda\x91\xf1 \x8cP\x84=\xa0\x1a\x87\xba\xa8\x9c\xd6\xf7\n\'\x99\xb9\xd5L\xd2u\x7f\x13\xf3^_T\xc3\x806\x94\xbe\x94\xee\x0cJ`\xba\xf1\n*\xc2\xc7?[\xa7\xdd\xcbX\x08\xafTsU\x81\xa5r\x86Q\x1b8\xcf\xc8\xab\xf1\x1e\xee,i\x15:*\xb4\x84\x01\xc0\x8f\xb3\xdcER%\xe2\x16\x9f\x80z:\xcdZ\xae$\x04\xbfa\xae+\x84U\xb6\x06 \xfe\xd5Y\xf7\xd9\xbftQ0\xbd\xf3\xf5O\x98\xad\x90n\x97\xbd\x81\x1f-\xe5\x1d\x14R\x94\x9cH\x8bf\x80*!E\x933\x88_\xf2]3\xa7g\x9d\\(S\xdc\xd7\x16OXZ\xf7\xc8\x98jU\xbc]\x92\xf3\xc2S\x0c>\';i.\xab\n\x90\xb33\x80\x17k\xfb9\x14\x1a\xd5\x89##?6Y^|{c\x86\x1cF\xc1\x9c\xf1\xcb^\x92\xed\x92$\x15\x81e:\xfc\x13\x1d\x07\xd9\xe9\xd5\x1f(\xef\xc1K\xeem\xa8f7O\x89\xa8\x08\xbd\x12\xeb\xa8\xa6\x9d\xba\xbe\x06\x820x\x18x\xe8A-<p\xd2-\x9c\x00\xde\xbdE\x1bn\x81\x93\x1c\xca\xfc\xe4($\x13\x147\x9d,(t\xffiT\xa6ZU\xc2\xd9<\xba\xa1F\x11\x19N\xb8\xeeA-jC\xdf\xff\x94k\xb5G\x8c\x9e\x19\xff\xf6\x8bg\xb4\x19!\xe9\\\xccB\xd0Y\x08\xfa\'\xc2\x0eYMW\x9fdM0\xb0A\xb5R\xd3t\x8b\t\xb5\xcew,f\x9c\xed\\t\xbc\xf11\xa9\xd3\xef\xdd\xf6\xcf\x96\xe1$\x9a@\xb3v\x05\xc5\xc3\x9e%\xb2\xf8\xe8\xdcd81u\xa8Y\x07\xb15\xe9\xa7\xae\xee\xa9GD\x9e\x7fP\xcf\xd8ca%\xb16\xb6\xc4FP\xed\x8e\x83\x05\x15F'
        encoded_data = ivre.utils.nmap_encode_data(raw_data)
        self.assertEqual(
            encoded_data,
            '\\xc6\\x97\\x05\\xc8\\x16\\x96\\xaei\\xe9\\xdd\\xe8"\\x07\\x16\\x15\\x8c\\xf5%x\\xb0\\x00\\xb4\\xbcv\\xb8A\\x19\\xefj+RbgH}U\\xec\\xb4\\x1bZ\\x08\\xd4\\xfe\\xca\\x95z\\xa0\\x0cB\\xabWM\\xf1\\xfd\\x95\\xb7)\\xbb\\xe9\\xa7\\x8a\\x08]\\x8a\\xcab\\xb3\\x1eI\\xc0Q0\\xec\\xd0\\xd4\\xd4bt\\xf7\\xbb1\\xc5\\x9c\\x85\\xf8\\x87\\x8b\\xb2\\x87\\xed\\x82R\\xf9}+\\xfc\\xa4\\xf2?\\xa5}\\x17k\\xa6\\xb6t\\xab\\x91\\x91\\x83?\\xb4\\x01L\\x1fO\\xff}\\x98j\\xa5\\x9a\\t,\\xf3\\x8b\\x1e\\xf4\\xd3~\\x83\\x87\\x0b\\x95\\\\\\xa9\\xaa\\xfbi5\\xfb\\xaau\\xc6y\\xff\\xac\\xcb\'\\xa5\\xf4y\\x8f\\xab\\xf2\\x04Z\\xf1\\xd7\\x08\\x17\\xa8\\xa5\\xe4\\x04\\xa5R0\\xdb\\xa3\\xe6\\xc0\\x88\\x9a\\xee\\x93\\x8c\\x8a\\x8b\\xa3\\x03\\xb6\\xdf\\xbbHp\\x1f\\x1d{\\x92\\xb2\\xd7B\\xc4\\x13\\xddD\\xb29\\xbd\\x0f\\xd8\\xed\\x94q\\xda\\x00\\x067\\xd8T\\xb3I\\xd3\\x88/wE\\xd4C\\xec!\\xf6 <H\\xaa\\xea\\xc1;\\x90\\x87)\\xc5\\xb6\\xd6\\n\\x81r\\x16\\xa1/\\xd0Q<\\xa4jT\\x0f\\xe4\\xad\\x14>0\\xf1\\xb7\\xec\\x08\\x7f>"\\x96P\\xd2;\\xc4:\\xed\\xc0\\xcb\\x85M\\x04&{|k\\xd0\\x06Yc_\\x12S\\xb0>\\xe0=:\\xca1\\xca\\n\\xcb.\\xf4\\xe2\\xb1e\\x0e\\x16\\xd6\\x8c\\xbc!\\xbcWd\\x19\\x0b\\xd7\\xa0\\xed\\x1d>$%\\xf7\\xfb\\xc2(\\xef\\x13\\x82\\xcc\\xa5\\xecc\\x1fy_\\x9f93\\xbcPv\\xd7\\x9b\\xbb\\x0b]\\x9a\\xc7\\xbd&5\\xb2\\x85\\x95\\xfb\\xf2j\\x11f\\xd8\\xdb\\x03\\xc0\\xb1\\xda\\x08aF\\x80\\xd8\\x18\\x7f\\xf3\\x86N\\x91\\xa6\\xd4i\\x83\\xd4*$_t\\x19\\xb3\\xa2\\x187w2 \\x0c#\\xe5\\xca\\x03\\xb3@H\\xb7\\xfb,a\\xb8\\x02\\xe4;/\\xc11\\xb7\\xd8\\xdd\\x9b\\xcc\\xdcg\\xb4\\x9f\\x81\\x10,\\x0e\\x0c\'_m\\xf8$\\xa10\\xc4\\xe9\\xc5G_\\x14\\x10\\xf5& \\xcf\\xa8\\x10:\\xee\\x1aGL\\x966\\xd7\\x1d?\\xb0:\\xee\\x11\\x89\\xb9\\xeb\\x8d\\xf7\\x02\\x00\\xdb\\xd9/\\x8a\\x01!\\xa5wRc?\\xfd\\x87\\x11E\\xa9\\x8f\\x9ed\\x0f.\\xffM\\xd1\\xb4\\xe9\\x19\\xb0\\xb0"\\xac\\x84\\xff5D\\xa9\\x12O\\xcc1G#\\xb5\\x16\\xba%{:\\xde\\xf6\\t"\\xe7\\xed\\xa0*\\xa3\\x89\\xabl\\x08p\\x1d\\xc1\\xae\\x14e)\\xf3=\\x16\\x80\\xa8\\x1b\\xe3OSD&V\\x16\\xf3*\\x8416\\xdd6\\xe6\\xbf,R$\\x93s>\\x87\\xbe\\x94\\x1c\\x10\\\\o,\\xc2\\x18ig\\xa2\\xf7\\xc9\\x9d|\\x8c\\xc6\\x94\\\\\\xee\\xb0\'\\x01\\x1c\\x94\\xf8\\xea\\xda\\x91\\xf1 \\x8cP\\x84=\\xa0\\x1a\\x87\\xba\\xa8\\x9c\\xd6\\xf7\\n\'\\x99\\xb9\\xd5L\\xd2u\\x7f\\x13\\xf3^_T\\xc3\\x806\\x94\\xbe\\x94\\xee\\x0cJ`\\xba\\xf1\\n*\\xc2\\xc7?[\\xa7\\xdd\\xcbX\\x08\\xafTsU\\x81\\xa5r\\x86Q\\x1b8\\xcf\\xc8\\xab\\xf1\\x1e\\xee,i\\x15:*\\xb4\\x84\\x01\\xc0\\x8f\\xb3\\xdcER%\\xe2\\x16\\x9f\\x80z:\\xcdZ\\xae$\\x04\\xbfa\\xae+\\x84U\\xb6\\x06 \\xfe\\xd5Y\\xf7\\xd9\\xbftQ0\\xbd\\xf3\\xf5O\\x98\\xad\\x90n\\x97\\xbd\\x81\\x1f-\\xe5\\x1d\\x14R\\x94\\x9cH\\x8bf\\x80*!E\\x933\\x88_\\xf2]3\\xa7g\\x9d\\\\(S\\xdc\\xd7\\x16OXZ\\xf7\\xc8\\x98jU\\xbc]\\x92\\xf3\\xc2S\\x0c>\';i.\\xab\\n\\x90\\xb33\\x80\\x17k\\xfb9\\x14\\x1a\\xd5\\x89##?6Y^|{c\\x86\\x1cF\\xc1\\x9c\\xf1\\xcb^\\x92\\xed\\x92$\\x15\\x81e:\\xfc\\x13\\x1d\\x07\\xd9\\xe9\\xd5\\x1f(\\xef\\xc1K\\xeem\\xa8f7O\\x89\\xa8\\x08\\xbd\\x12\\xeb\\xa8\\xa6\\x9d\\xba\\xbe\\x06\\x820x\\x18x\\xe8A-<p\\xd2-\\x9c\\x00\\xde\\xbdE\\x1bn\\x81\\x93\\x1c\\xca\\xfc\\xe4($\\x13\\x147\\x9d,(t\\xffiT\\xa6ZU\\xc2\\xd9<\\xba\\xa1F\\x11\\x19N\\xb8\\xeeA-jC\\xdf\\xff\\x94k\\xb5G\\x8c\\x9e\\x19\\xff\\xf6\\x8bg\\xb4\\x19!\\xe9\\\\\\xccB\\xd0Y\\x08\\xfa\'\\xc2\\x0eYMW\\x9fdM0\\xb0A\\xb5R\\xd3t\\x8b\\t\\xb5\\xcew,f\\x9c\\xed\\\\t\\xbc\\xf11\\xa9\\xd3\\xef\\xdd\\xf6\\xcf\\x96\\xe1$\\x9a@\\xb3v\\x05\\xc5\\xc3\\x9e%\\xb2\\xf8\\xe8\\xdcd81u\\xa8Y\\x07\\xb15\\xe9\\xa7\\xae\\xee\\xa9GD\\x9e\\x7fP\\xcf\\xd8ca%\\xb16\\xb6\\xc4FP\\xed\\x8e\\x83\\x05\\x15F',
        )
        self.assertEqual(
            ivre.utils.nmap_decode_data(encoded_data),
            raw_data,
        )

        # Math utils
        # http://stackoverflow.com/a/15285588/3223422
        def is_prime(n):
            if n == 2 or n == 3:
                return True
            if n < 2 or n % 2 == 0:
                return False
            if n < 9:
                return True
            if n % 3 == 0:
                return False
            r = int(n**0.5)
            f = 5
            while f <= r:
                if n % f == 0:
                    return False
                if n % (f + 2) == 0:
                    return False
                f += 6
            return True
        for _ in range(3):
            nbr = random.randint(2, 1000)
            factors = list(ivre.mathutils.factors(nbr))
            self.assertTrue(is_prime(nbr) or len(factors) > 1)
            self.assertTrue(all(is_prime(x) for x in factors))
            self.assertEqual(reduce(lambda x, y: x * y, factors), nbr)

        # Bro logs
        basepath = os.getenv('BRO_SAMPLES')
        badchars = re.compile('[%s]' % ''.join(
            re.escape(char) for char in [os.path.sep, '-', '.']
        ))
        if basepath:
            for dirname, _, fnames in os.walk(basepath):
                for fname in fnames:
                    if not fname.endswith('.log'):
                        continue
                    fname = os.path.join(dirname, fname)
                    brofd = ivre.parser.bro.BroFile(fname)
                    i = 0
                    for i, record in enumerate(brofd):
                        json.dumps(record, default=ivre.utils.serialize)
                    self.check_value(
                        'utils_bro_%s_count' % badchars.sub(
                            '_',
                            fname[len(basepath):-4].lstrip('/'),
                        ),
                        i + 1,
                    )

        # Iptables
        with ivre.parser.iptables.Iptables(os.path.join(SAMPLES, 'iptables.log')) as ipt_parser:
            count=0
            for res in ipt_parser:
                count+=1
                self.assertTrue(b'proto' in res  and b'src' in res and b'dst' in res)
                if res[b'proto'].decode() in ('udp', 'tcp'):
                    self.assertTrue(b'sport' in res and b'dport' in res)

            self.assertEqual(count, 40)

        # Web utils
        with self.assertRaises(ValueError):
            ivre.web.utils.query_from_params({'q': '"'})

    def test_scans(self):
        "Run scans, with and without agents"

        # Check simple runscans
        res, out, _ = RUN(["ivre", "runscans", "--output", "Test", "--test",
                           "2"])
        self.assertEqual(res, 0)
        self.assertTrue(b'\nRead address 127.0.0.1\n' in out)
        self.assertTrue(b'\nRead address 127.0.0.2\n' in out)
        res = RUN(["ivre", "runscans", "--network", "127.0.0.1/31"])[0]
        self.assertEqual(res, 0)
        fdesc = tempfile.NamedTemporaryFile(delete=False)
        fdesc.writelines(("127.0.0.%d\n" % i).encode() for i in range(2, 4))
        fdesc.close()
        res = RUN(["ivre", "runscans", "--file", fdesc.name, "--output",
                   "XMLFork"])[0]
        self.assertEqual(res, 0)
        os.unlink(fdesc.name)
        res = RUN(["ivre", "runscans", "--range", "127.0.0.4", "127.0.0.5",
                   "--output", "XMLFull"])[0]
        self.assertEqual(res, 0)
        count = sum(len(walk_elt[2]) for walk_elt in os.walk('scans'))
        self.assertEqual(count, 9)

        # Generate a command line
        res = RUN(["ivre", "runscans", "--output", "CommandLine"])[0]
        self.assertEqual(res, 0)

        # Scan using an agent
        with AgentScanner(self) as agent:
            agent.scan(["--test", "2"])

        # Count the results
        count = sum(len(walk_elt[2]) for walk_elt in os.walk('output/'))
        self.assertEqual(count, 2)

        # Clean
        shutil.rmtree('output')

        # Generate an agent
        res, out, _ = RUN(["ivre", "runscans", "--output", "Agent"])
        self.assertEqual(res, 0)
        with open('ivre-agent.sh', 'wb') as fdesc:
            fdesc.write(out)
        os.chmod('ivre-agent.sh', 0o0755)

        # Fork an agent
        ivre.utils.makedirs('tmp')
        pid_agent = subprocess.Popen([os.path.join(os.getcwd(),
                                                   "ivre-agent.sh")],
                                     preexec_fn=os.setsid,
                                     cwd='tmp').pid

        # Init DB for agents and for nmap
        self.init_nmap_db()
        res = RUN(["ivre", "runscansagentdb", "--init"],
                  stdin=open(os.devnull))[0]
        self.assertEqual(res, 0)
        res = RUN(["ivre", "runscansagentdb", "--add-local-master"])[0]
        self.assertEqual(res, 0)

        # Add local agent
        res = RUN(["ivre", "runscansagentdb", "--source", "TEST-AGENT-SOURCE",
                   "--add-agent", os.path.join(os.getcwd(), "tmp")])[0]
        self.assertEqual(res, 0)

        # Create test scans
        res = RUN(["ivre", "runscansagentdb", "--test", "2",
                   "--assign-free-agents"])[0]
        self.assertEqual(res, 0)
        fdesc = tempfile.NamedTemporaryFile(delete=False)
        fdesc.writelines(("127.0.0.%d\n" % i).encode() for i in range(3, 5))
        fdesc.close()
        res = RUN(["ivre", "runscansagentdb", "--file", fdesc.name,
                   "--assign-free-agents"])[0]
        self.assertEqual(res, 0)

        # Test the lock mechanism
        ## Check no scan is locked
        res, out, _ = RUN(["ivre", "runscansagentdb", "--list-scans"])
        self.assertEqual(res, 0)
        self.assertTrue(b'  - locked' not in out)
        ## Get a scan id
        scanid = next(iter(ivre.db.db.agent.get_scans()))
        ## Lock it
        locked_scan = ivre.db.db.agent.lock_scan(scanid)
        self.assertIsInstance(locked_scan, dict)
        self.assertEqual(locked_scan['pid'], os.getpid())
        self.assertIsNotNone(locked_scan.get('lock'))
        ## Check one scan is locked with our PID
        res, out, _ = RUN(["ivre", "runscansagentdb", "--list-scans"])
        self.assertEqual(res, 0)
        self.assertTrue(('  - locked (by %d)\n' % os.getpid()).encode() in out)
        ## Attempt to lock it again
        with(self.assertRaises(ivre.db.LockError)):
            ivre.db.db.agent.lock_scan(scanid)
        ## Unlock it
        self.assertEqual(ivre.db.db.agent.unlock_scan(locked_scan), True)
        ## Attempt to unlock it again
        with(self.assertRaises(ivre.db.LockError)):
            ivre.db.db.agent.unlock_scan(locked_scan)
        with(self.assertRaises(ivre.db.LockError)):
            ivre.db.db.agent.unlock_scan(ivre.db.db.agent.get_scan(scanid))
        ## Check no scan is locked
        res, out, _ = RUN(["ivre", "runscansagentdb", "--list-scans"])
        self.assertEqual(res, 0)
        self.assertTrue(b'  - locked' not in out)
        ## Lock the scan again
        locked_scan = ivre.db.db.agent.lock_scan(scanid)
        self.assertIsInstance(locked_scan, dict)
        self.assertEqual(locked_scan['pid'], os.getpid())
        self.assertIsNotNone(locked_scan.get('lock'))
        ## Check one scan is locked with our PID
        res, out, _ = RUN(["ivre", "runscansagentdb", "--list-scans"])
        self.assertEqual(res, 0)
        self.assertTrue(('  - locked (by %d)\n' % os.getpid()).encode() in out)
        ## Unlock all the scans from the CLI
        res = RUN(["ivre", "runscansagentdb", "--force-unlock"],
                  stdin=open(os.devnull))[0]
        self.assertEqual(res, 0)
        ## Check no scan is locked
        res, out, _ = RUN(["ivre", "runscansagentdb", "--list-scans"])
        self.assertEqual(res, 0)
        self.assertTrue(b'  - locked' not in out)

        # Fork a daemon
        daemon_cmd = ["runscansagentdb", "--daemon"]
        if USE_COVERAGE:
            daemon_cmd = COVERAGE + ["run", "--parallel-mode",
                                     which("ivre")] + daemon_cmd
        else:
            daemon_cmd = ["ivre"] + daemon_cmd
        pid_daemon = subprocess.Popen(daemon_cmd).pid
        # Make sure the daemon is running
        time.sleep(4)

        # We should have two scans, wait until one is over
        scanmatch = re.compile(b'scan:\n  - id: (?P<id>[0-9a-f]+)\n.*\n.*\n  '
                               b'- targets added: (?P<nbadded>\\d+)\n  '
                               b'- results fetched: (?P<nbfetched>\\d+)\n  '
                               b'- total targets to add: (?P<nbtargets>\\d+)\n')
        is_scan_over = lambda scan: int(scan['nbtargets']) == int(scan['nbfetched'])
        while True:
            res, out, _ = RUN(["ivre", "runscansagentdb", "--list-scans"])
            self.assertEqual(res, 0)
            scans = [scan.groupdict() for scan in scanmatch.finditer(out)]
            self.assertEqual(len(scans), 2)
            if any(is_scan_over(scan) for scan in scans):
                break
            time.sleep(2)
        scan = next(scan for scan in scans if not is_scan_over(scan))

        # We should have one agent
        agentmatch = re.compile(b'agent:\n  - id: (?P<id>[0-9a-f]+)\n')
        res, out, _ = RUN(["ivre", "runscansagentdb", "--list-agents"])
        self.assertEqual(res, 0)
        agents = [agent.groupdict() for agent in agentmatch.finditer(out)]
        self.assertEqual(len(agents), 1)
        agent = agents[0]

        # Assign the remaining scan to the agent
        res = RUN(["ivre", "runscansagentdb", "--assign",
                   "%s:%s" % (agent['id'].decode(), scan['id'].decode())])[0]
        self.assertEqual(res, 0)
        # Make sure the daemon handles the new scan
        time.sleep(4)

        # Wait until we have two scans, both of them over
        while True:
            res, out, _ = RUN(["ivre", "runscansagentdb", "--list-scans"])
            self.assertEqual(res, 0)
            scans = [scan.groupdict() for scan in scanmatch.finditer(out)]
            self.assertEqual(len(scans), 2)
            if all(is_scan_over(scan) for scan in scans):
                break
            time.sleep(2)

        # Wait for child processes to handle all the scans
        while any(walk[2] for dirname in ['tmp/input', 'tmp/cur', 'tmp/output',
                                          ivre.config.AGENT_MASTER_PATH]
                  for walk in os.walk(dirname)
                  if not (walk[0].startswith(os.path.join(
                          ivre.config.AGENT_MASTER_PATH, 'output', ''
                  )) or (walk[0] == ivre.config.AGENT_MASTER_PATH
                         and walk[2] == ['whoami']))):
            print(u"Waiting for runscans daemon & agent")
            time.sleep(2)

        # Kill the agent and the dameon
        os.kill(pid_agent, signal.SIGTERM)
        os.kill(pid_daemon, signal.SIGTERM)
        os.waitpid(pid_agent, 0)
        os.waitpid(pid_daemon, 0)

        # Check we have 4 scan results
        res, out, _ = RUN(["ivre", "scancli", "--count"])
        self.assertEqual(res, 0)
        self.assertEqual(int(out), 4)

        # Clean
        self.assertEqual(RUN(["ivre", "scancli", "--init"],
                             stdin=open(os.devnull))[0], 0)
        self.assertEqual(RUN(["ivre", "runscansagentdb", "--init"],
                             stdin=open(os.devnull))[0], 0)
        for dirname in ['scans', 'tmp']:
            shutil.rmtree(dirname)

    def test_conf(self):
        # Ensure env var IVRE_CONF is taken into account
        has_env_conf = "IVRE_CONF" in os.environ
        if has_env_conf:
            env_conf = os.environ["IVRE_CONF"]
        else:
            env_conf = __file__
            os.environ["IVRE_CONF"] = env_conf
        all_confs = list(ivre.config.get_config_file())
        self.assertTrue(env_conf in all_confs,
                        "Env conf %s should be in %s" % (env_conf, all_confs))
        if not has_env_conf:
            del os.environ["IVRE_CONF"]


TESTS = set(["nmap", "passive", "data", "utils", "scans", "conf"])


DATABASES = {
    # **excluded** tests
    #"mongo": ["flow"],
    "postgres": ["scans"],
}


def parse_args():
    global SAMPLES, USE_COVERAGE
    try:
        import argparse
        parser = argparse.ArgumentParser(
            description='Run IVRE tests',
        )
        use_argparse = True
    except ImportError:
        import optparse
        parser = optparse.OptionParser(
            description='Run IVRE tests',
        )
        parser.parse_args_orig = parser.parse_args
        def my_parse_args():
            res = parser.parse_args_orig()
            try:
                test = next(test for test in res[1] if test not in TESTS)
            except StopIteration:
                pass
            else:
                raise optparse.OptionError(
                    "invalid choice: %r (choose from %s)" % (
                        test,
                        ", ".join(repr(val) for val in sorted(TESTS)),
                    ),
                    "tests",
                )
            res[0].ensure_value('tests', res[1])
            return res[0]
        parser.parse_args = my_parse_args
        parser.add_argument = parser.add_option
        use_argparse = False
    parser.add_argument('--samples', metavar='DIR',
                        default="./samples/")
    parser.add_argument('--coverage', action="store_true")
    if use_argparse:
        parser.add_argument('tests', nargs='*', choices=list(TESTS) + [[]])
    args = parser.parse_args()
    SAMPLES = args.samples
    USE_COVERAGE = args.coverage
    if args.tests:
        for test in TESTS.difference(args.tests):
            test = "test_%s" % test
            setattr(IvreTests, test,
                    unittest.skip("User request")(getattr(IvreTests, test)))
    sys.argv = [sys.argv[0]]


def parse_env():
    global DATABASE
    DATABASE = os.getenv("DB")
    for test in DATABASES.get(DATABASE, []):
        test = "test_%s" % test
        setattr(
            IvreTests,
            test,
            unittest.skip("Desactivated for database %r" % DATABASE)(
                getattr(IvreTests, test),
            ),
        )


if __name__ == '__main__':
    SAMPLES = None
    parse_args()
    parse_env()
    if not ivre.config.DEBUG:
        sys.stderr.write("You *must* have the DEBUG config value set to "
                         "True to run the tests.\n")
        sys.exit(-1)
    if USE_COVERAGE:
        COVERAGE = [sys.executable,
                    os.path.dirname(__import__("coverage").__file__)]
        RUN = coverage_run
        RUN_ITER = coverage_run_iter
    else:
        RUN = python_run
        RUN_ITER = python_run_iter
    try:
        # Python 2 & 3 compatibility
        IvreTests.assertItemsEqual = IvreTests.assertCountEqual
    except AttributeError:
        pass
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.TestLoader().loadTestsFromTestCase(IvreTests),
    )
    print("run=%d fail=%d errors=%d skipped=%d" % (result.testsRun,
                                                   len(result.failures),
                                                   len(result.errors),
                                                   len(result.skipped)))
    sys.exit(len(result.failures) + len(result.errors))
