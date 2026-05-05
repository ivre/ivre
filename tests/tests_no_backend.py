#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2026 Pierre LALET <pierre@droids-corp.org>
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


"""Backend-free tests for IVRE.

This module collects regression tests that do not require a configured
database backend. It is safe to run with::

    python -m unittest tests.tests_no_backend

or::

    pytest tests/tests_no_backend.py

It also accepts the following optional command-line arguments when
invoked as a script (``python tests/tests_no_backend.py``):

- ``--samples DIR``  Path to the IVRE samples directory (default:
  ``./samples`` relative to ``tests/``).
- ``--coverage``     Run helper subprocess invocations under
  ``coverage run`` (mirrors ``tests/tests.py``).

The module currently contains:

- :class:`XMLParserHardeningTests` -- regression tests for
  defusedxml-based SAX parser.
- :class:`ScreenshotContainmentTests` -- regression tests for
  screenshot path containment.
- :class:`UtilsTests` -- the formerly-monolithic ``test_utils``
  routine moved out of ``tests/tests.py`` (it exercises a wide range
  of ``ivre`` utility functions, parsers, and CLI tools that do not
  touch a database).
"""

from __future__ import annotations

import errno
import inspect
import io
import json
import os
import random
import re
import shutil
import subprocess  # nosec B404  # required to drive the `ivre` CLI in UtilsTests
import sys
import tempfile
import unittest
from ast import literal_eval
from datetime import datetime
from functools import reduce
from unittest import mock
from xml.sax.handler import (  # nosec B406  # used only as a no-op SAX event sink against the defusedxml-hardened parser
    ContentHandler,
)

import defusedxml.expatreader  # type: ignore[import-untyped]
from defusedxml.common import (  # type: ignore[import-untyped]
    DTDForbidden,
    EntitiesForbidden,
    ExternalReferenceForbidden,
)

import ivre.analyzer.ntlm
import ivre.config
import ivre.mathutils
import ivre.parser.iptables
import ivre.parser.zeek
import ivre.passive
import ivre.utils
import ivre.web.utils
from ivre import xmlnmap
from ivre.db import DBNmap

# ---------------------------------------------------------------------
# Module-level helpers (RUN, SAMPLES, etc.)
#
# These mirror the ones defined in `tests/tests.py` so that tests can
# be moved between the two files without rewriting their bodies. They
# are configured at import time with sensible defaults so the tests
# also run under `pytest` discovery without any special setup.
# ---------------------------------------------------------------------


SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")
USE_COVERAGE = False
COVERAGE: list[str] = []


def run_iter(
    cmd,
    interp=None,
    stdin=None,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    env=None,
):
    if interp is not None:
        cmd = interp + [shutil.which(cmd[0])] + cmd[1:]
    return subprocess.Popen(  # nosec B603  # argv list, no shell=True
        cmd, stdin=stdin, stdout=stdout, stderr=stderr, env=env
    )


def run_cmd(cmd, interp=None, stdin=None, stdout=subprocess.PIPE, env=None):
    proc = run_iter(cmd, interp=interp, stdin=stdin, stdout=stdout, env=env)
    out, err = proc.communicate()
    return proc.returncode, out, err


def python_run(cmd, stdin=None, stdout=subprocess.PIPE, env=None):
    return run_cmd(cmd, interp=[sys.executable], stdin=stdin, stdout=stdout, env=env)


def python_run_iter(cmd, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
    return run_iter(
        cmd, interp=[sys.executable], stdin=stdin, stdout=stdout, stderr=stderr
    )


def coverage_run(cmd, stdin=None, stdout=subprocess.PIPE, env=None):
    return run_cmd(
        cmd,
        interp=COVERAGE + ["run", "--parallel-mode"],
        stdin=stdin,
        stdout=stdout,
        env=env,
    )


def coverage_run_iter(cmd, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
    return run_iter(
        cmd,
        interp=COVERAGE + ["run", "--parallel-mode"],
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
    )


# Default RUN: run subprocesses through the current Python interpreter.
# Switched to `coverage_run` if the script is invoked with --coverage.
RUN = python_run
RUN_ITER = python_run_iter


# A minimal but valid 1x1 transparent PNG, used to exercise the
# legitimate (non-adversarial) screenshot path.
_PNG_1X1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "000000017352474200aece1ce90000000d49444154789c6300010000000500010d"
    "0a2db40000000049454e44ae426082"
)


# ---------------------------------------------------------------------
# XMLParserHardeningTests
# ---------------------------------------------------------------------


_NMAP_DOCTYPE_FIXTURE = (
    b'<?xml version="1.0"?>\n'
    b'<?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?>\n'
    b'<!DOCTYPE nmaprun PUBLIC "-//IDN nmap.org//DTD Nmap XML 1.04//EN"'
    b' "https://svn.nmap.org/nmap/docs/nmap.dtd">\n'
    b'<nmaprun scanner="nmap" args="nmap -p 1 127.0.0.1" start="1" '
    b'startstr="" version="7.95" xmloutputversion="1.05">\n'
    b"  <host>\n"
    b'    <status state="up" reason="conn-refused" reason_ttl="0"/>\n'
    b'    <address addr="127.0.0.1" addrtype="ipv4"/>\n'
    b"    <ports>\n"
    b'      <port protocol="tcp" portid="1">\n'
    b'        <state state="closed" reason="conn-refused" reason_ttl="0"/>\n'
    b'        <service name="tcpmux" method="table" conf="3"/>\n'
    b"      </port>\n"
    b"    </ports>\n"
    b"  </host>\n"
    b'  <runstats><finished time="2"/>'
    b'<hosts up="1" down="0" total="1"/></runstats>\n'
    b"</nmaprun>\n"
)


class XMLParserHardeningTests(unittest.TestCase):
    """Regression tests for XML parser hardening.

    Asserts that the parser used by `DBNmap.store_scan_xml`:

    1. is a `defusedxml.expatreader.DefusedExpatParser` (not the stdlib
       `xml.sax` parser);
    2. raises on every adversarial XML pattern we care about
       (billion-laughs, external general entity, external parameter
       entity);
    3. does NOT raise on legitimate Nmap-style XML carrying a DOCTYPE
       SYSTEM URI (e.g. `https://svn.nmap.org/nmap/docs/nmap.dtd`),
       which is the standard output of `nmap -oX` and `ivre auditdom`;
    4. does NOT actually fetch that DOCTYPE URI over the network.

    The combination is achieved by passing
    ``forbid_external=False`` to ``defusedxml.expatreader.create_parser``
    while keeping the default ``forbid_entities=True``: the security
    work is done by ``forbid_entities`` (which raises on every
    `<!ENTITY ...>` declaration, internal or external), and
    ``forbid_external`` would only have added a *redundant* raise on
    DOCTYPE SYSTEM URIs that expat does not dereference anyway
    (`feature_external_pes` defaults to False).
    """

    def setUp(self) -> None:
        # Adversary-controlled secret file XXE payloads attempt to read.
        fd, self._secret_path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "wb") as fdesc:
            fdesc.write(b"PWNED-SECRET-CONTENT")

    def tearDown(self) -> None:
        os.unlink(self._secret_path)

    def _make_parser(self):
        """Build the SAX parser exactly like `DBNmap.store_scan_xml`."""
        return defusedxml.expatreader.create_parser(forbid_external=False)

    def _parse(self, payload: bytes) -> None:
        """Drive the defused SAX parser exactly like `store_scan_xml`."""
        parser = self._make_parser()
        parser.setContentHandler(ContentHandler())
        parser.parse(io.BytesIO(payload))

    def _ingest_via_store_scan_xml(self, payload: bytes) -> None:
        """Run `payload` through the same `store_scan_xml` code path
        used by `ivre scan2db`. Bypasses the database backend by
        skipping the actual store_host/store_or_merge_host calls.
        """
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as fdesc:
            fdesc.write(payload)
            xml_path = fdesc.name
        try:
            res, out, err = RUN(["ivre", "scan2db", "--test", xml_path])
        finally:
            os.unlink(xml_path)
        self.assertEqual(
            res,
            0,
            "ivre scan2db --test exit=%d, stderr=%r" % (res, err.decode()[-1000:]),
        )

    # --- parser configuration ---

    def test_make_parser_returns_defused_expat_parser(self) -> None:
        """The parser used by `store_scan_xml` must be a
        `DefusedExpatParser`. Guards against an ImportError regression
        that would silently fall back to the stdlib parser."""
        from defusedxml.expatreader import (  # type: ignore[import-untyped]
            DefusedExpatParser,
        )

        self.assertIsInstance(self._make_parser(), DefusedExpatParser)

    def test_store_scan_xml_uses_defusedxml(self) -> None:
        """`DBNmap.store_scan_xml` must call
        `defusedxml.expatreader.create_parser(forbid_external=False)`
        and must not fall back to `xml.sax.make_parser()` or rely on
        the legacy `feature_external_*es = 0` / `NoExtResolver`
        pattern."""
        src = inspect.getsource(DBNmap.store_scan_xml)
        self.assertIn("defusedxml.expatreader.create_parser", src)
        self.assertIn("forbid_external=False", src)
        # Look for `xml.sax.make_parser` not preceded by `defused`.
        self.assertIsNone(
            re.search(r"(?<!defused)xml\.sax\.make_parser", src),
            "store_scan_xml must not call the stdlib xml.sax.make_parser",
        )
        self.assertNotIn("feature_external_ges", src)
        self.assertNotIn("feature_external_pes", src)
        self.assertNotIn("NoExtResolver", src)

    def test_no_ext_resolver_class_removed(self) -> None:
        """`xmlnmap.NoExtResolver` was removed alongside the
        `feature_external_*es = 0` flags as redundant in the presence
        of `DefusedExpatParser`."""
        self.assertFalse(
            hasattr(xmlnmap, "NoExtResolver"),
            "xmlnmap.NoExtResolver should not exist anymore",
        )

    # --- attack-class regressions ---

    def test_billion_laughs_raises_entities_forbidden(self) -> None:
        """Pure-internal entity expansion (billion-laughs) must raise
        before any expansion happens. This is the attack class the
        legacy `feature_external_*es = 0` flags did NOT cover."""
        payload = (
            b'<?xml version="1.0"?>\n'
            b"<!DOCTYPE l ["
            b'<!ENTITY a "a">'
            b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
            b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">'
            b"]>"
            b"<r>&c;</r>"
        )
        with self.assertRaises(EntitiesForbidden):
            self._parse(payload)

    def test_external_general_entity_raises(self) -> None:
        """An external general entity (the canonical XXE pattern) must
        raise instead of resolving the URI."""
        payload = (
            b'<?xml version="1.0"?>\n'
            b"<!DOCTYPE r ["
            b'<!ENTITY xxe SYSTEM "file://' + self._secret_path.encode() + b'">'
            b"]>"
            b"<r>&xxe;</r>"
        )
        with self.assertRaises(EntitiesForbidden):
            self._parse(payload)

    def test_external_parameter_entity_raises(self) -> None:
        """External parameter entities -- used to smuggle
        attacker-supplied DTD fragments -- must raise."""
        payload = (
            b'<?xml version="1.0"?>\n'
            b"<!DOCTYPE r ["
            b'<!ENTITY % pe SYSTEM "file://' + self._secret_path.encode() + b'">'
            b"%pe;"
            b"]>"
            b"<r/>"
        )
        # External parameter entities can be reported either as a
        # forbidden entity declaration or as a forbidden external
        # reference, depending on the order in which the underlying
        # expat handlers fire. Either is acceptable; both prove the
        # parser refused to load the URI.
        with self.assertRaises(
            (EntitiesForbidden, ExternalReferenceForbidden, DTDForbidden)
        ):
            self._parse(payload)

    # --- legitimate-input regressions (DOCTYPE SYSTEM tolerance) ---

    def test_nmap_doctype_fixture_parses_cleanly(self) -> None:
        """A minimal hand-crafted Nmap-style XML, including the
        `<!DOCTYPE nmaprun PUBLIC "..." SYSTEM "https://...">` line
        emitted by every `nmap -oX` and `ivre auditdom` invocation,
        must parse without raising."""
        parser = self._make_parser()
        parser.setContentHandler(ContentHandler())
        parser.parse(io.BytesIO(_NMAP_DOCTYPE_FIXTURE))

    def test_nmap_doctype_fixture_ingestible_by_scan2db(self) -> None:
        """End-to-end: the same fixture is accepted by
        `ivre scan2db --test`, the entry point that broke when
        `forbid_external=True` was the default."""
        self._ingest_via_store_scan_xml(_NMAP_DOCTYPE_FIXTURE)

    def test_doctype_url_is_not_fetched(self) -> None:
        """Defence-in-depth pin: with ``forbid_external=False`` we are
        relying on expat's ``feature_external_pes=False`` default to
        ensure the DOCTYPE SYSTEM URI is never dereferenced. Stand up a
        local HTTP server, point a fixture's DOCTYPE at it, parse, and
        assert zero hits."""
        import http.server
        import socket
        import socketserver
        import threading

        hits: list[str] = []

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - stdlib handler signature
                hits.append(self.path)
                self.send_response(404)
                self.end_headers()

            def log_message(self, *args, **kwargs):
                # Silence the default per-request stderr noise.
                pass

        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        srv = socketserver.TCPServer(("127.0.0.1", port), _Handler)
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        try:
            url = ("http://127.0.0.1:%d/nmap.dtd" % port).encode()
            payload = (
                b'<?xml version="1.0"?>\n'
                b"<!DOCTYPE nmaprun PUBLIC "
                b'"-//IDN nmap.org//DTD Nmap XML 1.04//EN" "' + url + b'">\n'
                b'<nmaprun><host><address addr="1.2.3.4" addrtype="ipv4"/>'
                b"</host></nmaprun>\n"
            )
            parser = self._make_parser()
            parser.setContentHandler(ContentHandler())
            parser.parse(io.BytesIO(payload))
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertEqual(
            hits,
            [],
            "DOCTYPE SYSTEM URI was fetched -- expat default "
            "feature_external_pes=False is no longer holding "
            "(got hits: %r)" % (hits,),
        )

    def test_real_ivre_auditdom_output_ingestible(self) -> None:
        """Real-world regression: `ivre auditdom ivre.rocks` must
        produce XML that `ivre scan2db --test` can ingest. This is the
        precise failure mode that surfaced in CI."""
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as fdesc:
            xml_path = fdesc.name
        try:
            with open(xml_path, "wb") as out_fdesc:
                res, _, err = RUN(
                    ["ivre", "auditdom", "--ipv4", "ivre.rocks"],
                    stdout=out_fdesc,
                )
            if res != 0:
                self.skipTest(
                    "ivre auditdom failed (likely no DNS/network in this "
                    "environment): exit=%d, stderr=%r" % (res, err.decode()[-500:])
                )
            # Sanity: the XML really does carry a DOCTYPE referring to
            # an external DTD (otherwise the test is no longer
            # exercising the forbid_external=False path).
            with open(xml_path, "rb") as in_fdesc:
                head = in_fdesc.read(4096)
            self.assertIn(b"<!DOCTYPE nmaprun", head)
            self.assertIn(b"nmap.dtd", head)
            res, out, err = RUN(["ivre", "scan2db", "--test", xml_path])
            self.assertEqual(
                res,
                0,
                "ivre scan2db --test failed on real auditdom XML: "
                "exit=%d, stderr=%r" % (res, err.decode()[-1000:]),
            )
        finally:
            os.unlink(xml_path)

    def test_real_nmap_output_ingestible(self) -> None:
        """Real-world regression: `nmap -vv -p 1 127.0.0.1 -oX <file>`
        must produce XML that `ivre scan2db --test` can ingest. Also
        guards against any future change to Nmap's XML preamble that
        IVRE would need to follow."""
        # `RUN` injects the current Python interpreter as a wrapper
        # (mirroring `tests/tests.py`), which is fine for `ivre <cmd>`
        # entrypoints but cannot run a native binary like `nmap`. Drive
        # nmap through a plain subprocess.run() instead.
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as fdesc:
            xml_path = fdesc.name
        try:
            subprocess.check_call(
                ["nmap", "-vv", "-p", "1", "127.0.0.1", "-oX", xml_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            with open(xml_path, "rb") as in_fdesc:
                head = in_fdesc.read(4096)
            # Both old (DOCTYPE PUBLIC ".dtd") and new (bare DOCTYPE
            # nmaprun) forms are accepted by `ivre scan2db --test`. We
            # only assert there is an `nmaprun` root and a DOCTYPE
            # decl; the ingestion check below is what we actually
            # care about.
            self.assertIn(b"<!DOCTYPE nmaprun", head)
            self.assertIn(b"<nmaprun", head)
            res, out, err = RUN(["ivre", "scan2db", "--test", xml_path])
            self.assertEqual(
                res,
                0,
                "ivre scan2db --test failed on real nmap XML: "
                "exit=%d, stderr=%r" % (res, err.decode()[-1000:]),
            )
        finally:
            os.unlink(xml_path)


# ---------------------------------------------------------------------
# ScreenshotContainmentTests
# ---------------------------------------------------------------------


class _StubNmapHandler(xmlnmap.NmapHandler):
    """Lightweight `NmapHandler` subclass used to drive the screenshot
    code path without instantiating a real database backend.

    It bypasses the parent ``__init__`` and pre-populates only the
    attributes that ``endElement('script')`` accesses inside the
    screenshot block.
    """

    def __init__(self, fname: str) -> None:  # type: ignore[no-untyped-def]
        # Deliberately do not call super().__init__: the real one wires
        # up the database backend, which we explicitly avoid here.
        # pylint: disable=super-init-not-called
        self._fname = fname
        self._curport = {
            "port": 80,
            "protocol": "tcp",
            "state_state": "open",
        }
        self._curhost = {"addr": "127.0.0.1", "ports": [self._curport]}
        self._curtable: dict = {}
        self._curtablepath: list = []
        self._curscript: dict | None = None
        self.callback = None

    def _to_binary(self, data: bytes) -> bytes:
        return data


class ScreenshotContainmentTests(unittest.TestCase):
    """Regression tests for screenshots filename validation

    Drive ``NmapHandler.endElement('script')`` with adversarial NSE
    ``*-screenshot`` ``output`` values and assert that no file outside
    the two trusted resolution roots (``dirname(scan_xml)`` and
    ``os.getcwd()``) is opened. The mitigation has two layers
    (basename validation in `screenshot_extract` and `realpath`
    containment in the `endElement` block); the tests cover both.
    """

    def setUp(self) -> None:
        self._scan_dir = tempfile.mkdtemp()
        self._scan_path = os.path.join(self._scan_dir, "scan.xml")
        with open(self._scan_path, "wb"):
            pass
        self._attacker_dir = tempfile.mkdtemp()
        # Use a dedicated cwd so the tests do not pick up files from
        # the developer's working directory.
        self._cwd_dir = tempfile.mkdtemp()
        self._old_cwd = os.getcwd()
        os.chdir(self._cwd_dir)

    def tearDown(self) -> None:
        # Restore cwd before deleting the temp dir, otherwise the
        # rmtree below races with our own working directory.
        try:
            os.chdir(self._old_cwd)
        except OSError:
            pass
        shutil.rmtree(self._scan_dir, ignore_errors=True)
        shutil.rmtree(self._attacker_dir, ignore_errors=True)
        shutil.rmtree(self._cwd_dir, ignore_errors=True)

    def _drive(
        self, output: str, intercept_open: bool = True
    ) -> tuple[_StubNmapHandler, list[str]]:
        """Run ``endElement('script')`` for a given screenshot
        ``output`` value. When ``intercept_open`` is True, every
        ``open()`` call inside the handler is recorded and made to
        raise ``FileNotFoundError`` so we can prove containment kicks
        in *before* any read happens."""
        handler = _StubNmapHandler(self._scan_path)
        handler._curscript = {"id": "http-screenshot", "output": output}
        opened: list[str] = []

        if not intercept_open:
            handler.endElement("script")
            return handler, opened

        def spy(path, *args, **kwargs):  # type: ignore[no-untyped-def]
            opened.append(os.fspath(path))
            raise FileNotFoundError(path)

        with mock.patch("builtins.open", side_effect=spy):
            handler.endElement("script")
        return handler, opened

    def test_absolute_path_rejected_at_extract(self) -> None:
        """An absolute path in the script ``output`` must be rejected
        by ``screenshot_extract`` before any ``open()`` is attempted."""
        handler, opened = self._drive("Saved to /etc/passwd")
        self.assertNotIn("screendata", handler._curport)
        self.assertEqual(opened, [])

    def test_traversal_path_rejected_at_extract(self) -> None:
        handler, opened = self._drive("Saved to ../../../../etc/shadow")
        self.assertNotIn("screendata", handler._curport)
        self.assertEqual(opened, [])

    def test_subdirectory_path_rejected_at_extract(self) -> None:
        """A relative path with a ``/`` separator must be rejected by
        the ``basename(fname) == fname`` check, even if the basename
        component would have been benign."""
        handler, opened = self._drive("Saved to subdir/foo.png")
        self.assertNotIn("screendata", handler._curport)
        self.assertEqual(opened, [])

    def test_disallowed_extension_rejected(self) -> None:
        """Anything outside ``SCREENSHOT_ALLOWED_EXT`` must be
        rejected, even with a valid basename."""
        handler, opened = self._drive("Saved to evil.exe")
        self.assertNotIn("screendata", handler._curport)
        self.assertEqual(opened, [])

    def test_no_match_returns_none(self) -> None:
        """Output that does not match the ``Saved to`` pattern must be
        a no-op."""
        handler, opened = self._drive("nothing was saved")
        self.assertNotIn("screendata", handler._curport)
        self.assertEqual(opened, [])

    def test_symlink_escape_in_scan_dir_rejected_by_realpath(self) -> None:
        """A symlink with a basename-valid name placed in the
        scan-file directory and pointing outside it must be caught by
        the ``realpath`` containment check before any read.

        The cwd fallback is also exercised here: the resolved cwd
        candidate either does not exist (skipped) or also lives
        outside both trusted roots; in either case ``open()`` must
        never be called.
        """
        target = os.path.join(self._attacker_dir, "secret.png")
        with open(target, "wb") as fdesc:
            fdesc.write(b"SECRET")
        link = os.path.join(self._scan_dir, "trap.png")
        os.symlink(target, link)

        handler, opened = self._drive("Saved to trap.png")

        self.assertNotIn("screendata", handler._curport)
        self.assertEqual(
            opened,
            [],
            "open() must NOT be called when the resolved path is "
            "outside both trusted directories; got: %r" % (opened,),
        )

    def test_symlink_escape_in_cwd_rejected_by_realpath(self) -> None:
        """Same pattern as above, but the symlink is planted in the
        cwd resolution root (the historical fallback). Containment
        must still reject it."""
        target = os.path.join(self._attacker_dir, "secret.png")
        with open(target, "wb") as fdesc:
            fdesc.write(b"SECRET")
        link = os.path.join(self._cwd_dir, "trap.png")
        os.symlink(target, link)

        handler, opened = self._drive("Saved to trap.png")

        self.assertNotIn("screendata", handler._curport)
        self.assertEqual(
            opened,
            [],
            "open() must NOT be called for a cwd-rooted symlink that "
            "escapes the cwd; got: %r" % (opened,),
        )

    def test_legitimate_image_in_scan_dir_is_read(self) -> None:
        """A valid image with a benign basename, sitting next to the
        scan file, is read and stored (no cwd fallback needed)."""
        legit = os.path.join(self._scan_dir, "shot.png")
        with open(legit, "wb") as fdesc:
            fdesc.write(_PNG_1X1)

        handler, _ = self._drive("Saved to shot.png", intercept_open=False)

        self.assertIn("screendata", handler._curport)
        self.assertEqual(handler._curport["screendata"], _PNG_1X1)

    def test_legitimate_image_in_cwd_is_read(self) -> None:
        """Regression test for the workflow used by
        ``tests/tests.py::test_scans``: the screenshots are extracted
        from a tarball into ``cwd``, while the XML lives elsewhere.
        The cwd fallback must locate the screenshot and store it.
        """
        legit = os.path.join(self._cwd_dir, "shot.png")
        with open(legit, "wb") as fdesc:
            fdesc.write(_PNG_1X1)
        # Sanity: the scan-file directory must NOT contain the file,
        # so success can only come from the cwd fallback.
        self.assertFalse(os.path.exists(os.path.join(self._scan_dir, "shot.png")))

        handler, _ = self._drive("Saved to shot.png", intercept_open=False)

        self.assertIn("screendata", handler._curport)
        self.assertEqual(handler._curport["screendata"], _PNG_1X1)

    def test_scan_dir_is_preferred_over_cwd(self) -> None:
        """If the screenshot exists in both trusted roots, the
        scan-file directory wins (more specific source)."""
        scan_payload = b"SCAN-DIR-WINS"
        cwd_payload = b"CWD-LOSES"
        with open(os.path.join(self._scan_dir, "shot.png"), "wb") as fdesc:
            fdesc.write(_PNG_1X1)
            scan_path = fdesc.name
        with open(os.path.join(self._cwd_dir, "shot.png"), "wb") as fdesc:
            fdesc.write(_PNG_1X1)
        # Differentiate the two by overwriting after the fact: we want
        # the bytes to differ but both files to remain valid PNG-ish.
        with open(scan_path, "wb") as fdesc:
            fdesc.write(scan_payload)
        with open(os.path.join(self._cwd_dir, "shot.png"), "wb") as fdesc:
            fdesc.write(cwd_payload)

        handler, _ = self._drive("Saved to shot.png", intercept_open=False)

        self.assertIn("screendata", handler._curport)
        self.assertEqual(handler._curport["screendata"], scan_payload)


# ---------------------------------------------------------------------
# JSONP-removal regressions
# ---------------------------------------------------------------------


class JsonpDroppedTests(unittest.TestCase):
    """Regression tests asserting that JSONP support has been removed
    from the Web API.

    JSONP existed to allow cross-origin GETs by wrapping JSON
    responses as ``callback(...);`` JavaScript. Modern setups serve
    the IVRE Web UI from the same origin as the API, making JSONP
    unnecessary; the wrapping itself is a class of MIME-confusion
    risk (the response Content-Type was ``application/javascript``,
    so any reflected data could potentially be interpreted as
    script). Removing JSONP closes Finding 3 of the security review.
    """

    @staticmethod
    def _read_py(module) -> str:
        """Read a Python module's source via its imported file path.

        Reading from a hard-coded ``ivre/`` filesystem path would fail
        in CI where ``install.sh`` renames the in-tree ``ivre/``
        directory to ``ivre_bak/`` to force tests to use the installed
        package. Going through ``module.__file__`` finds the source
        regardless of layout.
        """
        path = inspect.getsourcefile(module)
        assert path is not None, f"no source file for {module!r}"
        with open(path, encoding="utf8") as fdesc:
            return fdesc.read()

    @staticmethod
    def _read_static(relpath: str) -> str:
        """Read a file under ``web/static/`` relative to the repo
        root. The ``web/`` tree is not renamed by ``install.sh``, so
        the ``__file__`` of this test module still gives a usable
        repo root."""
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(repo_root, relpath), encoding="utf8") as fdesc:
            return fdesc.read()

    def test_app_py_has_no_callback_query_param(self) -> None:
        """``ivre/web/app.py`` no longer reads ``request.params.get(
        "callback")``, no longer threads a ``callback`` field through
        ``FilterParams``, and no longer emits ``callback(...);``
        wrappers."""
        from ivre.web import app

        src = self._read_py(app)
        # The query parameter is gone:
        self.assertNotIn('request.params.get("callback")', src)
        self.assertNotIn("flt_params.callback", src)
        # No JSONP wrapper expressions like `f"{callback}(` remain:
        self.assertIsNone(
            re.search(r'f"\{[a-zA-Z_.]*callback[a-zA-Z_.]*\}\(', src),
            "JSONP wrapper expression must not remain in app.py",
        )
        # The Content-Type lie (application/javascript for JSON
        # responses) is gone too. The `/config` route legitimately
        # emits JS via <script src=...>, so we accept at most one
        # occurrence (the `/config` route).
        self.assertLessEqual(
            src.count('"application/javascript"'),
            1,
            "Only the /config route may set Content-Type: " "application/javascript",
        )

    def test_filter_params_has_no_callback_field(self) -> None:
        """The ``FilterParams`` namedtuple no longer carries a
        ``callback`` field."""
        from ivre.web.app import FilterParams

        self.assertNotIn("callback", FilterParams._fields)

    def test_js_alert_helpers_removed(self) -> None:
        """``js_alert`` and ``js_del_alert`` (which produced inline
        JS snippets to be embedded in JSONP responses) are gone."""
        from ivre.web import utils as webutils

        self.assertFalse(hasattr(webutils, "js_alert"))
        self.assertFalse(hasattr(webutils, "js_del_alert"))

    def test_angularjs_callers_use_plain_json(self) -> None:
        """The three AngularJS ``$.ajax`` JSONP callers (graph.js,
        filters.js x2) have been migrated to plain JSON. They are
        same-origin so JSONP is unnecessary."""
        for relpath in (
            "web/static/ivre/graph.js",
            "web/static/ivre/filters.js",
        ):
            src = self._read_static(relpath)
            self.assertNotIn('dataType: "jsonp"', src, msg=relpath)
            self.assertNotIn('jsonp: "callback"', src, msg=relpath)

    def test_security_headers_include_nosniff(self) -> None:
        """``X-Content-Type-Options: nosniff`` is set on every
        response by the Bottle ``after_request`` hook."""
        from ivre.web import base

        src = self._read_py(base)
        self.assertIn("X-Content-Type-Options", src)
        self.assertIn("nosniff", src)


# ---------------------------------------------------------------------
# RIR HTTP backend / MCP tool tests
# ---------------------------------------------------------------------


class RirBackendTests(unittest.TestCase):
    """Regression tests for the HTTP-backed `db.rir` purpose.

    These tests cover the surface of `HttpDBRir`: backend resolution,
    filter construction, the round-trip with `web.utils.parse_filter`,
    and inheritance of the base `DBRir.get_best` implementation. They
    do not connect to any upstream IVRE.
    """

    def test_from_url_resolves_to_http_backend(self):
        from ivre.db import DBRir
        from ivre.db.http import HttpDBRir

        inst = DBRir.from_url("http://example.com/cgi")
        self.assertIsInstance(inst, HttpDBRir)
        self.assertEqual(inst.route, "rir")

    def test_https_url_also_resolves(self):
        from ivre.db import DBRir
        from ivre.db.http import HttpDBRir

        inst = DBRir.from_url("https://example.com/cgi")
        self.assertIsInstance(inst, HttpDBRir)

    def test_search_filters_emit_sealed_dicts(self):
        """`HttpDBRir.search*` produce the sealed-dict shape consumed
        by the server-side `web.utils.parse_filter`."""
        from urllib.parse import urlparse

        from ivre.db.http import HttpDBRir

        hdb = HttpDBRir(urlparse("http://x"))
        self.assertEqual(hdb.searchhost("8.8.8.8"), {"f": "host", "a": ["8.8.8.8"]})
        self.assertEqual(hdb.searchcountry("FR"), {"f": "country", "a": ["FR"]})
        self.assertEqual(hdb.searchtext("orange"), {"f": "text", "a": ["orange"]})

    def test_flt_combinators_emit_sealed_dicts(self):
        from urllib.parse import urlparse

        from ivre.db.http import HttpDBRir

        hdb = HttpDBRir(urlparse("http://x"))
        flt_and = hdb.flt_and(hdb.searchcountry("FR"), hdb.searchtext("orange"))
        self.assertEqual(flt_and["f"], "and")
        self.assertEqual(len(flt_and["a"]), 2)
        flt_or = hdb.flt_or(hdb.searchhost("1.1.1.1"), hdb.searchhost("8.8.8.8"))
        self.assertEqual(flt_or["f"], "or")
        self.assertEqual(len(flt_or["a"]), 2)

    def test_filter_round_trips_through_parse_filter(self):
        """A filter built by `HttpDBRir` is JSON-serialised on the
        wire and re-resolved on the server side by `parse_filter`
        against the target backend's `searchXxx` methods."""
        from urllib.parse import urlparse

        from ivre.db.http import HttpDBRir
        from ivre.web.utils import parse_filter

        hdb = HttpDBRir(urlparse("http://x"))
        flt = hdb.flt_and(hdb.searchcountry("FR"), hdb.searchtext("orange"))
        # Mimic the JSON serialisation that goes over the wire.
        wire = json.loads(json.dumps(flt))

        calls = []

        class _StubDBRir:
            flt_empty = {}

            @staticmethod
            def flt_and(*args):
                calls.append(("flt_and", args))
                return ("AND", args)

            @staticmethod
            def flt_or(*args):
                calls.append(("flt_or", args))
                return ("OR", args)

            @staticmethod
            def searchcountry(*args, **kwargs):
                calls.append(("searchcountry", args, kwargs))
                return ("country", args)

            @staticmethod
            def searchtext(*args, **kwargs):
                calls.append(("searchtext", args, kwargs))
                return ("text", args)

        parse_filter(_StubDBRir(), wire)
        names = [c[0] for c in calls]
        self.assertIn("searchcountry", names)
        self.assertIn("searchtext", names)
        self.assertIn("flt_and", names)
        # Confirm the right arguments propagated.
        country_call = next(c for c in calls if c[0] == "searchcountry")
        self.assertEqual(country_call[1], ("FR",))
        text_call = next(c for c in calls if c[0] == "searchtext")
        self.assertEqual(text_call[1], ("orange",))

    def test_get_best_inherits_from_dbrir(self):
        """`HttpDBRir.get_best` must be inherited unchanged from
        `DBRir`. The base implementation builds `searchhost(addr)`
        and calls `self.get(...)`, both of which resolve to HTTP
        requests through the existing `HttpDB` machinery; an HTTP-
        specific override would be redundant."""
        from ivre.db import DBRir
        from ivre.db.http import HttpDBRir

        self.assertIs(HttpDBRir.get_best, DBRir.get_best)

    def test_count_url_shape(self):
        """`HttpDBRir.count(flt)` builds a URL of the form
        `<base>/rir/count?f=<sealed-filter>`. We don't make a network
        call; we just rebuild the URL the way the implementation
        would and assert it shape-matches what the server route
        accepts."""
        from urllib.parse import unquote, urlparse

        from ivre.db.http import HttpDBRir

        hdb = HttpDBRir(urlparse("http://upstream.example/cgi"))
        flt = hdb.flt_and(hdb.searchcountry("FR"))
        rendered = hdb._output_filter(flt)
        url = f"{hdb.db.baseurl}/{hdb.route}/count?f={rendered}"
        self.assertTrue(url.startswith("http://upstream.example/cgi/rir/count?f="))
        decoded = json.loads(unquote(rendered))
        self.assertEqual(decoded["f"], "and")


class RirWebRoutesTests(unittest.TestCase):
    """Regression tests for the `/rir` Bottle web routes."""

    @classmethod
    def setUpClass(cls):
        # Importing the app instantiates the route table once.
        from ivre.web.app import application

        cls.routes = [(r.method, r.rule) for r in application.routes]

    def _has_route(self, method, rule):
        return (method, rule) in self.routes

    def test_rir_records_route_registered(self):
        self.assertTrue(self._has_route("GET", "/rir"))

    def test_rir_count_route_registered(self):
        self.assertTrue(self._has_route("GET", "/rir/count"))

    def test_rir_in_distinct_route_pattern(self):
        """The shared `<subdb>/distinct/<field>` route must include
        `rir` in its allowed-purpose regex."""
        distinct_rules = [
            rule
            for method, rule in self.routes
            if method == "GET" and "/distinct/" in rule
        ]
        self.assertTrue(distinct_rules)
        self.assertTrue(
            any("rir" in r for r in distinct_rules),
            "no /distinct/ route includes 'rir' in its purpose regex; "
            "found: %r" % distinct_rules,
        )

    def test_rir_in_top_route_pattern(self):
        top_rules = [
            rule for method, rule in self.routes if method == "GET" and "/top/" in rule
        ]
        self.assertTrue(top_rules)
        self.assertTrue(
            any("rir" in r for r in top_rules),
            "no /top/ route includes 'rir' in its purpose regex; "
            "found: %r" % top_rules,
        )


class RirMcpToolsTests(unittest.TestCase):
    """Regression tests for the RIR MCP tools.

    Skipped when the optional ``mcp`` dependency is not installed.
    """

    @classmethod
    def setUpClass(cls):
        from ivre.tools import mcp_server

        if mcp_server.FastMCP is None:
            raise unittest.SkipTest("mcp dependency not installed")
        cls.mcp = mcp_server._build_server()

    def _tool_names(self):
        import asyncio

        tools = asyncio.run(self.mcp.list_tools())
        return {t.name for t in tools}

    def test_rir_tools_registered(self):
        names = self._tool_names()
        self.assertIn("rir_lookup", names)
        self.assertIn("rir_search", names)
        self.assertIn("rir_count", names)

    def test_rir_lookup_signature(self):
        """`rir_lookup` takes a single positional `addr` argument."""
        import asyncio

        tools = asyncio.run(self.mcp.list_tools())
        spec = next(t for t in tools if t.name == "rir_lookup")
        # FastMCP exposes JSON-Schema-shaped inputSchema.
        props = spec.inputSchema.get("properties", {})
        self.assertIn("addr", props)

    def test_rir_search_signature(self):
        """`rir_search` accepts optional `query`, `country`, `limit`."""
        import asyncio

        tools = asyncio.run(self.mcp.list_tools())
        spec = next(t for t in tools if t.name == "rir_search")
        props = spec.inputSchema.get("properties", {})
        for key in ("query", "country", "limit"):
            self.assertIn(key, props)


# ---------------------------------------------------------------------
# RegexComplexityTests -- defence-in-depth budget for user-supplied
# regex literals reaching MongoDB ``$regex``.
# ---------------------------------------------------------------------


class RegexComplexityTests(unittest.TestCase):
    """Tests for ``ivre.web.utils.validate_regex_complexity`` and
    the ``ivre.web.utils.str2regexp`` / ``str2regexpnone``
    wrappers.

    The validator is the regexploit-based ReDoS analyser sitting
    in front of ``re.compile()`` and MongoDB's ``$regex``. It
    complements the server-side ``MONGODB_QUERY_TIMEOUT_MS`` cap
    put in place earlier: where the timeout bounds the worst-case
    wall clock, this budget rejects patterns proven exploitable
    by static analysis before they get a chance to run.
    """

    @staticmethod
    def _validator():
        return ivre.web.utils.validate_regex_complexity

    def test_short_simple_regex_passes(self):
        # Realistic patterns operators submit through the Web API.
        validate = self._validator()
        for ok in [
            "^foo$",
            "cdn\\.cloudflare\\.com",
            "^192\\.168\\.",
            "(GET|POST) ",
            "[a-z]+",
            "abc{2,5}",
            "foo|bar|baz",
            "a*b*c*d*e*f*",
        ]:
            with self.subTest(pattern=ok):
                validate(ok)

    def test_non_string_input_is_a_no_op(self):
        # Defensive: callers may forward arbitrary JSON values.
        validate = self._validator()
        validate(None)  # type: ignore[arg-type]
        validate(42)  # type: ignore[arg-type]

    def test_length_cap(self):
        validate = self._validator()
        long_pattern = "a" * 200
        validate(long_pattern, max_length=200)
        with self.assertRaises(ValueError):
            validate(long_pattern, max_length=199)

    def test_length_cap_can_be_disabled(self):
        validate = self._validator()
        validate("x" * 100_000, max_length=None)

    def test_starriness_check_can_be_disabled(self):
        validate = self._validator()
        # An exploitable pattern: regexploit reports starriness 11.
        validate("(a+)+x", starriness_limit=None)

    def test_starriness_threshold_is_tunable(self):
        validate = self._validator()
        # ``a*b*`` is non-exploitable (no killer); regexploit
        # reports starriness 0 so even a strict limit accepts it.
        validate("a*b*", starriness_limit=0)
        # Adversarial example: ``(a+)+x`` is starriness 11.
        with self.assertRaises(ValueError):
            validate("(a+)+x", starriness_limit=2)

    def test_canonical_evil_regexes_rejected(self):
        # Classic nested-quantifier ReDoS shapes with a
        # ``killer`` suffix — regexploit detects the pumping
        # sequence in each.
        validate = self._validator()
        for evil in [
            "(a+)+x",
            "(a*)*x",
            "(.*)*x",
            "(?:a+)+x",
            "(?:.*)+x",
            "(.+)*x",
            "(.*)+x",
            # Quantified alternative with matching character
            # class — regexploit picks this one up via its
            # branch-expansion pass.
            "([0-9]|[0-9]+)+x",
            # The original Finding 5 report's example.
            ".*(.*)*.*(.*)*.*(.*)*x",
            "(?P<bad>a+)+x",
        ]:
            with self.subTest(pattern=evil):
                with self.assertRaises(ValueError):
                    validate(evil)

    def test_known_limitations_are_pinned(self):
        # Static analysis of regex ReDoS is undecidable in the
        # general case; both regexploit and the previous
        # hand-rolled walker have blind spots. The most notable
        # is alternation-with-equal-branches (``(a|a)*x``,
        # ``(a|aa)+x``): regexploit's branch expansion does not
        # detect the pumping sequence here. The
        # ``MONGODB_QUERY_TIMEOUT_MS`` server-side cap is the
        # backstop for these cases. This test pins the contract
        # so callers do not silently rely on a broader check.
        validate = self._validator()
        for limitation in ["(a|a)*x", "(a|aa)+x", "(\\w|\\d)+x"]:
            with self.subTest(pattern=limitation):
                # Should NOT raise — regexploit accepts these.
                validate(limitation)

    def test_unkilled_nested_quantifier_is_not_rejected(self):
        # ``(a+)+`` and ``(.*)*`` without a killer suffix are
        # *not* exploitable in practice — any input matches at
        # the first attempt without backtracking. regexploit
        # accepts them by design; the previous syntactic walker
        # was over-conservative here. This test pins the new
        # contract.
        validate = self._validator()
        validate("(a+)+")
        validate("(a*)*")
        validate("(.*)*")

    def test_named_groups_are_walked(self):
        # ``(?P<name>...)`` should be analysed normally; both
        # benign and malicious named-group patterns work.
        validate = self._validator()
        validate("(?P<host>[a-z]+)\\.example")
        with self.assertRaises(ValueError):
            validate("(?P<bad>a+)+x")

    def test_lookaround_is_walked(self):
        validate = self._validator()
        validate("foo(?=bar)")
        validate("foo(?!bar)")
        validate("(?<=foo)bar")
        validate("(?<!foo)bar")

    def test_invalid_regex_raises_value_error(self):
        # Malformed patterns surface as ``ValueError`` (which
        # Bottle turns into 400) rather than ``re.error``.
        validate = self._validator()
        for bad in ["[abc", "foo(", "(?P<bad)", "*invalid"]:
            with self.subTest(pattern=bad):
                with self.assertRaises(ValueError):
                    validate(bad)

    def test_web_wrapper_validates_regex_input(self):
        webutils = ivre.web.utils

        self.assertEqual(webutils.str2regexp("plain"), "plain")
        # Valid regex passes through and yields a compiled pattern.
        compiled = webutils.str2regexp("/^foo$/")
        self.assertTrue(hasattr(compiled, "pattern"))
        # Exploitable regex is rejected.
        with self.assertRaises(ValueError):
            webutils.str2regexp("/(a+)+x/")
        # Length cap (use a freshly large pattern to exceed the
        # default).
        with self.assertRaises(ValueError):
            webutils.str2regexp(
                "/" + ("a" * (ivre.config.WEB_REGEX_MAX_LENGTH + 1)) + "/"
            )

    def test_web_wrapper_str2regexpnone_passes_dash_through(self):
        webutils = ivre.web.utils

        self.assertIs(webutils.str2regexpnone("-"), False)
        with self.assertRaises(ValueError):
            webutils.str2regexpnone("/(a+)+x/")

    def test_web_wrapper_handles_trailing_flags(self):
        webutils = ivre.web.utils

        # Flags suffix should be stripped before length checks; a
        # very long flags suffix would otherwise inflate ``len``.
        compiled = webutils.str2regexp("/foo/i")
        self.assertTrue(hasattr(compiled, "pattern"))
        self.assertEqual(compiled.flags & re.IGNORECASE, re.IGNORECASE)


# ---------------------------------------------------------------------
# ElasticDBSearchFieldTests -- pin the wire shape of the Elastic
# ``_search_field`` helper extraction (the round-2 follow-up that
# consolidates the scalar / list / regex / neg ladder on the
# Elasticsearch backend, mirroring ``MongoDB._search_field``).
# ---------------------------------------------------------------------


try:
    import elasticsearch_dsl as _elasticsearch_dsl  # type: ignore[import-untyped]

    _HAVE_ELASTICSEARCH_DSL = True
    _ = _elasticsearch_dsl  # silence unused-import lint
except ImportError:
    _HAVE_ELASTICSEARCH_DSL = False


@unittest.skipUnless(
    _HAVE_ELASTICSEARCH_DSL,
    "elasticsearch_dsl is required (install with the ``elasticsearch`` extras)",
)
class ElasticDBSearchFieldTests(unittest.TestCase):
    """Pin the ``ElasticDB._search_field`` dispatch and the wire
    shape of the search methods that delegate to it. The four
    migrated methods (``searchcategory``, ``searchcountry``,
    ``searchasnum``, ``searchasname``) must produce the exact
    same Elasticsearch ``Query`` body the legacy hand-written
    ladders did, so the wire stays compatible across the
    refactor.

    Asserts via ``Query.to_dict()`` (the canonical wire-shape
    accessor) so the comparison is independent of
    ``elasticsearch_dsl`` internal class identity.
    """

    @staticmethod
    def _ED():
        from ivre.db.elastic import ElasticDB

        return ElasticDB

    @staticmethod
    def _EV():
        from ivre.db.elastic import ElasticDBView

        return ElasticDBView

    def test_search_field_scalar_positive(self):
        ED = self._ED()
        q = ED._search_field("categories", "admin")
        self.assertEqual(q.to_dict(), {"match": {"categories": "admin"}})

    def test_search_field_scalar_negation(self):
        ED = self._ED()
        q = ED._search_field("categories", "admin", neg=True)
        # ``~`` on a leaf query is wrapped in a ``bool.must_not``.
        self.assertEqual(
            q.to_dict(),
            {"bool": {"must_not": [{"match": {"categories": "admin"}}]}},
        )

    def test_search_field_list_uses_terms(self):
        ED = self._ED()
        q = ED._search_field("categories", ["a", "b"])
        self.assertEqual(q.to_dict(), {"terms": {"categories": ["a", "b"]}})

    def test_search_field_list_of_one_collapses_to_match(self):
        # ``len(value) == 1`` collapses to the scalar ``match``
        # form, matching the Mongo backend's ``[x]`` -> ``x``
        # collapse and keeping the wire output minimal.
        ED = self._ED()
        q = ED._search_field("categories", ["solo"])
        self.assertEqual(q.to_dict(), {"match": {"categories": "solo"}})

    def test_search_field_regex_uses_regexp(self):
        # The pattern is rewritten by ``_get_pattern`` to match
        # Elasticsearch's anchored-by-default semantics: a Python
        # /admin/ becomes /.*admin.*/ on the wire.
        ED = self._ED()
        pat = re.compile("admin")
        q = ED._search_field("categories", pat)
        self.assertEqual(q.to_dict(), {"regexp": {"categories": ".*admin.*"}})

    def test_searchcategory_legacy_shape_preserved(self):
        # Wire shape pinned bit-for-bit against the pre-refactor
        # method body. ``searchcategory`` is defined on
        # ``ElasticDBActive``; the View backend inherits it so
        # we exercise it through ``_EV()``.
        EV = self._EV()
        self.assertEqual(
            EV.searchcategory("admin").to_dict(),
            {"match": {"categories": "admin"}},
        )
        self.assertEqual(
            EV.searchcategory(["a", "b"]).to_dict(),
            {"terms": {"categories": ["a", "b"]}},
        )
        pat = re.compile("admin")
        self.assertEqual(
            EV.searchcategory(pat).to_dict(),
            {"regexp": {"categories": ".*admin.*"}},
        )
        self.assertEqual(
            EV.searchcategory("admin", neg=True).to_dict(),
            {"bool": {"must_not": [{"match": {"categories": "admin"}}]}},
        )

    def test_searchcountry_unaliases_then_delegates(self):
        # ``utils.country_unalias`` maps a few historical aliases
        # ('UK' -> 'GB' etc.); the helper sees the canonical
        # value. Test on a plain code (no aliasing applied) to
        # pin the wire shape; the aliasing itself is tested by
        # ``utils`` tests.
        EV = self._EV()
        self.assertEqual(
            EV.searchcountry("FR").to_dict(),
            {"match": {"infos.country_code": "FR"}},
        )
        self.assertEqual(
            EV.searchcountry(["FR", "US"]).to_dict(),
            {"terms": {"infos.country_code": ["FR", "US"]}},
        )
        self.assertEqual(
            EV.searchcountry("FR", neg=True).to_dict(),
            {"bool": {"must_not": [{"match": {"infos.country_code": "FR"}}]}},
        )

    def test_searchasnum_int_coercion_preserved(self):
        # ``int()`` coercion of every element is kept; behaviour
        # matches the pre-refactor method bit-for-bit. Strings
        # like ``"AS1234"`` still raise ``ValueError`` (the
        # backend has no ``_coerce_asnum`` equivalent today).
        EV = self._EV()
        self.assertEqual(
            EV.searchasnum("1234").to_dict(),
            {"match": {"infos.as_num": 1234}},
        )
        self.assertEqual(
            EV.searchasnum(1234).to_dict(),
            {"match": {"infos.as_num": 1234}},
        )
        self.assertEqual(
            EV.searchasnum(["1234", "5678"]).to_dict(),
            {"terms": {"infos.as_num": [1234, 5678]}},
        )
        self.assertEqual(
            EV.searchasnum(1234, neg=True).to_dict(),
            {"bool": {"must_not": [{"match": {"infos.as_num": 1234}}]}},
        )
        with self.assertRaises(ValueError):
            EV.searchasnum("AS1234")

    def test_searchasname_regex_and_scalar_preserved(self):
        EV = self._EV()
        self.assertEqual(
            EV.searchasname("Cloudflare").to_dict(),
            {"match": {"infos.as_name": "Cloudflare"}},
        )
        pat = re.compile("Cloud")
        self.assertEqual(
            EV.searchasname(pat).to_dict(),
            {"regexp": {"infos.as_name": ".*Cloud.*"}},
        )
        self.assertEqual(
            EV.searchasname("Cloudflare", neg=True).to_dict(),
            {"bool": {"must_not": [{"match": {"infos.as_name": "Cloudflare"}}]}},
        )


# ---------------------------------------------------------------------
# PostgresExplainTests -- defence-in-depth check that values
# inlined into the ``EXPLAIN`` statement go through SQLAlchemy's
# per-type literal binding, not Python ``repr``.
# ---------------------------------------------------------------------


try:
    import sqlalchemy as _sqlalchemy  # type: ignore[import-untyped]
    from sqlalchemy.dialects import (
        postgresql as _sqlalchemy_postgresql,  # type: ignore[import-untyped]
    )

    _HAVE_SQLALCHEMY = True
except ImportError:
    _HAVE_SQLALCHEMY = False


@unittest.skipUnless(
    _HAVE_SQLALCHEMY,
    "sqlalchemy is required (install with the ``postgres`` extras)",
)
class PostgresExplainTests(unittest.TestCase):
    """Tests for the literal-binds quoting path used by
    ``ivre.db.sql.postgres.PostgresDB.explain``.

    The previous implementation built the ``EXPLAIN`` statement
    by ``%``-interpolating ``repr(value)`` for each parameter,
    which only coincidentally produced valid SQL for plain
    strings and integers. This class pins the new contract: each
    bind goes through SQLAlchemy's per-type literal processor.
    """

    def _compile(self, query):
        return str(
            query.compile(
                dialect=_sqlalchemy_postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )

    @staticmethod
    def _users_table():
        sa = _sqlalchemy
        meta = sa.MetaData()
        return sa.Table(
            "users",
            meta,
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("name", sa.String),
            sa.Column("blob", sa.LargeBinary),
            sa.Column("active", sa.Boolean),
            sa.Column("created", sa.DateTime),
        )

    def test_string_with_single_quote_is_escaped(self):
        # The classic SQL-injection payload arrives as a string
        # value: SQLAlchemy's literal_processor must double the
        # embedded ``'`` so the value remains a string literal.
        sa = _sqlalchemy
        users = self._users_table()
        sql = self._compile(
            sa.select(users).where(users.c.name == "'; DROP TABLE users; --")
        )
        self.assertIn("'''; DROP TABLE users; --'", sql)
        self.assertNotIn("DROP TABLE users; --'", sql.split("'''", 1)[0])

    def test_none_is_emitted_as_NULL(self):
        # ``repr(None)`` is ``'None'`` (a Python literal, not SQL).
        # The literal-binds path must emit ``NULL`` instead.
        sa = _sqlalchemy
        users = self._users_table()
        sql = self._compile(sa.select(users).where(users.c.name.is_(None)))
        self.assertIn("IS NULL", sql.upper())
        self.assertNotIn("'None'", sql)

    def test_boolean_is_emitted_as_true_false(self):
        sa = _sqlalchemy
        users = self._users_table()
        sql = self._compile(sa.select(users).where(users.c.active.is_(True)))
        # PG dialect emits ``true`` / ``false`` (lowercase) as
        # native boolean literals; never the Python ``True``.
        self.assertNotIn("'True'", sql)
        self.assertIn("true", sql.lower())

    def test_integer_passthrough(self):
        sa = _sqlalchemy
        users = self._users_table()
        sql = self._compile(sa.select(users).where(users.c.id == 42))
        # Integer literal goes through unquoted.
        self.assertIn("= 42", sql)

    def test_no_pyformat_placeholders_remain(self):
        # The compile result must contain no ``%(name)s`` markers
        # — every parameter must be inlined as a literal.
        sa = _sqlalchemy
        users = self._users_table()
        sql = self._compile(
            sa.select(users)
            .where(users.c.name == "alice")
            .where(users.c.id == 7)
            .where(users.c.active.is_(True))
        )
        self.assertNotRegex(sql, r"%\(\w+\)s")

    def test_explain_function_does_not_use_repr(self):
        # White-box: pin that the executable code no longer
        # interpolates ``repr(value)`` into the EXPLAIN statement,
        # and that it uses ``literal_binds`` plus
        # ``exec_driver_sql``. AST-based so the docstring's
        # historical reference to ``repr(value)`` is ignored.
        import ast
        from inspect import getsource
        from textwrap import dedent

        from ivre.db.sql import postgres as pgmod

        src = dedent(getsource(pgmod.PostgresDB.explain))
        tree = ast.parse(src)
        repr_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "repr"
        ]
        self.assertEqual(repr_calls, [], "explain() should not call repr()")
        # Sanity: the new control-flow markers are present.
        self.assertIn("literal_binds", src)
        self.assertIn("exec_driver_sql", src)

    def test_inet_literal_renders_with_cast(self):
        # SQLAlchemy 2.0 dropped the default ``literal_processor``
        # for ``postgresql.INET``; without a replacement,
        # ``PostgresDB.explain()`` raises ``CompileError: No
        # literal value renderer is available for literal value
        # "'192.0.2.1'" with datatype INET``. The
        # ``ivre.db.sql.tables.INETLiteral`` subclass restores
        # the renderer; pin both the renderer's existence and
        # the rendered form ('192.0.2.1'::inet).
        sa = _sqlalchemy
        from ivre.db.sql.tables import SQLINET

        meta = sa.MetaData()
        hosts = sa.Table(
            "hosts",
            meta,
            sa.Column("addr", SQLINET),
        )
        sql = self._compile(sa.select(hosts).where(hosts.c.addr == "192.0.2.1"))
        # Quoted IP value, explicit ``::inet`` cast, no
        # ``%(name)s`` placeholder remaining.
        self.assertIn("'192.0.2.1'::inet", sql)
        self.assertNotRegex(sql, r"%\(\w+\)s")

    def test_inet_literal_escapes_single_quote(self):
        # Defence-in-depth: any value reaching the renderer must
        # have ``'`` doubled before being inlined as a SQL
        # literal. The PG driver / column type rejects garbage
        # at write time, but if a malformed string ever reached
        # the literal-binds path the renderer must not break out
        # of the string literal.
        sa = _sqlalchemy
        from ivre.db.sql.tables import SQLINET

        meta = sa.MetaData()
        hosts = sa.Table(
            "hosts",
            meta,
            sa.Column("addr", SQLINET),
        )
        sql = self._compile(
            sa.select(hosts).where(hosts.c.addr == "'; DROP TABLE hosts; --")
        )
        # The single quote is doubled inside the string literal.
        self.assertIn("'''; DROP TABLE hosts; --'", sql)
        self.assertNotIn("DROP TABLE hosts; --'::inet", sql.split("'''", 1)[0])

    def test_inet_literal_none_renders_NULL(self):
        # ``None`` must render as the SQL keyword ``NULL`` (not
        # the Python literal ``'None'`` quoted as a string).
        sa = _sqlalchemy
        from ivre.db.sql.tables import SQLINET

        meta = sa.MetaData()
        hosts = sa.Table(
            "hosts",
            meta,
            sa.Column("addr", SQLINET),
        )
        sql = self._compile(sa.select(hosts).where(hosts.c.addr.is_(None)))
        self.assertIn("IS NULL", sql.upper())
        self.assertNotIn("'None'", sql)


# ---------------------------------------------------------------------
# SQLDBSearchFieldTests -- pin the shared ``_search_field``
# dispatch on the SQL backends and the wire shape of the
# search methods that delegate to it. Mirrors
# ``MongoDBSearchFieldTests`` /
# ``ElasticDBSearchFieldTests`` so a reader sees a
# consistent helper-shape across all three backends.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_SQLALCHEMY,
    "sqlalchemy is required (install with the ``postgres`` extras)",
)
class SQLDBSearchFieldTests(unittest.TestCase):
    """Behaviour-pin for ``ivre.db.sql.SQLDB._search_field``
    and the ``SQLDBNmap.searchsource`` migration that delegates
    to it.

    The previous implementation hand-rolled a scalar / list /
    regex ladder per call site (round-2 SQL audit follow-up
    flagged ``SQLDBNmap.searchsource``). The shared helper
    matches the wire-shape contract of
    :meth:`MongoDB._search_field` so a regex / list / scalar
    accept-shape is identical across backends, with one
    deliberate change vs. the legacy SQL ladder: a
    single-element list now collapses to ``field = 'A'``
    instead of emitting ``field IN ('A')``. The two forms have
    identical query plans on PostgreSQL.
    """

    @staticmethod
    def _compile(clause):
        # Inline binds via the PostgreSQL dialect so the
        # rendered string is human-readable and stable across
        # SA versions (1.4 / 2.0).
        return str(
            clause.compile(
                dialect=_sqlalchemy_postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )

    @staticmethod
    def _scan_source_column():
        sa = _sqlalchemy
        meta = sa.MetaData()
        scan = sa.Table("scan", meta, sa.Column("source", sa.String))
        return scan.c.source

    def _SQLDB(self):  # noqa: N802 -- factory accessor
        from ivre.db.sql import SQLDB

        return SQLDB

    def test_scalar_positive(self):
        col = self._scan_source_column()
        sql = self._compile(self._SQLDB()._search_field(col, "X"))
        self.assertEqual(sql, "scan.source = 'X'")

    def test_scalar_negative(self):
        col = self._scan_source_column()
        sql = self._compile(self._SQLDB()._search_field(col, "X", neg=True))
        self.assertEqual(sql, "scan.source != 'X'")

    def test_list_positive(self):
        col = self._scan_source_column()
        sql = self._compile(self._SQLDB()._search_field(col, ["A", "B"]))
        self.assertEqual(sql, "scan.source IN ('A', 'B')")

    def test_list_negative(self):
        col = self._scan_source_column()
        sql = self._compile(self._SQLDB()._search_field(col, ["A", "B"], neg=True))
        # SQLAlchemy parenthesises NOT IN; assert on the
        # SQL primitive instead of strict equality so the
        # exact parenthesisation is not over-pinned.
        self.assertIn("NOT IN", sql)
        self.assertIn("('A', 'B')", sql)

    def test_list_of_one_collapses_to_scalar(self):
        # Behaviour change vs. legacy ``searchsource``: a
        # single-element list now emits ``= 'A'`` not
        # ``IN ('A')``. PG plans them identically; the
        # rewrite matches Mongo / Elastic semantics.
        col = self._scan_source_column()
        self.assertEqual(
            self._compile(self._SQLDB()._search_field(col, ["A"])),
            "scan.source = 'A'",
        )
        self.assertEqual(
            self._compile(self._SQLDB()._search_field(col, ["A"], neg=True)),
            "scan.source != 'A'",
        )

    def test_regex_positive(self):
        col = self._scan_source_column()
        sql = self._compile(self._SQLDB()._search_field(col, re.compile("^foo")))
        self.assertEqual(sql, "scan.source ~ '^foo'")

    def test_regex_case_insensitive(self):
        col = self._scan_source_column()
        sql = self._compile(self._SQLDB()._search_field(col, re.compile("^foo", re.I)))
        # PostgreSQL ``~*`` is the case-insensitive POSIX-regex
        # operator (vs. ``~`` for case-sensitive).
        self.assertEqual(sql, "scan.source ~* '^foo'")

    def test_regex_negative(self):
        col = self._scan_source_column()
        sql = self._compile(
            self._SQLDB()._search_field(col, re.compile("^foo"), neg=True)
        )
        self.assertIn("NOT", sql)
        self.assertIn("scan.source ~ '^foo'", sql)

    def test_map_scalar(self):
        # ``map_=str`` mirrors ``SQLDBActive.searchasnum`` --
        # AS numbers are stored as text, callers pass ints.
        col = self._scan_source_column()
        sql = self._compile(self._SQLDB()._search_field(col, 1234, map_=str))
        self.assertEqual(sql, "scan.source = '1234'")

    def test_map_list(self):
        col = self._scan_source_column()
        sql = self._compile(self._SQLDB()._search_field(col, [1, 2, 3], map_=str))
        self.assertEqual(sql, "scan.source IN ('1', '2', '3')")

    def test_map_with_regex_raises(self):
        # ``map_`` is an element-wise coercion; pairing it with
        # a compiled regex pattern is undefined and rejected
        # explicitly so callers don't get silently-broken
        # filters at query time.
        col = self._scan_source_column()
        with self.assertRaises(TypeError):
            self._SQLDB()._search_field(col, re.compile("foo"), map_=str)

    def test_searchsource_nmap_delegates_to_helper(self):
        # End-to-end: the ``SQLDBNmap.searchsource`` migration
        # produces the same SQL as a direct
        # ``_search_field`` call on the ``scan.source`` column.
        # We compare the two ``.main`` clauses bit-for-bit so
        # the round-2 follow-up is pinned end-to-end.
        from ivre.db.sql import SQLDBNmap

        nmap_filter = SQLDBNmap.searchsource(["A", "B"], neg=True)
        direct = SQLDBNmap._search_field(
            SQLDBNmap.tables.scan.source, ["A", "B"], neg=True
        )
        self.assertEqual(self._compile(nmap_filter.main), self._compile(direct))

    def test_searchcountry_view_delegates_to_helper(self):
        # ``SQLDBView.searchcountry`` migrated from the legacy
        # ``_searchstring_list`` helper to the unified
        # ``_search_field`` helper. The migration is internal:
        # same accept-shape (scalar / list -- regex is rejected
        # earlier in the pipeline by ``utils.country_unalias``),
        # same emitted SQL, just routed through one helper. Pin
        # both list and scalar paths bit-for-bit against direct
        # ``_search_field`` calls.
        from ivre.db.sql import SQLDBView

        col = SQLDBView.tables.scan.info["country_code"].astext
        # ``country_unalias`` is the identity on uppercase
        # 2-letter codes, so the comparison is bit-for-bit.
        for value in ("FR", ["FR", "DE"], ["FR"]):
            with self.subTest(value=value):
                self.assertEqual(
                    self._compile(SQLDBView.searchcountry(value).main),
                    self._compile(SQLDBView._search_field(col, value)),
                )

    def test_searchasnum_view_preserves_str_coercion(self):
        # ``SQLDBView.searchasnum`` historically called
        # ``_searchstring_list(map_=str)`` to stringify integer
        # AS numbers stored in the JSONB-as-text
        # ``info.as_num`` column. The migration to
        # ``_search_field(map_=str)`` must preserve this:
        # callers passing an int / list-of-int still produce
        # quoted-string clauses.
        from ivre.db.sql import SQLDBView

        # Scalar int.
        sql = self._compile(SQLDBView.searchasnum(1234).main)
        # The JSONB getitem expression on the LHS quotes the
        # key, so we only assert on the RHS literal.
        self.assertIn("'1234'", sql)
        # List of ints.
        sql = self._compile(SQLDBView.searchasnum([1, 2, 3]).main)
        self.assertIn("'1', '2', '3'", sql)

    def test_searchja4client_passive_canonical_value(self):
        # M4.0.4: ``SQLDBPassive.searchja4client`` mirrors
        # ``MongoDBPassive.searchja4client`` (mongo.py:5655).
        # Passing the canonical string form
        # (``ja4_a_ja4_b_ja4_c``) must split out the indexed
        # components and constrain each via the
        # ``moreinfo`` JSONB column.
        from ivre.db.sql import SQLDBPassive

        flt = SQLDBPassive.searchja4client(value="t13d1715h2_5b57614c22b0_93c9c6ee0ce4")
        sql = self._compile(flt.main)
        self.assertIn("passive.recontype = 'SSL_CLIENT'", sql)
        self.assertIn("passive.source = 'ja4'", sql)
        self.assertIn("passive.value = 't13d1715h2_5b57614c22b0_93c9c6ee0ce4'", sql)
        self.assertIn("(passive.moreinfo ->> 'ja4_a') = 't13d1715h2'", sql)
        self.assertIn("(passive.moreinfo ->> 'ja4_b') = '5b57614c22b0'", sql)
        self.assertIn("(passive.moreinfo ->> 'ja4_c') = '93c9c6ee0ce4'", sql)

    def test_searchja4client_passive_individual_components(self):
        # Individual ``ja4_*`` parameters bypass parsing; each
        # constrains exactly one ``moreinfo`` JSONB key.
        from ivre.db.sql import SQLDBPassive

        flt = SQLDBPassive.searchja4client(ja4_a="t13d1715h2", ja4_b="5b57614c22b0")
        sql = self._compile(flt.main)
        self.assertIn("(passive.moreinfo ->> 'ja4_a') = 't13d1715h2'", sql)
        self.assertIn("(passive.moreinfo ->> 'ja4_b') = '5b57614c22b0'", sql)
        # ``ja4_c`` not constrained when not passed; check the
        # short bare key is absent (ignoring ``ja4_c1_raw`` /
        # ``ja4_c2_raw`` substrings which would false-positive).
        scrubbed = sql.replace("ja4_c1_raw", "").replace("ja4_c2_raw", "")
        self.assertNotIn("'ja4_c'", scrubbed)

    def test_searchja4client_passive_raw_splits_c1_c2(self):
        # The ``raw`` parameter splits ``ja4_c_raw`` further
        # into ``ja4_c1_raw`` / ``ja4_c2_raw`` when it contains
        # an underscore.
        from ivre.db.sql import SQLDBPassive

        flt = SQLDBPassive.searchja4client(raw="t13d1715h2_002f,0035_aaaaaa_bbbbbb")
        sql = self._compile(flt.main)
        self.assertIn("(passive.moreinfo ->> 'ja4_a') = 't13d1715h2'", sql)
        self.assertIn("(passive.moreinfo ->> 'ja4_b_raw') = '002f,0035'", sql)
        self.assertIn("(passive.moreinfo ->> 'ja4_c1_raw') = 'aaaaaa'", sql)
        self.assertIn("(passive.moreinfo ->> 'ja4_c2_raw') = 'bbbbbb'", sql)

    def test_searchja4client_passive_neg_wraps_in_not(self):
        # ``neg=True`` wraps the whole AND-chain in
        # ``not_(...)`` -- one NOT around the conjunction, not
        # one per condition.
        from ivre.db.sql import SQLDBPassive

        flt = SQLDBPassive.searchja4client(ja4_a="t13d1715h2", neg=True)
        sql = self._compile(flt.main)
        self.assertTrue(sql.startswith("NOT ("))
        self.assertIn("(passive.moreinfo ->> 'ja4_a') = 't13d1715h2'", sql)

    def test_searchtag_lifted_to_sqldbactive(self):
        # M4.0.5: ``searchtag`` was previously defined only on
        # ``SQLDBView``. Both ``SQLDBView`` and ``SQLDBNmap`` have
        # a ``tag`` table in ``tables`` and a ``base_filter``
        # (``ActiveFilter`` subclass) that accepts the ``tag=``
        # keyword, so the implementation lifts cleanly to
        # ``SQLDBActive`` and both backends inherit it.
        from ivre.db.sql import SQLDBActive, SQLDBNmap, SQLDBView

        # Method is owned by ``SQLDBActive`` (not duplicated on
        # the subclasses).
        self.assertIs(SQLDBNmap.searchtag.__func__, SQLDBActive.searchtag.__func__)
        self.assertIs(SQLDBView.searchtag.__func__, SQLDBActive.searchtag.__func__)

    def test_searchtag_nmap_produces_nmap_filter(self):
        # ``SQLDBNmap.searchtag(value)`` builds a ``NmapFilter``
        # with a ``(positive, value-equality)`` entry on the
        # ``tag`` axis. Pin both the filter type and the entry
        # shape so the lift cannot accidentally degrade the
        # NmapFilter into a base ActiveFilter.
        from ivre.db.sql import SQLDBNmap
        from ivre.db.sql.tables import N_Tag

        flt = SQLDBNmap.searchtag("CDN")
        self.assertEqual(type(flt).__name__, "NmapFilter")
        # One entry: (True, <equality clause>).
        self.assertEqual(len(flt.tag), 1)
        positive, clause = flt.tag[0]
        self.assertTrue(positive)
        # The clause references the Nmap tag table's ``value``
        # column (not the View tag table).
        sql = self._compile(clause)
        self.assertIn("n_tag.value = 'CDN'", sql)
        self.assertEqual(N_Tag.__tablename__, "n_tag")

    def test_searchtag_nmap_with_dict_constrains_multiple_keys(self):
        # Passing a dict (e.g.
        # ``{"value": "CDN", "info": "Cloudflare"}``) constrains
        # multiple ``tag`` columns AND-ed together.
        from ivre.db.sql import SQLDBNmap

        flt = SQLDBNmap.searchtag({"value": "CDN", "info": "Cloudflare"})
        self.assertEqual(len(flt.tag), 1)
        positive, clause = flt.tag[0]
        self.assertTrue(positive)
        sql = self._compile(clause)
        self.assertIn("n_tag.value = 'CDN'", sql)
        self.assertIn("n_tag.info = 'Cloudflare'", sql)

    def test_searchtag_nmap_neg(self):
        # ``neg=True`` flips the polarity flag on the tag entry
        # (the per-axis evaluator handles the inversion); the
        # value clause itself stays positive.
        from ivre.db.sql import SQLDBNmap

        flt = SQLDBNmap.searchtag("CDN", neg=True)
        self.assertEqual(len(flt.tag), 1)
        positive, _clause = flt.tag[0]
        self.assertFalse(positive)

    def test_searchstring_re_inarray_regex_positive(self):
        # ``SQLDB._searchstring_re_inarray`` over an array column
        # with a regex value returns ``idfield IN (subquery)``
        # where the subquery unnests the array and filters on the
        # regex match. The PostgreSQL ``~`` operator (``~*`` for
        # case-insensitive) is the regex matcher.
        sa = _sqlalchemy
        from ivre.db.sql import SQLDB

        meta = sa.MetaData()
        scan = sa.Table(
            "scan",
            meta,
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column(
                "source", _sqlalchemy_postgresql.ARRAY(sa.String), nullable=False
            ),
        )
        clause = SQLDB._searchstring_re_inarray(
            scan.c.id, scan.c.source, re.compile("^source-")
        )
        sql = self._compile(clause)
        self.assertIn("scan.id IN", sql)
        self.assertIn("WHERE field ~ '^source-'", sql)

    def test_searchstring_re_inarray_regex_negative(self):
        # M4.0.3: the negative regex path used to ``raise
        # ValueError("Not implemented")``. The fix mirrors the
        # positive form via ``idfield.notin_(base2)``: rows whose
        # array contains zero elements matching the regex (plus
        # rows with empty or NULL arrays) match. Pin the SQL
        # primitive so any future rewrite preserves the
        # contract.
        sa = _sqlalchemy
        from ivre.db.sql import SQLDB

        meta = sa.MetaData()
        scan = sa.Table(
            "scan",
            meta,
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column(
                "source", _sqlalchemy_postgresql.ARRAY(sa.String), nullable=False
            ),
        )
        clause = SQLDB._searchstring_re_inarray(
            scan.c.id, scan.c.source, re.compile("^source-"), neg=True
        )
        sql = self._compile(clause)
        # ``NOT IN`` (with parentheses inserted by SA) over the
        # subquery built from the unnest CTE.
        self.assertIn("NOT IN", sql)
        self.assertIn("WHERE field ~ '^source-'", sql)

    def test_searchstring_re_inarray_regex_negative_case_insensitive(self):
        # Case-insensitive regex (``re.I``) must use the
        # PostgreSQL ``~*`` operator for the unnest filter, with
        # the negative path still wrapping in ``NOT IN``.
        sa = _sqlalchemy
        from ivre.db.sql import SQLDB

        meta = sa.MetaData()
        scan = sa.Table(
            "scan",
            meta,
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column(
                "source", _sqlalchemy_postgresql.ARRAY(sa.String), nullable=False
            ),
        )
        clause = SQLDB._searchstring_re_inarray(
            scan.c.id, scan.c.source, re.compile("^source-", re.I), neg=True
        )
        sql = self._compile(clause)
        self.assertIn("NOT IN", sql)
        self.assertIn("WHERE field ~* '^source-'", sql)


# ---------------------------------------------------------------------
# CertExtensionFormatTests -- pin the format of
# ``result["san"]`` produced by ``ivre.utils.get_cert_info`` after
# the migration off pyOpenSSL's removed ``X509.get_extension(i)``
# index loop. Each entry must keep the OpenSSL CLI ``v2i_GENERAL_NAME``
# shape ("DNS:foo", "IP Address:1.2.3.4", "email:a@b", "URI:...")
# so downstream consumers (``ivre.active.data.cert_lines``, the
# ``ssl-cert`` script output renderer, etc.) keep working.
# ---------------------------------------------------------------------


try:
    import datetime as _cert_datetime
    import ipaddress as _cert_ipaddress

    from cryptography import x509 as _cert_x509  # type: ignore[import-untyped]
    from cryptography.hazmat.primitives import (
        hashes as _cert_hashes,  # type: ignore[import-untyped]
    )
    from cryptography.hazmat.primitives import (
        serialization as _cert_serialization,  # type: ignore[import-untyped]
    )
    from cryptography.hazmat.primitives.asymmetric import (
        rsa as _cert_rsa,  # type: ignore[import-untyped]
    )
    from cryptography.x509.oid import (
        NameOID as _cert_NameOID,  # type: ignore[import-untyped]
    )

    _HAVE_CRYPTOGRAPHY = True
except ImportError:
    _HAVE_CRYPTOGRAPHY = False

try:
    # ``cryptography`` alone is not enough -- ``ivre.utils.get_cert_info``
    # is only defined when ``USE_PYOPENSSL`` is true.
    from OpenSSL import (  # type: ignore[import-untyped] # noqa: F401
        crypto as _cert_osslc,
    )

    _HAVE_PYOPENSSL = True
except ImportError:
    _HAVE_PYOPENSSL = False


@unittest.skipUnless(
    _HAVE_CRYPTOGRAPHY and _HAVE_PYOPENSSL,
    "cryptography and pyOpenSSL are required for CertExtensionFormatTests",
)
class CertExtensionFormatTests(unittest.TestCase):
    """Pin the SAN-string format produced by
    ``ivre.utils.get_cert_info`` and the standalone
    ``_format_san_general_name`` helper.

    Background: pyOpenSSL 26.x removed ``X509.get_extension(i)``
    (deprecated since 23.3); ``ivre.utils.get_cert_info`` used to
    iterate that legacy API and call ``str(ext)`` to get the
    ``"DNS:..., IP Address:..."`` text. The migration routes the
    lookup through ``X509.to_cryptography()`` and rebuilds the
    same strings from the typed ``GeneralName`` objects, so this
    class pins each subtype's expected output shape and the
    end-to-end ``get_cert_info(cert)["san"]`` list ordering.
    """

    @staticmethod
    def _build_cert(general_names: "list") -> bytes:
        """Build a self-signed DER cert with the given list of
        ``cryptography.x509`` ``GeneralName`` objects in its
        ``SubjectAlternativeName`` extension."""
        key = _cert_rsa.generate_private_key(65537, 2048)
        subject = issuer = _cert_x509.Name(
            [_cert_x509.NameAttribute(_cert_NameOID.COMMON_NAME, "test.example.com")]
        )
        now = _cert_datetime.datetime.now(_cert_datetime.timezone.utc)
        builder = (
            _cert_x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(_cert_x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + _cert_datetime.timedelta(days=10))
            .add_extension(
                _cert_x509.SubjectAlternativeName(general_names), critical=False
            )
        )
        cert = builder.sign(key, _cert_hashes.SHA256())
        return cert.public_bytes(_cert_serialization.Encoding.DER)

    def test_format_helper_dns(self) -> None:
        from ivre.utils import _format_san_general_name

        self.assertEqual(
            _format_san_general_name(_cert_x509.DNSName("example.com")),
            "DNS:example.com",
        )

    def test_format_helper_ipv4(self) -> None:
        from ivre.utils import _format_san_general_name

        self.assertEqual(
            _format_san_general_name(
                _cert_x509.IPAddress(_cert_ipaddress.IPv4Address("192.0.2.1"))
            ),
            "IP Address:192.0.2.1",
        )

    def test_format_helper_email(self) -> None:
        from ivre.utils import _format_san_general_name

        self.assertEqual(
            _format_san_general_name(_cert_x509.RFC822Name("admin@example.com")),
            "email:admin@example.com",
        )

    def test_format_helper_uri(self) -> None:
        from ivre.utils import _format_san_general_name

        self.assertEqual(
            _format_san_general_name(
                _cert_x509.UniformResourceIdentifier("https://example.com/")
            ),
            "URI:https://example.com/",
        )

    def test_format_helper_registered_id(self) -> None:
        from ivre.utils import _format_san_general_name

        self.assertEqual(
            _format_san_general_name(
                _cert_x509.RegisteredID(_cert_x509.ObjectIdentifier("1.2.3.4"))
            ),
            "Registered ID:1.2.3.4",
        )

    def test_get_cert_info_san_dns_and_ip(self) -> None:
        from ivre import utils

        if not utils.USE_PYOPENSSL:
            self.skipTest("pyOpenSSL bindings unavailable in this build")
        der = self._build_cert(
            [
                _cert_x509.DNSName("example.com"),
                _cert_x509.DNSName("www.example.com"),
                _cert_x509.IPAddress(_cert_ipaddress.IPv4Address("192.0.2.1")),
            ]
        )
        info = utils.get_cert_info(der)
        self.assertEqual(
            info["san"],
            [
                "DNS:example.com",
                "DNS:www.example.com",
                "IP Address:192.0.2.1",
            ],
        )

    def test_get_cert_info_san_missing(self) -> None:
        # No SAN extension at all -> ``result`` must NOT contain
        # the ``"san"`` key (downstream code uses ``"san" in info``
        # as the presence check).
        from ivre import utils

        if not utils.USE_PYOPENSSL:
            self.skipTest("pyOpenSSL bindings unavailable in this build")
        # Build a SAN-less cert by overriding ``_build_cert`` inline.
        key = _cert_rsa.generate_private_key(65537, 2048)
        subject = issuer = _cert_x509.Name(
            [_cert_x509.NameAttribute(_cert_NameOID.COMMON_NAME, "no-san.example")]
        )
        now = _cert_datetime.datetime.now(_cert_datetime.timezone.utc)
        cert = (
            _cert_x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(_cert_x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + _cert_datetime.timedelta(days=10))
            .sign(key, _cert_hashes.SHA256())
        )
        info = utils.get_cert_info(cert.public_bytes(_cert_serialization.Encoding.DER))
        self.assertNotIn("san", info)

    def test_get_cert_info_continues_when_to_cryptography_raises(self) -> None:
        """If ``X509.to_cryptography()`` raises -- because
        ``cryptography``'s strict ASN.1 parser rejects a malformed
        but pyOpenSSL-tolerated cert (real-world examples include
        ``InvalidVersion: 3 is not a valid X509 version``,
        ``ParseError ... Time::UtcTime``, ``BasicConstraints::ca``
        ``EncodedDefault``) -- the SAN lookup must be skipped
        without aborting the rest of ``get_cert_info``.

        Critical invariant: ``result["pubkey"]["exponent"]`` and
        ``result["pubkey"]["modulus"]`` must still be populated
        for RSA keys, because ``ivre getmoduli`` (the consumer
        exercised by ``test_30_nmap`` in ``tests/tests.py``)
        reads ``key["exponent"]`` and crashes with ``KeyError`` on
        a missing field.
        """
        from unittest import mock

        from ivre import utils

        if not utils.USE_PYOPENSSL:
            self.skipTest("pyOpenSSL bindings unavailable in this build")
        der = self._build_cert([_cert_x509.DNSName("example.com")])
        # Patch ``X509.to_cryptography`` at the class level so the
        # call inside ``get_cert_info`` raises the same ``ValueError``
        # the strict ``cryptography`` ASN.1 parser would emit on a
        # malformed real-world cert.
        with mock.patch.object(
            _cert_osslc.X509,
            "to_cryptography",
            side_effect=ValueError(
                "simulated cryptography ASN.1 parse error on malformed cert"
            ),
        ):
            info = utils.get_cert_info(der)
        # SAN absent (lookup failed and was skipped).
        self.assertNotIn("san", info)
        # Pubkey block fully populated -- this is the field
        # ``getmoduli`` requires.
        self.assertIn("pubkey", info)
        self.assertIn("type", info["pubkey"])
        self.assertEqual(info["pubkey"]["type"], "rsa")
        self.assertIn("exponent", info["pubkey"])
        self.assertIn("modulus", info["pubkey"])
        self.assertIn("bits", info["pubkey"])
        # Subject / issuer / serial / dates also recovered.
        # ``_parse_subject`` maps short OIDs (``CN``) to their long
        # form (``commonName``) via the ``_CERTKEYS`` table and joins
        # components with ``/``; for a single-component DN there is
        # no leading ``/``.
        self.assertEqual(info["subject_text"], "commonName=test.example.com")
        self.assertEqual(info["issuer_text"], "commonName=test.example.com")
        self.assertIn("serial_number", info)
        self.assertIn("version", info)


# ---------------------------------------------------------------------
# PassiveDatetimeCoercionTests -- the ``/cgi/passive`` route's
# datetime-to-timestamp helper must accept the three concrete
# field shapes that show up in real datasets (datetime, numeric,
# ISO string) so the route does not 500 mid-stream.
# ---------------------------------------------------------------------


class PassiveDatetimeCoercionTests(unittest.TestCase):
    """Regression tests for ``ivre.web.app._convert_datetime_value``.

    The helper used to assume ``datetime.datetime`` unconditionally
    (it called ``value.replace(tzinfo=...).timestamp()``). Real
    operator data turns out to mix the four datetime fields
    declared by ``DBPassive.datetime_fields`` (``firstseen``,
    ``lastseen``, ``infos.not_after``, ``infos.not_before``)
    between ``datetime`` instances, ``float``/``int`` Unix
    timestamps (older ingestion paths stored cert validity dates
    as floats), and ``"YYYY-MM-DD HH:MM:SS"`` strings (some Zeek
    scripts emit cert dates that way). Hitting any of the
    non-datetime forms used to crash the streaming response with
    ``AttributeError: 'float' object has no attribute 'replace'``,
    which Bottle silently truncates because the response had
    already started.
    """

    @staticmethod
    def _convert():
        from ivre.web import app as appmod

        return appmod._convert_datetime_value  # pylint: disable=protected-access

    def test_datetime_input(self):
        convert = self._convert()
        # 2024-01-02 10:00:00 UTC.
        dt = datetime(2024, 1, 2, 10, 0, 0)
        self.assertEqual(convert(dt), 1704189600)

    def test_float_input_passes_through_as_int(self):
        # The exact crash reported from the field: a passive cert
        # ``infos.not_after`` is a Python ``float``.
        convert = self._convert()
        self.assertEqual(convert(1704189600.0), 1704189600)
        self.assertEqual(convert(1704189600.999), 1704189600)

    def test_int_input_passes_through(self):
        convert = self._convert()
        self.assertEqual(convert(1704189600), 1704189600)

    def test_iso_like_string_is_parsed(self):
        # ``"YYYY-MM-DD HH:MM:SS"`` (no timezone) is the legacy
        # storage shape for some cert validity dates.
        convert = self._convert()
        result = convert("2024-01-02 10:00:00")
        # The value is interpreted as UTC by the helper.
        self.assertEqual(result, 1704189600)

    def test_unknown_type_raises(self):
        convert = self._convert()
        with self.assertRaises((TypeError, AttributeError)):
            convert(object())


# ---------------------------------------------------------------------
# PassiveFltFromQueryTests -- the ``recontype`` and ``sensor``
# query parameters reach a real ``$regex`` clause rather than
# falling through to ``flt_from_query``'s ``unused`` list.
# ---------------------------------------------------------------------


class PassiveFltFromQueryTests(unittest.TestCase):
    """Regression tests for the Web API ``q=`` filter parser when
    talking to ``db.passive``.

    Background: ``flt_from_query`` used to recognise a long list
    of params (``host``, ``net``, ``country``, ``asnum``,
    ``source``, ...) but neither ``recontype`` nor ``sensor``,
    even though both are first-class facet keys exposed by
    ``/cgi/passive/top/<field>`` and rendered in the React
    Passive section's facet sidebar. The result was that
    clicking a facet row (or typing ``recontype:DNS_ANSWER`` in
    the filter bar) appeared to do nothing — the URL changed,
    the request fired, but the backend silently dropped the
    token into the ``unused`` list. This class pins the
    contract for the two passive-specific facet keys.
    """

    @staticmethod
    def _stub_dbase():
        # A minimal duck-typed stand-in for ``DBPassive`` that
        # records the calls the parser makes to it. We do not
        # want to depend on having a configured backend at test
        # time (this file runs in the no-backend matrix).
        from ivre.db import db as _db  # noqa: F401  pylint: disable=unused-import

        class _StubDB:
            calls: list = []
            flt_empty = {"_marker": "empty"}

            @staticmethod
            def flt_and(*args):
                # Last non-empty filter wins for the purposes of
                # the assertions below.
                non_empty = [a for a in args if a and a != _StubDB.flt_empty]
                return non_empty[-1] if non_empty else _StubDB.flt_empty

            @staticmethod
            def searchrecontype(rectype=None, source=None, neg=False):
                _StubDB.calls.append(
                    ("searchrecontype", rectype, source, neg),
                )
                return {"rectype": rectype, "source": source, "neg": neg}

            @staticmethod
            def searchsensor(value, neg=False):
                _StubDB.calls.append(("searchsensor", value, neg))
                return {"sensor": value, "neg": neg}

        _StubDB.calls = []
        return _StubDB

    def _parse(self, q, dbase):
        from ivre.web import utils as webutils

        # Bypass the global init filter — for the no-backend
        # test we only want to know which ``searchXXX`` helpers
        # the parser invokes.
        with mock.patch.object(webutils, "get_init_flt", return_value=dbase.flt_empty):
            query = webutils.query_from_params({"q": q})
            return webutils.flt_from_query(dbase, query, base_flt=dbase.flt_empty)

    def test_recontype_invokes_searchrecontype(self):
        dbase = self._stub_dbase()
        flt, _sortby, unused, *_ = self._parse("recontype:DNS_ANSWER", dbase)
        self.assertEqual(unused, [])
        self.assertEqual(
            [c for c in dbase.calls if c[0] == "searchrecontype"],
            [("searchrecontype", "DNS_ANSWER", None, False)],
        )
        self.assertEqual(flt.get("rectype"), "DNS_ANSWER")
        self.assertIsNone(flt.get("source"))
        self.assertFalse(flt.get("neg"))

    def test_sensor_invokes_searchsensor(self):
        dbase = self._stub_dbase()
        flt, _sortby, unused, *_ = self._parse("sensor:TEST", dbase)
        self.assertEqual(unused, [])
        self.assertEqual(
            [c for c in dbase.calls if c[0] == "searchsensor"],
            [("searchsensor", "TEST", False)],
        )
        self.assertEqual(flt.get("sensor"), "TEST")

    def test_negated_recontype_propagates_neg_flag(self):
        dbase = self._stub_dbase()
        self._parse("-recontype:HTTP_SERVER_HEADER", dbase)
        self.assertEqual(
            [c for c in dbase.calls if c[0] == "searchrecontype"],
            [("searchrecontype", "HTTP_SERVER_HEADER", None, True)],
        )

    def test_recontype_falls_through_when_backend_lacks_helper(self):
        # ``hasattr(dbase, 'searchrecontype')`` is the gate; a
        # backend without the helper (the View / Active path)
        # treats the token as unused, which is the expected
        # legacy behaviour for those sections.
        from ivre.web import utils as webutils

        class _LegacyDB:
            flt_empty = {}

            @staticmethod
            def flt_and(*args):
                return args[-1] if args else _LegacyDB.flt_empty

        with mock.patch.object(
            webutils, "get_init_flt", return_value=_LegacyDB.flt_empty
        ):
            query = webutils.query_from_params({"q": "recontype:DNS_ANSWER"})
            _, _, unused, *_ = webutils.flt_from_query(
                _LegacyDB, query, base_flt=_LegacyDB.flt_empty
            )
        self.assertEqual(unused, ["recontype=DNS_ANSWER"])

    def test_source_with_colon_invokes_combined_searchrecontype(self):
        # Tuple form: ``source:RECONTYPE:VALUE`` dispatches to
        # ``searchrecontype(rectype=…, source=…)`` so the
        # backend filters on both fields at once.
        dbase = self._stub_dbase()
        flt, _sortby, unused, *_ = self._parse(
            "source:HTTP_SERVER_HEADER:SERVER", dbase
        )
        self.assertEqual(unused, [])
        self.assertEqual(
            [c for c in dbase.calls if c[0] == "searchrecontype"],
            [("searchrecontype", "HTTP_SERVER_HEADER", "SERVER", False)],
        )
        self.assertEqual(flt.get("rectype"), "HTTP_SERVER_HEADER")
        self.assertEqual(flt.get("source"), "SERVER")

    def test_source_without_colon_invokes_searchrecontype_source_only(self):
        # Legacy single-value form. Routes through
        # ``searchrecontype(source=…)`` rather than
        # ``searchsource(…)`` (which is not implemented on
        # ``DBPassive``).
        dbase = self._stub_dbase()
        flt, _sortby, unused, *_ = self._parse("source:cert", dbase)
        self.assertEqual(unused, [])
        self.assertEqual(
            [c for c in dbase.calls if c[0] == "searchrecontype"],
            [("searchrecontype", None, "cert", False)],
        )
        self.assertIsNone(flt.get("rectype"))
        self.assertEqual(flt.get("source"), "cert")
        # Crucially, ``searchsource`` is *not* invoked on the
        # passive path.
        self.assertEqual(
            [c for c in dbase.calls if c[0] == "searchsource"],
            [],
        )

    def test_negated_combined_source_propagates_neg(self):
        dbase = self._stub_dbase()
        self._parse("-source:SSL_SERVER:cert", dbase)
        self.assertEqual(
            [c for c in dbase.calls if c[0] == "searchrecontype"],
            [("searchrecontype", "SSL_SERVER", "cert", True)],
        )

    def test_searchrecontype_scalar_only_keeps_legacy_shape(self):
        # Direct unit test of the static method: the
        # ``recontype`` only positive case must produce the
        # historical ``{"recontype": value}`` shape so existing
        # query plans / indexes are unaffected.
        from ivre.db.mongo import MongoDBPassive as M

        self.assertEqual(
            M.searchrecontype(rectype="DNS_ANSWER"), {"recontype": "DNS_ANSWER"}
        )
        self.assertEqual(
            M.searchrecontype(rectype="DNS_ANSWER", neg=True),
            {"recontype": {"$ne": "DNS_ANSWER"}},
        )
        # List of length > 1 → ``$in``; length 1 collapses to scalar.
        self.assertEqual(
            M.searchrecontype(rectype=["A", "B"]),
            {"recontype": {"$in": ["A", "B"]}},
        )
        self.assertEqual(M.searchrecontype(rectype=["A"]), {"recontype": "A"})
        # Negated list → ``$nin``.
        self.assertEqual(
            M.searchrecontype(rectype=["A", "B"], neg=True),
            {"recontype": {"$nin": ["A", "B"]}},
        )

    def test_searchrecontype_combined_uses_and(self):
        # Both ``rectype`` and ``source`` set: positive form is
        # the AND, negative form wraps the AND in ``$nor``.
        from ivre.db.mongo import MongoDBPassive as M

        self.assertEqual(
            M.searchrecontype(rectype="SSL_SERVER", source="cert"),
            {"$and": [{"recontype": "SSL_SERVER"}, {"source": "cert"}]},
        )
        self.assertEqual(
            M.searchrecontype(rectype="SSL_SERVER", source="cert", neg=True),
            {"$nor": [{"$and": [{"recontype": "SSL_SERVER"}, {"source": "cert"}]}]},
        )

    def test_searchrecontype_source_only_via_searchsource_override(self):
        # ``MongoDBPassive.searchsource`` exists (overrides the
        # generic one inherited from ``MongoDB``) and delegates
        # to ``searchrecontype(source=…)``.
        from ivre.db.mongo import MongoDBPassive as M

        self.assertEqual(M.searchsource("cert"), {"source": "cert"})
        self.assertEqual(M.searchsource("cert", neg=True), {"source": {"$ne": "cert"}})
        # Equivalent to ``searchrecontype(source=…)``.
        self.assertEqual(M.searchsource("cert"), M.searchrecontype(source="cert"))

    def test_searchrecontype_degenerate_returns_match_all_or_none(self):
        # No fields specified: positive matches everything (the
        # canonical empty filter), negative matches nothing
        # (``searchnonexistent``).
        from ivre.db.mongo import MongoDBPassive as M

        self.assertEqual(M.searchrecontype(), {})
        # Match-none filter: any non-empty dict that no real
        # passive record can satisfy. We only assert it is
        # non-empty so this test does not couple to the exact
        # ``searchnonexistent`` implementation detail.
        self.assertNotEqual(M.searchrecontype(neg=True), {})

    def test_source_dispatch_falls_back_to_searchsource_on_active(self):
        # View / Active backends do not expose ``searchrecontype``;
        # the parser keeps using the legacy ``searchsource`` for
        # those sections, with the colon-bearing value passed
        # verbatim as a regex match (no tuple split).
        from ivre.web import utils as webutils

        class _ActiveDB:
            calls: list = []
            flt_empty = {}

            @staticmethod
            def flt_and(*args):
                return args[-1] if args else _ActiveDB.flt_empty

            @staticmethod
            def searchsource(value, neg=False):
                _ActiveDB.calls.append(("searchsource", value, neg))
                return {"source": value, "neg": neg}

        _ActiveDB.calls = []
        with mock.patch.object(
            webutils, "get_init_flt", return_value=_ActiveDB.flt_empty
        ):
            query = webutils.query_from_params({"q": "source:cert"})
            webutils.flt_from_query(_ActiveDB, query, base_flt=_ActiveDB.flt_empty)
        self.assertEqual(
            _ActiveDB.calls,
            [("searchsource", "cert", False)],
        )


# ---------------------------------------------------------------------
# MongoDBSearchFieldTests -- the shared ``MongoDB._search_field``
# helper and a sample of the search methods refactored to use it.
# All assertions check the produced MongoDB expression literally;
# the refactor is required to be wire-shape preserving (the file
# has many hand-written ``$ne`` / ``$nin`` / ``$not`` ladders that
# this helper now replaces, and the goal is an identical query).
# ---------------------------------------------------------------------


class MongoDBSearchFieldTests(unittest.TestCase):
    """Pin the shared ``_search_field`` dispatch and the wire
    shape of the search methods that delegate to it. Behaviour
    must match the legacy hand-written ladders bit-for-bit so
    DocumentDB and any external tooling inspecting
    ``find().explain()`` output see no change."""

    @staticmethod
    def _M():
        from ivre.db.mongo import MongoDB

        return MongoDB

    @staticmethod
    def _MA():
        from ivre.db.mongo import MongoDBActive

        return MongoDBActive

    @staticmethod
    def _MV():
        from ivre.db.mongo import MongoDBView

        return MongoDBView

    @staticmethod
    def _MP():
        from ivre.db.mongo import MongoDBPassive

        return MongoDBPassive

    @staticmethod
    def _MR():
        from ivre.db.mongo import MongoDBRir

        return MongoDBRir

    def test_search_field_scalar_positive(self):
        self.assertEqual(self._M()._search_field("source", "X"), {"source": "X"})

    def test_search_field_scalar_negative(self):
        self.assertEqual(
            self._M()._search_field("source", "X", neg=True),
            {"source": {"$ne": "X"}},
        )

    def test_search_field_list_positive(self):
        self.assertEqual(
            self._M()._search_field("source", ["A", "B"]),
            {"source": {"$in": ["A", "B"]}},
        )

    def test_search_field_list_negative(self):
        self.assertEqual(
            self._M()._search_field("source", ["A", "B"], neg=True),
            {"source": {"$nin": ["A", "B"]}},
        )

    def test_search_field_list_of_one_collapses_to_scalar(self):
        # The legacy ladders carefully collapse single-element
        # lists down to scalar form; the helper preserves that so
        # the wire shape never has redundant ``$in: [x]`` /
        # ``$nin: [x]`` clauses.
        self.assertEqual(
            self._M()._search_field("source", ["A"]),
            {"source": "A"},
        )
        self.assertEqual(
            self._M()._search_field("source", ["A"], neg=True),
            {"source": {"$ne": "A"}},
        )

    def test_search_field_regex_positive(self):
        pat = re.compile("^foo")
        self.assertEqual(
            self._M()._search_field("source", pat),
            {"source": pat},
        )

    def test_search_field_regex_negative(self):
        pat = re.compile("^foo")
        self.assertEqual(
            self._M()._search_field("source", pat, neg=True),
            {"source": {"$not": pat}},
        )

    def test_searchsource_active_delegates_to_helper(self):
        self.assertEqual(self._MA().searchsource("X"), {"source": "X"})
        self.assertEqual(
            self._MA().searchsource(["A", "B"], neg=True),
            {"source": {"$nin": ["A", "B"]}},
        )

    def test_searchcategory_legacy_shapes_preserved(self):
        self.assertEqual(self._MA().searchcategory("X"), {"categories": "X"})
        self.assertEqual(
            self._MA().searchcategory(["A"], neg=True),
            {"categories": {"$ne": "A"}},
        )
        self.assertEqual(
            self._MA().searchcategory(["A", "B"]),
            {"categories": {"$in": ["A", "B"]}},
        )
        pat = re.compile("admin")
        self.assertEqual(
            self._MA().searchcategory(pat, neg=True),
            {"categories": {"$not": pat}},
        )

    def test_searchdomain_passes_regex_negation(self):
        pat = re.compile("\\.example\\.com$")
        self.assertEqual(
            self._MA().searchdomain(pat, neg=True),
            {"hostnames.domains": {"$not": pat}},
        )

    def test_searchhostname_active_negation_shapes(self):
        # ``MongoDBActive.searchhostname``'s ``neg=True`` branch is
        # the canonical scalar/regex/None ladder over
        # ``hostnames.name`` (None means "no hostnames at all" via
        # ``hostnames.domains.$exists``). Pinned here so the
        # round-2 helper migration of that branch stays
        # wire-shape-identical.
        MA = self._MA()
        self.assertEqual(
            MA.searchhostname(neg=True),
            {"hostnames.domains": {"$exists": False}},
        )
        self.assertEqual(
            MA.searchhostname("host.example.com", neg=True),
            {"hostnames.name": {"$ne": "host.example.com"}},
        )
        pat = re.compile(r"\.example\.com$")
        self.assertEqual(
            MA.searchhostname(pat, neg=True),
            {"hostnames.name": {"$not": pat}},
        )

    def test_searchasnum_view_coercion_shapes(self):
        # ``MongoDBView.searchasnum`` accepts ``"AS1234"``, ``"1234"``,
        # ``1234``, lists thereof, and a regex. Pinning *before* the
        # round-2 migration that aligns View on the same
        # ``_coerce_asnum`` helper RIR uses.
        MV = self._MV()
        self.assertEqual(MV.searchasnum("AS1234"), {"infos.as_num": 1234})
        self.assertEqual(MV.searchasnum("1234"), {"infos.as_num": 1234})
        self.assertEqual(MV.searchasnum(1234), {"infos.as_num": 1234})
        self.assertEqual(
            MV.searchasnum(["AS1234", "AS5678"]),
            {"infos.as_num": {"$in": [1234, 5678]}},
        )
        self.assertEqual(
            MV.searchasnum("AS1234", neg=True),
            {"infos.as_num": {"$ne": 1234}},
        )
        self.assertEqual(
            MV.searchasnum(["AS1234", "AS5678"], neg=True),
            {"infos.as_num": {"$nin": [1234, 5678]}},
        )
        pat = re.compile(r"^12")
        self.assertEqual(MV.searchasnum(pat), {"infos.as_num": pat})

    def test_searchfileid_rir_scalar_shapes(self):
        # ``MongoDBRir.searchfileid`` is a degenerate scalar +
        # ``$ne`` ladder today. Pinning the wire shape *before*
        # the round-2 migration to ``_search_field`` (which
        # additionally lets callers pass lists / regexes — the
        # widening is deliberate and lossless for the legacy
        # scalar callers).
        MR = self._MR()
        self.assertEqual(MR.searchfileid("abc123"), {"source_hash": "abc123"})
        self.assertEqual(
            MR.searchfileid("abc123", neg=True),
            {"source_hash": {"$ne": "abc123"}},
        )

    def test_searchport_passive_shapes(self):
        # ``MongoDBPassive.searchport`` is the canonical scalar +
        # ``$ne`` ladder against the ``port`` field, with two
        # ``raise ValueError`` paths for the (currently
        # unsupported) ``protocol != "tcp"`` and
        # ``state != "open"`` arguments. Pinned before the
        # round-2 migration that lifts the scalar branch onto
        # ``_search_field``.
        MP = self._MP()
        self.assertEqual(MP.searchport(443), {"port": 443})
        self.assertEqual(MP.searchport(443, neg=True), {"port": {"$ne": 443}})
        with self.assertRaises(ValueError):
            MP.searchport(443, protocol="udp")
        with self.assertRaises(ValueError):
            MP.searchport(443, state="closed")

    def test_searchdns_passive_negation_shapes(self):
        # ``DBPassive.searchdomain`` / ``searchhostname`` /
        # ``searchdns`` accept ``neg=True`` (regression: the
        # ``flt_from_query`` filter parser calls them
        # unconditionally with ``neg=neg``, so any backend that
        # rejects the kwarg blows up the route — see ``/cgi/dns``
        # which queries both active and passive backends with the
        # same parsed filter set). The ``recontype == "DNS_ANSWER"``
        # constraint stays positive so the result remains scoped
        # to DNS records.
        MP = self._MP()
        # Scalar name + neg=True via searchdomain (subdomains=True).
        self.assertEqual(
            MP.searchdomain("example.com", neg=True),
            {"recontype": "DNS_ANSWER", "infos.domain": {"$ne": "example.com"}},
        )
        # Regex name + neg=True via searchhostname (subdomains=False).
        pat = re.compile("\\.example\\.com$")
        self.assertEqual(
            MP.searchhostname(pat, neg=True),
            {"recontype": "DNS_ANSWER", "value": {"$not": pat}},
        )
        # List of one collapses to scalar.
        self.assertEqual(
            MP.searchdomain(["example.com"], neg=True),
            {"recontype": "DNS_ANSWER", "infos.domain": {"$ne": "example.com"}},
        )
        # List of many uses ``$nin`` under negation, ``$in`` otherwise.
        self.assertEqual(
            MP.searchdomain(["a.com", "b.com"], neg=True),
            {"recontype": "DNS_ANSWER", "infos.domain": {"$nin": ["a.com", "b.com"]}},
        )
        self.assertEqual(
            MP.searchdomain(["a.com", "b.com"]),
            {"recontype": "DNS_ANSWER", "infos.domain": {"$in": ["a.com", "b.com"]}},
        )
        # Positive (neg=False) shape unchanged from the historical form.
        self.assertEqual(
            MP.searchdomain("example.com"),
            {"recontype": "DNS_ANSWER", "infos.domain": "example.com"},
        )
        self.assertEqual(
            MP.searchhostname(pat),
            {"recontype": "DNS_ANSWER", "value": pat},
        )
        # ``name=None`` (the "any DNS record" probe) ignores neg.
        self.assertEqual(MP.searchhostname(neg=True), {"recontype": "DNS_ANSWER"})
        # ``dnstype`` constraint stays positive even when negating
        # the name (the user is asking "DNS A records that are
        # not for example.com", not "any non-DNS-A record").
        # ``re.Pattern`` objects compare by identity, so unpack
        # the source pattern and compare it as a string.
        flt = MP.searchdns(name="example.com", dnstype="A", neg=True)
        source_re = flt.pop("source")
        self.assertEqual(
            flt,
            {
                "recontype": "DNS_ANSWER",
                "value": {"$ne": "example.com"},
            },
        )
        self.assertEqual(source_re.pattern, "^A-")

    def test_searchcity_legacy_shapes_preserved(self):
        # City lives on the View backend (GeoIP-enriched data).
        self.assertEqual(
            self._MV().searchcity("Carcassonne"),
            {"infos.city": "Carcassonne"},
        )
        self.assertEqual(
            self._MV().searchcity("Carcassonne", neg=True),
            {"infos.city": {"$ne": "Carcassonne"}},
        )

    def test_searchasname_legacy_shapes_preserved(self):
        # AS name lives on the View backend (GeoIP-enriched data).
        pat = re.compile("Cloudflare")
        self.assertEqual(self._MV().searchasname(pat), {"infos.as_name": pat})
        self.assertEqual(
            self._MV().searchasname(pat, neg=True),
            {"infos.as_name": {"$not": pat}},
        )

    def test_searchsensor_passive_legacy_shapes_preserved(self):
        self.assertEqual(self._MP().searchsensor("S"), {"sensor": "S"})
        self.assertEqual(
            self._MP().searchsensor(["A", "B"], neg=True),
            {"sensor": {"$nin": ["A", "B"]}},
        )

    def test_searchsourcefile_rir_legacy_shapes_preserved(self):
        # ``source_file`` filters live on the RIR backend (the
        # provenance of inetnum dumps).
        self.assertEqual(
            self._MR().searchsourcefile("/tmp/scan.xml"),
            {"source_file": "/tmp/scan.xml"},
        )
        self.assertEqual(
            self._MR().searchsourcefile(["a", "b"]),
            {"source_file": {"$in": ["a", "b"]}},
        )

    def test_searchsource_passive_routes_through_searchrecontype(self):
        # Cross-check that the passive override still produces
        # a single-field clause via the shared helper (no
        # ``$nor`` wrapping for the bare-source case).
        self.assertEqual(self._MP().searchsource("cert"), {"source": "cert"})
        self.assertEqual(
            self._MP().searchsource("cert", neg=True),
            {"source": {"$ne": "cert"}},
        )


# ---------------------------------------------------------------------
# DnsMergeTests -- the cross-backend ``(name, addr)`` pseudo-record
# merge helper used by both the ``ivre iphost`` CLI and the
# ``/cgi/dns`` web endpoint.
# ---------------------------------------------------------------------


class MongoDBRirSearchTests(unittest.TestCase):
    """Pin the wire shape of the RIR-specific search methods on
    ``MongoDBRir`` (``searchnet``, ``searchrange``, ``searchasnum``,
    ``searchasname``, ``searchsourcefile``) and the schema-v1→v2
    ``size`` backfill. The active assertion target is the Mongo
    filter dict / Decimal128 value, so no backend connection is
    required.
    """

    @staticmethod
    def _MR():
        from ivre.db.mongo import MongoDBRir

        return MongoDBRir

    def test_searchsourcefile_uses_search_field(self):
        # Wire shape pinned bit-for-bit; ``searchsourcefile`` is a
        # one-line delegation to the ``_search_field`` helper, which
        # in turn dispatches the scalar/list/regex/neg ladder.
        MR = self._MR()
        self.assertEqual(
            MR.searchsourcefile("ripe.db.inetnum.gz"),
            {"source_file": "ripe.db.inetnum.gz"},
        )
        self.assertEqual(
            MR.searchsourcefile("apnic.db.inetnum.gz", neg=True),
            {"source_file": {"$ne": "apnic.db.inetnum.gz"}},
        )
        pat = re.compile(r"^ripe\.")
        self.assertEqual(
            MR.searchsourcefile(pat),
            {"source_file": pat},
        )

    def test_searchnet_overlap_semantics(self):
        # ``searchnet`` matches every record whose ``(start, stop)``
        # range overlaps with the queried network at all (not just
        # records that fully contain it). The filter is composed of
        # two AND-ed clauses: ``record.start <= net.stop`` and
        # ``record.stop >= net.start``, each expressed via the
        # dual-key compare idiom that stays index-friendly on
        # (start_0, stop_0, start_1, stop_1).
        MR = self._MR()
        flt = MR.searchnet("192.0.2.0/24")
        self.assertIn("$and", flt)
        clauses = flt["$and"]
        self.assertEqual(len(clauses), 2)
        # First clause: record.start <= net.stop (192.0.2.255).
        # Second clause: record.stop >= net.start (192.0.2.0).
        # Both must use $or with start_0/stop_0 dual-key compares.
        for clause in clauses:
            self.assertIn("$or", clause)
        # neg=True is rejected (mirrors searchhost); the route /
        # web layer should never reach this with neg=True.
        with self.assertRaises(ValueError):
            MR.searchnet("192.0.2.0/24", neg=True)

    def test_searchrange_overlap_semantics(self):
        # Two-endpoint form of the overlap query. Same shape as
        # ``searchnet`` (both delegate to ``_searchrange_overlap``).
        MR = self._MR()
        flt = MR.searchrange("10.0.0.1", "10.0.0.255")
        self.assertIn("$and", flt)
        with self.assertRaises(ValueError):
            MR.searchrange("10.0.0.1", "10.0.0.255", neg=True)

    def test_searchasnum_coerces_string_and_list(self):
        # ``aut-num`` is stored as int; the helper accepts the common
        # operator-typed forms ("AS1234", "1234", 1234, lists) and
        # coerces them. Regex passes through unchanged.
        MR = self._MR()
        self.assertEqual(MR.searchasnum("AS1234"), {"aut-num": 1234})
        self.assertEqual(MR.searchasnum("1234"), {"aut-num": 1234})
        self.assertEqual(MR.searchasnum(1234), {"aut-num": 1234})
        self.assertEqual(
            MR.searchasnum(["AS1234", "AS5678"]),
            {"aut-num": {"$in": [1234, 5678]}},
        )
        self.assertEqual(
            MR.searchasnum("AS1234", neg=True),
            {"aut-num": {"$ne": 1234}},
        )
        pat = re.compile(r"^12")
        self.assertEqual(MR.searchasnum(pat), {"aut-num": pat})

    def test_searchasname_uses_search_field(self):
        MR = self._MR()
        self.assertEqual(MR.searchasname("Cloudflare"), {"as-name": "Cloudflare"})
        self.assertEqual(
            MR.searchasname("Cloudflare", neg=True),
            {"as-name": {"$ne": "Cloudflare"}},
        )
        pat = re.compile(r"Cloud")
        self.assertEqual(MR.searchasname(pat), {"as-name": pat})

    def test_compute_rir_size_inetnum_v4(self):
        # /24 IPv4: 256 addresses (inclusive). Round-trip the IVRE
        # internal-IP halves through ``_compute_rir_size`` and
        # check the Decimal128 value.
        import bson

        MR = self._MR()
        start_0, start_1 = MR.ip2internal("192.0.2.0")
        stop_0, stop_1 = MR.ip2internal("192.0.2.255")
        size = MR._compute_rir_size(
            {
                "start_0": start_0,
                "start_1": start_1,
                "stop_0": stop_0,
                "stop_1": stop_1,
            }
        )
        self.assertIsInstance(size, bson.Decimal128)
        self.assertEqual(int(size.to_decimal()), 256)

    def test_compute_rir_size_inetnum_v4_single_host(self):
        # /32 single-host: size == 1.
        MR = self._MR()
        start_0, start_1 = MR.ip2internal("192.0.2.42")
        stop_0, stop_1 = MR.ip2internal("192.0.2.42")
        size = MR._compute_rir_size(
            {
                "start_0": start_0,
                "start_1": start_1,
                "stop_0": stop_0,
                "stop_1": stop_1,
            }
        )
        self.assertEqual(int(size.to_decimal()), 1)

    def test_compute_rir_size_inet6num_huge_range(self):
        # IPv6 /48: 2**80 addresses. Decimal128 has 34-decimal-digit
        # precision; 2**80 = 1208925819614629174706176 (22 digits)
        # fits losslessly. Confirms we don't accidentally truncate.
        MR = self._MR()
        start_0, start_1 = MR.ip2internal("2001:db8::")
        stop_0, stop_1 = MR.ip2internal("2001:db8:0:ffff:ffff:ffff:ffff:ffff")
        size = MR._compute_rir_size(
            {
                "start_0": start_0,
                "start_1": start_1,
                "stop_0": stop_0,
                "stop_1": stop_1,
            }
        )
        self.assertEqual(int(size.to_decimal()), 2**80)

    def test_compute_rir_size_autnum_returns_none(self):
        # ``aut-num`` records carry no range and therefore no
        # ``size``. The helper signals this with ``None``; the
        # sparse index on ``size`` then ignores them.
        MR = self._MR()
        self.assertIsNone(MR._compute_rir_size({"aut-num": 1234, "as-name": "Example"}))

    def test_serialize_decimal128_small_value_as_int(self):
        # Wire shape for the new ``size`` field: small enough to be
        # a JS-safe integer → emit as a JSON number directly.
        import bson

        from ivre import utils

        self.assertEqual(utils.serialize(bson.Decimal128("256")), 256)
        # 2**32 (a /0 IPv4 range) — well within JS safe integer.
        self.assertEqual(utils.serialize(bson.Decimal128(str(2**32))), 2**32)

    def test_serialize_decimal128_huge_value_as_string(self):
        # IPv6 ranges wider than /74 overflow JS safe integer
        # (2**53 - 1) and would silently lose precision if emitted
        # as a JSON number; downgrade to a string in that case.
        import bson

        from ivre import utils

        out = utils.serialize(bson.Decimal128(str(2**80)))
        self.assertIsInstance(out, str)
        self.assertEqual(int(out), 2**80)


class DnsMergeTests(unittest.TestCase):
    """Tests for ``ivre.utils.merge_dns_results``: the helper
    that folds two ``(name, addr) -> {types, sources, firstseen,
    lastseen, count}`` mappings together. Both backends'
    ``iter_dns`` methods produce inputs in this shape (active
    via ``DBActive.iter_dns``, passive via
    ``DBPassive.iter_dns``); the helper merges them by union-ing
    the ``types`` / ``sources`` sets, summing the ``count``, and
    extending the ``firstseen`` / ``lastseen`` interval.
    """

    @staticmethod
    def _record(*, types, sources, firstseen, lastseen, count):
        return {
            "types": set(types),
            "sources": set(sources),
            "firstseen": firstseen,
            "lastseen": lastseen,
            "count": count,
        }

    def test_empty_merge_into_empty_is_no_op(self):
        target: dict = {}
        ivre.utils.merge_dns_results(target, {})
        self.assertEqual(target, {})

    def test_merge_into_empty_target_copies_each_key(self):
        source = {
            ("example.com", "1.2.3.4"): self._record(
                types=["A"],
                sources=["sensor1"],
                firstseen=100,
                lastseen=200,
                count=5,
            ),
        }
        target: dict = {}
        ivre.utils.merge_dns_results(target, source)
        self.assertEqual(set(target), {("example.com", "1.2.3.4")})
        merged = target[("example.com", "1.2.3.4")]
        self.assertEqual(merged["types"], {"A"})
        self.assertEqual(merged["sources"], {"sensor1"})
        self.assertEqual(merged["firstseen"], 100)
        self.assertEqual(merged["lastseen"], 200)
        self.assertEqual(merged["count"], 5)

    def test_merge_unions_types_and_sources(self):
        target = {
            ("example.com", "1.2.3.4"): self._record(
                types=["A"],
                sources=["sensor1"],
                firstseen=100,
                lastseen=200,
                count=5,
            ),
        }
        ivre.utils.merge_dns_results(
            target,
            {
                ("example.com", "1.2.3.4"): self._record(
                    types=["PTR", "user"],
                    sources=["scan-2024-Q1"],
                    firstseen=50,
                    lastseen=300,
                    count=2,
                ),
            },
        )
        merged = target[("example.com", "1.2.3.4")]
        self.assertEqual(merged["types"], {"A", "PTR", "user"})
        self.assertEqual(merged["sources"], {"sensor1", "scan-2024-Q1"})

    def test_merge_extends_firstseen_lastseen_interval(self):
        target = {
            ("example.com", "1.2.3.4"): self._record(
                types=["A"],
                sources=[],
                firstseen=100,
                lastseen=200,
                count=1,
            ),
        }
        ivre.utils.merge_dns_results(
            target,
            {
                ("example.com", "1.2.3.4"): self._record(
                    types=["A"],
                    sources=[],
                    firstseen=50,
                    lastseen=150,
                    count=1,
                ),
            },
        )
        merged = target[("example.com", "1.2.3.4")]
        self.assertEqual(merged["firstseen"], 50)
        self.assertEqual(merged["lastseen"], 200)

    def test_merge_sums_count(self):
        target = {
            ("example.com", "1.2.3.4"): self._record(
                types=["A"],
                sources=[],
                firstseen=100,
                lastseen=200,
                count=120,
            ),
        }
        ivre.utils.merge_dns_results(
            target,
            {
                ("example.com", "1.2.3.4"): self._record(
                    types=["A"],
                    sources=[],
                    firstseen=100,
                    lastseen=200,
                    count=5,
                ),
            },
        )
        self.assertEqual(target[("example.com", "1.2.3.4")]["count"], 125)

    def test_merge_keeps_disjoint_keys_separate(self):
        target = {
            ("a.example", "1.2.3.4"): self._record(
                types=["A"],
                sources=["sensor1"],
                firstseen=100,
                lastseen=200,
                count=1,
            ),
        }
        ivre.utils.merge_dns_results(
            target,
            {
                ("b.example", "5.6.7.8"): self._record(
                    types=["AAAA"],
                    sources=["sensor2"],
                    firstseen=300,
                    lastseen=400,
                    count=2,
                ),
            },
        )
        self.assertEqual(
            set(target), {("a.example", "1.2.3.4"), ("b.example", "5.6.7.8")}
        )

    def test_merge_tolerates_records_without_count(self):
        # Defensive: legacy callers (older ``iphost`` versions)
        # may pass records lacking the ``count`` key. The helper
        # treats them as ``count=0`` rather than raising.
        target: dict = {}
        ivre.utils.merge_dns_results(
            target,
            {
                ("example.com", "1.2.3.4"): {
                    "types": set(),
                    "sources": set(),
                    "firstseen": 100,
                    "lastseen": 200,
                },
            },
        )
        self.assertEqual(target[("example.com", "1.2.3.4")]["count"], 0)


# ---------------------------------------------------------------------
# WebModulesTests -- WEB_MODULES allowlist & per-module backend gating
# ---------------------------------------------------------------------


class WebModulesTests(unittest.TestCase):
    """Pin the behaviour of ``ivre.web.modules`` (the helper that
    decides which data sections the web layer exposes). The result
    is the intersection of the operator's ``WEB_MODULES``
    allowlist (``None`` means "all") and the
    backends actually configured (``db.<purpose> is not None``).

    The tests stub ``MetaDB`` properties directly so no real
    backend connection is required.
    """

    _PURPOSES = ("view", "nmap", "passive", "rir", "flow", "data", "auth")

    def setUp(self):
        # Save state we mutate.
        from ivre import config
        from ivre.db import db

        self._saved_web_modules = config.WEB_MODULES
        # ``MetaDB`` caches each ``db.<purpose>`` result on
        # ``self._<purpose>``. Save the existing values (most
        # likely ``AttributeError`` in a fresh process) so we
        # can restore them in tearDown.
        self._saved_attrs: dict[str, object] = {}
        for purpose in self._PURPOSES:
            attr = f"_{purpose}"
            if hasattr(db, attr):
                self._saved_attrs[attr] = getattr(db, attr)
        # Default presence: every purpose configured. Tests
        # that need an absent backend call ``self._set(...)``.
        for purpose in self._PURPOSES:
            setattr(db, f"_{purpose}", _BACKEND_SENTINEL)

    def tearDown(self):
        from ivre import config
        from ivre.db import db

        config.WEB_MODULES = self._saved_web_modules
        for purpose in self._PURPOSES:
            attr = f"_{purpose}"
            try:
                delattr(db, attr)
            except AttributeError:
                pass
            if attr in self._saved_attrs:
                setattr(db, attr, self._saved_attrs[attr])

    def _set(self, **presence):
        """Force selected ``db.<purpose>`` properties to either
        the test sentinel (``True``) or ``None`` (``False``)."""
        from ivre.db import db

        for purpose, present in presence.items():
            setattr(db, f"_{purpose}", _BACKEND_SENTINEL if present else None)

    def test_default_all_backends_present_returns_all(self):
        from ivre import config
        from ivre.web.modules import ALL_MODULES, enabled_modules

        config.WEB_MODULES = None
        self.assertEqual(enabled_modules(), list(ALL_MODULES))

    def test_default_passive_absent_drops_passive_only(self):
        # ``dns`` is the special case: it survives as long as
        # *one* of nmap or passive is configured.
        from ivre import config
        from ivre.web.modules import enabled_modules

        config.WEB_MODULES = None
        self._set(passive=False)
        self.assertEqual(
            enabled_modules(),
            ["view", "active", "dns", "rir", "flow"],
        )

    def test_default_both_dns_backends_absent_drops_dns(self):
        # Neither nmap nor passive => dns module disappears too.
        from ivre import config
        from ivre.web.modules import enabled_modules

        config.WEB_MODULES = None
        self._set(nmap=False, passive=False)
        self.assertEqual(enabled_modules(), ["view", "rir", "flow"])

    def test_default_only_nmap_keeps_dns(self):
        from ivre import config
        from ivre.web.modules import enabled_modules

        config.WEB_MODULES = None
        self._set(passive=False, view=False, rir=False, flow=False)
        # Active alone keeps DNS alive (nmap branch of the
        # cross-backend rule).
        self.assertEqual(enabled_modules(), ["active", "dns"])

    def test_default_only_passive_keeps_dns(self):
        from ivre import config
        from ivre.web.modules import enabled_modules

        config.WEB_MODULES = None
        self._set(nmap=False, view=False, rir=False, flow=False)
        # Passive alone keeps DNS alive (passive branch).
        self.assertEqual(enabled_modules(), ["passive", "dns"])

    def test_explicit_empty_list_returns_empty(self):
        from ivre import config
        from ivre.web.modules import enabled_modules

        config.WEB_MODULES = []
        self.assertEqual(enabled_modules(), [])

    def test_explicit_allowlist_intersects_with_backends(self):
        from ivre import config
        from ivre.web.modules import enabled_modules

        config.WEB_MODULES = ["view", "passive", "rir"]
        self._set(passive=False)  # not in DBs
        self.assertEqual(enabled_modules(), ["view", "rir"])

    def test_explicit_allowlist_canonical_order(self):
        # Order is canonical (the ``ALL_MODULES`` order), not the
        # order the operator wrote in ``WEB_MODULES``. This makes
        # the value emitted by ``/cgi/config`` diffable in
        # operator runbooks and stable in tests.
        from ivre import config
        from ivre.web.modules import enabled_modules

        config.WEB_MODULES = ["rir", "view", "active"]
        self.assertEqual(enabled_modules(), ["view", "active", "rir"])

    def test_explicit_allowlist_unknown_name_filtered(self):
        # Unknown module names in ``WEB_MODULES`` (typos, future
        # modules an older deployment doesn't know about) are
        # silently dropped — the canonical set is fixed by code,
        # not by config.
        from ivre import config
        from ivre.web.modules import enabled_modules

        config.WEB_MODULES = ["view", "made-up-module"]
        self.assertEqual(enabled_modules(), ["view"])

    def test_is_module_enabled_consistent_with_enabled_modules(self):
        from ivre import config
        from ivre.web.modules import enabled_modules, is_module_enabled

        config.WEB_MODULES = ["view", "rir"]
        self._set(rir=False)
        self.assertTrue(is_module_enabled("view"))
        self.assertFalse(is_module_enabled("rir"))
        self.assertFalse(is_module_enabled("active"))
        # Sanity-check: ``is_module_enabled`` agrees with the
        # ``enabled_modules`` set bit-for-bit.
        for m in ("view", "active", "passive", "dns", "rir", "flow"):
            self.assertEqual(
                is_module_enabled(m),
                m in enabled_modules(),
            )

    def test_require_module_aborts_404_when_disabled(self):
        from ivre import config
        from ivre.web.modules import require_module

        config.WEB_MODULES = ["view"]

        # ``require_module`` raises ``bottle.HTTPError`` (the
        # type ``bottle.abort`` raises) with status 404 when the
        # module is not exposed. The status code matters: 404
        # makes a direct probe look like a missing endpoint.
        try:
            require_module("rir")
        except Exception as exc:
            self.assertEqual(getattr(exc, "status_code", None), 404)
        else:
            self.fail("require_module should have aborted")

    def test_require_module_passes_when_enabled(self):
        from ivre import config
        from ivre.web.modules import require_module

        config.WEB_MODULES = None
        # No exception expected when every backend is wired.
        require_module("view")


class _BackendSentinel:
    """Sentinel ``MetaDB.get_class`` returns when a given purpose
    is "configured" in the test harness above. The web-module
    helpers only check ``is not None`` so any non-None value
    works — using a dedicated sentinel makes tracebacks clearer
    if a test accidentally calls a method on the fake."""


_BACKEND_SENTINEL = _BackendSentinel()


# ---------------------------------------------------------------------
# UtilsTests -- moved verbatim from tests/tests.py::IvreTests.test_utils
# ---------------------------------------------------------------------


class UtilsTests(unittest.TestCase):
    """Catch-all regression tests for ``ivre`` utility functions,
    parsers, and CLI tools that do not need a database backend.

    Historically a single ``test_utils`` method on ``IvreTests`` in
    ``tests/tests.py``; moved here to (a) make it runnable without a
    configured backend, and (b) decouple it from the long-running
    backend-specific test suite.
    """

    maxDiff = None

    def setUp(self):
        try:
            with open(os.path.join(SAMPLES, "results")) as fdesc:
                self.results = {
                    line[: line.index(" = ")]: literal_eval(
                        line[line.index(" = ") + 3 : -1]
                    )
                    for line in fdesc
                    if " = " in line
                }
        except IOError as exc:
            if exc.errno != errno.ENOENT:
                raise exc
            self.results = {}
        self.new_results: set[str] = set()
        self.used_prefixes: set[str] = set()
        self.unused_results = set(self.results)

    def tearDown(self):
        ivre.utils.cleandir("logs")
        ivre.utils.cleandir(".state")
        if self.new_results:
            with open(os.path.join(SAMPLES, "results"), "a") as fdesc:
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
        self.used_prefixes.add(name.split("_", 1)[0] + "_")
        if name not in self.results:
            self.results[name] = value
            sys.stderr.write("NEW VALUE for key %r: %r\n" % (name, value))
            self.new_results.add(name)
        try:
            check(value, self.results[name])
        except AssertionError:
            print(
                f"check_value() fail for {name}: got {value!r}, "
                f"expected {self.results[name]!r}"
            )
            raise

    def test_utils(self):
        """Functions that have not yet been tested"""

        self.assertIsNotNone(ivre.config.guess_prefix("zeek"))
        self.assertIsNone(ivre.config.guess_prefix("inexistent"))

        # Version / help
        res, out1, err = RUN(["ivre"])
        self.assertEqual(res, 0)
        self.assertFalse(err)
        res, out2, err = RUN(["ivre", "help"])
        self.assertEqual(res, 0)
        self.assertFalse(err)
        self.assertEqual(out1, out2)
        res, _, err = RUN(["ivre", "version"])
        self.assertEqual(res, 0)
        self.assertFalse(err)
        res, _, _ = RUN(["ivre", "inexistent"])
        self.assertTrue(res)

        # IP addresses manipulation utils
        with self.assertRaises(ValueError):
            list(ivre.utils.range2nets((2, 1)))

        # Special cases for range2nets & net2range
        self.assertEqual(
            list(ivre.utils.range2nets(("0.0.0.0", "255.255.255.255"))), ["0.0.0.0/0"]
        )
        self.assertEqual(
            ivre.utils.net2range("0.0.0.0/0"), ("0.0.0.0", "255.255.255.255")
        )
        self.assertEqual(
            ivre.utils.net2range("::ffff:ffff:ffff:ffff/80"),
            ("::ffff:0:0:0", "::ffff:ffff:ffff:ffff"),
        )
        self.assertEqual(
            ivre.utils.net2range("192.168.0.0/255.255.255.0"),
            ("192.168.0.0", "192.168.0.255"),
        )
        self.assertEqual(
            ivre.utils.net2range("::/48"), ("::", "::ffff:ffff:ffff:ffff:ffff")
        )

        # String utils
        teststr = b"TEST STRING -./*'"
        self.assertEqual(ivre.utils.regexp2pattern(teststr), (re.escape(teststr), 0))
        self.assertEqual(
            ivre.utils.regexp2pattern(re.compile(b"^" + re.escape(teststr) + b"$")),
            (re.escape(teststr), 0),
        )
        self.assertEqual(
            ivre.utils.regexp2pattern(re.compile(re.escape(teststr))),
            (b".*" + re.escape(teststr) + b".*", 0),
        )
        self.assertEqual(ivre.utils.str2list(teststr), teststr)
        teststr = "1,2|3"
        self.assertCountEqual(ivre.utils.str2list(teststr), ["1", "2", "3"])
        self.assertTrue(ivre.utils.isfinal(1))
        self.assertTrue(ivre.utils.isfinal("1"))
        self.assertFalse(ivre.utils.isfinal([]))
        self.assertFalse(ivre.utils.isfinal({}))

        # Nmap ports
        ports = [1, 3, 2, 4, 6, 80, 5, 5, 110, 111]
        self.assertEqual(
            set(ports), ivre.utils.nmapspec2ports(ivre.utils.ports2nmapspec(ports))
        )
        self.assertEqual(ivre.utils.ports2nmapspec(ports), "1-6,80,110-111")

        # Nmap fingerprints
        match = ivre.utils.match_nmap_svc_fp(
            b"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u7\r\n"
        )
        self.assertEqual(match["service_name"], "ssh")
        self.assertEqual(match["service_extrainfo"], "protocol 2.0")
        self.assertEqual(match["service_ostype"], "Linux")
        self.assertEqual(match["service_product"], "OpenSSH")
        self.assertEqual(match["service_version"], "6.0p1 Debian 4+deb7u7")
        match = ivre.utils.match_nmap_svc_fp(
            b"HTTP/1.1 400 Bad Request\r\n"
            b"Date: Sun, 22 Apr 2018 12:21:46 GMT\r\n"
            b"Server: Apache/2.4.10 (Debian)\r\n"
            b"Content-Length: 312\r\n"
            b"Connection: close\r\n"
            b"Content-Type: text/html; charset=iso-8859-1\r\n",
            probe="GetRequest",
        )
        self.assertEqual(match["service_name"], "http")
        self.assertEqual(match["service_extrainfo"], "(Debian)")
        self.assertEqual(match["service_product"], "Apache httpd")
        self.assertEqual(match["service_version"], "2.4.10")
        match = ivre.utils.match_nmap_svc_fp(
            b"220 localhost.localdomain ESMTP Server (Microsoft Exchange "
            b"Internet Mail Service 5.5.2653.13) ready\n"
        )
        self.assertEqual(match["service_name"], "smtp")
        self.assertEqual(match["service_hostname"], "localhost.localdomain")
        self.assertEqual(match["service_ostype"], "Windows")
        self.assertEqual(match["service_product"], "Microsoft Exchange smtpd")
        self.assertEqual(match["service_version"], "5.5.2653.13")

        # Nmap (and Zeek) encoding & decoding
        # >>> from random import randint
        # >>> bytes(randint(0, 255) for _ in range(1000))
        raw_data = (
            b'\xc6\x97\x05\xc8\x16\x96\xaei\xe9\xdd\xe8"\x07\x16\x15\x8c\xf5'
            b"%x\xb0\x00\xb4\xbcv\xb8A\x19\xefj+RbgH}U\xec\xb4\x1bZ\x08\xd4"
            b"\xfe\xca\x95z\xa0\x0cB\xabWM\xf1\xfd\x95\xb7)\xbb\xe9\xa7\x8a"
            b"\x08]\x8a\xcab\xb3\x1eI\xc0Q0\xec\xd0\xd4\xd4bt\xf7\xbb1\xc5"
            b"\x9c\x85\xf8\x87\x8b\xb2\x87\xed\x82R\xf9}+\xfc\xa4\xf2?\xa5"
            b"}\x17k\xa6\xb6t\xab\x91\x91\x83?\xb4\x01L\x1fO\xff}\x98j\xa5"
            b"\x9a\t,\xf3\x8b\x1e\xf4\xd3~\x83\x87\x0b\x95\\\xa9\xaa\xfbi5"
            b"\xfb\xaau\xc6y\xff\xac\xcb'\xa5\xf4y\x8f\xab\xf2\x04Z\xf1\xd7"
            b"\x08\x17\xa8\xa5\xe4\x04\xa5R0\xdb\xa3\xe6\xc0\x88\x9a\xee"
            b"\x93\x8c\x8a\x8b\xa3\x03\xb6\xdf\xbbHp\x1f\x1d{\x92\xb2\xd7B"
            b"\xc4\x13\xddD\xb29\xbd\x0f\xd8\xed\x94q\xda\x00\x067\xd8T\xb3"
            b"I\xd3\x88/wE\xd4C\xec!\xf6 <H\xaa\xea\xc1;\x90\x87)\xc5\xb6"
            b"\xd6\n\x81r\x16\xa1/\xd0Q<\xa4jT\x0f\xe4\xad\x14>0\xf1\xb7"
            b'\xec\x08\x7f>"\x96P\xd2;\xc4:\xed\xc0\xcb\x85M\x04&{|k\xd0'
            b"\x06Yc_\x12S\xb0>\xe0=:\xca1\xca\n\xcb.\xf4\xe2\xb1e\x0e\x16"
            b"\xd6\x8c\xbc!\xbcWd\x19\x0b\xd7\xa0\xed\x1d>$%\xf7\xfb\xc2("
            b"\xef\x13\x82\xcc\xa5\xecc\x1fy_\x9f93\xbcPv\xd7\x9b\xbb\x0b]"
            b"\x9a\xc7\xbd&5\xb2\x85\x95\xfb\xf2j\x11f\xd8\xdb\x03\xc0\xb1"
            b"\xda\x08aF\x80\xd8\x18\x7f\xf3\x86N\x91\xa6\xd4i\x83\xd4*$_t"
            b"\x19\xb3\xa2\x187w2 \x0c#\xe5\xca\x03\xb3@H\xb7\xfb,a\xb8\x02"
            b"\xe4;/\xc11\xb7\xd8\xdd\x9b\xcc\xdcg\xb4\x9f\x81\x10,\x0e\x0c"
            b"'_m\xf8$\xa10\xc4\xe9\xc5G_\x14\x10\xf5& \xcf\xa8\x10:\xee"
            b"\x1aGL\x966\xd7\x1d?\xb0:\xee\x11\x89\xb9\xeb\x8d\xf7\x02\x00"
            b"\xdb\xd9/\x8a\x01!\xa5wRc?\xfd\x87\x11E\xa9\x8f\x9ed\x0f.\xff"
            b'M\xd1\xb4\xe9\x19\xb0\xb0"\xac\x84\xff5D\xa9\x12O\xcc1G#\xb5'
            b'\x16\xba%{:\xde\xf6\t"\xe7\xed\xa0*\xa3\x89\xabl\x08p\x1d'
            b"\xc1\xae\x14e)\xf3=\x16\x80\xa8\x1b\xe3OSD&V\x16\xf3*\x8416"
            b"\xdd6\xe6\xbf,R$\x93s>\x87\xbe\x94\x1c\x10\\o,\xc2\x18ig\xa2"
            b"\xf7\xc9\x9d|\x8c\xc6\x94\\\xee\xb0'\x01\x1c\x94\xf8\xea\xda"
            b"\x91\xf1 \x8cP\x84=\xa0\x1a\x87\xba\xa8\x9c\xd6\xf7\n'\x99"
            b"\xb9\xd5L\xd2u\x7f\x13\xf3^_T\xc3\x806\x94\xbe\x94\xee\x0cJ`"
            b"\xba\xf1\n*\xc2\xc7?[\xa7\xdd\xcbX\x08\xafTsU\x81\xa5r\x86Q"
            b"\x1b8\xcf\xc8\xab\xf1\x1e\xee,i\x15:*\xb4\x84\x01\xc0\x8f\xb3"
        )
        encoded_data = ivre.utils.nmap_encode_data(raw_data)
        # The exact encoded representations are quite long; we
        # round-trip through the decoder to ensure the output is the
        # original bytes again. The Nmap and Zeek encoders differ in
        # how they escape a few control bytes (e.g. \t / \n / \\), but
        # both are required to be the exact inverse of their decoder.
        self.assertEqual(ivre.utils.nmap_decode_data(encoded_data), raw_data)
        encoded_data = ivre.utils.zeek_encode_data(raw_data)
        self.assertEqual(ivre.utils.nmap_decode_data(encoded_data), raw_data)
        # Specific Nmap representation for null bytes & escape random
        # chars (used in nmap-service-probes)
        self.assertEqual(
            ivre.utils.nmap_decode_data("\\0\\#", arbitrary_escapes=True),
            b"\x00#",
        )
        self.assertEqual(
            ivre.utils.nmap_decode_data("\\0\\#"),
            b"\x00\\#",
        )

        # get_addr_type()
        # ipv4
        self.assertEqual(ivre.utils.get_addr_type("0.123.45.67"), "Current-Net")
        self.assertIsNone(ivre.utils.get_addr_type("8.8.8.8"))
        self.assertEqual(ivre.utils.get_addr_type("10.0.0.0"), "Private")
        self.assertIsNone(ivre.utils.get_addr_type("100.63.255.255"))
        self.assertEqual(ivre.utils.get_addr_type("100.67.89.123"), "CGN")
        self.assertEqual(ivre.utils.get_addr_type("239.255.255.255"), "Multicast")
        self.assertEqual(ivre.utils.get_addr_type("240.0.0.0"), "Reserved")
        self.assertEqual(ivre.utils.get_addr_type("255.255.255.254"), "Reserved")
        self.assertEqual(ivre.utils.get_addr_type("255.255.255.255"), "Broadcast")
        # ipv6
        self.assertEqual(ivre.utils.get_addr_type("::"), "Unspecified")
        self.assertEqual(ivre.utils.get_addr_type("::1"), "Loopback")
        self.assertIsNone(ivre.utils.get_addr_type("::ffff:8.8.8.8"))
        self.assertEqual(
            ivre.utils.get_addr_type("64:ff9b::8.8.8.8"), "Well-known prefix"
        )
        self.assertEqual(ivre.utils.get_addr_type("100::"), "Discard (RTBH)")
        self.assertEqual(ivre.utils.get_addr_type("2001::"), "Protocol assignments")
        self.assertIsNone(ivre.utils.get_addr_type("2001:4860:4860::8888"))
        self.assertEqual(ivre.utils.get_addr_type("2001:db8::db2"), "Documentation")
        self.assertEqual(ivre.utils.get_addr_type("fc00::"), "Unique Local Unicast")
        self.assertEqual(ivre.utils.get_addr_type("fe80::"), "Link Local Unicast")
        self.assertEqual(ivre.utils.get_addr_type("ff00::"), "Multicast")

        # ip2int() / int2ip()
        self.assertEqual(ivre.utils.ip2int("1.0.0.1"), (1 << 24) + 1)
        self.assertEqual(ivre.utils.int2ip((1 << 24) + 1), "1.0.0.1")
        self.assertEqual(ivre.utils.ip2int("::2:0:0:0:2"), (2 << 64) + 2)
        self.assertEqual(ivre.utils.int2ip((2 << 64) + 2), "::2:0:0:0:2")
        self.assertEqual(
            ivre.utils.int2ip6(0x1234567890ABCDEFFED0000000004321),
            "1234:5678:90ab:cdef:fed0::4321",
        )
        # ip2bin
        # unicode error
        self.assertEqual(
            ivre.utils.ip2bin(b"\x33\xe6\x34\x35"),
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff3\xe645",
        )
        with self.assertRaises(ValueError):
            ivre.utils.ip2bin(b"\xe6")
        # else case
        with self.assertRaises(ValueError):
            ivre.utils.ip2bin(b"23T")
        self.assertEqual(
            ivre.utils.ip2bin(b"23TT"),
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff23TT",
        )
        self.assertEqual(ivre.utils.ip2bin(b"T3STTESTTESTTEST"), b"T3STTESTTESTTEST")
        self.assertEqual(
            ivre.utils.ip2bin(b" \x01H`\x00\x00 \x01\x00\x00\x00\x00\x00\x00\x00h"),
            b" \x01H`\x00\x00 \x01\x00\x00\x00\x00\x00\x00\x00h",
        )
        # str2pyval
        self.assertEqual(ivre.utils.str2pyval("{'test': 0}"), {"test": 0})
        self.assertEqual(ivre.utils.str2pyval("{'test: 0}"), "{'test: 0}")
        # all2datetime
        # NOTICE : compared to datetime.utcfromtimestamp
        self.assertEqual(
            ivre.utils.all2datetime(1410532663), datetime(2014, 9, 12, 14, 37, 43)
        )
        self.assertEqual(
            ivre.utils.all2datetime(1410532663.0), datetime(2014, 9, 12, 14, 37, 43)
        )

        # fields2csv_head
        self.assertCountEqual(
            ivre.utils.fields2csv_head(
                {
                    "field": {
                        "subfield": {
                            "subsubfield": True,
                            "subsubfunc": lambda: None,
                            "notsubsubfield": False,
                        }
                    }
                }
            ),
            ["field.subfield.subsubfield", "field.subfield.subsubfunc"],
        )
        # doc2csv
        self.assertCountEqual(
            ivre.utils.doc2csv(
                {"field": {"subfield": {"subsubfield": 1}, "subvalue": 1}},
                {"field": {"subfield": {"subsubfield": lambda x: 0}, "subvalue": True}},
            )[0],
            [0, 1],
        )
        # serialize
        self.assertEqual(
            ivre.utils.serialize(re.compile("^test$", re.I | re.U)), "/^test$/iu"
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
            nbr = random.randint(2, 1000)  # nosec B311  # not security-sensitive
            factors = list(ivre.mathutils.factors(nbr))
            self.assertTrue(is_prime(nbr) or len(factors) > 1)
            self.assertTrue(all(is_prime(x) for x in factors))
            self.assertEqual(reduce(lambda x, y: x * y, factors), nbr)
        # Readables
        self.assertEqual(ivre.utils.num2readable(1000), "1k")
        self.assertEqual(ivre.utils.num2readable(1000000000000000000000000), "1Y")
        self.assertEqual(ivre.utils.num2readable(1049000.0), "1.049M")

        # Zeek logs
        basepath = os.getenv("ZEEK_SAMPLES")
        badchars = re.compile(
            "[%s]" % "".join(re.escape(char) for char in [os.path.sep, "-", "."])
        )
        if basepath:
            for dirname, _, fnames in os.walk(basepath):
                for fname in fnames:
                    if not fname.endswith(".log"):
                        continue
                    fname = os.path.join(dirname, fname)
                    zeekfd = ivre.parser.zeek.ZeekFile(fname)
                    i = 0
                    for i, record in enumerate(zeekfd):
                        json.dumps(record, default=ivre.utils.serialize)
                    self.check_value(
                        "utils_zeek_%s_count"
                        % badchars.sub(
                            "_",
                            fname[len(basepath) : -4].lstrip("/"),
                        ),
                        i + 1,
                    )

        # Iptables
        with ivre.parser.iptables.Iptables(
            os.path.join(SAMPLES, "iptables.log")
        ) as ipt_parser:
            count = 0
            for res in ipt_parser:
                count += 1
                self.assertTrue("proto" in res and "src" in res and "dst" in res)
                if res["proto"] in {"udp", "tcp"}:
                    self.assertTrue("sport" in res and "dport" in res)

            self.assertEqual(count, 40)

        # Web utils
        with self.assertRaises(ValueError):
            ivre.web.utils.query_from_params({"q": '"'})

        # Country aliases
        europe = ivre.utils.country_unalias("EU")
        self.assertTrue("FR" in europe)
        self.assertTrue("DE" in europe)
        self.assertFalse("US" in europe)
        self.assertFalse("GB" in europe)
        self.assertEqual(
            ivre.utils.country_unalias("UK"), ivre.utils.country_unalias("GB")
        )
        ukfr = ivre.utils.country_unalias(["FR", "UK"])
        self.assertTrue("FR" in ukfr)
        self.assertTrue("GB" in ukfr)
        self.assertEqual(ivre.utils.country_unalias("FR"), "FR")

        # Serveur port guess
        self.assertEqual(ivre.utils.guess_srv_port(67, 68, proto="udp"), 1)
        self.assertEqual(ivre.utils.guess_srv_port(65432, 80), -1)
        self.assertEqual(ivre.utils.guess_srv_port(666, 666), 0)
        # Certificate argument parsing
        self.assertCountEqual(
            list(ivre.utils.parse_cert_subject_string('O = "Test\\", Inc."')),
            [("O", 'Test", Inc.')],
        )

        # ipcalc tool
        res, out, _ = RUN(["ivre", "ipcalc", "192.168.0.0/16"])
        self.assertEqual(res, 0)
        self.assertEqual(out, b"192.168.0.0-192.168.255.255\n")
        res, out, _ = RUN(["ivre", "ipcalc", "10.0.0.0-10.255.255.255"])
        self.assertEqual(res, 0)
        self.assertEqual(out, b"10.0.0.0/8\n")
        res, out, _ = RUN(["ivre", "ipcalc", "8.8.8.8"])
        self.assertEqual(res, 0)
        self.assertEqual(out, b"134744072\n")
        res, out, _ = RUN(["ivre", "ipcalc", "134744072"])
        self.assertEqual(res, 0)
        self.assertEqual(out, b"8.8.8.8\n")
        res, out, _ = RUN(["ivre", "ipcalc", "::"])
        self.assertEqual(res, 0)
        self.assertEqual(out, b"0\n")
        res, out, _ = RUN(["ivre", "ipcalc", "::", "-", "::ff"])
        self.assertEqual(res, 0)
        self.assertEqual(out, b"::/120\n")
        res, out, _ = RUN(["ivre", "ipcalc", "::", "-", "::ff"])
        self.assertEqual(res, 0)
        self.assertEqual(out, b"::/120\n")
        res, out, _ = RUN(
            ["ivre", "ipcalc", "::", "-", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        )
        self.assertEqual(res, 0)
        self.assertEqual(out, b"::/0\n")
        res, out, _ = RUN(
            ["ivre", "ipcalc", "::", "-", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]
        )
        self.assertEqual(res, 0)
        self.assertEqual(out, b"::/0\n")
        res, out, _ = RUN(["ivre", "ipcalc", "abcd:ef::", "-", "abcd:ff::ffff"])
        self.assertEqual(res, 0)
        self.assertEqual(
            out,
            (
                b"abcd:ef::/32\nabcd:f0::/29\nabcd:f8::/30\nabcd:fc::/31\n"
                b"abcd:fe::/32\nabcd:ff::/112\n"
            ),
        )

        # IPADDR regexp, based on
        # <https://gist.github.com/dfee/6ed3a4b05cfe7a6faf40a2102408d5d8>
        addr_tests_ipv6 = [
            "1::",
            "1:2:3:4:5:6:7::",
            "1::8",
            "1:2:3:4:5:6::8",
            "1:2:3:4:5:6::8",
            "1::7:8",
            "1:2:3:4:5::7:8",
            "1:2:3:4:5::8",
            "1::6:7:8",
            "1:2:3:4::6:7:8",
            "1:2:3:4::8",
            "1::5:6:7:8",
            "1:2:3::5:6:7:8",
            "1:2:3::8",
            "1::4:5:6:7:8",
            "1:2::4:5:6:7:8",
            "1:2::8",
            "1::3:4:5:6:7:8",
            "1::3:4:5:6:7:8",
            "1::8",
            "::2:3:4:5:6:7:8",
            "::2:3:4:5:6:7:8",
            "::8",
            "::",
            "fe80::7:8%eth0",
            "fe80::7:8%1",
            "::255.255.255.255",
            "::0.0.0.0",
            "::ffff:255.255.255.255",
            "::ffff:0.0.0.0",
            "::ffff:0:255.255.255.255",
            "::ffff:0:0.0.0.0",
            "2001:db8:3:4::192.0.2.33",
            "2001:db8:3:4::0.0.2.33",
            "64:ff9b::192.0.2.33",
            "64:ff9b::0.0.2.33",
        ]
        addr_tests_ipv4 = [
            "0.0.0.0",
            "0.0.2.33",
            "10.0.2.33",
            "10.10.2.33",
            "192.0.2.33",
            "255.255.255.255",
        ]
        for test in [addr_tests_ipv4, addr_tests_ipv6]:
            for addr in addr_tests_ipv6:
                match = ivre.utils.IPADDR.search(addr)
                self.assertTrue(match)
                self.assertEqual(len(match.groups()), 1)
                self.assertEqual(match.groups()[0], addr)
                if "%" not in addr:
                    self.assertIsNone(ivre.utils.IPADDR.search("x%s" % addr))
                    self.assertIsNone(ivre.utils.IPADDR.search("%sx" % addr))
                addr = addr.swapcase()
                match = ivre.utils.IPADDR.search(addr)
                self.assertTrue(match)
                self.assertEqual(len(match.groups()), 1)
                self.assertEqual(match.groups()[0], addr)
                if "%" not in addr:
                    self.assertIsNone(ivre.utils.IPADDR.search("X%s" % addr))
                    self.assertIsNone(ivre.utils.IPADDR.search("%sX" % addr))
        for addr in addr_tests_ipv4:
            for netmask in [
                "0",
                "7",
                "24",
                "32",
                "0.0.0.0",
                "255.0.0.0",
                "255.255.255.255",
            ]:
                naddr = "%s/%s" % (addr, netmask)
                match = ivre.utils.NETADDR.search(naddr)
                self.assertTrue(match)
                self.assertEqual(len(match.groups()), 2)
                self.assertEqual(match.groups(), tuple(naddr.split("/")))
        for addr in addr_tests_ipv6:
            for netmask in [0, 7, 24, 32, 64, 127, 128]:
                naddr = "%s/%d" % (addr, netmask)
                match = ivre.utils.NETADDR.search(naddr)
                self.assertTrue(match)
                self.assertEqual(len(match.groups()), 2)
                self.assertEqual(match.groups(), tuple(naddr.split("/")))
        for mac, res in [
            (
                "00:00:00:00:00:00",
                ("Xerox", "Xerox Corporation"),
            ),
            ("00:00:01:00:00:00", ("Xerox", "Xerox Corporation")),
            ("00:01:01:00:00:00", ("Private", None)),
            ("01:00:00:00:00:00", None),
        ]:
            self.assertEqual(ivre.utils.mac2manuf(mac), res)

        # Banner "canonicalization"
        for expr, result in ivre.passive.TCP_SERVER_PATTERNS:
            if not isinstance(result, bytes):
                # Not tested yet
                continue
            if b"\\1" in result or b"\\g<" in result:
                # Not tested yet
                continue
            # The substitution must match the pattern.
            self.assertTrue(expr.search(result) is not None)
            # The transformation must leave the result expression
            # unchanged.
            self.assertEqual(expr.sub(result, result), result)

        # DNS audit domain
        for output in [], ["--json"]:
            with tempfile.NamedTemporaryFile(delete=False) as fdesc:
                res = RUN(
                    ["ivre", "auditdom", "--ipv4"]
                    + output
                    + ["ivre.rocks", "zonetransfer.me", "hardenize.com"],
                    stdout=fdesc,
                )[0]
                self.assertEqual(res, 0)
            res, out, err = RUN(["ivre", "scan2db", "--test", fdesc.name])
            os.unlink(fdesc.name)
            self.assertEqual(res, 0)
            out = out.decode().splitlines()
            found_zone_transfer = False
            found_dns_servers = set()
            found_dns_tls_rpt = set()
            for line in out:
                rec = json.loads(line)
                for port in rec.get("ports", []):
                    self.assertEqual(len(port["scripts"]), 1)
                    for script in port["scripts"]:
                        self.assertIn(
                            script["id"],
                            {
                                "dns-check-consistency",  # may happen
                                "dns-domains",
                                "dns-domains-mx",
                                "dns-tls-rpt",
                                "dns-zone-transfer",
                            },
                        )
                        if script["id"] == "dns-domains":
                            self.assertEqual(
                                script["output"][:28], "Server is authoritative for "
                            )
                            self.assertIn(
                                script["dns-domains"][0]["domain"],
                                {"ivre.rocks", "zonetransfer.me", "hardenize.com"},
                            )
                            found_dns_servers.add(script["dns-domains"][0]["domain"])
                        elif script["id"] == "dns-zone-transfer":
                            self.assertEqual(len(script["dns-zone-transfer"]), 1)
                            self.assertEqual(
                                script["dns-zone-transfer"][0]["domain"],
                                "zonetransfer.me",
                            )
                            found_zone_transfer = True
                        elif script["id"] == "dns-tls-rpt":
                            self.assertIn(
                                script["dns-tls-rpt"][0]["domain"],
                                {"ivre.rocks", "zonetransfer.me", "hardenize.com"},
                            )
                            if script["dns-tls-rpt"][0]["domain"] == "hardenize.com":
                                self.assertNotIn("warnings", script["dns-tls-rpt"])
                                self.assertEqual(
                                    script["output"],
                                    "Domain hardenize.com has no TLS-RPT configuration",
                                )
                            found_dns_tls_rpt.add(script["dns-tls-rpt"][0]["domain"])
            self.assertTrue(found_zone_transfer)
            self.assertEqual(len(found_dns_servers), 3)
            self.assertEqual(len(found_dns_tls_rpt), 3)

        # url2hostport()
        with self.assertRaises(ValueError):
            ivre.utils.url2hostport("http://[::1]X/")
        with self.assertRaises(ValueError):
            ivre.utils.url2hostport("http://[::1/")
        self.assertEqual(ivre.utils.url2hostport("http://[::1]/"), ("::1", 80))
        self.assertEqual(ivre.utils.url2hostport("https://[::]:1234/"), ("::", 1234))
        self.assertEqual(ivre.utils.url2hostport("https://[::]:1234/"), ("::", 1234))
        self.assertEqual(ivre.utils.url2hostport("https://1.2.3.4/"), ("1.2.3.4", 443))
        self.assertEqual(
            ivre.utils.url2hostport("ftp://1.2.3.4:2121/"), ("1.2.3.4", 2121)
        )

        # NTLM Analyzer
        self.assertEqual(ivre.analyzer.ntlm._is_ntlm_message("NTLM"), False)
        self.assertEqual(ivre.analyzer.ntlm._is_ntlm_message("NTLM    "), False)
        self.assertEqual(
            ivre.analyzer.ntlm._is_ntlm_message(
                "Negotiate a87421000492aa874209af8bc028"
            ),
            False,
        )  # https://tools.ietf.org/html/rfc4559
        self.assertEqual(
            ivre.analyzer.ntlm._is_ntlm_message(
                "NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA="
            ),
            True,
        )
        self.assertEqual(
            ivre.analyzer.ntlm._is_ntlm_message(
                "Negotiate TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA="
            ),
            True,
        )
        self.assertEqual(
            ivre.analyzer.ntlm.ntlm_extract_info(
                b"NTLMSSP\x00\x0b\x00\x00\x00\x07\x82\x08\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            ),
            {},
        )
        self.assertEqual(
            ivre.analyzer.ntlm.ntlm_extract_info(
                b"NTLMSSP\x00\x01\x00\x00\x00\x01\x82\x08\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            ),
            {"ntlm-fingerprint": "0x00088201"},
        )
        negotiate = ivre.analyzer.ntlm.ntlm_extract_info(
            b"NTLMSSP\x00\x01\x00\x00\x00\x06\xb2\x08\xa0\x0a\x00\x0a\x00\x28\x00"
            b"\x00\x00\x08\x00\x08\x00\x20\x00\x00\x00NAMETESTDOMAINTEST"
        )
        self.assertEqual(negotiate["NetBIOS_Domain_Name"], "DOMAINTEST")
        self.assertEqual(negotiate["Workstation"], "NAMETEST")

        res, out, err = RUN(["ivre", "localscan"])
        self.assertEqual(res, 0)
        self.assertFalse(err)
        with tempfile.NamedTemporaryFile(delete=False) as fdesc:
            fdesc.write(out)
        res, out, _ = RUN(
            [
                "ivre",
                "scan2db",
                "--test",
                "--tags=LocalScan:info:ivre localscan,LocalScan:info:insert from XML",
                fdesc.name,
            ]
        )
        self.assertEqual(res, 0)
        for line in out.splitlines():
            data = json.loads(line)
            self.assertTrue(isinstance(data, dict))
            tags = [t for t in data["tags"] if t.get("value") == "LocalScan"]
            self.assertEqual(len(tags), 1)
            self.assertEqual(len(tags[0]["info"]), 2)

        res, out, err = RUN(["ivre", "localscan", "--json"])
        self.assertEqual(res, 0)
        self.assertFalse(err)
        with tempfile.NamedTemporaryFile(delete=False) as fdesc:
            fdesc.write(out)
        for line in out.splitlines():
            self.assertTrue(isinstance(json.loads(line), dict))
        res, out, _ = RUN(
            [
                "ivre",
                "scan2db",
                "--test",
                "--tags=LocalScan:info:ivre localscan,LocalScan:info:insert from JSON",
                fdesc.name,
            ]
        )
        self.assertEqual(res, 0)
        for line in out.splitlines():
            data = json.loads(line)
            self.assertTrue(isinstance(data, dict))
            tags = [t for t in data["tags"] if t.get("value") == "LocalScan"]
            self.assertEqual(len(tags), 1)
            self.assertEqual(len(tags[0]["info"]), 2)

        with tempfile.NamedTemporaryFile(delete=False) as fdesc:
            fdesc.write(
                b"ivre.rocks\ngithub.com\n::1\n127.0.0.1\nivre.rocks\n"
                b"127.1.0.0/16\n127.1.0.0/24"
            )
        with open(fdesc.name, "rb") as ifdesc:
            res, out, err = RUN(["ivre", "sort"], stdin=ifdesc)
        self.assertEqual(res, 0)
        self.assertFalse(err)
        self.assertEqual(
            out.splitlines(),
            [
                b"127.0.0.1",
                b"127.1.0.0/16",
                b"127.1.0.0/24",
                b"::1",
                b"github.com",
                b"ivre.rocks",
                b"ivre.rocks",
            ],
        )
        with open(fdesc.name, "rb") as ifdesc:
            res, out, err = RUN(["ivre", "sort", "-u"], stdin=ifdesc)
        self.assertEqual(res, 0)
        self.assertFalse(err)
        self.assertEqual(
            out.splitlines(),
            [
                b"127.0.0.1",
                b"127.1.0.0/16",
                b"127.1.0.0/24",
                b"::1",
                b"github.com",
                b"ivre.rocks",
            ],
        )
        os.unlink(fdesc.name)


def _parse_args() -> None:
    """Parse the optional ``--samples`` and ``--coverage`` flags when
    this module is invoked as a script. Mirrors ``tests/tests.py``."""
    global SAMPLES, USE_COVERAGE, COVERAGE, RUN, RUN_ITER  # noqa: PLW0603
    import argparse

    parser = argparse.ArgumentParser(description="Run IVRE backend-free tests")
    parser.add_argument("--samples", metavar="DIR", default=SAMPLES)
    parser.add_argument("--coverage", action="store_true")
    args, remaining = parser.parse_known_args()
    SAMPLES = args.samples
    USE_COVERAGE = args.coverage
    if USE_COVERAGE:
        COVERAGE = [sys.executable, os.path.dirname(__import__("coverage").__file__)]
        RUN = coverage_run
        RUN_ITER = coverage_run_iter
    # Re-inject the unparsed args so unittest.main() sees them.
    sys.argv = [sys.argv[0]] + remaining


if __name__ == "__main__":
    _parse_args()
    unittest.main()
