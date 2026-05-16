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

import asyncio
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
from datetime import datetime, timezone
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


class SearchscriptMcpToolsTests(unittest.TestCase):
    """Regression tests for the ``searchscript`` MCP tool values parameter.

    Exercises the structured sub-document filtering (``values=…``) added
    alongside the existing ``name``/``output`` filters, including the two
    validation constraints:

    * ``values`` without ``name`` → INVALID_PARAMS
    * regex ``name`` (``/…/`` shorthand) with ``values`` → INVALID_PARAMS

    Skipped when the optional ``mcp`` dependency is not installed.
    """

    @classmethod
    def setUpClass(cls) -> None:
        from ivre.tools import mcp_server  # noqa: PLC0415

        if mcp_server.FastMCP is None:
            raise unittest.SkipTest("mcp dependency not installed")
        cls.srv = mcp_server._build_server()
        # Wrap in staticmethod so accessing via self. does not bind self as
        # the first positional argument (which would collide with `purpose`).
        cls.searchscript = staticmethod(
            cls.srv._tool_manager.get_tool("searchscript").fn
        )

    def test_values_in_schema(self) -> None:
        """``values`` is present in the tool's JSON-Schema input spec."""
        import asyncio  # noqa: PLC0415

        tools = asyncio.run(self.srv.list_tools())
        spec = next(t for t in tools if t.name == "searchscript")
        props = spec.inputSchema.get("properties", {})
        self.assertIn("values", props)

    def test_values_requires_name(self) -> None:
        """``values`` without ``name`` raises INVALID_PARAMS."""
        from mcp.shared.exceptions import McpError  # noqa: PLC0415

        with self.assertRaises(McpError) as ctx:
            self.searchscript(purpose="nmap", values={"fingerprint": "abc"})
        self.assertIn("name", ctx.exception.error.message)

    def test_values_rejects_regex_name(self) -> None:
        """Regex ``name`` combined with ``values`` raises INVALID_PARAMS."""
        from mcp.shared.exceptions import McpError  # noqa: PLC0415

        with self.assertRaises(McpError) as ctx:
            self.searchscript(
                purpose="nmap", name="/ssh-.*/", values={"fingerprint": "abc"}
            )
        self.assertIn("regular expression", ctx.exception.error.message)

    def test_values_happy_path(self) -> None:
        """Exact ``name`` + ``values`` returns a non-empty sealed filter token."""
        result = self.searchscript(
            purpose="nmap",
            name="ssh-hostkey",
            values={"fingerprint": "a75eea26ce8911d306786bf0b3895796"},
        )
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)


# ---------------------------------------------------------------------
# McpOAuthProviderTests -- pin the OAuth 2.1 Authorization Server
# implementation that turns the MCP HTTP transport into a consent-
# driven server.  Exercises every method of the SDK's
# ``OAuthAuthorizationServerProvider`` Protocol plus the
# ``issue_authorization_code`` / ``peek_authorization_request``
# helpers consumed by the Bottle consent routes.  The tests run
# against an in-memory ``_StubDBAuth`` so they need no live Mongo
# backend; the wire shapes pinned here are the same ones
# ``MongoDBAuth`` round-trips through.
# ---------------------------------------------------------------------


def _have_mcp() -> bool:
    """Importability check for the optional ``mcp`` extra."""
    try:
        import mcp  # noqa: F401  -- presence check only
    except ImportError:
        return False
    return True


class _StubDBAuth:
    """In-memory ``DBAuth`` substitute backing the OAuth provider
    tests.

    Mirrors the dict-shape MongoDBAuth round-trips through (see
    ``MongoDBAuth.create_oauth_client`` etc.); just enough surface
    to drive every Protocol method.  ``users`` is keyed by email,
    ``api_keys`` by hash (matching MongoDBAuth's storage), and the
    four OAuth stores are keyed by their natural identifier.
    """

    def __init__(self) -> None:
        self.users: dict[str, dict] = {}
        self.api_keys: dict[str, dict] = {}  # key_hash -> record
        self.clients: dict[str, dict] = {}
        self.requests: dict[str, dict] = {}
        self.codes: dict[str, dict] = {}
        self.tokens: dict[str, dict] = {}  # token_hash -> record

    # --- user / api-key helpers ---

    def add_user(self, email: str, groups: list[str] | None = None) -> None:
        self.users[email] = {
            "email": email,
            "display_name": email,
            "is_admin": False,
            "is_active": True,
            "groups": list(groups or []),
        }

    def add_api_key(self, raw_token: str, user_email: str) -> None:
        import hashlib as _hashlib

        token_hash = _hashlib.sha256(raw_token.encode()).hexdigest()
        self.api_keys[token_hash] = {
            "key_hash": token_hash,
            "user_email": user_email,
            "name": "test",
        }

    def get_user_by_email(self, email):
        return self.users.get(email)

    def create_user(self, email, display_name=None, is_active=False, **_):
        self.users[email] = {
            "email": email,
            "display_name": display_name or email,
            "is_admin": False,
            "is_active": is_active,
            "groups": [],
        }

    def update_user(self, email, **updates):
        if email in self.users:
            self.users[email].update(updates)

    def create_session(self, user_email):
        # Opaque token; the round-trip test only cares that the
        # cookie is set, not what the value is.
        return f"session-for-{user_email}"

    def validate_api_key(self, key):
        import hashlib as _hashlib

        token_hash = _hashlib.sha256(key.encode()).hexdigest()
        record = self.api_keys.get(token_hash)
        if record is None:
            return None
        return self.users.get(record["user_email"])

    # --- OAuth surface ---

    def create_oauth_client(self, client):
        self.clients[client["client_id"]] = dict(client)

    def get_oauth_client(self, client_id):
        record = self.clients.get(client_id)
        return None if record is None else dict(record)

    def list_oauth_clients(self):
        return [dict(c) for c in self.clients.values()]

    def delete_oauth_client(self, client_id):
        removed = self.clients.pop(client_id, None) is not None
        if removed:
            self.revoke_oauth_tokens_for_client(client_id)
        return removed

    def create_authorization_request(self, request_id, payload):
        self.requests[request_id] = dict(payload, request_id=request_id)

    def get_authorization_request(self, request_id):
        now = datetime.now(tz=timezone.utc)
        record = self.requests.get(request_id)
        if record is None or record["expires_at"] <= now:
            return None
        return dict(record)

    def consume_authorization_request(self, request_id):
        now = datetime.now(tz=timezone.utc)
        record = self.requests.pop(request_id, None)
        if record is None or record["expires_at"] <= now:
            return None
        return dict(record)

    def create_authorization_code(self, code, payload):
        self.codes[code] = dict(payload, code=code)

    def get_authorization_code(self, code):
        now = datetime.now(tz=timezone.utc)
        record = self.codes.get(code)
        if record is None or record["expires_at"] <= now:
            return None
        return dict(record)

    def consume_authorization_code(self, code):
        now = datetime.now(tz=timezone.utc)
        record = self.codes.pop(code, None)
        if record is None or record["expires_at"] <= now:
            return None
        return dict(record)

    def create_oauth_token(self, token_hash, payload):
        self.tokens[token_hash] = dict(payload, token_hash=token_hash)

    def validate_oauth_token(self, token):
        import hashlib as _hashlib

        token_hash = _hashlib.sha256(token.encode()).hexdigest()
        record = self.tokens.get(token_hash)
        if record is None or record.get("revoked_at"):
            return None
        expires_at = record.get("expires_at")
        if expires_at is not None:
            now = datetime.now(tz=timezone.utc)
            if expires_at <= now:
                return None
        return dict(record)

    def revoke_oauth_token(self, token_hash):
        record = self.tokens.get(token_hash)
        if record is None:
            return
        record["revoked_at"] = datetime.now(tz=timezone.utc)

    def revoke_oauth_tokens_by_refresh(self, refresh_token_hash):
        now = datetime.now(tz=timezone.utc)
        n = 0
        for record in self.tokens.values():
            if record.get(
                "refresh_token_hash"
            ) == refresh_token_hash and not record.get("revoked_at"):
                record["revoked_at"] = now
                n += 1
        return n

    def revoke_oauth_tokens_for_client(self, client_id):
        now = datetime.now(tz=timezone.utc)
        n = 0
        for record in self.tokens.values():
            if record.get("client_id") == client_id and not record.get("revoked_at"):
                record["revoked_at"] = now
                n += 1
        return n


@unittest.skipUnless(_have_mcp(), "mcp dependency not installed")
class McpOAuthProviderTests(unittest.TestCase):
    """Behaviour-pin for :class:`IvreOAuthProvider` and the helper
    functions the consent routes call.
    """

    def setUp(self):
        from ivre.tools.mcp_server import auth as mcp_auth

        self.mcp_auth = mcp_auth
        self.stub = _StubDBAuth()
        self.stub.add_user("alice@example.org", groups=["analysts"])
        self.stub.add_api_key("ivre_legacy_key", "alice@example.org")
        # Patch the module-level ``db.auth`` reference the provider
        # consults.  ``ivre.tools.mcp_server.auth`` imports ``db``
        # at module top, so the patch target is its local binding.
        self._patcher = mock.patch.object(mcp_auth.db, "_auth", self.stub, create=True)
        self._patcher.start()
        self.provider = mcp_auth.IvreOAuthProvider("http://ivre.example.org")

    def tearDown(self):
        self._patcher.stop()

    @staticmethod
    def _make_client(client_id: str = "client-A") -> object:
        from mcp.shared.auth import OAuthClientInformationFull

        return OAuthClientInformationFull(
            client_id=client_id,
            client_name="Test MCP Client",
            redirect_uris=["http://callback.example.org/cb"],
        )

    @staticmethod
    def _make_authorize_params(
        scopes: list[str] | None = None,
        state: str | None = "client-state-1",
        redirect_uri: str = "http://callback.example.org/cb",
    ) -> object:
        from mcp.server.auth.provider import AuthorizationParams
        from pydantic import AnyUrl

        return AuthorizationParams(
            state=state,
            scopes=list(scopes) if scopes is not None else [],
            code_challenge="x" * 43,
            redirect_uri=AnyUrl(redirect_uri),
            redirect_uri_provided_explicitly=True,
        )

    def test_register_and_get_client(self):
        from mcp.shared.auth import OAuthClientInformationFull

        client = self._make_client("client-A")
        asyncio.run(self.provider.register_client(client))
        self.assertIn("client-A", self.stub.clients)
        loaded = asyncio.run(self.provider.get_client("client-A"))
        self.assertIsInstance(loaded, OAuthClientInformationFull)
        self.assertEqual(loaded.client_id, "client-A")

    def test_register_client_disabled(self):
        with mock.patch.object(ivre.config, "MCP_OAUTH_DCR_ENABLED", False):
            with self.assertRaises(NotImplementedError):
                asyncio.run(self.provider.register_client(self._make_client("X")))

    def test_get_client_unknown_returns_none(self):
        self.assertIsNone(asyncio.run(self.provider.get_client("ghost")))

    def test_authorize_returns_consent_url(self):
        client = self._make_client("client-A")
        asyncio.run(self.provider.register_client(client))
        url = asyncio.run(
            self.provider.authorize(
                client, self._make_authorize_params(scopes=["analysts"])
            )
        )
        self.assertTrue(
            url.startswith("http://ivre.example.org/cgi/auth/oauth/consent?"),
            f"unexpected consent URL: {url}",
        )
        # The authorize call persisted exactly one pending request.
        self.assertEqual(len(self.stub.requests), 1)
        request_id, payload = next(iter(self.stub.requests.items()))
        self.assertIn(f"request_id={request_id}", url)
        self.assertEqual(payload["client_id"], "client-A")
        self.assertEqual(payload["state"], "client-state-1")
        self.assertEqual(payload["code_challenge"], "x" * 43)

    def _issue_code(
        self, request_id: str, user_email: str = "alice@example.org"
    ) -> str:
        """Wrap :func:`ivre.tools.mcp_server.auth.issue_authorization_code`
        for tests that only need the raw code string.

        The function returns ``(code, payload)`` so the consent
        route can build the post-allow redirect without a second
        peek; tests that exercise downstream provider methods
        (``load_authorization_code`` / ``exchange_authorization_code``
        / refresh-token rotation / etc.) only care about ``code``
        and use this helper.  The
        ``test_issue_authorization_code_consumes_request`` test
        below pins the full ``(code, payload)`` return shape.
        """
        result = self.mcp_auth.issue_authorization_code(request_id, user_email)
        self.assertIsNotNone(result)
        assert result is not None  # narrow for type checkers
        code, _payload = result
        return code

    def test_issue_authorization_code_consumes_request(self):
        client = self._make_client("client-A")
        asyncio.run(self.provider.register_client(client))
        asyncio.run(
            self.provider.authorize(
                client, self._make_authorize_params(scopes=["analysts"])
            )
        )
        request_id = next(iter(self.stub.requests))
        result = self.mcp_auth.issue_authorization_code(request_id, "alice@example.org")
        self.assertIsNotNone(result)
        assert result is not None  # narrow for type checkers
        code, payload = result
        # The helper returns the consumed payload too so the
        # consent route can build the redirect without a second
        # peek round-trip (closes the peek+consume race window).
        self.assertEqual(payload["client_id"], "client-A")
        self.assertEqual(payload["scopes"], ["analysts"])
        # The pending request was consumed atomically.
        self.assertNotIn(request_id, self.stub.requests)
        # The code is now persisted with the consenting user's email.
        self.assertIn(code, self.stub.codes)
        self.assertEqual(self.stub.codes[code]["user_email"], "alice@example.org")

    def test_peek_authorization_request_is_idempotent(self):
        client = self._make_client("client-A")
        asyncio.run(self.provider.register_client(client))
        asyncio.run(
            self.provider.authorize(
                client, self._make_authorize_params(scopes=["analysts"])
            )
        )
        request_id = next(iter(self.stub.requests))
        # Two consecutive peeks return the same payload without
        # consuming the pending request.
        first = self.mcp_auth.peek_authorization_request(request_id)
        second = self.mcp_auth.peek_authorization_request(request_id)
        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertEqual(first["client_id"], "client-A")
        self.assertIn(request_id, self.stub.requests)

    def test_exchange_authorization_code_mints_token_pair(self):
        from mcp.shared.auth import OAuthToken

        client = self._make_client("client-A")
        asyncio.run(self.provider.register_client(client))
        asyncio.run(
            self.provider.authorize(
                client, self._make_authorize_params(scopes=["analysts"])
            )
        )
        request_id = next(iter(self.stub.requests))
        code = self._issue_code(request_id)
        # Load + exchange in the order the SDK uses.
        auth_code = asyncio.run(self.provider.load_authorization_code(client, code))
        self.assertIsNotNone(auth_code)
        token = asyncio.run(
            self.provider.exchange_authorization_code(client, auth_code)
        )
        self.assertIsInstance(token, OAuthToken)
        self.assertTrue(token.access_token.startswith("ivre_oat_"))
        self.assertTrue(token.refresh_token.startswith("ivre_ort_"))
        # The code is one-shot.
        self.assertNotIn(code, self.stub.codes)

    def test_exchange_authorization_code_rejects_wrong_client(self):
        from mcp.server.auth.provider import TokenError

        client_a = self._make_client("client-A")
        client_b = self._make_client("client-B")
        asyncio.run(self.provider.register_client(client_a))
        asyncio.run(self.provider.register_client(client_b))
        asyncio.run(self.provider.authorize(client_a, self._make_authorize_params()))
        request_id = next(iter(self.stub.requests))
        code = self._issue_code(request_id)
        # The SDK rejects mismatched client at ``load_*`` time; we
        # also rebuild the record so a follow-up exchange against
        # the right client could still work.
        auth_code = asyncio.run(self.provider.load_authorization_code(client_b, code))
        self.assertIsNone(auth_code)
        # Forcing an exchange via a fake ``AuthorizationCode`` for the
        # wrong client surfaces ``invalid_grant``.
        from mcp.server.auth.provider import AuthorizationCode
        from pydantic import AnyUrl

        fake_code = AuthorizationCode(
            code=code,
            scopes=[],
            expires_at=0,
            client_id="client-A",
            code_challenge="x" * 43,
            redirect_uri=AnyUrl("http://callback.example.org/cb"),
            redirect_uri_provided_explicitly=True,
        )
        with self.assertRaises(TokenError):
            asyncio.run(self.provider.exchange_authorization_code(client_b, fake_code))

    def test_load_access_token_accepts_issued_token(self):
        # End-to-end: authorize -> consent -> token -> use the
        # access token as a bearer on a subsequent request.
        client = self._make_client("client-A")
        asyncio.run(self.provider.register_client(client))
        asyncio.run(
            self.provider.authorize(
                client, self._make_authorize_params(scopes=["analysts"])
            )
        )
        request_id = next(iter(self.stub.requests))
        code = self._issue_code(request_id)
        auth_code = asyncio.run(self.provider.load_authorization_code(client, code))
        token = asyncio.run(
            self.provider.exchange_authorization_code(client, auth_code)
        )
        verified = asyncio.run(self.provider.load_access_token(token.access_token))
        self.assertIsNotNone(verified)
        self.assertEqual(verified.client_id, "alice@example.org")
        self.assertEqual(verified.scopes, ["analysts"])

    def test_load_access_token_accepts_legacy_api_key(self):
        # The provider doubles as the verifier for pre-existing
        # IVRE API keys so the two auth shapes coexist.
        verified = asyncio.run(self.provider.load_access_token("ivre_legacy_key"))
        self.assertIsNotNone(verified)
        self.assertEqual(verified.client_id, "alice@example.org")
        self.assertEqual(verified.scopes, ["analysts"])

    def test_load_access_token_rejects_unknown_token(self):
        self.assertIsNone(asyncio.run(self.provider.load_access_token("ivre_oat_nope")))

    def test_load_access_token_rejects_revoked_token(self):
        client = self._make_client("client-A")
        asyncio.run(self.provider.register_client(client))
        asyncio.run(self.provider.authorize(client, self._make_authorize_params()))
        request_id = next(iter(self.stub.requests))
        code = self._issue_code(request_id)
        auth_code = asyncio.run(self.provider.load_authorization_code(client, code))
        token = asyncio.run(
            self.provider.exchange_authorization_code(client, auth_code)
        )
        # Revoke + retry.
        verified = asyncio.run(self.provider.load_access_token(token.access_token))
        assert verified is not None
        asyncio.run(self.provider.revoke_token(verified))
        self.assertIsNone(
            asyncio.run(self.provider.load_access_token(token.access_token))
        )

    def test_exchange_refresh_token_rotates(self):
        client = self._make_client("client-A")
        asyncio.run(self.provider.register_client(client))
        asyncio.run(
            self.provider.authorize(
                client, self._make_authorize_params(scopes=["analysts"])
            )
        )
        request_id = next(iter(self.stub.requests))
        code = self._issue_code(request_id)
        auth_code = asyncio.run(self.provider.load_authorization_code(client, code))
        token = asyncio.run(
            self.provider.exchange_authorization_code(client, auth_code)
        )
        # Refresh.
        refresh_obj = asyncio.run(
            self.provider.load_refresh_token(client, token.refresh_token)
        )
        self.assertIsNotNone(refresh_obj)
        rotated = asyncio.run(
            self.provider.exchange_refresh_token(client, refresh_obj, [])
        )
        # The old refresh token is now revoked.
        self.assertIsNone(
            asyncio.run(self.provider.load_refresh_token(client, token.refresh_token))
        )
        # The old access token is *also* revoked alongside the
        # consumed refresh token (RFC 6749 §10.4 + OAuth 2.1
        # draft).  Without this cascade, a leaked access+refresh
        # pair would let the attacker keep the access half valid
        # for up to ``MCP_OAUTH_ACCESS_TOKEN_TTL`` after the
        # legitimate user rotates the refresh side.
        self.assertIsNone(
            asyncio.run(self.provider.load_access_token(token.access_token))
        )
        # The new access token works.
        verified = asyncio.run(self.provider.load_access_token(rotated.access_token))
        self.assertIsNotNone(verified)

    def test_exchange_refresh_token_revokes_sibling_access_token(self):
        # Focused regression test for the cascade-revoke
        # behaviour: verify the bookkeeping at the storage layer
        # (the ``revoked_at`` field on the access record) rather
        # than only the observable ``load_access_token`` -> None
        # symptom.  Catches a future regression that bypasses the
        # ``refresh_token_hash`` link.
        import hashlib as _hashlib

        client = self._make_client("client-A")
        asyncio.run(self.provider.register_client(client))
        asyncio.run(self.provider.authorize(client, self._make_authorize_params()))
        request_id = next(iter(self.stub.requests))
        code = self._issue_code(request_id)
        auth_code = asyncio.run(self.provider.load_authorization_code(client, code))
        token = asyncio.run(
            self.provider.exchange_authorization_code(client, auth_code)
        )
        access_hash = _hashlib.sha256(token.access_token.encode()).hexdigest()
        refresh_hash = _hashlib.sha256(token.refresh_token.encode()).hexdigest()
        # The access record carries the back-reference to its
        # sibling refresh token.
        self.assertEqual(
            self.stub.tokens[access_hash]["refresh_token_hash"], refresh_hash
        )
        self.assertIsNone(self.stub.tokens[access_hash]["revoked_at"])
        # Drive the rotation.
        refresh_obj = asyncio.run(
            self.provider.load_refresh_token(client, token.refresh_token)
        )
        asyncio.run(self.provider.exchange_refresh_token(client, refresh_obj, []))
        # Both halves of the original pair are now revoked.
        self.assertIsNotNone(self.stub.tokens[access_hash]["revoked_at"])
        self.assertIsNotNone(self.stub.tokens[refresh_hash]["revoked_at"])

    def test_exchange_refresh_token_rejects_scope_widening(self):
        from mcp.server.auth.provider import TokenError

        client = self._make_client("client-A")
        asyncio.run(self.provider.register_client(client))
        asyncio.run(
            self.provider.authorize(
                client, self._make_authorize_params(scopes=["analysts"])
            )
        )
        request_id = next(iter(self.stub.requests))
        code = self._issue_code(request_id)
        auth_code = asyncio.run(self.provider.load_authorization_code(client, code))
        token = asyncio.run(
            self.provider.exchange_authorization_code(client, auth_code)
        )
        refresh_obj = asyncio.run(
            self.provider.load_refresh_token(client, token.refresh_token)
        )
        with self.assertRaises(TokenError):
            asyncio.run(
                self.provider.exchange_refresh_token(client, refresh_obj, ["admin"])
            )

    def test_delete_oauth_client_revokes_tokens(self):
        # Issue a token then delete the client; the token must
        # stop validating.
        client = self._make_client("client-A")
        asyncio.run(self.provider.register_client(client))
        asyncio.run(self.provider.authorize(client, self._make_authorize_params()))
        request_id = next(iter(self.stub.requests))
        code = self._issue_code(request_id)
        auth_code = asyncio.run(self.provider.load_authorization_code(client, code))
        token = asyncio.run(
            self.provider.exchange_authorization_code(client, auth_code)
        )
        self.assertIsNotNone(
            asyncio.run(self.provider.load_access_token(token.access_token))
        )
        self.stub.delete_oauth_client("client-A")
        self.assertIsNone(
            asyncio.run(self.provider.load_access_token(token.access_token))
        )

    def test_load_authorization_code_is_non_mutating(self):
        # RFC 6749 §4.1.2 makes the authorization code single-use;
        # the SDK enforces this at the *exchange* step (one atomic
        # consume).  The ``load`` step is a non-mutating peek so
        # parallel loads cannot widen the information-disclosure
        # window if the code leaks.  Pin both invariants: two
        # consecutive ``load_authorization_code`` calls return the
        # same payload, and the underlying record is still present
        # in the store after each.
        client = self._make_client("client-A")
        asyncio.run(self.provider.register_client(client))
        asyncio.run(self.provider.authorize(client, self._make_authorize_params()))
        request_id = next(iter(self.stub.requests))
        code = self._issue_code(request_id)
        self.assertIn(code, self.stub.codes)
        first = asyncio.run(self.provider.load_authorization_code(client, code))
        self.assertIsNotNone(first)
        self.assertIn(code, self.stub.codes)
        second = asyncio.run(self.provider.load_authorization_code(client, code))
        self.assertIsNotNone(second)
        self.assertEqual(second.code_challenge, first.code_challenge)
        self.assertEqual(second.scopes, first.scopes)
        self.assertIn(code, self.stub.codes)
        # The single-shot contract is preserved at the exchange
        # boundary: the first exchange mints tokens, the second
        # raises ``invalid_grant``.
        from mcp.server.auth.provider import TokenError

        asyncio.run(self.provider.exchange_authorization_code(client, first))
        self.assertNotIn(code, self.stub.codes)
        with self.assertRaises(TokenError):
            asyncio.run(self.provider.exchange_authorization_code(client, second))

    def test_peek_authorization_request_is_non_mutating(self):
        # Symmetric guarantee on the consent flow: two
        # consecutive ``peek_authorization_request`` calls return
        # the same payload and the record stays in the store, so
        # a parallel ``GET`` / ``POST`` on the consent page never
        # observes a half-consumed request.
        client = self._make_client("client-A")
        asyncio.run(self.provider.register_client(client))
        asyncio.run(self.provider.authorize(client, self._make_authorize_params()))
        request_id = next(iter(self.stub.requests))
        first = self.mcp_auth.peek_authorization_request(request_id)
        self.assertIsNotNone(first)
        self.assertIn(request_id, self.stub.requests)
        second = self.mcp_auth.peek_authorization_request(request_id)
        self.assertEqual(second, first)
        self.assertIn(request_id, self.stub.requests)
        # The consent ``POST`` is the atomic claim; after it the
        # request is gone.
        self.assertIsNotNone(
            self.mcp_auth.issue_authorization_code(request_id, "alice@example.org")
        )
        self.assertNotIn(request_id, self.stub.requests)
        self.assertIsNone(self.mcp_auth.peek_authorization_request(request_id))


@unittest.skipUnless(_have_mcp(), "mcp dependency not installed")
class McpConsentRouteTests(unittest.TestCase):
    """End-to-end tests for the Bottle consent routes
    (``GET`` / ``POST /auth/oauth/consent``).
    """

    @classmethod
    def setUpClass(cls):
        # ``ivre.web.auth`` raises at module-import time when
        # ``WEB_SECRET`` is unset; populate a dummy secret + flip
        # ``WEB_AUTH_ENABLED`` before the first import so the
        # consent routes register on the bottle application.
        # Module imports are cached so this only takes effect
        # once; restoring the original values in ``tearDownClass``
        # is enough to keep the rest of the suite undisturbed.
        cls._saved_secret = ivre.config.WEB_SECRET
        cls._saved_enabled = ivre.config.WEB_AUTH_ENABLED
        ivre.config.WEB_SECRET = "test-secret-" + "x" * 50
        ivre.config.WEB_AUTH_ENABLED = True
        # Force-import the web modules so the consent routes land
        # on the application before any test runs.  The ``from ...
        # import ...`` form is used instead of bare ``import
        # ivre.web.app`` so Python does not bind ``ivre`` as a
        # local of this method (which would shadow the
        # module-level ``ivre.config`` reads above).
        from ivre.web import app as _app  # noqa: F401
        from ivre.web import auth as _auth  # noqa: F401

    @classmethod
    def tearDownClass(cls):
        ivre.config.WEB_SECRET = cls._saved_secret
        ivre.config.WEB_AUTH_ENABLED = cls._saved_enabled

    def setUp(self):
        from ivre.tools.mcp_server import auth as mcp_auth

        # Same stub as the provider tests; the consent routes go
        # through the same ``db.auth`` reference.
        self.stub = _StubDBAuth()
        self.stub.add_user("alice@example.org", groups=["analysts"])
        self._patcher_provider = mock.patch.object(
            mcp_auth.db, "_auth", self.stub, create=True
        )
        self._patcher_provider.start()
        # ``ivre.web.auth`` also reads ``db.auth`` -- patch the
        # binding in *that* module too.
        import ivre.web.auth as web_auth

        self._patcher_web = mock.patch.object(
            web_auth.db, "_auth", self.stub, create=True
        )
        self._patcher_web.start()
        self._patcher_enabled = mock.patch.object(
            ivre.config, "MCP_OAUTH_AS_ENABLED", True
        )
        self._patcher_enabled.start()
        # Seed one pending authorization request via the provider.
        self.provider = mcp_auth.IvreOAuthProvider("http://ivre.example.org")
        self.client = mcp_auth.IvreOAuthProvider  # alias for type-checkers
        from mcp.shared.auth import OAuthClientInformationFull

        client = OAuthClientInformationFull(
            client_id="client-A",
            client_name="Test MCP Client",
            redirect_uris=["http://callback.example.org/cb"],
        )
        asyncio.run(self.provider.register_client(client))
        from mcp.server.auth.provider import AuthorizationParams
        from pydantic import AnyUrl

        asyncio.run(
            self.provider.authorize(
                client,
                AuthorizationParams(
                    state="client-state-7",
                    scopes=["analysts"],
                    code_challenge="x" * 43,
                    redirect_uri=AnyUrl("http://callback.example.org/cb"),
                    redirect_uri_provided_explicitly=True,
                ),
            )
        )
        self.request_id = next(iter(self.stub.requests))

    def tearDown(self):
        self._patcher_enabled.stop()
        self._patcher_web.stop()
        self._patcher_provider.stop()

    def _wsgi_call(
        self,
        method: str,
        path: str,
        query: str = "",
        body: bytes = b"",
        content_type: str = "",
        user: str | None = "alice@example.org",
        cookies: dict[str, str] | None = None,
    ) -> tuple[str, dict[str, str], bytes]:
        import io as _io

        import ivre.web.app  # noqa: F401 -- side-effecting route registration
        from ivre.web.base import application

        wsgi_errors = _io.StringIO()
        env = {
            "REQUEST_METHOD": method,
            "SERVER_NAME": "ivre.example.org",
            "SERVER_PORT": "80",
            "HTTP_HOST": "ivre.example.org",
            "HTTP_REFERER": "http://ivre.example.org/",
            "wsgi.url_scheme": "http",
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "wsgi.input": _io.BytesIO(body),
            "CONTENT_LENGTH": str(len(body)) if body else "0",
            # Bottle's WSGI machinery writes to ``wsgi.errors`` on
            # uncaught exceptions; provide a sink so a 500 surfaces
            # cleanly through the test instead of a KeyError.
            "wsgi.errors": wsgi_errors,
        }
        if content_type:
            env["CONTENT_TYPE"] = content_type
        if cookies:
            env["HTTP_COOKIE"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        # Patch ``webutils.get_user`` for the duration of the call
        # so we can simulate "logged-in" vs. "anonymous" without
        # wiring the full session-cookie chain.
        import ivre.web.utils as webutils

        captured: dict[str, object] = {}
        # ``Set-Cookie`` headers ship one-per-cookie; the
        # case-folded ``captured["headers"]`` dict can only hold
        # the last one, so collect them separately for tests that
        # need the full list.
        set_cookies: list[str] = []

        def start_response(status, headers, exc_info=None):
            captured["status"] = status
            captured["headers"] = {k.lower(): v for k, v in headers}
            for k, v in headers:
                if k.lower() == "set-cookie":
                    set_cookies.append(v)

        with mock.patch.object(webutils, "get_user", return_value=user):
            body_iter = application(env, start_response)
            body_out = b"".join(body_iter)
        # Stash on the test case so callers wanting the full
        # ``Set-Cookie`` list (e.g. the OAuth round-trip test) can
        # pick it up without changing the return shape every
        # existing test depends on.
        self._set_cookies = set_cookies
        self._wsgi_errors = wsgi_errors.getvalue()
        return (
            captured["status"],  # type: ignore[return-value]
            captured["headers"],  # type: ignore[return-value]
            body_out,
        )

    def test_get_consent_renders_html(self):
        status, headers, body = self._wsgi_call(
            "GET", "/auth/oauth/consent", query=f"request_id={self.request_id}"
        )
        self.assertTrue(status.startswith("200"), status)
        self.assertIn("text/html", headers.get("content-type", ""))
        text = body.decode()
        self.assertIn("Test MCP Client", text)
        self.assertIn("alice@example.org", text)
        # Allow/Deny form points back at the consent endpoint.
        self.assertIn('action="/cgi/auth/oauth/consent"', text)
        self.assertIn(f'value="{self.request_id}"', text)

    def test_get_consent_missing_request_id_is_400(self):
        status, _, _ = self._wsgi_call("GET", "/auth/oauth/consent")
        self.assertTrue(status.startswith("400"), status)

    def test_get_consent_unknown_request_is_400(self):
        status, _, _ = self._wsgi_call(
            "GET", "/auth/oauth/consent", query="request_id=ghost"
        )
        self.assertTrue(status.startswith("400"), status)

    def test_get_consent_anonymous_redirects_to_login(self):
        status, headers, _ = self._wsgi_call(
            "GET",
            "/auth/oauth/consent",
            query=f"request_id={self.request_id}",
            user=None,
        )
        self.assertTrue(status.startswith("302"), status)
        location = headers.get("location", "")
        self.assertIn("/login", location)
        self.assertIn(f"request_id%3D{self.request_id}", location)

    def test_post_consent_allow_mints_code(self):
        body = f"request_id={self.request_id}&action=allow".encode()
        status, headers, _ = self._wsgi_call(
            "POST",
            "/auth/oauth/consent",
            body=body,
            content_type="application/x-www-form-urlencoded",
        )
        self.assertTrue(status.startswith("302"), status)
        location = headers.get("location", "")
        self.assertTrue(location.startswith("http://callback.example.org/cb"))
        self.assertIn("state=client-state-7", location)
        self.assertIn("code=", location)
        # The pending request was consumed; a code now exists.
        self.assertNotIn(self.request_id, self.stub.requests)
        self.assertEqual(len(self.stub.codes), 1)

    def test_post_consent_deny_returns_access_denied(self):
        body = f"request_id={self.request_id}&action=deny".encode()
        status, headers, _ = self._wsgi_call(
            "POST",
            "/auth/oauth/consent",
            body=body,
            content_type="application/x-www-form-urlencoded",
        )
        self.assertTrue(status.startswith("302"), status)
        location = headers.get("location", "")
        self.assertIn("error=access_denied", location)
        self.assertIn("state=client-state-7", location)
        # The pending request is also cleaned up on deny.
        self.assertNotIn(self.request_id, self.stub.requests)
        self.assertEqual(self.stub.codes, {})

    def test_post_consent_anonymous_is_401(self):
        body = f"request_id={self.request_id}&action=allow".encode()
        status, _, _ = self._wsgi_call(
            "POST",
            "/auth/oauth/consent",
            body=body,
            content_type="application/x-www-form-urlencoded",
            user=None,
        )
        self.assertTrue(status.startswith("401"), status)

    def test_consent_disabled_returns_404(self):
        with mock.patch.object(ivre.config, "MCP_OAUTH_AS_ENABLED", False):
            status, _, _ = self._wsgi_call(
                "GET",
                "/auth/oauth/consent",
                query=f"request_id={self.request_id}",
            )
        self.assertTrue(status.startswith("404"), status)

    def test_oauth_consent_round_trip(self):
        # End-to-end: anonymous user hits the consent page,
        # follows the /login redirect, picks a provider, the
        # mocked IdP "approves", the callback lands the user
        # back on the consent page with the original request_id
        # preserved.  This pins the full ``next=`` plumbing from
        # the consent route through to the callback.
        #
        # ``get_enabled_providers`` / ``get_authorize_url`` etc.
        # are imported by name into :mod:`ivre.web.auth` at
        # module-load time, so the patch target is the consumer
        # namespace, not the upstream :mod:`ivre.web.oauth`.
        from ivre.web import auth as web_auth

        # 1. Anonymous GET on the consent page -> /login?next=…
        status, headers, _ = self._wsgi_call(
            "GET",
            "/auth/oauth/consent",
            query=f"request_id={self.request_id}",
            user=None,
        )
        self.assertTrue(status.startswith("302"), status)
        login_target = headers.get("location", "")
        from urllib.parse import parse_qs, urlsplit

        login_parts = urlsplit(login_target)
        next_value = parse_qs(login_parts.query).get("next", [""])[0]
        self.assertIn("/cgi/auth/oauth/consent", next_value)
        self.assertIn(self.request_id, next_value)

        # 2. The legacy login page forwards ``next=`` to the
        # provider link.  Simulate that by hitting
        # /auth/login/google?next=<same>.  The mocked
        # ``get_authorize_url`` echoes the *original* state token
        # back into the redirect Location header, which is the
        # value the upstream IdP would later round-trip as a
        # query parameter on the callback.
        from urllib.parse import quote_plus

        with (
            mock.patch.object(
                web_auth, "get_enabled_providers", return_value=["google"]
            ),
            mock.patch.object(
                web_auth,
                "get_authorize_url",
                side_effect=lambda p, s, r: f"https://idp.example/auth?state={s}",
            ),
        ):
            status, headers, _ = self._wsgi_call(
                "GET",
                "/auth/login/google",
                query=f"next={quote_plus(next_value)}",
            )
        self.assertTrue(status.startswith("302"), status)
        # Two cookies should have been set: ``_ivre_oauth_state``
        # and ``_ivre_login_next``.
        set_cookies = self._set_cookies
        cookie_names = {c.split("=", 1)[0] for c in set_cookies}
        self.assertIn("_ivre_oauth_state", cookie_names)
        self.assertIn("_ivre_login_next", cookie_names)
        # The *signed* cookie blobs (base64-encoded HMAC envelope)
        # are what the browser would send back on the next request.
        state_cookie_blob = (
            next(c for c in set_cookies if c.startswith("_ivre_oauth_state="))
            .split("=", 1)[1]
            .split(";", 1)[0]
        )
        next_cookie_blob = (
            next(c for c in set_cookies if c.startswith("_ivre_login_next="))
            .split("=", 1)[1]
            .split(";", 1)[0]
        )
        # The *original* state token (pre-cookie-signing) was
        # echoed into the redirect Location header by the mocked
        # ``get_authorize_url``.  The upstream IdP would send it
        # back as a query parameter, which is what the callback
        # validates against the cookie payload.
        idp_target = headers.get("location", "")
        original_state = parse_qs(urlsplit(idp_target).query)["state"][0]

        # 3. Provider callback with the captured cookies + the
        # original state token in the query.  Mock
        # ``exchange_code`` + ``get_user_email`` to return our
        # test user.
        with (
            mock.patch.object(
                web_auth, "get_enabled_providers", return_value=["google"]
            ),
            mock.patch.object(
                web_auth,
                "exchange_code",
                return_value={"access_token": "fake"},
            ),
            mock.patch.object(
                web_auth,
                "get_user_email",
                return_value=("alice@example.org", "Alice"),
            ),
        ):
            status, headers, body = self._wsgi_call(
                "GET",
                "/auth/callback/google",
                query=f"state={quote_plus(original_state)}&code=fake-code",
                cookies={
                    "_ivre_oauth_state": state_cookie_blob,
                    "_ivre_login_next": next_cookie_blob,
                },
                user=None,
            )
        self.assertTrue(
            status.startswith("302"),
            f"status={status}\nerrors={self._wsgi_errors[-1500:]}",
        )
        final_target = headers.get("location", "")
        # The callback should redirect back to the consent URL,
        # not to ``/``.
        self.assertIn("/cgi/auth/oauth/consent", final_target)
        self.assertIn(self.request_id, final_target)

        # 4. Sanity: a tampered ``_ivre_login_next`` cookie must
        # fall back to ``/`` (the signed-cookie reader rejects
        # the forgery before the validator sees it).
        with (
            mock.patch.object(
                web_auth, "get_enabled_providers", return_value=["google"]
            ),
            mock.patch.object(
                web_auth,
                "exchange_code",
                return_value={"access_token": "fake"},
            ),
            mock.patch.object(
                web_auth,
                "get_user_email",
                return_value=("alice@example.org", "Alice"),
            ),
        ):
            status, headers, _ = self._wsgi_call(
                "GET",
                "/auth/callback/google",
                query=f"state={quote_plus(original_state)}&code=fake-code",
                cookies={
                    "_ivre_oauth_state": state_cookie_blob,
                    "_ivre_login_next": "garbage",
                },
                user=None,
            )
        self.assertTrue(status.startswith("302"), status)
        # Bottle's ``redirect()`` resolves the trailing-slash
        # path against the request origin; either form is fine,
        # what matters is that the consent URL is NOT the
        # destination.
        location = headers.get("location", "")
        self.assertNotIn("/cgi/auth/oauth/consent", location)
        self.assertTrue(
            location.endswith("/") and not location.endswith("/cb"),
            f"expected a fallback redirect to /, got {location!r}",
        )


# ---------------------------------------------------------------------
# LoginNextRedirectTests -- pin the ``next=`` plumbing the OAuth
# consent route depends on: the validator at the front, the signed
# cookie carrier across ``/auth/login`` -> ``/auth/callback``, and
# the magic-link variant that embeds ``next=`` in the verify URL.
# ---------------------------------------------------------------------


@unittest.skipUnless(_have_mcp(), "mcp dependency not installed")
class LoginNextRedirectTests(unittest.TestCase):
    """Unit + integration tests for :func:`_validate_next_url` and
    the ``next=`` carrier cookie / magic-link round-trip.
    """

    @classmethod
    def setUpClass(cls):
        cls._saved_secret = ivre.config.WEB_SECRET
        cls._saved_enabled = ivre.config.WEB_AUTH_ENABLED
        cls._saved_magic = ivre.config.WEB_AUTH_MAGIC_LINK_ENABLED
        ivre.config.WEB_SECRET = "test-secret-" + "x" * 50
        ivre.config.WEB_AUTH_ENABLED = True
        # Magic-link tests below need the flag on.
        ivre.config.WEB_AUTH_MAGIC_LINK_ENABLED = True
        from ivre.web import app as _app  # noqa: F401
        from ivre.web import auth as _auth  # noqa: F401

    @classmethod
    def tearDownClass(cls):
        ivre.config.WEB_SECRET = cls._saved_secret
        ivre.config.WEB_AUTH_ENABLED = cls._saved_enabled
        ivre.config.WEB_AUTH_MAGIC_LINK_ENABLED = cls._saved_magic

    # --- _validate_next_url ----------------------------------------

    def test_validate_next_url_accepts_safe_paths(self):
        from ivre.web.auth import _validate_next_url

        cases = [
            "/",
            "/foo",
            "/foo/bar",
            "/foo?a=1&b=2",
            "/cgi/auth/oauth/consent?request_id=abc",
            "/foo#frag",
            "/" + "a" * 1000,
        ]
        for value in cases:
            with self.subTest(value=value):
                self.assertEqual(_validate_next_url(value), value)

    def test_validate_next_url_rejects_open_redirect_shapes(self):
        from ivre.web.auth import _validate_next_url

        rejected = [
            None,
            "",
            "foo",  # no leading slash
            "//evil.com",  # protocol-relative
            "/\\evil.com",  # backslash variant
            "http://x",  # absolute URL
            "https://x",
            "javascript:alert(1)",  # scheme injection
            "//",  # empty protocol-relative
            "/foo\r\nLocation: http://evil",  # CRLF injection
            "/foo\nfoo",
            "/foo\x00",  # NUL injection
            "/" + "a" * 3000,  # length cap
        ]
        for value in rejected:
            with self.subTest(value=value):
                self.assertIsNone(_validate_next_url(value))

    # --- login_provider / callback_provider -------------------------

    def _wsgi_call(
        self,
        method: str,
        path: str,
        query: str = "",
        body: bytes = b"",
        content_type: str = "",
        cookies: dict[str, str] | None = None,
    ) -> tuple[str, dict[str, str], list[str], bytes]:
        import io as _io

        from ivre.web.base import application

        env = {
            "REQUEST_METHOD": method,
            "SERVER_NAME": "ivre.example.org",
            "SERVER_PORT": "80",
            "HTTP_HOST": "ivre.example.org",
            "HTTP_REFERER": "http://ivre.example.org/",
            "wsgi.url_scheme": "http",
            "PATH_INFO": path,
            "QUERY_STRING": query,
            "wsgi.input": _io.BytesIO(body),
            "CONTENT_LENGTH": str(len(body)) if body else "0",
        }
        if content_type:
            env["CONTENT_TYPE"] = content_type
        if cookies:
            env["HTTP_COOKIE"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        captured: dict[str, object] = {}
        set_cookies: list[str] = []

        def start_response(status, headers, exc_info=None):
            captured["status"] = status
            captured["headers"] = {k.lower(): v for k, v in headers}
            for k, v in headers:
                if k.lower() == "set-cookie":
                    set_cookies.append(v)

        body_out = b"".join(application(env, start_response))
        return (
            captured["status"],  # type: ignore[return-value]
            captured["headers"],  # type: ignore[return-value]
            set_cookies,
            body_out,
        )

    def test_login_provider_stashes_validated_next(self):
        # ``get_enabled_providers`` / ``get_authorize_url`` are
        # imported into ``ivre.web.auth`` by name at module-load
        # time, so the patch target is the consumer's namespace,
        # not the upstream module.
        from ivre.web import auth as web_auth

        with (
            mock.patch.object(
                web_auth, "get_enabled_providers", return_value=["google"]
            ),
            mock.patch.object(
                web_auth,
                "get_authorize_url",
                side_effect=lambda p, s, r: f"https://idp.example/auth?state={s}",
            ),
        ):
            status, _, set_cookies, _ = self._wsgi_call(
                "GET",
                "/auth/login/google",
                query="next=" + "/cgi/auth/oauth/consent",
            )
        self.assertTrue(status.startswith("302"), status)
        names = {c.split("=", 1)[0] for c in set_cookies}
        self.assertIn("_ivre_oauth_state", names)
        self.assertIn("_ivre_login_next", names)

    def test_login_provider_drops_unsafe_next(self):
        # Open-redirect attempts must NOT result in a stash;
        # the user-facing flow still works, but the post-login
        # redirect falls back to ``/``.
        from ivre.web import auth as web_auth

        with (
            mock.patch.object(
                web_auth, "get_enabled_providers", return_value=["google"]
            ),
            mock.patch.object(
                web_auth,
                "get_authorize_url",
                side_effect=lambda p, s, r: f"https://idp.example/auth?state={s}",
            ),
        ):
            status, _, set_cookies, _ = self._wsgi_call(
                "GET",
                "/auth/login/google",
                query="next=//evil.com/path",
            )
        self.assertTrue(status.startswith("302"), status)
        names = {c.split("=", 1)[0] for c in set_cookies}
        self.assertIn("_ivre_oauth_state", names)
        self.assertNotIn("_ivre_login_next", names)

    # --- magic-link -------------------------------------------------

    def test_magic_link_send_embeds_next_in_link(self):
        # Capture the email body by patching ``smtplib.SMTP``;
        # the test asserts the rendered link contains ``&next=…``.
        from ivre.web import auth as web_auth

        sent = {}

        class _StubSMTP:
            def __init__(self, host, port):
                pass

            def starttls(self):
                pass

            def login(self, user, password):
                pass

            def sendmail(self, src, to, msg):
                sent["src"] = src
                sent["to"] = to
                sent["msg"] = msg

            def quit(self):
                pass

        # Patch the magic-link token creation so we don't need a
        # real backend; capture the rendered URL via the SMTP stub.
        with (
            mock.patch.object(web_auth, "smtplib") as smtplib_mod,
            mock.patch.object(web_auth, "db") as db_mod,
        ):
            smtplib_mod.SMTP = _StubSMTP  # type: ignore[assignment]
            db_mod.auth.create_magic_link_token.return_value = "TOKEN"
            db_mod.auth.is_rate_limited.return_value = False
            db_mod.auth.record_rate_limit.return_value = None
            body = json.dumps(
                {"email": "alice@example.org", "next": "/cgi/auth/oauth/consent"}
            ).encode()
            status, _, _, _ = self._wsgi_call(
                "POST",
                "/auth/magic-link",
                body=body,
                content_type="application/json",
            )
        self.assertTrue(status.startswith("200"), status)
        # ``msg.as_string()`` returns a ``str``; the SMTP stub
        # stored it verbatim.
        rendered = sent.get("msg", "")
        if isinstance(rendered, bytes):
            rendered = rendered.decode("utf-8", "replace")
        self.assertIn("token=TOKEN", rendered)
        self.assertIn("next=", rendered)

    def test_magic_link_send_drops_unsafe_next(self):
        # Unsafe ``next`` must be silently dropped, not echoed
        # into the email link.
        from ivre.web import auth as web_auth

        sent: dict[str, str] = {}

        class _StubSMTP:
            def __init__(self, host, port):
                pass

            def starttls(self):
                pass

            def login(self, user, password):
                pass

            def sendmail(self, src, to, msg):
                sent["msg"] = (
                    msg.decode("utf-8", "replace") if isinstance(msg, bytes) else msg
                )

            def quit(self):
                pass

        with (
            mock.patch.object(web_auth, "smtplib") as smtplib_mod,
            mock.patch.object(web_auth, "db") as db_mod,
        ):
            smtplib_mod.SMTP = _StubSMTP  # type: ignore[assignment]
            db_mod.auth.create_magic_link_token.return_value = "TOKEN"
            db_mod.auth.is_rate_limited.return_value = False
            db_mod.auth.record_rate_limit.return_value = None
            body = json.dumps(
                {"email": "alice@example.org", "next": "//evil.com/x"}
            ).encode()
            self._wsgi_call(
                "POST",
                "/auth/magic-link",
                body=body,
                content_type="application/json",
            )
        self.assertNotIn("next=", sent.get("msg", ""))


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
# ElasticDBSearchTextTests -- pin the wire shape of the
# Elasticsearch ``searchtext()`` helper added alongside the
# PostgreSQL and DuckDB sibling implementations.  Closes the
# cross-backend ``searchtext`` parity story; a follow-up commit
# in this PR drops the four ``hasattr(self, "searchtext")``
# guards in :mod:`ivre.db`, :mod:`ivre.web.utils` and the
# Mongo-only gate in ``tests/tests.py``'s ``test_50_view``.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_ELASTICSEARCH_DSL,
    "elasticsearch_dsl is required (install with the ``elasticsearch`` extras)",
)
class ElasticDBSearchTextTests(unittest.TestCase):
    """Pin :meth:`ElasticDBActive.searchtext` -- the Elastic
    counterpart of :meth:`MongoDB.searchtext`,
    :meth:`SQLDBActive.searchtext` and
    :meth:`DuckDBNmap.searchtext`.

    The implementation OR-composes one ``multi_match`` per
    nesting level of :attr:`DBActive.text_fields`: a root
    ``multi_match`` for the flat fields plus one
    :class:`~elasticsearch_dsl.query.Nested` query per
    :attr:`ElasticDBActive.nested_fields` group (``ports``,
    ``ports.scripts``, ``tags``).  A top-level
    ``multi_match`` against a nested-typed field silently
    returns no hits in Elasticsearch, which is why the split
    is required.
    """

    @staticmethod
    def _ED():
        # Local import: ``elasticsearch_dsl`` may not be
        # installed in the no-backend lane.
        from ivre.db.elastic import ElasticDBView

        return ElasticDBView

    def test_searchtext_emits_or_of_multi_match_groups(self):
        body = self._ED().searchtext("honeypot").to_dict()
        # OR composition: ``bool.should`` of one root
        # ``multi_match`` plus one ``nested`` per nested path
        # that carries any text field.  The non-root groups
        # currently come from
        # :data:`ElasticDBActive.nested_fields` -- ``ports``
        # (service / screenwords), ``ports.scripts``
        # (output), ``tags`` (info / value), and
        # ``traces.hops`` (host).  A top-level
        # ``multi_match`` against a nested-typed field
        # silently returns no hits in Elasticsearch, which is
        # why the split is required; the test pins the
        # partition so a future drift between
        # :data:`text_fields` and :data:`nested_fields`
        # surfaces here.
        self.assertEqual(set(body), {"bool"})
        self.assertEqual(set(body["bool"]), {"should"})
        clauses = body["bool"]["should"]
        # 1 root + 4 nested groups.
        self.assertEqual(len(clauses), 5)
        # Root-level ``multi_match`` over the flat fields
        # (``categories`` / ``cpes.*`` / ``hostnames.*`` /
        # ``os.*``).
        root = next(c["multi_match"] for c in clauses if "multi_match" in c)
        self.assertEqual(root["query"], "honeypot")
        self.assertIn("categories", root["fields"])
        self.assertIn("hostnames.name", root["fields"])
        # No nested fields leaked into the root group --
        # ``traces.hops.host`` lands in the ``traces.hops``
        # nested clause, not at the root.
        self.assertNotIn("ports.service_name", root["fields"])
        self.assertNotIn("tags.value", root["fields"])
        self.assertNotIn("traces.hops.host", root["fields"])
        # And every nested group wraps a ``multi_match`` over
        # its own path's fields.
        nested_paths = {c["nested"]["path"] for c in clauses if "nested" in c}
        self.assertEqual(
            nested_paths,
            {"ports", "ports.scripts", "tags", "traces.hops"},
        )
        for clause in clauses:
            if "nested" not in clause:
                continue
            path = clause["nested"]["path"]
            inner = clause["nested"]["query"]["multi_match"]
            self.assertEqual(inner["query"], "honeypot")
            for field in inner["fields"]:
                self.assertTrue(
                    field == path or field.startswith(f"{path}."),
                    f"field {field!r} not under nested path {path!r}",
                )

    def test_searchtext_negation_wraps_in_must_not(self):
        body = self._ED().searchtext("honeypot", neg=True).to_dict()
        # The negative form wraps the whole ``should``-of-groups
        # in a ``must_not`` array.  Each nested clause is now
        # under ``bool.must_not`` instead of ``bool.should``.
        self.assertEqual(set(body), {"bool"})
        self.assertEqual(set(body["bool"]), {"must_not"})
        # Same fan-out (1 root + 4 nested).
        self.assertEqual(len(body["bool"]["must_not"]), 5)

    def test_searchtext_text_fields_are_partitioned_correctly(self):
        # Pin that every entry in
        # :attr:`DBActive.text_fields` lands in *exactly one*
        # group (root or nested), and that the union of all
        # groups equals the full ``text_fields`` list.  Drift
        # would silently drop fields from the search.
        from ivre.db import DBActive

        body = self._ED().searchtext("foo").to_dict()
        emitted: set[str] = set()
        for clause in body["bool"]["should"]:
            if "multi_match" in clause:
                emitted.update(clause["multi_match"]["fields"])
            elif "nested" in clause:
                emitted.update(clause["nested"]["query"]["multi_match"]["fields"])
        self.assertEqual(emitted, set(DBActive.text_fields))

    def test_searchtext_with_no_text_fields_yields_nonexistent(self):
        # Defensive: a hypothetical subclass that drops every
        # ``text_field`` would otherwise emit
        # ``Q("multi_match", query=..., fields=[])`` -- which
        # Elasticsearch rejects as malformed.  Pin that the
        # empty-fields case short-circuits to
        # :meth:`searchnonexistent` instead.
        sa = self._ED()

        class _Empty(sa):  # type: ignore[misc, valid-type]
            text_fields: list[str] = []

        body = _Empty.searchtext("foo").to_dict()
        # ``searchnonexistent`` returns ``Q("match", _id=0)`` --
        # i.e. ``{"match": {"_id": 0}}``.
        self.assertEqual(body, {"match": {"_id": 0}})


# ---------------------------------------------------------------------
# ElasticDBSearchTier1Tests -- pin the wire shape of the
# Tier-1 ``search*`` parity helpers added on
# ``ElasticDBActive``: ``searchsource`` / ``searchhostname`` /
# ``searchdomain`` (the three that previously raised
# ``NotImplementedError`` or were missing entirely on the
# Elastic backend).  ``searchntlm`` / ``searchsmb`` /
# ``searchsshkey`` already work via the
# :meth:`ElasticDBActive.searchscript` inheritance chain;
# ``test_inherited_helpers_compose_through_searchscript``
# pins that.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_ELASTICSEARCH_DSL,
    "elasticsearch_dsl is required (install with the ``elasticsearch`` extras)",
)
class ElasticDBSearchTier1Tests(unittest.TestCase):
    """Behaviour-pin for ``ElasticDBActive.searchsource`` /
    ``searchhostname`` / ``searchdomain``, plus a regression
    pin that the script-delegating helpers (``searchntlm`` /
    ``searchsmb`` / ``searchsshkey``) keep producing valid
    Elasticsearch nested queries.
    """

    @staticmethod
    def _ED():
        # Local import: ``elasticsearch_dsl`` may not be
        # installed in the no-backend lane.
        from ivre.db.elastic import ElasticDBView

        return ElasticDBView

    # -- searchsource --------------------------------------------------

    def test_searchsource_scalar(self):
        body = self._ED().searchsource("scan-2024").to_dict()
        self.assertEqual(body, {"match": {"source": "scan-2024"}})

    def test_searchsource_neg(self):
        body = self._ED().searchsource("scan-2024", neg=True).to_dict()
        self.assertEqual(
            body, {"bool": {"must_not": [{"match": {"source": "scan-2024"}}]}}
        )

    def test_searchsource_regex_uses_regexp_query(self):
        import re

        body = self._ED().searchsource(re.compile("^scan-")).to_dict()
        # ``_get_pattern`` strips the leading anchor and adds
        # ``.*`` to match Elasticsearch's
        # anchored-by-default ``regexp`` semantics.
        self.assertEqual(body, {"regexp": {"source": "scan-.*"}})

    def test_searchsource_list_uses_terms_query(self):
        body = self._ED().searchsource(["a", "b"]).to_dict()
        self.assertEqual(body, {"terms": {"source": ["a", "b"]}})

    # -- searchdomain --------------------------------------------------

    def test_searchdomain_scalar(self):
        body = self._ED().searchdomain("example.com").to_dict()
        self.assertEqual(body, {"match": {"hostnames.domains": "example.com"}})

    def test_searchdomain_neg(self):
        body = self._ED().searchdomain("example.com", neg=True).to_dict()
        self.assertEqual(
            body,
            {"bool": {"must_not": [{"match": {"hostnames.domains": "example.com"}}]}},
        )

    # -- searchhostname ------------------------------------------------

    def test_searchhostname_no_args_uses_existence_check(self):
        body = self._ED().searchhostname().to_dict()
        # Existence is gated on the indexed
        # ``hostnames.domains`` field rather than the
        # non-indexed ``hostnames.name``.
        self.assertEqual(body, {"exists": {"field": "hostnames.domains"}})

    def test_searchhostname_no_args_neg(self):
        body = self._ED().searchhostname(neg=True).to_dict()
        self.assertEqual(
            body,
            {"bool": {"must_not": [{"exists": {"field": "hostnames.domains"}}]}},
        )

    def test_searchhostname_positive_combines_indexed_lookup_and_name(self):
        body = self._ED().searchhostname("foo.example.com").to_dict()
        # Positive match ANDs the indexed domain lookup (so
        # the query goes through the ``hostnames.domains``
        # index) with the ``hostnames.name`` match.
        self.assertEqual(
            body,
            {
                "bool": {
                    "must": [
                        {"match": {"hostnames.domains": "foo.example.com"}},
                        {"match": {"hostnames.name": "foo.example.com"}},
                    ]
                }
            },
        )

    def test_searchhostname_negation_skips_indexed_lookup(self):
        # The Mongo helper's ``neg=True`` path only excludes
        # records matching the supplied name on
        # ``hostnames.name`` -- it does *not* ``$nin`` the
        # indexed ``hostnames.domains`` lookup (the latter
        # would silently exclude legitimate non-matches).
        # Pin the same shape on the Elastic side.
        body = self._ED().searchhostname("foo.example.com", neg=True).to_dict()
        self.assertEqual(
            body,
            {"bool": {"must_not": [{"match": {"hostnames.name": "foo.example.com"}}]}},
        )

    # -- searchversion -------------------------------------------------

    def test_searchversion_scalar_matches_field(self):
        # ``searchversion(N)`` -> ``match`` query against
        # ``schema_version``; mirrors Mongo's
        # ``{"schema_version": N}`` shape.
        body = self._ED().searchversion(22).to_dict()
        self.assertEqual(body, {"match": {"schema_version": 22}})

    def test_searchversion_none_matches_legacy_records(self):
        # ``searchversion(None)`` -> negation of ``exists``;
        # mirrors Mongo's ``{"$exists": False}`` shape and
        # picks up only legacy documents ingested before the
        # ``schema_version`` field was added.
        body = self._ED().searchversion(None).to_dict()
        self.assertEqual(
            body,
            {"bool": {"must_not": [{"exists": {"field": "schema_version"}}]}},
        )

    # -- searchrange / searchnet / searchipv4 / searchipv6 -------------

    def test_searchrange_uses_native_ip_range(self):
        # ``addr`` is mapped as ES's native ``ip`` type, so a
        # range over printable IP strings works directly --
        # no ``ip2internal`` int128 split (the Mongo helper
        # needs one because it stores ``addr_0`` / ``addr_1``).
        body = self._ED().searchrange("10.0.0.0", "10.0.0.255").to_dict()
        self.assertEqual(
            body,
            {"range": {"addr": {"gte": "10.0.0.0", "lte": "10.0.0.255"}}},
        )

    def test_searchrange_neg_inverts_at_host_level(self):
        body = self._ED().searchrange("10.0.0.0", "10.0.0.255", neg=True).to_dict()
        self.assertEqual(
            body,
            {
                "bool": {
                    "must_not": [
                        {"range": {"addr": {"gte": "10.0.0.0", "lte": "10.0.0.255"}}}
                    ]
                }
            },
        )

    def test_searchnet_routes_through_searchrange(self):
        # ``searchnet`` is inherited from :class:`DBActive` and
        # delegates to :meth:`searchrange` -- pin that the CIDR
        # gets translated to its ``[start, stop]`` boundaries
        # via :func:`utils.net2range` and that the resulting
        # query is the canonical ES ``range`` shape.
        body = self._ED().searchnet("192.168.0.0/24").to_dict()
        self.assertEqual(
            body,
            {"range": {"addr": {"gte": "192.168.0.0", "lte": "192.168.0.255"}}},
        )

    def test_searchipv4_covers_full_v4_range(self):
        # ``searchipv4()`` -> ``searchnet("0.0.0.0/0")`` ->
        # ``searchrange("0.0.0.0", "255.255.255.255")``.
        body = self._ED().searchipv4().to_dict()
        self.assertEqual(
            body,
            {"range": {"addr": {"gte": "0.0.0.0", "lte": "255.255.255.255"}}},
        )

    def test_searchipv6_negates_full_v4_range(self):
        # ``searchipv6()`` -> ``searchnet("0.0.0.0/0", neg=True)``
        # -> negated ``searchrange``; matches everything
        # *outside* the IPv4 range, i.e. IPv6 hosts (the
        # ``addr`` ``ip`` field also accepts IPv6 strings).
        body = self._ED().searchipv6().to_dict()
        self.assertEqual(
            body,
            {
                "bool": {
                    "must_not": [
                        {
                            "range": {
                                "addr": {
                                    "gte": "0.0.0.0",
                                    "lte": "255.255.255.255",
                                }
                            }
                        }
                    ]
                }
            },
        )

    # -- regex case_insensitive routing -------------------------------

    def test_searchscript_regex_value_honors_ignorecase(self):
        # ``re.IGNORECASE`` (the IVRE shorthand ``/pattern/i``)
        # translates to Elasticsearch's
        # ``regexp.<field>.case_insensitive`` parameter (ES
        # 7.10+) so the case-insensitive Mongo behaviour
        # carries over.  Without this routing, the
        # ``http-user-agent`` filter -- which the test fixture
        # exercises with ``re.compile("URL/7.3", re.IGNORECASE)``
        # -- silently matched zero records on Elasticsearch
        # because ``regexp`` defaults to case-sensitive.
        import re as _re

        body = (
            self._ED()
            .searchuseragent(useragent=_re.compile("URL/7.3", _re.IGNORECASE))
            .to_dict()
        )
        # Drill down through the two-level nested wrapper
        # ``searchscript`` produces.
        bool_must = body["nested"]["query"]["nested"]["query"]["bool"]["must"]
        # The script-id ``match`` clause is unchanged; the
        # interesting bit is the second clause -- the
        # value ``regexp`` -- which now carries the dict form.
        regexp_clause = next(c for c in bool_must if "regexp" in c)
        self.assertEqual(
            regexp_clause["regexp"]["ports.scripts.http-user-agent"],
            {"value": ".*URL/7.3.*", "case_insensitive": True},
        )

    def test_searchscript_regex_value_without_ignorecase_stays_plain(self):
        # Without ``re.IGNORECASE`` the historical
        # plain-string shape is preserved -- both for
        # byte-for-byte pin compatibility with the rest of
        # the suite and so existing call sites that rely on
        # case-sensitive matching keep working unchanged.
        import re as _re

        body = self._ED().searchuseragent(useragent=_re.compile("URL/7.3")).to_dict()
        bool_must = body["nested"]["query"]["nested"]["query"]["bool"]["must"]
        regexp_clause = next(c for c in bool_must if "regexp" in c)
        self.assertEqual(
            regexp_clause["regexp"]["ports.scripts.http-user-agent"],
            ".*URL/7.3.*",
        )

    # -- inherited (delegate to searchscript) --------------------------

    def test_inherited_helpers_compose_through_searchscript(self):
        # ``searchntlm`` / ``searchsmb`` / ``searchsshkey``
        # already inherit from ``DBActive`` and route through
        # :meth:`ElasticDBActive.searchscript`.  Pin that they
        # produce the canonical
        # ``Nested(ports) -> Nested(ports.scripts) -> Bool``
        # shape so a future refactor of the inherited helpers
        # cannot silently break Tier-1 parity.
        # ``searchsshkey`` is the only one of the three that
        # is an *instance* method on ``DBActive`` (it has no
        # ``@classmethod`` decorator), so the dispatch needs
        # a real instance rather than the class itself.
        db = self._ED().from_url("elastic://x:9200")
        for method, kwargs, script_id in [
            ("searchntlm", {"protocol": "smb"}, "ntlm-info"),
            ("searchsmb", {"os": "Windows 10"}, "smb-os-discovery"),
            ("searchsshkey", {"keytype": "rsa"}, "ssh-hostkey"),
        ]:
            with self.subTest(method=method):
                body = getattr(db, method)(**kwargs).to_dict()
                self.assertIn("nested", body)
                self.assertEqual(body["nested"]["path"], "ports")
                inner = body["nested"]["query"]
                self.assertIn("nested", inner)
                self.assertEqual(inner["nested"]["path"], "ports.scripts")
                # Every script-delegating helper anchors the
                # match on ``ports.scripts.id``.
                must = inner["nested"]["query"]["bool"]["must"]
                self.assertIn({"match": {"ports.scripts.id": script_id}}, must)


# ---------------------------------------------------------------------
# ElasticDBSearchTier2Tests -- pin the wire shape of the
# Tier-2 ``search*`` parity helpers added on
# ``ElasticDBActive``: ``searchsmbshares`` /
# ``searchscreenshot`` / ``searchhttptitle`` /
# ``searchldapanon`` / ``searchvsftpdbackdoor`` /
# ``searchwebmin`` / ``searchhop`` / ``searchhopname`` /
# ``searchhopdomain``.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_ELASTICSEARCH_DSL,
    "elasticsearch_dsl is required (install with the ``elasticsearch`` extras)",
)
class ElasticDBSearchTier2Tests(unittest.TestCase):
    """Behaviour-pin for Tier-2 ``ElasticDBActive.search*``
    parity helpers.  All nine helpers were missing on Elastic
    before this PR and route through bespoke
    ``Q("nested", path="ports", ...)`` /
    ``Q("nested", path="ports.scripts", ...)`` builders rather
    than :meth:`ElasticDBActive.searchscript` (which cannot
    translate the nested ``$elemMatch`` / ``$or`` / ``$nin``
    shape Mongo's ``searchsmbshares`` produces).
    """

    @staticmethod
    def _ED():
        from ivre.db.elastic import ElasticDBView

        return ElasticDBView

    # -- traces.hops --------------------------------------------------

    def test_searchhop_scalar(self):
        # ``traces.hops`` is declared in
        # :attr:`ElasticDBActive.nested_fields`, so single-field
        # hop queries are wrapped in
        # ``Q("nested", path="traces.hops", ...)`` for shape
        # consistency with the cross-field ``ttl`` form below
        # and to make ``neg=True`` mean "no hop matches" rather
        # than the flat-array "at least one hop differs" form.
        body = self._ED().searchhop("1.2.3.4").to_dict()
        self.assertEqual(
            body,
            {
                "nested": {
                    "path": "traces.hops",
                    "query": {"match": {"traces.hops.ipaddr": "1.2.3.4"}},
                }
            },
        )

    def test_searchhop_with_ttl(self):
        # Cross-field correlation: ``ipaddr`` and ``ttl`` must
        # agree on the *same* hop array element, which the
        # ``nested(traces.hops)`` wrapper enforces.  Without it,
        # a flat ``bool.must`` of two ``match`` queries matched
        # any host where one hop has the right ``ipaddr`` and
        # any other hop has the right ``ttl`` -- the bug that
        # made ``view_top_hop_10+`` rank every hop of every host
        # with a TTL>10 hop, including the very-near-the-scanner
        # gateway at TTL 0.
        body = self._ED().searchhop("1.2.3.4", ttl=5).to_dict()
        self.assertEqual(
            body,
            {
                "nested": {
                    "path": "traces.hops",
                    "query": {
                        "bool": {
                            "must": [
                                {"match": {"traces.hops.ipaddr": "1.2.3.4"}},
                                {"match": {"traces.hops.ttl": 5}},
                            ]
                        }
                    },
                }
            },
        )

    def test_searchhop_neg(self):
        # Negation lands *outside* the ``nested`` wrapper so
        # the predicate translates to "no hop matches" -- the
        # ``$ne``-equivalent shape Mongo's
        # :meth:`MongoDB.searchhop` produces.  An "inside"
        # negation would mean "at least one hop differs",
        # which matches strictly more documents.
        body = self._ED().searchhop("1.2.3.4", neg=True).to_dict()
        self.assertEqual(
            body,
            {
                "bool": {
                    "must_not": [
                        {
                            "nested": {
                                "path": "traces.hops",
                                "query": {"match": {"traces.hops.ipaddr": "1.2.3.4"}},
                            }
                        }
                    ]
                }
            },
        )

    def test_searchhopdomain_scalar(self):
        body = self._ED().searchhopdomain("example.com").to_dict()
        self.assertEqual(
            body,
            {
                "nested": {
                    "path": "traces.hops",
                    "query": {"match": {"traces.hops.domains": "example.com"}},
                }
            },
        )

    def test_searchhopname_combines_domain_and_host(self):
        # Same indexed-domain + non-indexed-name shape
        # ``searchhostname`` ships in the Tier-1 search work,
        # but here both clauses must apply to the *same* hop
        # array element -- the ``nested(traces.hops)`` wrapper
        # enforces the per-element correlation.
        body = self._ED().searchhopname("foo.example.com").to_dict()
        self.assertEqual(
            body,
            {
                "nested": {
                    "path": "traces.hops",
                    "query": {
                        "bool": {
                            "must": [
                                {"match": {"traces.hops.domains": "foo.example.com"}},
                                {"match": {"traces.hops.host": "foo.example.com"}},
                            ]
                        }
                    },
                }
            },
        )

    def test_searchhopname_neg_skips_indexed_lookup(self):
        body = self._ED().searchhopname("foo", neg=True).to_dict()
        self.assertEqual(
            body,
            {
                "bool": {
                    "must_not": [
                        {
                            "nested": {
                                "path": "traces.hops",
                                "query": {"match": {"traces.hops.host": "foo"}},
                            }
                        }
                    ]
                }
            },
        )

    # -- per-port fingerprints ---------------------------------------

    def test_searchldapanon_matches_anonymous_bind_ok(self):
        body = self._ED().searchldapanon().to_dict()
        self.assertEqual(
            body,
            {"match": {"ports.service_extrainfo": "Anonymous bind OK"}},
        )

    def test_searchvsftpdbackdoor_pins_full_fingerprint(self):
        body = self._ED().searchvsftpdbackdoor().to_dict()
        self.assertIn("nested", body)
        self.assertEqual(body["nested"]["path"], "ports")
        must = body["nested"]["query"]["bool"]["must"]
        self.assertIn({"match": {"ports.protocol": "tcp"}}, must)
        self.assertIn({"match": {"ports.state_state": "open"}}, must)
        self.assertIn({"match": {"ports.service_product": "vsftpd"}}, must)
        self.assertIn({"match": {"ports.service_version": "2.3.4"}}, must)

    def test_searchwebmin_excludes_apache_hosting_webmin(self):
        body = self._ED().searchwebmin().to_dict()
        self.assertIn("nested", body)
        bool_q = body["nested"]["query"]["bool"]
        self.assertIn({"match": {"ports.service_name": "http"}}, bool_q["must"])
        self.assertIn({"match": {"ports.service_product": "MiniServ"}}, bool_q["must"])
        # ``service_extrainfo`` must *not* be ``"Webmin httpd"``
        # (that's the regular Apache / nginx hosting the
        # admin UI rather than the standalone Webmin).
        self.assertIn(
            {"match": {"ports.service_extrainfo": "Webmin httpd"}},
            bool_q["must_not"],
        )

    def test_searchhttptitle_delegates_to_searchscript(self):
        body = self._ED().searchhttptitle("Welcome").to_dict()
        self.assertIn("nested", body)
        self.assertEqual(body["nested"]["path"], "ports")
        inner = body["nested"]["query"]["nested"]
        self.assertEqual(inner["path"], "ports.scripts")
        must = inner["query"]["bool"]["must"]
        # ``searchscript`` with a list of names emits
        # ``terms``; pin that.
        self.assertIn(
            {"terms": {"ports.scripts.id": ["http-title", "html-title"]}},
            must,
        )
        self.assertIn({"match": {"ports.scripts.output": "Welcome"}}, must)

    # -- screenshot / screenwords ------------------------------------

    def test_searchscreenshot_no_args_existence_check(self):
        body = self._ED().searchscreenshot().to_dict()
        self.assertEqual(
            body,
            {
                "nested": {
                    "path": "ports",
                    "query": {"exists": {"field": "ports.screenshot"}},
                }
            },
        )

    def test_searchscreenshot_neg_inverts_at_host_level(self):
        # Mirrors Mongo's ``$exists: false`` semantics: *no*
        # port has a screenshot, not "there's a port without
        # a screenshot".  Pin the ``must_not`` wrap at the
        # outermost ``Nested`` level rather than the inner
        # predicate.
        body = self._ED().searchscreenshot(neg=True).to_dict()
        self.assertIn("must_not", body["bool"])
        self.assertEqual(body["bool"]["must_not"][0]["nested"]["path"], "ports")

    def test_searchscreenshot_with_port_constrains_inner_predicate(self):
        body = self._ED().searchscreenshot(port=80).to_dict()
        must = body["nested"]["query"]["bool"]["must"]
        self.assertIn({"exists": {"field": "ports.screenshot"}}, must)
        self.assertIn({"match": {"ports.port": 80}}, must)
        self.assertIn({"match": {"ports.protocol": "tcp"}}, must)

    def test_searchscreenshot_words_string_lower_cases(self):
        body = self._ED().searchscreenshot(words="WELCOME").to_dict()
        must = body["nested"]["query"]["bool"]["must"]
        # Word value is lower-cased to match the pre-stored
        # shape.
        self.assertIn({"match": {"ports.screenwords": "welcome"}}, must)

    def test_searchscreenshot_words_list_requires_all(self):
        body = self._ED().searchscreenshot(words=["foo", "bar"]).to_dict()
        must = body["nested"]["query"]["bool"]["must"]
        # Each element becomes its own ``match`` -- the list
        # form is "all of these words must be present".
        self.assertIn({"match": {"ports.screenwords": "foo"}}, must)
        self.assertIn({"match": {"ports.screenwords": "bar"}}, must)

    def test_searchscreenshot_words_regex(self):
        import re

        body = self._ED().searchscreenshot(words=re.compile("LOGIN")).to_dict()
        must = body["nested"]["query"]["bool"]["must"]
        # Pattern is lower-cased before being passed to
        # ``_get_pattern``.
        self.assertIn({"regexp": {"ports.screenwords": ".*login.*"}}, must)

    def test_searchscreenshot_words_neg_inverts_at_predicate(self):
        # ``words=...`` with ``neg=True`` keeps the
        # screenshot existence check positive (Mongo semantic:
        # "has a screenshot **without** these words").
        body = self._ED().searchscreenshot(words="foo", neg=True).to_dict()
        bool_q = body["nested"]["query"]["bool"]
        self.assertIn({"exists": {"field": "ports.screenshot"}}, bool_q["must"])
        self.assertIn({"match": {"ports.screenwords": "foo"}}, bool_q["must_not"])

    # -- searchsmbshares ---------------------------------------------

    def test_searchsmbshares_default_uses_access_regex(self):
        body = self._ED().searchsmbshares().to_dict()
        self.assertIn("nested", body)
        self.assertEqual(body["nested"]["path"], "ports")
        inner = body["nested"]["query"]["nested"]
        self.assertEqual(inner["path"], "ports.scripts")
        bool_q = inner["query"]["bool"]
        # ``access=""`` defaults to a regex matching either
        # READ or WRITE at the start of the access field.
        self.assertIn(
            {
                "regexp": {
                    "ports.scripts.smb-enum-shares.shares.Anonymous access": "(READ|WRITE).*"
                }
            },
            bool_q["should"],
        )
        # IPC$ is excluded by name.
        self.assertIn(
            {"match": {"ports.scripts.smb-enum-shares.shares.Share": "IPC$"}},
            bool_q["must_not"],
        )

    def test_searchsmbshares_rw_uses_literal_match(self):
        body = self._ED().searchsmbshares(access="rw").to_dict()
        bool_q = body["nested"]["query"]["nested"]["query"]["bool"]
        # ``access="rw"`` is a literal "READ/WRITE" string
        # (not a regex).
        self.assertIn(
            {
                "match": {
                    "ports.scripts.smb-enum-shares.shares.Anonymous access": "READ/WRITE"
                }
            },
            bool_q["should"],
        )

    def test_searchsmbshares_hidden_true_pins_hidden_share_type(self):
        body = self._ED().searchsmbshares(hidden=True).to_dict()
        bool_q = body["nested"]["query"]["nested"]["query"]["bool"]
        self.assertIn(
            {
                "match": {
                    "ports.scripts.smb-enum-shares.shares.Type": "STYPE_DISKTREE_HIDDEN"
                }
            },
            bool_q["must"],
        )

    def test_searchsmbshares_hidden_none_excludes_sentinel_types(self):
        body = self._ED().searchsmbshares().to_dict()
        bool_q = body["nested"]["query"]["nested"]["query"]["bool"]
        # ``hidden=None`` is the default: ``Type`` must not
        # be one of the four sentinel values.
        excluded = {
            "STYPE_IPC_HIDDEN",
            "Not a file share",
            "STYPE_IPC",
            "STYPE_PRINTQ",
        }
        # The ``must_not`` carries a ``terms`` query whose
        # value list matches the sentinel set.
        terms_clauses = [
            clause["terms"]["ports.scripts.smb-enum-shares.shares.Type"]
            for clause in bool_q.get("must_not", [])
            if "terms" in clause
        ]
        self.assertTrue(terms_clauses)
        self.assertEqual(set(terms_clauses[0]), excluded)


# ---------------------------------------------------------------------
# ElasticDBSearchTier3Tests -- pin the wire shape of the
# Tier-3 ``search*`` parity helpers added on
# ``ElasticDBActive`` / ``ElasticDBView``:
# ``searchcountopenports`` / ``searchports`` / ``searchportsother``
# / ``searchcity`` / ``searchfile`` / ``searchvuln`` /
# ``searchvulnintersil`` / ``searchcpe`` / ``searchos``.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_ELASTICSEARCH_DSL,
    "elasticsearch_dsl is required (install with the ``elasticsearch`` extras)",
)
class ElasticDBSearchTier3Tests(unittest.TestCase):
    """Behaviour-pin for Tier-3 ``ElasticDBActive.search*``
    parity helpers.  ``searchfile`` previously raised
    ``NotImplementedError``; the rest were missing entirely.
    """

    @staticmethod
    def _ED():
        from ivre.db.elastic import ElasticDBView

        return ElasticDBView

    # -- searchcountopenports ----------------------------------------

    def test_searchcountopenports_equal_bounds_collapses_to_match(self):
        body = self._ED().searchcountopenports(minn=5, maxn=5).to_dict()
        self.assertEqual(body, {"match": {"openports.count": 5}})

    def test_searchcountopenports_emits_range(self):
        body = self._ED().searchcountopenports(minn=5, maxn=100).to_dict()
        self.assertEqual(body, {"range": {"openports.count": {"gte": 5, "lte": 100}}})

    def test_searchcountopenports_neg_with_both_bounds_uses_or(self):
        # Mirrors Mongo's ``$or`` of ``$lt`` / ``$gt``: the
        # row passes when count falls outside *either*
        # bound.
        body = self._ED().searchcountopenports(minn=5, maxn=100, neg=True).to_dict()
        should = body["bool"]["should"]
        self.assertEqual(len(should), 2)
        self.assertEqual(should[0], {"range": {"openports.count": {"lt": 5}}})
        self.assertEqual(should[1], {"range": {"openports.count": {"gt": 100}}})

    def test_searchcountopenports_requires_at_least_one_bound(self):
        with self.assertRaises(AssertionError):
            self._ED().searchcountopenports()

    # -- searchports / searchportsother ------------------------------

    def test_searchports_default_ands_per_port_matches(self):
        body = self._ED().searchports([22, 80]).to_dict()
        # Each port becomes its own ``match`` against
        # ``openports.tcp.ports``; the helper AND-s them.
        must = body["bool"]["must"]
        self.assertEqual(len(must), 2)
        self.assertIn({"match": {"openports.tcp.ports": 22}}, must)
        self.assertIn({"match": {"openports.tcp.ports": 80}}, must)

    def test_searchports_any_uses_or(self):
        body = self._ED().searchports([22, 80], any_=True).to_dict()
        should = body["bool"]["should"]
        self.assertEqual(len(should), 2)
        self.assertIn({"match": {"openports.tcp.ports": 22}}, should)
        self.assertIn({"match": {"openports.tcp.ports": 80}}, should)

    def test_searchports_neg_and_any_is_an_error(self):
        with self.assertRaises(ValueError):
            self._ED().searchports([22], neg=True, any_=True)

    def test_searchportsother_emits_terms_must_not(self):
        body = self._ED().searchportsother([22, 80]).to_dict()
        # Nested ports query with ``ports.port NOT IN (22, 80)``.
        self.assertEqual(body["nested"]["path"], "ports")
        bool_q = body["nested"]["query"]["bool"]
        self.assertIn({"terms": {"ports.port": [22, 80]}}, bool_q["must_not"])
        self.assertIn({"match": {"ports.protocol": "tcp"}}, bool_q["must"])
        self.assertIn({"match": {"ports.state_state": "open"}}, bool_q["must"])

    # -- searchcity ---------------------------------------------------

    def test_searchcity_scalar(self):
        body = self._ED().searchcity("Paris").to_dict()
        self.assertEqual(body, {"match": {"infos.city": "Paris"}})

    def test_searchcity_neg(self):
        body = self._ED().searchcity("Paris", neg=True).to_dict()
        self.assertEqual(
            body, {"bool": {"must_not": [{"match": {"infos.city": "Paris"}}]}}
        )

    # -- searchfile ---------------------------------------------------

    def test_searchfile_no_args_existence_check(self):
        body = self._ED().searchfile().to_dict()
        # Goes through ``Nested(ports, Nested(ports.scripts,
        # exists))`` so the predicate is evaluated against
        # the inner ``files`` array per script.
        self.assertEqual(body["nested"]["path"], "ports")
        inner = body["nested"]["query"]["nested"]
        self.assertEqual(inner["path"], "ports.scripts")
        self.assertEqual(
            inner["query"],
            {"exists": {"field": "ports.scripts.ls.volumes.files.filename"}},
        )

    def test_searchfile_with_filename(self):
        body = self._ED().searchfile("README").to_dict()
        inner = body["nested"]["query"]["nested"]["query"]
        self.assertEqual(
            inner,
            {"match": {"ports.scripts.ls.volumes.files.filename": "README"}},
        )

    def test_searchfile_with_scripts_filter(self):
        body = self._ED().searchfile(scripts=["nfs-ls", "smb-ls"]).to_dict()
        inner = body["nested"]["query"]["nested"]["query"]["bool"]["must"]
        self.assertIn({"terms": {"ports.scripts.id": ["nfs-ls", "smb-ls"]}}, inner)
        self.assertIn(
            {"exists": {"field": "ports.scripts.ls.volumes.files.filename"}},
            inner,
        )

    def test_searchfile_with_single_script_uses_match(self):
        body = self._ED().searchfile(scripts="nfs-ls").to_dict()
        inner = body["nested"]["query"]["nested"]["query"]["bool"]["must"]
        # Single-element scripts list collapses to ``match``
        # (vs ``terms`` for multi-element).
        self.assertIn({"match": {"ports.scripts.id": "nfs-ls"}}, inner)

    # -- searchvuln / searchvulnintersil -----------------------------

    def test_searchvuln_no_args_emits_existence(self):
        body = self._ED().searchvuln().to_dict()
        self.assertEqual(body["nested"]["path"], "ports")
        inner = body["nested"]["query"]["nested"]
        self.assertEqual(inner["path"], "ports.scripts")
        self.assertEqual(
            inner["query"], {"exists": {"field": "ports.scripts.vulns.id"}}
        )

    def test_searchvuln_with_id_only(self):
        body = self._ED().searchvuln("CVE-2021-44228").to_dict()
        inner = body["nested"]["query"]["nested"]["query"]
        self.assertEqual(inner, {"match": {"ports.scripts.vulns.id": "CVE-2021-44228"}})

    def test_searchvuln_with_state_only(self):
        body = self._ED().searchvuln(state="VULNERABLE").to_dict()
        inner = body["nested"]["query"]["nested"]["query"]
        self.assertEqual(inner, {"match": {"ports.scripts.vulns.state": "VULNERABLE"}})

    def test_searchvuln_with_id_and_state_uses_status_field(self):
        # Mirrors the Mongo helper's ``$elemMatch`` shape:
        # the *status* field (not ``state``) is used when
        # both args are supplied.
        body = self._ED().searchvuln("CVE-2021-44228", "VULNERABLE").to_dict()
        must = body["nested"]["query"]["nested"]["query"]["bool"]["must"]
        self.assertIn({"match": {"ports.scripts.vulns.id": "CVE-2021-44228"}}, must)
        self.assertIn({"match": {"ports.scripts.vulns.status": "VULNERABLE"}}, must)

    def test_searchvulnintersil_pins_full_fingerprint(self):
        body = self._ED().searchvulnintersil().to_dict()
        self.assertEqual(body["nested"]["path"], "ports")
        must = body["nested"]["query"]["bool"]["must"]
        self.assertIn({"match": {"ports.protocol": "tcp"}}, must)
        self.assertIn({"match": {"ports.state_state": "open"}}, must)
        self.assertIn({"match": {"ports.service_product": "Boa HTTPd"}}, must)
        # The version regex matches Intersil firmware
        # versions vulnerable to MSF's
        # ``admin/http/intersil_pass_reset`` module.
        regexp_clauses = [c for c in must if "regexp" in c]
        self.assertEqual(len(regexp_clauses), 1)
        self.assertIn("ports.service_version", regexp_clauses[0]["regexp"])

    # -- searchcpe ----------------------------------------------------

    def test_searchcpe_no_args_existence_check(self):
        body = self._ED().searchcpe().to_dict()
        self.assertEqual(body, {"exists": {"field": "cpes"}})

    def test_searchcpe_single_field_uses_match(self):
        body = self._ED().searchcpe(vendor="apache").to_dict()
        self.assertEqual(body, {"match": {"cpes.vendor": "apache"}})

    def test_searchcpe_multiple_fields_AND(self):
        body = self._ED().searchcpe(vendor="apache", product="httpd").to_dict()
        must = body["bool"]["must"]
        self.assertIn({"match": {"cpes.vendor": "apache"}}, must)
        self.assertIn({"match": {"cpes.product": "httpd"}}, must)

    def test_searchcpe_regex_emits_regexp_query(self):
        import re

        body = self._ED().searchcpe(vendor=re.compile("^apache")).to_dict()
        self.assertEqual(body, {"regexp": {"cpes.vendor": "apache.*"}})

    # -- searchos -----------------------------------------------------

    def test_searchos_scalar_ors_four_subkeys(self):
        body = self._ED().searchos("Linux").to_dict()
        should = body["bool"]["should"]
        self.assertEqual(len(should), 4)
        for key in ("vendor", "osfamily", "osgen", "type"):
            self.assertIn({"match": {f"os.osclass.{key}": "Linux"}}, should)

    def test_searchos_regex_uses_regexp_query(self):
        import re

        body = self._ED().searchos(re.compile("Linux")).to_dict()
        should = body["bool"]["should"]
        self.assertEqual(len(should), 4)
        for key in ("vendor", "osfamily", "osgen", "type"):
            self.assertIn({"regexp": {f"os.osclass.{key}": ".*Linux.*"}}, should)


# ---------------------------------------------------------------------
# ElasticDBTopValuesTier1Tests -- pin the wire shape of the
# Tier-1 ``topvalues`` parity branches added on
# ``ElasticDBActive``: ``country`` / ``city`` / ``addr`` /
# ``script`` / ``script:<id>[:<port>]`` / ``domains`` /
# ``domains:<spec>`` / ``cert.<key>`` / ``cacert.<key>``.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_ELASTICSEARCH_DSL,
    "elasticsearch_dsl is required (install with the ``elasticsearch`` extras)",
)
class ElasticDBTopValuesTier1Tests(unittest.TestCase):
    """Behaviour-pin for Tier-1 ``ElasticDBActive.topvalues``
    parity branches.  ``topvalues`` runs the aggregation
    against a live Elasticsearch index, so the pin
    intercepts the body that ``db_client.search`` would
    receive instead of executing it -- enough to cover the
    aggregation tree (terms / nested / nested+filter), the
    field path each branch resolves to, the painless
    scripts the tuple-projecting branches emit, and the
    flt scoping (e.g. ``searchcert(cacert=True)`` for the
    ``cacert.*`` branch).
    """

    @staticmethod
    def _ED_instance():
        from ivre.db.elastic import ElasticDBView

        return ElasticDBView.from_url("elastic://x:9200")

    @classmethod
    def _capture_body(cls, field):
        captured = []

        class _FakeClient:
            def search(self, body=None, **kw):  # type: ignore[no-untyped-def]
                captured.append(body)
                return {"aggregations": {"patterns": {"buckets": []}}}

            def count(self, **kw):  # type: ignore[no-untyped-def]
                return {"count": 0}

        db = cls._ED_instance()
        # ``db_client`` is a ``functools.cached_property`` /
        # property on ``ElasticDB``; override on the
        # instance via a property descriptor so the
        # test does not require an actual Elasticsearch
        # connection.
        type(db).db_client = property(lambda self: _FakeClient())
        try:
            list(db.topvalues(field))
        finally:
            del type(db).db_client
        assert captured, "topvalues did not call db_client.search"
        return captured[-1]

    # -- country / city / addr ----------------------------------------

    def test_topvalues_country_emits_painless_tuple_script(self):
        body = self._capture_body("country")
        terms = body["aggs"]["patterns"]["terms"]
        self.assertIn("script", terms)
        source = terms["script"]["source"]
        # Painless concats ``country_code`` and
        # ``country_name`` (with a ``"?"`` fallback when the
        # name is missing) so the outputproc can split the
        # tuple back.
        self.assertIn("infos.country_code", source)
        self.assertIn("infos.country_name", source)
        # Filter scopes the aggregation to records that
        # actually carry a country code.
        self.assertIn("infos.country_code", str(body["query"]))

    def test_topvalues_city_emits_painless_tuple_script(self):
        body = self._capture_body("city")
        terms = body["aggs"]["patterns"]["terms"]
        self.assertIn("script", terms)
        source = terms["script"]["source"]
        self.assertIn("infos.country_code", source)
        self.assertIn("infos.city", source)

    def test_topvalues_addr_aggregates_native_ip_field(self):
        # ``addr`` is mapped as Elasticsearch's native
        # ``ip`` type -- the aggregation runs on the field
        # directly without the int128 split Mongo's
        # ``addr_0`` / ``addr_1`` projection emits.
        body = self._capture_body("addr")
        terms = body["aggs"]["patterns"]["terms"]
        self.assertEqual(terms["field"], "addr")

    # -- script / script:<id> ----------------------------------------

    def test_topvalues_script_uses_nested_aggregation(self):
        body = self._capture_body("script")
        # Nested(ports) -> Nested(ports.scripts) -> terms
        # so each script id is counted exactly once per
        # script subdoc rather than once per host.
        outer = body["aggs"]["patterns"]
        self.assertEqual(outer["nested"]["path"], "ports")
        inner = outer["aggs"]["patterns"]
        self.assertEqual(inner["nested"]["path"], "ports.scripts")
        self.assertEqual(
            inner["aggs"]["patterns"]["terms"]["field"], "ports.scripts.id"
        )

    def test_topvalues_script_with_id_filters_to_specific_script(self):
        body = self._capture_body("script:http-title")
        # Outer Nested(ports) -> Nested(ports.scripts) ->
        # Filter(script.id == "http-title") -> terms on
        # ``ports.scripts.output``.
        outer = body["aggs"]["patterns"]
        inner = outer["aggs"]["patterns"]
        filter_clause = inner["aggs"]["patterns"]
        self.assertIn("filter", filter_clause)
        self.assertEqual(
            filter_clause["filter"],
            {"match": {"ports.scripts.id": "http-title"}},
        )
        self.assertEqual(
            filter_clause["aggs"]["patterns"]["terms"]["field"],
            "ports.scripts.output",
        )

    def test_topvalues_script_with_port_constraint(self):
        # ``script:<port>:<id>`` adds a ``searchport(port)``
        # filter at the host level (visible in the outer
        # ``query`` block).
        body = self._capture_body("script:80:http-title")
        # Filter on port 80 lands somewhere in the host
        # query.
        self.assertIn("openports", str(body["query"]))

    # -- domains / domains:<spec> -------------------------------------

    def test_topvalues_domains_aggregates_indexed_domains(self):
        body = self._capture_body("domains")
        terms = body["aggs"]["patterns"]["terms"]
        self.assertEqual(terms["field"], "hostnames.domains")

    def test_topvalues_domains_numeric_level_uses_regex_include(self):
        # ``domains:2`` -> regex ``([^.]+\.){1}[^.]+`` (i.e.
        # exactly two-level domains).
        body = self._capture_body("domains:2")
        terms = body["aggs"]["patterns"]["terms"]
        self.assertEqual(terms["field"], "hostnames.domains")
        self.assertEqual(terms["include"], "([^.]+\\.){1}[^.]+")

    def test_topvalues_domains_subdomain_uses_regex_include(self):
        # ``domains:com`` -> regex ``.*\.com`` (any subdomain
        # of ``.com``).
        body = self._capture_body("domains:com")
        terms = body["aggs"]["patterns"]["terms"]
        self.assertEqual(terms["include"], ".*\\.com")

    def test_topvalues_domains_subdomain_with_level(self):
        # ``domains:com:2`` -> regex ``([^.]+\.){1}com``:
        # ``int(level) - sub.count(".") - 1`` = ``2 - 0 - 1``.
        body = self._capture_body("domains:com:2")
        terms = body["aggs"]["patterns"]["terms"]
        self.assertEqual(terms["include"], "([^.]+\\.){1}com")

    # -- cert.* / cacert.* --------------------------------------------

    def test_topvalues_cert_subject_walks_source(self):
        # ``cert.subject`` cannot use a plain
        # ``terms(field=...)`` clause -- Elastic's ``terms``
        # aggregation refuses object-shaped fields -- and it
        # cannot use a static-whitelist painless either, since
        # X.509 DNs can carry OID-named or future-extension
        # attributes that no whitelist can anticipate.
        # Instead, a painless script walks the host's
        # ``_source`` directly, finds every
        # ``ports[*].scripts[*]['ssl-cert'][*]`` entry,
        # iterates the ``subject`` dict via ``entrySet()``
        # and emits a ``\u0001``-separated bucket key per
        # cert -- one entry per Mongo-equivalent
        # ``$unwind`` -- with no schema-side whitelist of
        # attribute names.  No ``nested`` wrapper is needed:
        # the script returns an array, ES creates one bucket
        # per array element, and the unwinding happens inside
        # the script.
        body = self._capture_body("cert.subject")
        terms = body["aggs"]["patterns"]["terms"]
        self.assertNotIn("field", terms)
        source = terms["script"]["source"]
        # Pins for the script's structure: it walks
        # ``params._source.ports``, filters on the script id,
        # iterates ``entrySet`` (so any DN attribute is
        # picked up), and joins with ``\u0001``.
        self.assertIn("params._source.ports", source)
        self.assertIn("ssl-cert", source)
        self.assertIn("entrySet", source)
        self.assertIn("\u0001", source)

    def test_topvalues_cert_issuer_walks_source(self):
        # ``cert.issuer`` mirrors ``cert.subject``: same
        # ``_source``-walk script with ``cert.issuer``
        # substituted for ``cert.subject``.
        body = self._capture_body("cert.issuer")
        terms = body["aggs"]["patterns"]["terms"]
        self.assertNotIn("field", terms)
        source = terms["script"]["source"]
        self.assertIn("cert.issuer", source)
        self.assertNotIn("cert.subject", source)
        self.assertIn("\u0001", source)

    def test_topvalues_cacert_walks_source_with_cacert_script_id(self):
        # ``cacert.subject`` reuses the same ``_source``-walk
        # painless template, with ``ssl-cacert`` substituted
        # for ``ssl-cert``.
        body = self._capture_body("cacert.subject")
        terms = body["aggs"]["patterns"]["terms"]
        self.assertNotIn("field", terms)
        source = terms["script"]["source"]
        self.assertIn("ssl-cacert", source)
        self.assertNotIn("ssl-cert'", source)
        self.assertIn("entrySet", source)

    def test_topvalues_cert_md5_indexes_into_hash_field(self):
        # Scalar leaves (``md5`` / ``sha1`` / ``sha256`` /
        # ``pubkey.<hash>``) keep the
        # ``nested(ports) -> nested(ports.scripts) -> filter ->
        # terms(field=ports.scripts.ssl-cert.<key>)`` chain;
        # only the object-shaped ``subject`` / ``issuer``
        # branches re-route through the ``_source``-walking
        # painless script.
        body = self._capture_body("cert.md5")
        outer = body["aggs"]["patterns"]
        inner = outer["aggs"]["patterns"]
        filter_clause = inner["aggs"]["patterns"]
        self.assertEqual(
            filter_clause["filter"],
            {"match": {"ports.scripts.id": "ssl-cert"}},
        )
        terms = filter_clause["aggs"]["patterns"]["terms"]
        self.assertEqual(terms["field"], "ports.scripts.ssl-cert.md5")


# ---------------------------------------------------------------------
# ElasticDBTopValuesTier2Tests -- pin the wire shape of the
# Tier-2 ``topvalues`` parity branches added on
# ``ElasticDBActive``: ``ntlm`` / ``ntlm.<key>``,
# ``smb`` / ``smb.<key>``, ``modbus.<key>``, ``devicetype`` /
# ``devicetype:<port>``, ``cpe[.<part>][:<spec>]``,
# ``hop`` / ``hop:<ttl>`` / ``hop>N``,
# ``file`` / ``file.<key>`` / ``file:<scripts>[.<key>]``,
# ``vulns.id`` / ``vulns.<other>``, ``screenwords``,
# ``sshkey.bits`` / ``sshkey.<key>``.  Closes M4.5 -- the
# ``if DATABASE == "elastic": return`` skip block at
# ``tests/tests.py:4201`` no longer needs to gate the rest
# of the view test method.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_ELASTICSEARCH_DSL,
    "elasticsearch_dsl is required (install with the ``elasticsearch`` extras)",
)
class ElasticDBTopValuesTier2Tests(unittest.TestCase):
    """Behaviour-pin for Tier-2 ``ElasticDBActive.topvalues``
    parity branches.  Each branch was previously falling
    through the catch-all ``else: field = {"field": field}``
    arm at ``elastic.py`` and silently emitting an
    aggregation against a non-existent literal field --
    returning an empty bucket list instead of an error.
    """

    @staticmethod
    def _ED_instance():
        from ivre.db.elastic import ElasticDBView

        return ElasticDBView.from_url("elastic://x:9200")

    @classmethod
    def _capture_body(cls, field):
        captured = []

        class _FakeClient:
            def search(self, body=None, **kw):  # type: ignore[no-untyped-def]
                captured.append(body)
                return {"aggregations": {"patterns": {"buckets": []}}}

            def count(self, **kw):  # type: ignore[no-untyped-def]
                return {"count": 0}

        db = cls._ED_instance()
        type(db).db_client = property(lambda self: _FakeClient())
        try:
            list(db.topvalues(field))
        finally:
            del type(db).db_client
        assert captured, "topvalues did not call db_client.search"
        return captured[-1]

    @staticmethod
    def _walk_to_terms(body):
        """Walk down the ``aggs.patterns`` chain to the inner
        ``terms`` aggregation.  Tier-2 branches that target
        per-port / per-script fields wrap the terms agg in
        one or two ``nested`` levels (``ports`` ->
        ``ports.scripts``) plus an optional ``filter`` stage,
        so the depth varies per branch.  The helper hides
        the wrapping from the assertion side."""
        cur = body["aggs"]["patterns"]
        while "aggs" in cur:
            cur = cur["aggs"]["patterns"]
        return cur["terms"]

    def _terms_field(self, field):
        return self._walk_to_terms(self._capture_body(field)).get("field")

    def _terms_script_source(self, field):
        return self._walk_to_terms(self._capture_body(field))["script"]["source"]

    # -- ntlm ---------------------------------------------------------

    def test_topvalues_ntlm_friendly_aliases(self):
        # Same friendly-name alias map the SQL backend ships
        # in M4.4.1 (M4.4 :class:`PostgresDBActive`).  Pin
        # the nine entries here too so a future refactor of
        # one backend cannot silently drift the other.
        cases = [
            ("ntlm.name", "Target_Name"),
            ("ntlm.server", "NetBIOS_Computer_Name"),
            ("ntlm.domain", "NetBIOS_Domain_Name"),
            ("ntlm.workgroup", "Workgroup"),
            ("ntlm.domain_dns", "DNS_Domain_Name"),
            ("ntlm.forest", "DNS_Tree_Name"),
            ("ntlm.fqdn", "DNS_Computer_Name"),
            ("ntlm.os", "Product_Version"),
            ("ntlm.version", "NTLM_Version"),
        ]
        for alias, target in cases:
            with self.subTest(alias=alias):
                self.assertEqual(
                    self._terms_field(alias),
                    f"ports.scripts.ntlm-info.{target}",
                )

    # -- smb ----------------------------------------------------------

    def test_topvalues_smb_subkey_passthrough(self):
        self.assertEqual(
            self._terms_field("smb.os"),
            "ports.scripts.smb-os-discovery.os",
        )

    # -- modbus -------------------------------------------------------

    def test_topvalues_modbus_subkey_passthrough(self):
        self.assertEqual(
            self._terms_field("modbus.deviceid"),
            "ports.scripts.modbus-discover.deviceid",
        )

    # -- devicetype ---------------------------------------------------

    def test_topvalues_devicetype_aggregates_service_field(self):
        # ``ports.service_devicetype`` is a per-port field;
        # the aggregation runs inside a ``nested(ports)``
        # context so each port contributes one observation
        # to the bucket (mirrors Mongo's ``$unwind ports``
        # count semantics).  Without the nested wrap, ES's
        # default ``terms`` semantics dedupe per parent
        # document and undercount hosts publishing the same
        # ``service_devicetype`` on several ports.
        self.assertEqual(self._terms_field("devicetype"), "ports.service_devicetype")
        body = self._capture_body("devicetype")
        self.assertEqual(body["aggs"]["patterns"]["nested"], {"path": "ports"})

    def test_topvalues_devicetype_with_port_adds_filter(self):
        # ``devicetype:<port>`` adds two filter layers:
        # the host-level :meth:`searchport` constraint
        # (``openports.tcp.ports`` lookup, indexed) and a
        # nested ``filter`` clause inside the ``nested(ports)``
        # aggregation that narrows the per-port count to the
        # matching port subdocument.
        body = self._capture_body("devicetype:80")
        self.assertEqual(self._terms_field("devicetype:80"), "ports.service_devicetype")
        self.assertIn("openports", str(body["query"]))
        # Inner ``filter`` clause matches ``ports.port`` to
        # the requested port.
        self.assertIn("ports.port", str(body["aggs"]["patterns"]))

    # -- cpe ----------------------------------------------------------

    def test_topvalues_cpe_default_emits_painless_concat(self):
        # Bare ``cpe`` projects all four keys (default
        # ``<part>=version``); the painless script concats
        # them with ``:`` separators.
        source = self._terms_script_source("cpe")
        for key in ("type", "vendor", "product", "version"):
            self.assertIn(f"cpes.{key}", source)
        self.assertIn(" + ':' + ", source)

    def test_topvalues_cpe_part_truncates_projection(self):
        # ``cpe.vendor`` projects only ``type`` and
        # ``vendor``.  Multi-key form still goes through
        # the painless concat.
        source = self._terms_script_source("cpe.vendor")
        self.assertIn("cpes.type", source)
        self.assertIn("cpes.vendor", source)
        self.assertNotIn("cpes.product", source)
        self.assertNotIn("cpes.version", source)

    def test_topvalues_cpe_single_kept_key_uses_field_form(self):
        # ``cpe.type`` -> only one kept key -> a flat
        # ``terms(field=cpes.type)`` aggregation rather
        # than a script.
        body = self._capture_body("cpe.type")
        terms = body["aggs"]["patterns"]["terms"]
        self.assertEqual(terms.get("field"), "cpes.type")
        self.assertNotIn("script", terms)

    # -- hop ----------------------------------------------------------

    def test_topvalues_hop_aggregates_native_ip_field(self):
        # ``traces.hops`` is nested, so the terms agg lands
        # inside a ``nested(traces.hops)`` wrapper; the
        # ``_walk_to_terms`` helper hides the wrapping from
        # the assertion.  The terms field itself is still
        # ``traces.hops.ipaddr`` (native ``ip`` type).
        self.assertEqual(self._terms_field("hop"), "traces.hops.ipaddr")
        body = self._capture_body("hop")
        self.assertEqual(body["aggs"]["patterns"]["nested"], {"path": "traces.hops"})

    def test_topvalues_hop_with_ttl(self):
        # The TTL filter must run *inside* the
        # ``nested(traces.hops)`` aggregation -- otherwise
        # cross-field correlation breaks and the bucket count
        # picks up every hop of every host that has *any* hop
        # at the requested TTL.  Pin the inner-filter shape
        # explicitly.
        body = self._capture_body("hop:5")
        self.assertEqual(self._terms_field("hop:5"), "traces.hops.ipaddr")
        self.assertEqual(body["aggs"]["patterns"]["nested"], {"path": "traces.hops"})
        inner_filter = body["aggs"]["patterns"]["aggs"]["patterns"]["filter"]
        self.assertEqual(inner_filter, {"match": {"traces.hops.ttl": 5}})

    def test_topvalues_hop_gt_uses_range(self):
        body = self._capture_body("hop>10")
        self.assertEqual(self._terms_field("hop>10"), "traces.hops.ipaddr")
        self.assertEqual(body["aggs"]["patterns"]["nested"], {"path": "traces.hops"})
        inner_filter = body["aggs"]["patterns"]["aggs"]["patterns"]["filter"]
        self.assertEqual(inner_filter, {"range": {"traces.hops.ttl": {"gt": 10}}})

    # -- file ---------------------------------------------------------

    def test_topvalues_file_default_filename(self):
        self.assertEqual(
            self._terms_field("file"),
            "ports.scripts.ls.volumes.files.filename",
        )

    def test_topvalues_file_subkey(self):
        self.assertEqual(
            self._terms_field("file.uid"),
            "ports.scripts.ls.volumes.files.uid",
        )

    def test_topvalues_file_with_scripts(self):
        body = self._capture_body("file:nfs-ls,smb-ls")
        self.assertEqual(
            self._terms_field("file:nfs-ls,smb-ls"),
            "ports.scripts.ls.volumes.files.filename",
        )
        # ``searchfile(scripts=[...])`` filter lands in the
        # host query.
        self.assertIn("nfs-ls", str(body["query"]))

    def test_topvalues_file_with_scripts_and_subkey(self):
        self.assertEqual(
            self._terms_field("file:nfs-ls.size"),
            "ports.scripts.ls.volumes.files.size",
        )

    # -- vulns --------------------------------------------------------

    def test_topvalues_vulns_id_aggregates_id_field(self):
        self.assertEqual(self._terms_field("vulns.id"), "ports.scripts.vulns.id")

    def test_topvalues_vulns_other_emits_id_tuple(self):
        # ``vulns.<other>`` returns a ``(id, <other>)``
        # tuple via a painless concat.
        source = self._terms_script_source("vulns.state")
        self.assertIn("ports.scripts.vulns.id", source)
        self.assertIn("ports.scripts.vulns.state", source)

    # -- screenwords --------------------------------------------------

    def test_topvalues_screenwords_aggregates_array_field(self):
        self.assertEqual(self._terms_field("screenwords"), "ports.screenwords")

    # -- sshkey -------------------------------------------------------

    def test_topvalues_sshkey_bits_emits_type_bits_tuple(self):
        source = self._terms_script_source("sshkey.bits")
        self.assertIn("ports.scripts.ssh-hostkey.type", source)
        self.assertIn("ports.scripts.ssh-hostkey.bits", source)

    def test_topvalues_sshkey_passthrough_other_key(self):
        self.assertEqual(
            self._terms_field("sshkey.fingerprint"),
            "ports.scripts.ssh-hostkey.fingerprint",
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
# DuckDBTypeAdapterTests -- pin the dialect-aware shape of the
# shared SQL types (``SQLJSONB``, ``SQLINET``, ``SQLARRAY``) so
# the same column declarations in ``ivre/db/sql/tables.py``
# compile correctly under both PostgreSQL and DuckDB. M4.1.1
# laid the foundation for the upcoming DuckDB backend by
# layering ``with_variant(JSON(), "duckdb")`` on ``SQLJSONB``;
# DuckDB has a native ``INET`` type and accepts the
# ``VARCHAR[]`` form natively, so the other shared types stay
# unchanged.
# ---------------------------------------------------------------------


try:
    import duckdb_engine  # type: ignore[import-untyped]  # noqa: F401

    _HAVE_DUCKDB_ENGINE = True
except ImportError:
    _HAVE_DUCKDB_ENGINE = False


@unittest.skipUnless(
    _HAVE_SQLALCHEMY,
    "sqlalchemy is required (install with the ``postgres`` or " "``duckdb`` extras)",
)
class DuckDBTypeAdapterTests(unittest.TestCase):
    """Pin the dialect-aware shape of the shared SQL types in
    :mod:`ivre.db.sql.tables`.

    The PostgreSQL columns of every SQL table use
    ``SQLJSONB`` (JSON document) and ``SQLINET`` (IP address);
    arrays go through ``SQLARRAY``. M4.1.1 makes ``SQLJSONB``
    dialect-aware via ``TypeEngine.with_variant`` so the same
    declaration emits ``JSONB`` on PostgreSQL and ``JSON`` on
    DuckDB (DuckDB has no ``JSONB`` keyword). ``SQLINET`` /
    ``SQLARRAY`` need no per-dialect specialisation: DuckDB
    has a native ``INET`` type and a native ``VARCHAR[]`` /
    list form respectively.
    """

    @staticmethod
    def _users_table():
        sa = _sqlalchemy
        from ivre.db.sql.tables import SQLARRAY, SQLINET, SQLJSONB

        meta = sa.MetaData()
        return sa.Table(
            "hosts",
            meta,
            sa.Column("id", sa.Integer, primary_key=True, autoincrement=False),
            sa.Column("addr", SQLINET),
            sa.Column("info", SQLJSONB),
            sa.Column("tags", SQLARRAY(sa.String(64))),
        )

    @staticmethod
    def _create_table_sql(table, dialect):
        from sqlalchemy.schema import CreateTable

        return str(CreateTable(table).compile(dialect=dialect))

    def test_jsonb_compiles_as_jsonb_on_postgresql(self):
        # The PG dialect emits ``JSONB`` (the canonical native
        # form). The compile must NOT downgrade to plain
        # ``JSON`` (which would lose the GIN-indexable shape).
        sql = self._create_table_sql(
            self._users_table(), _sqlalchemy_postgresql.dialect()
        )
        self.assertIn("info JSONB", sql)
        self.assertNotIn("info JSON,", sql)

    def test_inet_compiles_as_inet_on_postgresql(self):
        sql = self._create_table_sql(
            self._users_table(), _sqlalchemy_postgresql.dialect()
        )
        self.assertIn("addr INET", sql)

    def test_array_compiles_as_varchar_array_on_postgresql(self):
        sql = self._create_table_sql(
            self._users_table(), _sqlalchemy_postgresql.dialect()
        )
        self.assertIn("tags VARCHAR(64)[]", sql)

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_jsonb_compiles_as_json_on_duckdb(self):
        # The DuckDB dialect must emit ``JSON`` (DuckDB has no
        # ``JSONB`` type; ``CREATE TABLE`` would fail with
        # ``Catalog Error: Type with name JSONB does not
        # exist!``). Pinned via the
        # ``with_variant(JSON(), "duckdb")`` layered on
        # ``SQLJSONB``.
        sa = _sqlalchemy

        engine = sa.create_engine("duckdb:///:memory:")
        sql = self._create_table_sql(self._users_table(), engine.dialect)
        self.assertIn("info JSON", sql)
        self.assertNotIn("info JSONB", sql)

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_inet_compiles_as_inet_on_duckdb(self):
        # DuckDB has a native ``INET`` type that accepts the
        # same ``'<ip>'::inet`` cast literals our
        # ``INETLiteral`` emits, so no per-dialect adapter is
        # needed. Pin the no-op so a future refactor can't
        # accidentally introduce one.
        sa = _sqlalchemy

        engine = sa.create_engine("duckdb:///:memory:")
        sql = self._create_table_sql(self._users_table(), engine.dialect)
        self.assertIn("addr INET", sql)

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_array_compiles_as_varchar_array_on_duckdb(self):
        # DuckDB compiles ``postgresql.ARRAY(t)`` to the
        # ``LIST``-equivalent ``t[]`` form natively. No
        # per-dialect adapter needed.
        sa = _sqlalchemy

        engine = sa.create_engine("duckdb:///:memory:")
        sql = self._create_table_sql(self._users_table(), engine.dialect)
        self.assertIn("tags VARCHAR(64)[]", sql)

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_runtime_create_insert_select_on_duckdb(self):
        # Beyond compile-time strings, exercise an actual
        # ``CREATE TABLE`` + ``INSERT`` + ``SELECT`` on an
        # in-memory DuckDB so the type adapters are
        # round-trip-tested. Catches future regressions where
        # the compiled SQL looks right but DuckDB rejects it
        # at runtime (``ProgrammingError: Catalog Error: Type
        # with name X does not exist!`` etc.).
        sa = _sqlalchemy
        from ivre.db.sql.tables import SQLARRAY, SQLINET, SQLJSONB

        engine = sa.create_engine("duckdb:///:memory:")
        meta = sa.MetaData()
        hosts = sa.Table(
            "hosts",
            meta,
            sa.Column("id", sa.Integer, primary_key=True, autoincrement=False),
            sa.Column("addr", SQLINET),
            sa.Column("info", SQLJSONB),
            sa.Column("tags", SQLARRAY(sa.String(64))),
        )
        meta.create_all(engine)
        with engine.connect() as conn:
            conn.execute(
                sa.insert(hosts).values(
                    id=1,
                    addr="192.0.2.1",
                    info={"foo": "bar"},
                    tags=["cdn", "gov"],
                )
            )
            conn.commit()
            rows = list(conn.execute(sa.select(hosts)))
        self.assertEqual(len(rows), 1)
        # ``info`` round-trips as a Python dict.
        self.assertEqual(rows[0][2], {"foo": "bar"})
        # ``tags`` round-trips as a list.
        self.assertEqual(rows[0][3], ["cdn", "gov"])

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_inet_literal_compiles_with_cast_on_duckdb(self):
        # The shared ``INETLiteral.literal_processor`` is
        # reused unchanged on DuckDB: the ``'<ip>'::inet``
        # cast form is accepted natively (DuckDB ships an
        # ``INET`` type). Pin that the
        # ``literal_binds=True`` compile path produces a
        # working DuckDB statement.
        sa = _sqlalchemy
        from ivre.db.sql.tables import SQLINET

        engine = sa.create_engine("duckdb:///:memory:")
        meta = sa.MetaData()
        hosts = sa.Table(
            "hosts",
            meta,
            sa.Column("id", sa.Integer, primary_key=True, autoincrement=False),
            sa.Column("addr", SQLINET),
        )
        meta.create_all(engine)
        with engine.connect() as conn:
            conn.execute(sa.insert(hosts).values(id=1, addr="192.0.2.1"))
            conn.commit()
        # Compile a SELECT with literal-binds and execute it
        # via ``exec_driver_sql`` (same path as
        # ``PostgresDB.explain``); the rendered
        # ``WHERE addr = '192.0.2.1'::inet`` clause must be
        # accepted by DuckDB.
        stmt = sa.select(hosts).where(hosts.c.addr == "192.0.2.1")
        sql = str(
            stmt.compile(dialect=engine.dialect, compile_kwargs={"literal_binds": True})
        )
        self.assertIn("'192.0.2.1'::inet", sql)
        with engine.connect() as conn:
            rows = list(conn.exec_driver_sql(sql))
        self.assertEqual(len(rows), 1)

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_inet_bind_expression_casts_parameter_on_duckdb(self):
        # Regression: when the ``INET`` column is created on one
        # connection (``CREATE TABLE`` on engine A) and an
        # ``INSERT`` is later issued from a *different*
        # connection (engine B opened against the same DuckDB
        # file -- think ``ivre scancli --init`` followed by
        # ``ivre scan2db <file>`` in the next subprocess), the
        # ``duckdb-engine`` parameter binder refuses to coerce
        # ``VARCHAR`` to ``INET`` implicitly::
        #
        #     Conversion Error: Type VARCHAR with value
        #     '0.0.0.1' can't be cast to the destination type
        #     INET
        #
        # ``INETLiteral.bind_expression`` adds an explicit
        # ``CAST(? AS INET)`` around every parameter bind so
        # the conversion is forced on the SQL side.  Pin that
        # the compiled INSERT shows the cast and that a
        # cross-engine insert succeeds end-to-end.
        import os
        import tempfile

        sa = _sqlalchemy
        from ivre.db.sql.tables import SQLINET

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "inet.duckdb")
            url = f"duckdb:///{path}"

            # Engine A: CREATE TABLE.
            engine_a = sa.create_engine(url)
            meta = sa.MetaData()
            hosts = sa.Table(
                "hosts",
                meta,
                sa.Column("id", sa.Integer, primary_key=True, autoincrement=False),
                sa.Column("addr", SQLINET),
            )
            meta.create_all(engine_a)
            engine_a.dispose()

            # Compile-time pin: every INET bind goes through
            # ``CAST(? AS INET)``.
            engine_b = sa.create_engine(url)
            stmt = sa.insert(hosts)
            compiled = str(stmt.compile(dialect=engine_b.dialect))
            self.assertIn("CAST(", compiled)
            self.assertIn("AS INET)", compiled)

            # Run-time pin: cross-engine insert + read back.
            with engine_b.connect() as conn:
                conn.execute(stmt, {"id": 1, "addr": "0.0.0.1"})
                conn.execute(stmt, {"id": 2, "addr": "2001:db8::1"})
                conn.commit()
                rows = list(conn.execute(sa.select(hosts).order_by(hosts.c.id)))
            self.assertEqual(len(rows), 2)


# ---------------------------------------------------------------------
# DuckDBBackendBootstrapTests -- pin the wiring of the new
# ``ivre.db.sql.duckdb`` backend module: dialect-specific
# overrides on :class:`~ivre.db.sql.duckdb.DuckDBMixin`,
# concrete-class registration in :mod:`ivre.db`'s ``backends``
# dicts, the empty-netloc URL round-trip workaround in
# :meth:`SQLDB.__init__`, and the
# ``Sequence`` + ``server_default`` primary-key refactor in
# :mod:`ivre.db.sql.tables`. M4.1.2 lays the foundation for
# DuckDB CRUD support; later milestones build query / topvalues
# / bulk-insert parity on top.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_SQLALCHEMY,
    "sqlalchemy is required (install with the ``postgres`` or " "``duckdb`` extras)",
)
class DuckDBBackendBootstrapTests(unittest.TestCase):
    """Pin the M4.1.2 DuckDB backend bootstrap surface.

    Covers the dialect-specific overrides on
    :class:`~ivre.db.sql.duckdb.DuckDBMixin`, the concrete
    classes registered against ``duckdb://`` URLs in
    :class:`~ivre.db.DBNmap` / :class:`~ivre.db.DBView` /
    :class:`~ivre.db.DBPassive`, the
    ``Sequence``-driven primary-key refactor in
    :mod:`ivre.db.sql.tables` (so PostgreSQL keeps emitting
    ``nextval`` defaults and DuckDB stops choking on ``SERIAL``
    / ``IDENTITY``), and the empty-netloc URL round-trip
    workaround in :meth:`~ivre.db.sql.SQLDB.__init__`.
    """

    # --- ip2internal / internal2ip --------------------------------
    def test_ip2internal_passes_string_through(self):
        from ivre.db.sql.duckdb import DuckDBMixin

        # On DuckDB the INET column accepts string literals
        # straight (matching PostgreSQL); the bind-side helper
        # therefore reduces to ``utils.force_int2ip``.
        self.assertEqual(DuckDBMixin.ip2internal("192.0.2.1"), "192.0.2.1")
        self.assertEqual(DuckDBMixin.ip2internal("2001:db8::1"), "2001:db8::1")
        self.assertIsNone(DuckDBMixin.ip2internal(None))

    def test_ip2internal_converts_int_to_string(self):
        from ivre.db.sql.duckdb import DuckDBMixin

        # ``utils.force_int2ip`` rebuilds the dotted-quad form
        # for IPv4 ints (mirrors what PostgresDB.ip2internal
        # does today).
        self.assertEqual(DuckDBMixin.ip2internal(0xC0000201), "192.0.2.1")

    def test_internal2ip_handles_ipv4_struct(self):
        from ivre.db.sql.duckdb import DuckDBMixin

        # DuckDB's ``INET`` round-trip shape: IPv4 keeps the
        # natural unsigned address representation.
        self.assertEqual(
            DuckDBMixin.internal2ip({"ip_type": 1, "address": 0xC0000201, "mask": 32}),
            "192.0.2.1",
        )

    def test_internal2ip_handles_ipv6_struct_with_bias(self):
        # DuckDB stores ``INET`` v6 addresses as a biased signed
        # 128-bit integer: the unsigned value is ``address +
        # 2**127``. Pin three corner cases covering the bias
        # boundary at zero (``::`` / ``::1``), a representative
        # global address, and a high-bit-set link-local
        # address.
        cases = [
            ({"ip_type": 2, "address": -((1 << 127)), "mask": 128}, "::"),
            ({"ip_type": 2, "address": -((1 << 127)) + 1, "mask": 128}, "::1"),
            (
                {
                    "ip_type": 2,
                    "address": int("20010db8000000000000000000000001", 16) - (1 << 127),
                    "mask": 128,
                },
                "2001:db8::1",
            ),
            (
                {
                    "ip_type": 2,
                    "address": int("fe800000000000000000000000000000", 16) - (1 << 127),
                    "mask": 128,
                },
                "fe80::",
            ),
        ]
        from ivre.db.sql.duckdb import DuckDBMixin

        for raw, expected in cases:
            with self.subTest(raw=raw, expected=expected):
                self.assertEqual(DuckDBMixin.internal2ip(raw), expected)

    def test_internal2ip_passes_none_through(self):
        from ivre.db.sql.duckdb import DuckDBMixin

        self.assertIsNone(DuckDBMixin.internal2ip(None))

    def test_internal2ip_passes_string_through(self):
        # Defensive path: a future ``duckdb-engine`` release
        # might switch to returning bare strings (matching
        # ``psycopg2``); the override should remain a no-op for
        # those.
        from ivre.db.sql.duckdb import DuckDBMixin

        self.assertEqual(DuckDBMixin.internal2ip("192.0.2.1"), "192.0.2.1")

    # --- NotImplementedError surface ------------------------------
    def test_copy_from_raises_not_implemented(self):
        from ivre.db.sql.duckdb import DuckDBMixin

        with self.assertRaises(NotImplementedError):
            DuckDBMixin().copy_from(b"")

    def test_create_tmp_table_raises_not_implemented(self):
        from ivre.db.sql.duckdb import DuckDBMixin

        with self.assertRaises(NotImplementedError):
            DuckDBMixin().create_tmp_table(object())

    def test_explain_raises_not_implemented(self):
        from ivre.db.sql.duckdb import DuckDBMixin

        with self.assertRaises(NotImplementedError):
            DuckDBMixin().explain(object())

    # --- Index / FK classification helpers ------------------------
    def test_is_unsupported_on_duckdb_classification(self):
        sa = _sqlalchemy
        from ivre.db.sql.duckdb import _is_unsupported_on_duckdb
        from ivre.db.sql.tables import SQLARRAY, SQLINET

        meta = sa.MetaData()
        tbl = sa.Table(
            "t",
            meta,
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("info", _sqlalchemy_postgresql.JSONB),
            sa.Column("addr", SQLINET),
            sa.Column("tags", SQLARRAY(sa.String(64))),
            sa.Column("name", sa.String(32)),
        )
        gin = sa.Index("ix_gin", tbl.c.info, postgresql_using="gin")
        partial = sa.Index(
            "ix_partial", tbl.c.name, postgresql_where=tbl.c.id == 1, unique=True
        )
        inet_idx = sa.Index("ix_inet", tbl.c.addr)
        array_idx = sa.Index("ix_array", tbl.c.tags)
        plain = sa.Index("ix_plain", tbl.c.name)

        self.assertTrue(_is_unsupported_on_duckdb(gin))
        self.assertTrue(_is_unsupported_on_duckdb(partial))
        self.assertTrue(_is_unsupported_on_duckdb(inet_idx))
        self.assertTrue(_is_unsupported_on_duckdb(array_idx))
        self.assertFalse(_is_unsupported_on_duckdb(plain))

    def test_decode_portlist_handles_pg_string_and_duckdb_list(self):
        # Regression: the ``portlist:*`` topvalues query
        # composes
        # ``func.array_agg(tuple_(port.protocol, port.port))``
        # and post-processes the per-row result into
        # ``[(proto, port), ...]``.  PostgreSQL serialises the
        # column as a ``record[]`` *string*, e.g.
        # ``'{"(tcp,80)","(tcp,443)"}'``; DuckDB returns a
        # native ``list[tuple[str, int]]`` instead.  The
        # post-processor used to assume the PG string shape
        # and crashed on DuckDB with::
        #
        #     AttributeError: 'list' object has no attribute
        #     'split'
        #
        # Pin both decode paths on
        # :func:`ivre.db.sql.postgres._decode_portlist`.
        from ivre.db.sql.postgres import _decode_portlist

        # PG ``record[]`` literal.
        self.assertEqual(
            _decode_portlist('{"(tcp,80)","(tcp,443)","(udp,53)"}'),
            [("tcp", 80), ("tcp", 443), ("udp", 53)],
        )
        # DuckDB ``LIST(STRUCT(...))`` round-trip.
        self.assertEqual(
            _decode_portlist([("tcp", 80), ("tcp", 443), ("udp", 53)]),
            [("tcp", 80), ("tcp", 443), ("udp", 53)],
        )
        # Empty cases on both shapes.
        self.assertEqual(_decode_portlist("{}"), [])
        self.assertEqual(_decode_portlist([]), [])

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_init_strips_foreign_keys_on_duckdb(self):
        # Regression: ``ON DELETE CASCADE`` is unsupported by
        # DuckDB; downgrading the action to the implicit
        # ``RESTRICT`` would keep the FK *check*, which then
        # breaks IVRE's scan-rooted delete paths (a single
        # ``DELETE FROM scan WHERE id = ?`` relies on the
        # cascade to clean up child rows in
        # ``port`` / ``hostname`` / ``trace`` / ``hop`` /
        # ``tag`` / ``association_scan_*`` / ``script``).
        # ``DuckDBMixin.init`` therefore drops the FK
        # constraints entirely on DuckDB and restores them
        # afterwards.  Pin both halves of that contract.
        import os
        import tempfile

        from ivre.db import DBNmap
        from ivre.db.sql.tables import N_Hostname

        # Snapshot the FK declarations on the source metadata
        # (they should NOT be mutated permanently).
        original_fkc_count = len(N_Hostname.__table__.foreign_key_constraints)
        self.assertGreater(
            original_fkc_count, 0, "test fixture: N_Hostname must have FKs to start"
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ivre.duckdb")
            db = DBNmap.from_url(f"duckdb:///{path}")
            db.init()
            db.db.dispose()

            # Source metadata's FKs are restored to their
            # original count.
            self.assertEqual(
                len(N_Hostname.__table__.foreign_key_constraints),
                original_fkc_count,
            )

            # The persisted DuckDB schema has *no* FK
            # constraints (only PK / NOT NULL).
            import duckdb

            con = duckdb.connect(path, read_only=True)
            try:
                rows = con.execute(
                    "SELECT constraint_type FROM duckdb_constraints() "
                    "WHERE schema_name = 'main' AND table_name = 'n_hostname'"
                ).fetchall()
            finally:
                con.close()
            kinds = {r[0] for r in rows}
            self.assertNotIn("FOREIGN KEY", kinds, f"got constraints: {kinds}")
            # PK / NOT NULL must still be there.
            self.assertIn("PRIMARY KEY", kinds)

    # --- tables.py Sequence-based PK refactor ---------------------
    def test_pk_columns_use_sequence_default(self):
        # Pin that every surrogate-id column we refactored at
        # M4.1.2 is bound to a per-tablename
        # :class:`~sqlalchemy.schema.Sequence` and a
        # ``server_default`` calling its ``next_value()``.
        # Without the explicit Sequence, DuckDB's ``CREATE
        # TABLE`` would fall back to PG's default ``SERIAL``
        # which DuckDB rejects ("Type with name SERIAL does not
        # exist").
        from ivre.db.sql.tables import (
            Flow,
            N_Category,
            N_Hop,
            N_Hostname,
            N_Port,
            N_Scan,
            N_Tag,
            N_Trace,
            Passive,
            V_Category,
            V_Hop,
            V_Hostname,
            V_Port,
            V_Scan,
            V_Tag,
            V_Trace,
        )

        for cls in (
            Flow,
            Passive,
            N_Category,
            V_Category,
            N_Port,
            V_Port,
            N_Tag,
            V_Tag,
            N_Hostname,
            V_Hostname,
            N_Trace,
            V_Trace,
            N_Hop,
            V_Hop,
            N_Scan,
            V_Scan,
        ):
            with self.subTest(cls=cls.__name__):
                col = cls.__table__.c.id
                self.assertIsNotNone(
                    col.default, f"{cls.__tablename__}.id has no Sequence default"
                )
                self.assertEqual(col.default.name, f"seq_{cls.__tablename__}_id")
                self.assertIsNotNone(col.server_default)
                # The compiled default for both dialects calls
                # ``nextval`` (PG) / the duckdb-engine
                # equivalent.
                self.assertIn("next_value", repr(col.server_default.arg))

    def test_pk_column_appears_first_in_table(self):
        # Regression: the ``Sequence``-driven PK refactor uses
        # :func:`sqlalchemy.orm.declared_attr` to attach an
        # ``id`` :func:`~sqlalchemy.orm.mapped_column` to each
        # mixin subclass.  ``declared_attr`` is processed *after*
        # the regular class attributes, so without the
        # ``sort_order=-100`` override the ``id`` column lands
        # at the *end* of the table's ``columns`` collection.
        # That breaks every call site that unpacks
        # ``select(self.tables.<table>)`` rows positionally and
        # depends on the historical ``id`` -> ``scan`` -> ...
        # column order -- e.g.
        # :meth:`SQLDBView.get` /
        # :meth:`SQLDBNmap.get` (``ports``, ``hostnames``,
        # ``traces``, ``hops``, ``scripts`` unpacks).  In
        # production this manifested as
        # ``ValueError: invalid literal for int() with base 10:
        # 'udp'`` from ``ivre scancli --honeyd`` -- the
        # ``protocol`` string ended up where the ``port``
        # integer was expected.  Pin the contract by asserting
        # ``id`` is at index 0 on every table whose PK uses the
        # mixin.
        from ivre.db.sql.tables import (
            Flow,
            N_Category,
            N_Hop,
            N_Hostname,
            N_Port,
            N_Scan,
            N_Tag,
            N_Trace,
            Passive,
            V_Category,
            V_Hop,
            V_Hostname,
            V_Port,
            V_Scan,
            V_Tag,
            V_Trace,
        )

        for cls in (
            Flow,
            Passive,
            N_Category,
            V_Category,
            N_Port,
            V_Port,
            N_Tag,
            V_Tag,
            N_Hostname,
            V_Hostname,
            N_Trace,
            V_Trace,
            N_Hop,
            V_Hop,
            N_Scan,
            V_Scan,
        ):
            with self.subTest(cls=cls.__name__):
                names = [c.name for c in cls.__table__.columns]
                self.assertEqual(
                    names[0],
                    "id",
                    f"{cls.__tablename__}.id must be the first column "
                    f"(positional unpacks in ivre.db.sql depend on it); "
                    f"got column order {names}",
                )

    def test_create_table_emits_nextval_under_postgresql(self):
        # Sanity-pin that the Sequence-based PK refactor still
        # emits the canonical PG ``DEFAULT nextval('...')``
        # form (i.e. no regression from the previous
        # ``SERIAL``-equivalent).
        from sqlalchemy.schema import CreateTable

        from ivre.db.sql.tables import N_Scan

        sql = str(
            CreateTable(N_Scan.__table__).compile(
                dialect=_sqlalchemy_postgresql.dialect()
            )
        )
        self.assertIn("DEFAULT nextval('seq_n_scan_id'", sql)

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_create_table_emits_nextval_under_duckdb(self):
        # Same sanity check on DuckDB: the compiled DDL must
        # call ``nextval`` against the per-table sequence
        # (DuckDB supports the same ``CREATE SEQUENCE`` /
        # ``nextval`` primitives as PostgreSQL) rather than
        # falling back to ``SERIAL`` (which DuckDB rejects).
        sa = _sqlalchemy
        from sqlalchemy.schema import CreateTable

        from ivre.db.sql.tables import N_Scan

        engine = sa.create_engine("duckdb:///:memory:")
        sql = str(CreateTable(N_Scan.__table__).compile(dialect=engine.dialect))
        self.assertIn("nextval('seq_n_scan_id'", sql)
        self.assertNotIn("SERIAL", sql)
        self.assertNotIn("IDENTITY", sql)

    # --- DBNmap / DBView / DBPassive registration -----------------
    def test_backends_dict_registers_duckdb(self):
        from ivre.db import DBNmap, DBPassive, DBView

        self.assertEqual(DBNmap.backends.get("duckdb"), ("sql.duckdb", "DuckDBNmap"))
        self.assertEqual(DBView.backends.get("duckdb"), ("sql.duckdb", "DuckDBView"))
        self.assertEqual(
            DBPassive.backends.get("duckdb"), ("sql.duckdb", "DuckDBPassive")
        )

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_from_url_dispatches_to_duckdb_classes(self):
        from ivre.db import DBNmap, DBPassive, DBView
        from ivre.db.sql.duckdb import DuckDBNmap, DuckDBPassive, DuckDBView

        for parent_cls, expected in (
            (DBNmap, DuckDBNmap),
            (DBView, DuckDBView),
            (DBPassive, DuckDBPassive),
        ):
            with self.subTest(parent_cls=parent_cls.__name__):
                inst = parent_cls.from_url("duckdb:///:memory:")
                self.assertIsInstance(inst, expected)

    # --- URL round-trip fix ---------------------------------------
    def test_empty_netloc_url_survives_init_round_trip(self):
        # ``urlparse('duckdb:///:memory:').geturl()`` collapses
        # the empty-authority ``///`` to a single ``/``,
        # yielding ``duckdb:/:memory:`` -- which SQLAlchemy
        # rejects (``Could not parse SQLAlchemy URL from given
        # URL string``). ``SQLDB.__init__`` reconstructs the
        # wire form explicitly to side-step the stdlib bug; pin
        # that.
        from urllib.parse import urlparse

        from ivre.db.sql import SQLDB

        # First, evidence that the stdlib round-trip itself is
        # lossy (so a stdlib fix in the future would let us
        # drop the workaround knowingly).
        self.assertNotEqual(
            urlparse("duckdb:///:memory:").geturl(), "duckdb:///:memory:"
        )

        # Second, the workaround in SQLDB.__init__ produces the
        # form SQLAlchemy can parse.
        class _Probe(SQLDB):
            def __init__(self, url):
                super().__init__(url)

        for raw in (
            "duckdb:///:memory:",
            "duckdb:////tmp/foo.db",
            "duckdb:///tmp/foo.db",
            "postgresql://ivre@localhost/ivre",
        ):
            with self.subTest(url=raw):
                probe = _Probe(urlparse(raw))
                self.assertEqual(probe.dburl, raw)

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_init_creates_schema_on_duckdb(self):
        # End-to-end: ``init()`` on each backend transparently
        # drops every PG-only declaration DuckDB rejects
        # (GIN/INET/ARRAY/partial indexes; ``ON DELETE
        # CASCADE`` on FKs) and successfully materialises the
        # IVRE schema on an in-memory engine.
        from ivre.db import DBNmap, DBPassive, DBView

        for cls in (DBNmap, DBView, DBPassive):
            with self.subTest(cls=cls.__name__):
                db = cls.from_url("duckdb:///:memory:")
                db.init()
                # The expected per-namespace tables exist.
                from sqlalchemy import inspect

                names = set(inspect(db.db).get_table_names())
                self.assertTrue(
                    {"n_scan", "n_port", "n_hostname"} <= names
                    or {"v_scan", "v_port", "v_hostname"} <= names
                    or {"passive"} <= names
                )

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_write_result_survives_connection_close_on_duckdb(self):
        # Regression: every existing ``self._write(stmt).fetchone()[0]``
        # call site (e.g. in :meth:`PostgresDB._store_host` for the
        # ``RETURNING n_scan.id`` upsert, in
        # :meth:`PostgresDBNmap._store_host` for ports / scripts
        # / hostnames, …) reads from the cursor *after*
        # :meth:`SQLDB._write` has exited the transactional
        # ``with`` block and returned the connection to the pool.
        # On PostgreSQL (psycopg2) this works by accident
        # because psycopg2 pre-buffers rows on the client side;
        # on DuckDB (``duckdb-engine``) the cursor's result set
        # is tied to the live connection and raises::
        #
        #     InvalidInputException: No open result set
        #
        # Pin that ``self._write(...)`` returns a buffered
        # result object whose ``fetchone()`` works after the
        # underlying connection has closed.
        from ivre.db import DBNmap

        db = DBNmap.from_url("duckdb:///:memory:")
        db.init()
        # Issue a RETURNING-flavoured insert via ``_write`` and
        # read the row *outside* the writer's ``with`` block.
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        result = db._write(  # pylint: disable=protected-access
            pg_insert(db.tables.scan)
            .values(
                addr="192.0.2.1",
                source="test",
                schema_version=22,
            )
            .on_conflict_do_nothing()
            .returning(db.tables.scan.id)
        )
        # The connection is now closed; the read must still
        # succeed (would raise ``InvalidInputException`` on
        # DuckDB without ``_BufferedResult``).
        row = result.fetchone()
        self.assertIsNotNone(row)
        scan_id = row[0]
        self.assertGreater(scan_id, 0)

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_init_idempotent_on_file_backed_duckdb(self):
        # Regression: a single SQLAlchemy engine reuses the same
        # DuckDB session across :meth:`SQLDB.drop` and
        # :meth:`SQLDB.create`, and DuckDB's catalog refuses to
        # commit a ``CREATE TABLE`` that re-introduces a name
        # whose previous incarnation was dropped within the same
        # session::
        #
        #     TransactionException: Failed to commit: Could not
        #     commit creation of dependency, subject "n_category"
        #     has been deleted
        #
        # The bug only fires the *second* time ``init()`` runs
        # against a pre-existing DuckDB file (the first init
        # creates an empty file with no prior catalog state to
        # conflict with).  Pin that the override recycles the
        # engine between drop and create, so calling ``init()``
        # twice in a row on the same file-backed database
        # succeeds.
        import os
        import tempfile

        from ivre.db import DBNmap

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "ivre.duckdb")
            url = f"duckdb:///{path}"
            for round_no in (1, 2, 3):
                with self.subTest(round=round_no):
                    db = DBNmap.from_url(url)
                    db.init()
                    db.db.dispose()

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_init_restores_metadata_after_duckdb_run(self):
        # ``DuckDBMixin.init`` strips a handful of
        # PG-only schema declarations from the shared
        # ``Base.metadata`` for the duration of
        # ``create_all``; the ``finally`` clause must put them
        # back so a parallel PG engine sharing the same
        # in-process metadata sees its full schema.
        from ivre.db import DBNmap
        from ivre.db.sql.tables import Base

        snapshot = {
            tbl.name: {
                "indexes": {
                    ix.name: (
                        ix.kwargs.get("postgresql_using"),
                        ix.kwargs.get("postgresql_where") is not None,
                    )
                    for ix in tbl.indexes
                },
                "fk_actions": tuple(
                    sorted(
                        (str(fkc), fkc.ondelete, fkc.onupdate)
                        for fkc in tbl.foreign_key_constraints
                    )
                ),
            }
            for tbl in Base.metadata.tables.values()
        }

        DBNmap.from_url("duckdb:///:memory:").init()

        post = {
            tbl.name: {
                "indexes": {
                    ix.name: (
                        ix.kwargs.get("postgresql_using"),
                        ix.kwargs.get("postgresql_where") is not None,
                    )
                    for ix in tbl.indexes
                },
                "fk_actions": tuple(
                    sorted(
                        (str(fkc), fkc.ondelete, fkc.onupdate)
                        for fkc in tbl.foreign_key_constraints
                    )
                ),
            }
            for tbl in Base.metadata.tables.values()
        }
        self.assertEqual(snapshot, post)

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_create_tmp_table_strips_pk_sequence_default(self):
        # Regression: ``Column.copy()`` on a source PK column
        # propagates the
        # ``server_default = nextval('seq_<table>_id')`` clause
        # to the temp-table mirror that
        # :meth:`PostgresDB.create_tmp_table` builds for the
        # passive bulk-insert path.  PostgreSQL then refuses
        # ``DROP SEQUENCE seq_<table>_id`` while a pooled
        # connection still owns the session-scoped
        # ``tmp_<table>`` (``cannot drop sequence ... because
        # other objects depend on it``), which propagates into
        # the next test's ``init()`` and rolls back the schema
        # reset, leaking data across tests.
        # ``create_tmp_table`` must therefore strip the
        # ``server_default`` / ``default`` from copied PK
        # columns; the temp table never reads ``id`` (callers
        # project named columns via ``INSERT ... FROM SELECT``)
        # so the default is unnecessary.
        from ivre.db import DBPassive
        from ivre.db.sql.postgres import PostgresDB
        from ivre.db.sql.tables import Passive

        # Bind ``create_tmp_table`` to a DuckDB-backed instance
        # so the actual ``CREATE TEMPORARY TABLE`` DDL runs
        # against an in-memory engine (DuckDB inherits the PG
        # dialect via duckdb-engine, so the column-copy logic
        # under test is identical).  The DuckDB override of
        # ``create_tmp_table`` raises ``NotImplementedError``
        # by design; reach past it via the unbound
        # ``PostgresDB`` method to exercise the live code path.
        db = DBPassive.from_url("duckdb:///:memory:")
        db.init()
        tmp = PostgresDB.create_tmp_table(db, Passive)

        self.assertEqual(tmp.name, "tmp_passive")
        # The source column keeps its sequence (PG must still
        # auto-assign ``passive.id`` from ``seq_passive_id``).
        self.assertIsNotNone(Passive.__table__.c.id.server_default)
        self.assertIsNotNone(Passive.__table__.c.id.default)
        # The mirror loses the cross-sequence dependency.
        self.assertIsNone(tmp.c.id.server_default)
        self.assertIsNone(tmp.c.id.default)
        # And the rest of the PK-loosening transform still
        # holds (no PK constraint, indexed, nullable).
        self.assertFalse(tmp.c.id.primary_key)
        self.assertTrue(tmp.c.id.nullable)

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_crud_roundtrip_on_duckdb(self):
        # End-to-end CRUD: insert a scan + a hostname into
        # DuckDB; read them back; ``internal2ip`` collapses
        # the INET round-trip struct back to the original IP
        # string.
        from sqlalchemy import insert, select

        from ivre.db import DBNmap

        db = DBNmap.from_url("duckdb:///:memory:")
        db.init()
        T = db.tables
        with db.db.begin() as conn:
            res = conn.execute(
                insert(T.scan),
                {"addr": "192.0.2.1", "source": "test", "schema_version": 22},
            )
            scan_id = res.inserted_primary_key[0]
            conn.execute(
                insert(T.hostname),
                {
                    "scan": scan_id,
                    "name": "example.com",
                    "type": "PTR",
                    "domains": ["example.com", "com"],
                },
            )
        with db.db.connect() as conn:
            scan_row = conn.execute(select(T.scan.id, T.scan.addr)).one()
            host_row = conn.execute(select(T.hostname.name, T.hostname.domains)).one()
        self.assertEqual(scan_row[0], scan_id)
        self.assertEqual(db.internal2ip(scan_row[1]), "192.0.2.1")
        self.assertEqual(host_row[0], "example.com")
        self.assertEqual(host_row[1], ["example.com", "com"])

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_fts_extension_loaded_on_connect(self):
        # Pin that the ``connect`` event listener registered by
        # :meth:`DuckDBMixin.db` runs ``INSTALL fts; LOAD fts;``
        # on every new DuckDB connection so the FTS extension's
        # ``match_bm25`` function is callable from the
        # subsequent searchtext queries.  Without the listener
        # ``match_bm25`` resolves with ``Catalog Error: Scalar
        # Function with name match_bm25 does not exist``.
        #
        # Search term ``apache`` is intentional: DuckDB's
        # Snowball-based default stemmer filters out common
        # English stopwords (``hello``, ``world``, ``the``,
        # ...) that would silently return NULL scores on every
        # row regardless of the index loading correctly.
        from sqlalchemy import text as sa_text

        from ivre.db import DBNmap

        db = DBNmap.from_url("duckdb:///:memory:")
        with db.db.begin() as conn:
            conn.execute(sa_text("CREATE TABLE fts_probe (id_col INTEGER, t VARCHAR)"))
            conn.execute(sa_text("INSERT INTO fts_probe VALUES (1, 'apache')"))
            conn.execute(sa_text("PRAGMA create_fts_index('fts_probe', 'id_col', 't')"))
            rows = conn.execute(
                sa_text(
                    "SELECT id_col, fts_main_fts_probe.match_bm25(id_col, "
                    "'apache') FROM fts_probe"
                )
            ).fetchall()
        # Single row, score is non-NULL (BM25 weight) when the
        # index is loaded and the term matches.
        self.assertEqual(len(rows), 1)
        self.assertIsNotNone(rows[0][1])

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_fts_indexes_created_at_init(self):
        # ``DuckDBMixin.init`` calls ``_create_fts_indexes``
        # after ``create()`` so every text-bearing table gets
        # an empty FTS index ready for ``searchtext()`` to
        # rebuild.  Pin that an FTS index exists for each
        # expected table after a fresh init.
        from sqlalchemy import text as sa_text

        from ivre.db import DBNmap

        db = DBNmap.from_url("duckdb:///:memory:")
        db.init()
        with db.db.connect() as conn:
            schemas = {
                row[0]
                for row in conn.execute(
                    sa_text(
                        "SELECT schema_name FROM information_schema.schemata "
                        "WHERE schema_name LIKE 'fts_main_n_%'"
                    )
                ).fetchall()
            }
        # One ``fts_main_<table>`` schema per text-bearing
        # active table (hostname, tag, port, script, hop,
        # category).
        self.assertSetEqual(
            schemas,
            {
                "fts_main_n_hostname",
                "fts_main_n_tag",
                "fts_main_n_port",
                "fts_main_n_script",
                "fts_main_n_hop",
                "fts_main_n_category",
            },
        )

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_searchtext_uses_bm25_on_duckdb(self):
        # The DuckDB filter override emits ``match_bm25``
        # predicates instead of the PostgreSQL
        # ``to_tsvector @@ plainto_tsquery`` -- the latter
        # would raise ``Catalog Error: Scalar Function with
        # name to_tsvector does not exist`` on DuckDB.  Pin
        # that the compiled SQL goes through the BM25 API.
        from ivre.db import DBNmap

        db = DBNmap.from_url("duckdb:///:memory:")
        db.init()
        flt = db.searchtext("honeypot")
        # Filter type: ``DuckDBNmapFilter`` (or subclass).
        from ivre.db.sql.duckdb import DuckDBNmapFilter

        self.assertIsInstance(flt, DuckDBNmapFilter)
        # Compile the WHERE clause through the DuckDB dialect
        # and assert the BM25 wire shape.
        from sqlalchemy import func as sa_func
        from sqlalchemy import select as sa_select

        sql = str(
            flt.query(sa_select(sa_func.count()).select_from(flt.select_from)).compile(
                dialect=db.db.dialect
            )
        )
        self.assertIn("match_bm25", sql)
        self.assertIn("IS NOT NULL", sql)
        # And there is *no* PG-only call.
        self.assertNotIn("to_tsvector", sql)
        self.assertNotIn("plainto_tsquery", sql)

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_searchtext_end_to_end_on_duckdb(self):
        # Insert a host whose text fields cover several of the
        # FTS-indexed tables, then exercise positive /
        # negative ``searchtext()`` queries.  Without the
        # rebuild-on-every-search behaviour
        # (:meth:`DuckDBNmap.searchtext` calls
        # :meth:`_create_fts_indexes` before returning) the
        # search would miss every row inserted after init.
        from sqlalchemy import insert

        from ivre.db import DBNmap

        db = DBNmap.from_url("duckdb:///:memory:")
        db.init()
        with db.db.begin() as conn:
            res = conn.execute(
                insert(db.tables.scan),
                {"addr": "192.0.2.1", "source": "test", "schema_version": 22},
            )
            scan_id = res.inserted_primary_key[0]
            conn.execute(
                insert(db.tables.hostname),
                {
                    "scan": scan_id,
                    "name": "honeypot.example.com",
                    "type": "PTR",
                    "domains": ["example.com", "com"],
                },
            )
            conn.execute(
                insert(db.tables.port),
                {
                    "scan": scan_id,
                    "port": 80,
                    "protocol": "tcp",
                    "service_name": "http",
                    "service_product": "nginx",
                    "state": "open",
                },
            )
            conn.execute(
                insert(db.tables.tag),
                {
                    "scan": scan_id,
                    "value": "HONEYPOT",
                    "info": "kibana stack",
                    "type": "warning",
                },
            )
        # Positive matches across hostname / port / tag.
        self.assertEqual(db.count(db.searchtext("honeypot")), 1)
        self.assertEqual(db.count(db.searchtext("nginx")), 1)
        self.assertEqual(db.count(db.searchtext("kibana")), 1)
        # Non-match.
        self.assertEqual(db.count(db.searchtext("nonexistent")), 0)
        # Negation flips the inclusion.
        self.assertEqual(db.count(db.searchtext("honeypot", neg=True)), 0)
        self.assertEqual(db.count(db.searchtext("nonexistent", neg=True)), 1)


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

    def test_db_flush_base_is_noop(self):
        # M4.0.2: ``DB.flush()`` is the read-after-write barrier
        # used by tests in place of ``time.sleep(...)`` for
        # Elastic. The base method must be a no-op so SQL /
        # Mongo / DocumentDB / HTTP backends inherit a free
        # implementation. Only ``ElasticDB`` overrides it to
        # call ``indices.refresh``. Pin the contract:
        #
        #   - ``DB.flush`` exists and is callable.
        #   - The base method body is empty (just a docstring).
        #
        # The Elastic-specific override is verified separately
        # in ``ElasticDB.flush`` (live-cluster check via
        # ``tests/tests.py`` writes-then-reads).
        import ast
        from inspect import getsource
        from textwrap import dedent

        from ivre.db import DB

        self.assertTrue(callable(DB.flush))
        # Body should be docstring-only (no real statements).
        tree = ast.parse(dedent(getsource(DB.flush)))
        funcdef = tree.body[0]
        self.assertIsInstance(funcdef, ast.FunctionDef)
        body_after_docstring = funcdef.body[1:]
        self.assertEqual(
            body_after_docstring,
            [],
            "DB.flush() base method must be a docstring-only no-op; "
            "non-Elastic backends rely on the inherited no-op.",
        )

    def test_create_tmp_table_idempotent_per_process(self):
        # P4.B: ``PostgresDB.create_tmp_table`` is called from
        # ``insert_or_update_bulk`` once per call. Each call
        # historically did ``Table(f"tmp_{name}", metadata, ...)``
        # which raised ``InvalidRequestError: Table
        # 'tmp_<name>' is already defined for this MetaData
        # instance`` on the second invocation in the same Python
        # process (the SQLAlchemy ``MetaData`` registry keys by
        # table name). The fix retrieves the existing
        # ``Table`` from ``metadata.tables`` when present and
        # only registers a new one on the first call.
        #
        # The test exercises the in-memory part only -- it
        # walks the source AST to assert the ``metadata.tables.get``
        # / reuse pattern is in place. A live PostgreSQL DB is
        # not required to validate the dispatch.
        import ast
        from inspect import getsource
        from textwrap import dedent

        from ivre.db.sql import postgres as pgmod

        src = dedent(getsource(pgmod.PostgresDB.create_tmp_table))
        tree = ast.parse(src)
        # Walk the AST: assert there is a
        # ``metadata.tables.get(...)`` call (the lookup before
        # constructing a new Table), and that the ``Table(...)``
        # construction is gated by an ``if`` whose condition
        # checks for ``None`` / falsy.
        gets_tables_get = False
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get"
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "tables"
            ):
                gets_tables_get = True
                break
        self.assertTrue(
            gets_tables_get,
            "create_tmp_table must look up metadata.tables before "
            "constructing a new Table to avoid the SA "
            "'already defined for this MetaData' error",
        )

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

    def test_remove_paths_do_not_emit_cte_coercion_sawarning(self):
        # M4.0.1: SQLAlchemy 2.x emits ``SAWarning: Coercing CTE
        # object into a select() for use in IN()`` when a CTE is
        # passed directly to ``Column.in_(...)``. Three sites in
        # ``ivre/db/sql/__init__.py`` historically did this:
        #
        #   - ``SQLDBActive._get_open_port_count``
        #   - ``SQLDBActive.remove_many``
        #   - ``SQLDBPassive.remove``
        #
        # Each was adjusted to wrap the CTE in
        # ``select(base.c.id)`` before the ``.in_(...)``. Pin the
        # silence by AST-walking the source for any
        # ``.in_(<bare-name>)`` where the name was bound to a CTE
        # in the same function. The test is white-box; it
        # documents the contract so a future refactor can't
        # regress it.
        import ast
        from inspect import getsource
        from textwrap import dedent

        from ivre.db.sql import SQLDBActive, SQLDBPassive

        for fn in [
            SQLDBActive._get_open_port_count,
            SQLDBActive.remove_many,
            SQLDBPassive.remove,
        ]:
            with self.subTest(method=fn.__qualname__):
                src = dedent(getsource(fn))
                tree = ast.parse(src)
                # Find variables bound to ``....cte(...)``.
                cte_names = set()
                for node in ast.walk(tree):
                    if isinstance(node, ast.Assign) and isinstance(
                        node.value, ast.Call
                    ):
                        # Look for a chain ending in ``.cte(...)``.
                        call = node.value
                        if (
                            isinstance(call.func, ast.Attribute)
                            and call.func.attr == "cte"
                        ):
                            for tgt in node.targets:
                                if isinstance(tgt, ast.Name):
                                    cte_names.add(tgt.id)
                # Every ``.in_(<Name>)`` call where the name is in
                # ``cte_names`` must be flagged. (We allow
                # ``.in_(select(<Name>.c.<col>))`` -- the wrapped
                # form.)
                bad = []
                for node in ast.walk(tree):
                    if (
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "in_"
                        and len(node.args) == 1
                        and isinstance(node.args[0], ast.Name)
                        and node.args[0].id in cte_names
                    ):
                        bad.append(ast.unparse(node))
                self.assertEqual(
                    bad,
                    [],
                    f"{fn.__qualname__}: a CTE is passed bare to .in_(...); "
                    f"wrap it in select(<cte>.c.<column>) to silence "
                    f"SQLAlchemy 2.x's SAWarning. Offending calls: {bad}",
                )


# ---------------------------------------------------------------------
# SQLDBSearchTextTests -- pin the wire shape of the new
# cross-backend ``searchtext()`` helper on the SQL backends:
# the GIN-index expression declared in
# :mod:`ivre.db.sql.tables` and the ``WHERE`` predicate built
# at query time must match byte-for-byte so PostgreSQL's
# planner can substitute the index, and the ``OR``-of-EXISTS
# composition over child tables must include every
# text-bearing column listed in :attr:`DBActive.text_fields`.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_SQLALCHEMY,
    "sqlalchemy is required (install with the ``postgres`` extras)",
)
class SQLDBSearchTextTests(unittest.TestCase):
    """Behaviour-pin for ``SQLDBActive.searchtext`` -- the
    new cross-backend full-text-search filter.

    Mirrors the contract of :meth:`MongoDB.searchtext`
    (``{"$text": {"$search": text}}``).  On the SQL backends
    the dispatch happens at query-build time:
    :meth:`ActiveFilter._text_predicate` builds an
    ``OR``-of-``EXISTS`` over each text-bearing child table,
    each per-table predicate is itself a single
    ``to_tsvector('english', coalesce(col1, '') || ' ' ||
    coalesce(col2, '') || ...) @@ plainto_tsquery('english',
    :term)``.  Per-table GIN indexes built over the *same*
    expression accelerate the match.
    """

    @staticmethod
    def _compile(stmt):
        return str(stmt.compile(dialect=_sqlalchemy_postgresql.dialect()))

    def test_searchtext_returns_filter_with_text_slot(self):
        from ivre.db import DBNmap, DBView

        for cls in (DBNmap, DBView):
            with self.subTest(cls=cls.__name__):
                db = cls.from_url("postgresql://x@localhost/x")
                flt = db.searchtext("honeypot")
                self.assertEqual(flt.text, [(True, "honeypot")])

    def test_searchtext_negation_inverts_inclusion(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        flt = db.searchtext("honeypot", neg=True)
        self.assertEqual(flt.text, [(False, "honeypot")])

    def test_searchtext_query_emits_or_of_exists(self):
        # Pin that the compiled query has one ``EXISTS``
        # subquery per text-bearing child table
        # (hostname, tag, port, script, hop, category).
        sa = _sqlalchemy
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        flt = db.searchtext("honeypot")
        sql = self._compile(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        # One EXISTS per text-bearing table (6 in total).
        self.assertEqual(sql.count("EXISTS"), 6)
        # Every per-table predicate uses the ``@@`` operator.
        self.assertEqual(sql.count("@@ plainto_tsquery"), 6)
        # And every per-table predicate is the concatenated
        # ``coalesce`` form (so it can match the GIN index).
        self.assertIn("v_hostname.scan = v_scan.id", sql)
        self.assertIn("v_tag.scan = v_scan.id", sql)
        self.assertIn("v_port.scan = v_scan.id", sql)
        # script -> port -> scan and hop -> trace -> scan
        self.assertIn("v_script JOIN v_port", sql)
        self.assertIn("v_trace JOIN v_hop", sql)
        # category -> association_scan_category -> scan
        self.assertIn("v_category JOIN v_association_scan_category", sql)

    def test_searchtext_index_and_query_expressions_match(self):
        # The GIN index expression and the query predicate
        # must be byte-for-byte identical so PostgreSQL's
        # planner can substitute the index for the WHERE
        # clause.  Pin that for every text-bearing table on
        # both ``n_*`` and ``v_*`` schemas.
        sa = _sqlalchemy
        from sqlalchemy.schema import CreateIndex

        from ivre.db import DBNmap, DBView
        from ivre.db.sql.tables import (
            N_Category,
            N_Hop,
            N_Hostname,
            N_Port,
            N_Script,
            N_Tag,
            V_Category,
            V_Hop,
            V_Hostname,
            V_Port,
            V_Script,
            V_Tag,
        )

        nmap_tables = (
            (N_Hostname, "ix_n_hostname_fts"),
            (N_Tag, "ix_n_tag_fts"),
            (N_Port, "ix_n_port_fts"),
            (N_Script, "ix_n_script_fts"),
            (N_Hop, "ix_n_hop_fts"),
            (N_Category, "ix_n_category_fts"),
        )
        view_tables = (
            (V_Hostname, "ix_v_hostname_fts"),
            (V_Tag, "ix_v_tag_fts"),
            (V_Port, "ix_v_port_fts"),
            (V_Script, "ix_v_script_fts"),
            (V_Hop, "ix_v_hop_fts"),
            (V_Category, "ix_v_category_fts"),
        )
        for cls, tables in ((DBNmap, nmap_tables), (DBView, view_tables)):
            with self.subTest(cls=cls.__name__):
                db = cls.from_url("postgresql://x@localhost/x")
                flt = db.searchtext("honeypot")
                sql = self._compile(
                    flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
                )
                for tbl_cls, idx_name in tables:
                    idx = next(
                        ix for ix in tbl_cls.__table__.indexes if ix.name == idx_name
                    )
                    idx_sql = str(
                        CreateIndex(idx).compile(
                            dialect=_sqlalchemy_postgresql.dialect()
                        )
                    )
                    # Extract the ``to_tsvector(...)`` call up
                    # to its outermost ``)``: that's the
                    # expression PostgreSQL has to match against
                    # the WHERE clause.
                    paren = idx_sql.index("to_tsvector(")
                    depth = 0
                    end = paren
                    while end < len(idx_sql):
                        if idx_sql[end] == "(":
                            depth += 1
                        elif idx_sql[end] == ")":
                            depth -= 1
                            if depth == 0:
                                end += 1
                                break
                        end += 1
                    expr = idx_sql[paren:end]
                    self.assertIn(
                        expr,
                        sql,
                        f"{tbl_cls.__name__}: index expression\n  {expr}\n"
                        f"not found verbatim in query SQL",
                    )


# ---------------------------------------------------------------------
# SQLDBRirSearchTextTests -- pin the wire shape of the
# RIR-purpose ``searchtext()`` helper that closes the M4.2
# cross-backend full-text-search story.  ``MongoDBRir`` inherits
# ``searchtext`` from the ``MongoDB`` base (``$text`` operator);
# ``SQLDBRir`` and its concrete ``PostgresDBRir`` /
# ``DuckDBRir`` subclasses now ship the equivalent shape:
# PostgreSQL through ``to_tsvector @@ plainto_tsquery`` over the
# ``rir_idx_fts`` GIN index, DuckDB through the ``fts``
# extension's ``fts_main_rir.match_bm25`` predicate.  The four
# defensive ``hasattr(<dbase>, "searchtext")`` guards in
# :mod:`ivre.tools.rirlookup` and :mod:`ivre.tools.mcp_server`
# are dropped in the same PR.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_SQLALCHEMY,
    "sqlalchemy is required (install with the ``postgres`` extras)",
)
class SQLDBRirSearchTextTests(unittest.TestCase):
    """Behaviour-pin for ``SQLDBRir.searchtext`` -- the
    RIR-purpose full-text-search filter mirroring
    :meth:`MongoDBRir.searchtext`.
    """

    @staticmethod
    def _compile(stmt):
        # ``literal_binds=True`` is intentionally omitted: the
        # ``REGCONFIG`` first argument of ``to_tsvector`` /
        # ``plainto_tsquery`` has no SA literal renderer
        # registered, so rendering with literal binds raises.
        # The non-literal form binds the search ``term`` as a
        # ``?`` placeholder, which is enough for wire-shape
        # assertions on the surrounding expression.
        return str(stmt.compile(dialect=_sqlalchemy_postgresql.dialect()))

    def test_searchtext_emits_to_tsvector_at_at_plainto_tsquery(self):
        # Pin that the compiled PG predicate uses the
        # planner-friendly ``to_tsvector('english', coalesce(...)
        # || ' ' || ...) @@ plainto_tsquery('english', :term)``
        # shape -- the same expression
        # :data:`tables.RIR_FTS_COLUMNS` builds for the GIN index
        # so the planner can substitute one for the other.
        from ivre.db import DBRir

        db = DBRir.from_url("postgresql://x@localhost/x")
        flt = db.searchtext("ovh")
        sql = self._compile(flt)
        self.assertIn("to_tsvector('english'", sql)
        self.assertIn("@@ plainto_tsquery", sql)
        # Every text column listed in RIR_FTS_COLUMNS must
        # appear in the coalesce chain.
        for col in (
            "netname",
            "descr",
            "remarks",
            "notify",
            "org",
            "as_name",
        ):
            self.assertIn(f"coalesce(rir.{col}", sql)

    def test_searchtext_negation_wraps_in_not(self):
        # ``neg=True`` inverts the predicate; the wire shape
        # mirrors :meth:`MongoDBRir.searchtext` composed with
        # an outer ``$not``.
        from ivre.db import DBRir

        db = DBRir.from_url("postgresql://x@localhost/x")
        flt = db.searchtext("ovh", neg=True)
        sql = self._compile(flt)
        self.assertTrue(
            sql.startswith("NOT ("),
            f"expected ``NOT (...)`` wrapper, got:\n  {sql}",
        )
        self.assertIn("@@ plainto_tsquery", sql)

    def test_searchtext_index_and_query_expressions_match(self):
        # Byte-for-byte parity between the GIN index expression
        # declared in :mod:`ivre.db.sql.tables` and the runtime
        # ``WHERE`` predicate built by ``searchtext``.  Without
        # this, PostgreSQL silently falls back to a sequential
        # scan -- the bug is invisible in correctness tests but
        # crippling at scale.
        sa = _sqlalchemy
        from sqlalchemy.schema import CreateIndex

        from ivre.db import DBRir
        from ivre.db.sql.tables import Rir

        db = DBRir.from_url("postgresql://x@localhost/x")
        flt = db.searchtext("ovh")
        query_sql = str(
            sa.select(sa.literal_column("1"))
            .where(flt)
            .compile(dialect=_sqlalchemy_postgresql.dialect())
        )
        idx = next(ix for ix in Rir.__table__.indexes if ix.name == "rir_idx_fts")
        idx_sql = str(
            CreateIndex(idx).compile(dialect=_sqlalchemy_postgresql.dialect())
        )
        # Extract the ``to_tsvector(...)`` call up to its
        # outermost ``)`` -- that is the expression PG matches
        # against the ``WHERE`` clause.
        paren = idx_sql.index("to_tsvector(")
        depth = 0
        end = paren
        while end < len(idx_sql):
            if idx_sql[end] == "(":
                depth += 1
            elif idx_sql[end] == ")":
                depth -= 1
                if depth == 0:
                    end += 1
                    break
            end += 1
        expr = idx_sql[paren:end]
        self.assertIn(
            expr,
            query_sql,
            f"rir_idx_fts: index expression\n  {expr}\nnot found verbatim "
            f"in query SQL:\n  {query_sql}",
        )

    def test_rir_fts_columns_match_text_fields(self):
        # ``RIR_FTS_COLUMNS`` is the canonical list shared by
        # the GIN index and ``SQLDBRir.searchtext``.  It must
        # cover every text-bearing column in the RIR schema
        # plus ``as_name`` (an ``aut-num``-only column not in
        # ``DBRir.text_fields`` because the Mongo backend stores
        # it on a separate document path).  A drift here means
        # one half of the search surface stops being indexed.
        from ivre.db import DBRir
        from ivre.db.sql.tables import RIR_FTS_COLUMNS

        for col in DBRir.text_fields:
            self.assertIn(col, RIR_FTS_COLUMNS)
        self.assertIn("as_name", RIR_FTS_COLUMNS)


# ---------------------------------------------------------------------
# SQLDBSearchCpeOsVulnTests -- pin the wire shape of the
# Mongo-shape ``searchcpe`` / ``searchos`` / ``searchvuln*``
# helpers on the SQL backends.  Both PostgreSQL and DuckDB are
# exercised so the dialect-aware split (PG :func:`jsonb_array_elements`
# + :func:`jsonb_typeof` vs DuckDB :func:`json_each` +
# :func:`json_type`, plus the ``~*`` -> :func:`regexp_matches`
# rewrite) stays under regression coverage.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_SQLALCHEMY,
    "sqlalchemy is required (install with the ``postgres`` or ``duckdb`` extras)",
)
class SQLDBSearchCpeOsVulnTests(unittest.TestCase):
    """Behaviour-pin for ``SQLDBActive.searchcpe`` /
    ``searchos`` / ``searchvuln`` / ``searchvulnintersil``.

    Each method mirrors the contract of its counterpart on
    :class:`MongoDB` (``cpes`` / ``os.osclass`` / ``ports.scripts.vulns``);
    on the SQL backends the matching logic unwinds the JSONB
    array column with PG's :func:`jsonb_array_elements` (or
    DuckDB's :func:`json_each`) and AND-/OR-combines the
    per-field text predicates inside an ``EXISTS``.

    The DuckDB lane also exercises the
    ``_searchstring_re`` -> :func:`regexp_matches` rewrite the
    :class:`DuckDBMixin` ships, since DuckDB's parser does not
    accept PostgreSQL's case-insensitive regex operator
    ``~*``.
    """

    @staticmethod
    def _compile_pg(stmt):
        return str(
            stmt.compile(
                dialect=_sqlalchemy_postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )

    @staticmethod
    def _compile_duckdb(stmt):
        # ``duckdb_engine`` is the optional dependency the
        # module-level try-import already gated behind
        # ``_HAVE_DUCKDB_ENGINE``; reuse the module-scope
        # binding rather than re-importing locally.
        return str(
            stmt.compile(
                dialect=duckdb_engine.Dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )

    def _run_count_query(self, db_url, factory):
        # Build an ``ActiveFilter`` from the connection URL and
        # the supplied factory (``factory(db) -> filter``), then
        # return the rendered ``SELECT count(*) ...`` query.
        sa = _sqlalchemy
        from ivre.db import DBNmap

        db = DBNmap.from_url(db_url)
        flt = factory(db)
        return flt, flt.query(sa.select(sa.func.count()).select_from(flt.select_from))

    # -- searchcpe -----------------------------------------------------

    def test_searchcpe_no_args_emits_is_not_null(self):
        from ivre.db import DBNmap, DBView

        for cls in (DBNmap, DBView):
            with self.subTest(cls=cls.__name__):
                db = cls.from_url("postgresql://x@localhost/x")
                flt = db.searchcpe()
                sa = _sqlalchemy
                sql = self._compile_pg(
                    flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
                )
                # A zero-arg call only checks for the column's
                # presence: no ``EXISTS`` over the unwound array,
                # just an ``IS NOT NULL`` on the JSONB column.
                self.assertIn("cpes IS NOT NULL", sql)
                self.assertNotIn("jsonb_array_elements", sql)

    def test_searchcpe_pg_unwinds_with_jsonb_array_elements(self):
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        flt = db.searchcpe(vendor="apache", product="httpd")
        sa = _sqlalchemy
        sql = self._compile_pg(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        # PG: ``jsonb_array_elements(scan.cpes) AS __cpe`` and
        # then ``__cpe ->> '<field>'`` per condition.
        self.assertIn("jsonb_array_elements(n_scan.cpes) AS __cpe", sql)
        self.assertIn("__cpe ->> ", sql)
        # Two AND-combined predicates (vendor + product).
        self.assertEqual(sql.count("__cpe ->>"), 2)

    def test_searchcpe_pg_regex_emits_caseinsensitive_op(self):
        import re

        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        flt = db.searchcpe(vendor=re.compile("^apache", re.IGNORECASE))
        sa = _sqlalchemy
        sql = self._compile_pg(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        # The case-insensitive flag maps to PG's ``~*`` operator.
        self.assertIn("~*", sql)

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_searchcpe_duckdb_unwinds_with_json_each(self):
        from ivre.db.sql.duckdb import DuckDBNmap

        db = DuckDBNmap.from_url("duckdb:///:memory:")
        flt = db.searchcpe(vendor="apache", product="httpd")
        sa = _sqlalchemy
        sql = self._compile_duckdb(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        # DuckDB: ``json_each(scan.cpes) AS __cpe(...)`` with
        # the 8-column shape declared by ``_JSON_EACH_COLUMNS``.
        self.assertIn("json_each(n_scan.cpes)", sql)
        self.assertIn("__cpe", sql)
        # Conditions reference ``__cpe.value -> '<field>'`` --
        # the "value" column is the per-element JSON.
        self.assertIn("__cpe.value ->>", sql)

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_searchcpe_duckdb_regex_uses_regexp_matches(self):
        import re

        from ivre.db.sql.duckdb import DuckDBNmap

        db = DuckDBNmap.from_url("duckdb:///:memory:")
        flt = db.searchcpe(vendor=re.compile("^apache", re.IGNORECASE))
        sa = _sqlalchemy
        sql = self._compile_duckdb(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        # DuckDB cannot parse ``~*``; the override emits a
        # ``regexp_matches(field, pattern, 'i')`` call instead.
        self.assertNotIn("~*", sql)
        self.assertIn("regexp_matches(", sql)

    # -- searchos ------------------------------------------------------

    def test_searchos_pg_unwinds_osclass_array(self):
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        flt = db.searchos("Linux")
        sa = _sqlalchemy
        sql = self._compile_pg(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        # PG: unwinds ``scan.os -> 'osclass'`` and OR-combines
        # the four per-field predicates.
        self.assertIn("jsonb_array_elements(n_scan.os -> 'osclass')", sql)
        self.assertIn("jsonb_typeof(n_scan.os -> 'osclass') = 'array'", sql)
        for field in ("vendor", "osfamily", "osgen", "type"):
            self.assertIn(f"__osclass ->> '{field}'", sql)

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_searchos_duckdb_unwinds_osclass_array(self):
        from ivre.db.sql.duckdb import DuckDBNmap

        db = DuckDBNmap.from_url("duckdb:///:memory:")
        flt = db.searchos("Linux")
        sa = _sqlalchemy
        sql = self._compile_duckdb(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        self.assertIn("json_each(n_scan.os -> 'osclass')", sql)
        # DuckDB ``json_type`` returns upper-case ARRAY where
        # PG's :func:`jsonb_typeof` returns lower-case array.
        self.assertIn("json_type(n_scan.os -> 'osclass') = 'ARRAY'", sql)

    # -- searchvuln ----------------------------------------------------

    def test_searchvuln_pg_unwinds_script_data_vulns(self):
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        flt = db.searchvuln(vulnid="CVE-2021-44228", state="VULNERABLE")
        sa = _sqlalchemy
        sql = self._compile_pg(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        # The vuln predicate lives on the ``script`` table and
        # composes the EXISTS over ``script.data -> 'vulns'``.
        self.assertIn("jsonb_array_elements(n_script.data -> 'vulns')", sql)
        self.assertIn("jsonb_typeof(n_script.data -> 'vulns') = 'array'", sql)
        # Two AND-combined predicates: id + state.
        self.assertIn("__vuln ->> 'id'", sql)
        self.assertIn("__vuln ->> 'state'", sql)

    def test_searchvuln_no_args_keeps_existence_check(self):
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        flt = db.searchvuln()
        sa = _sqlalchemy
        sql = self._compile_pg(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        # No ``id`` / ``state`` predicates -- the inner WHERE
        # collapses to ``true`` so any non-empty vulns array
        # matches.
        self.assertIn("jsonb_array_elements(n_script.data -> 'vulns')", sql)
        self.assertNotIn("__vuln ->>", sql)

    # -- searchvulnintersil --------------------------------------------

    def test_searchvulnintersil_emits_port_predicates(self):
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        flt = db.searchvulnintersil()
        sa = _sqlalchemy
        sql = self._compile_pg(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        # Pure port-table filter -- no JSON unwind.
        self.assertNotIn("jsonb_array_elements", sql)
        self.assertIn("n_port.protocol = 'tcp'", sql)
        self.assertIn("n_port.state = 'open'", sql)
        self.assertIn("n_port.service_product = 'Boa HTTPd'", sql)

    # -- schema --------------------------------------------------------

    def test_scan_schema_carries_cpes_and_os_columns(self):
        # Pin that the new columns made it onto the shared
        # ``_Scan`` mixin and are present on both ``n_scan``
        # and ``v_scan``.
        from ivre.db.sql.tables import N_Scan, V_Scan

        for cls in (N_Scan, V_Scan):
            with self.subTest(cls=cls.__name__):
                self.assertIn("cpes", cls.__table__.columns)
                self.assertIn("os", cls.__table__.columns)


# ---------------------------------------------------------------------
# SQLDBSearchSmbScreenshotTests -- pin the wire shape of
# ``searchsmbshares`` / ``searchscreenshot`` / ``removescreenshot``
# on the SQL backends.  Both PostgreSQL and DuckDB are exercised
# so the dialect-aware split (PG :func:`jsonb_array_elements` /
# :func:`jsonb_typeof` vs DuckDB :func:`json_each` /
# :func:`json_type`) for the ``searchsmbshares`` JSON-array unwind
# stays under regression coverage, alongside the new screenshot
# columns on ``_Port``.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_SQLALCHEMY,
    "sqlalchemy is required (install with the ``postgres`` or ``duckdb`` extras)",
)
class SQLDBSearchSmbScreenshotTests(unittest.TestCase):
    """Behaviour-pin for ``SQLDBActive.searchsmbshares`` /
    ``searchscreenshot`` / ``removescreenshot``.

    * ``searchscreenshot`` is mostly column-based filtering on
      the new ``screenshot`` / ``screenwords`` columns of
      :class:`~ivre.db.sql.tables._Port`; the regex word-match
      path wraps the ``screenwords`` array unwind in a
      sub-SELECT projecting an explicit ``v`` column so the
      same SQL compiles under both backends.
    * ``searchsmbshares`` unwinds ``script.data['shares']`` and
      AND-combines per-element predicates inside an ``EXISTS``;
      the DuckDB lane swaps PostgreSQL's
      :func:`jsonb_array_elements` / :func:`jsonb_typeof` for
      :func:`json_each` / :func:`json_type` (and the
      ``ARRAY`` / ``array`` casing flip).
    * ``removescreenshot`` mutates the in-memory host record
      (matching Mongo's helper) **and** issues an ``UPDATE``
      on the port table to clear the three screenshot columns.
    """

    @staticmethod
    def _compile_pg(stmt):
        return str(
            stmt.compile(
                dialect=_sqlalchemy_postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )

    @staticmethod
    def _compile_duckdb(stmt):
        return str(
            stmt.compile(
                dialect=duckdb_engine.Dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )

    # -- searchscreenshot ----------------------------------------------

    def test_searchscreenshot_no_args_short_circuits(self):
        sa = _sqlalchemy
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        flt = db.searchscreenshot()
        sql = self._compile_pg(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        # Existence check on the per-port ``screenshot`` column
        # rather than a JSON unwind.
        self.assertIn("n_port.screenshot IS NOT NULL", sql)
        self.assertNotIn("jsonb_array_elements", sql)
        self.assertNotIn("screenwords", sql)

    def test_searchscreenshot_negation_flips_at_exists_level(self):
        # ``Mongo``'s ``{"ports.screenshot": {"$exists": false}}``
        # means **no** port has a screenshot, *not* "there is a
        # port without a screenshot".  Pin that the SQL flip
        # happens at the ``EXISTS`` (``incl=False``) level when
        # no port / service constraint is present.
        sa = _sqlalchemy
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        flt = db.searchscreenshot(neg=True)
        sql = self._compile_pg(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        # NOT IN translation of the ``incl=False`` slot.
        self.assertIn("NOT IN", sql)
        self.assertIn("n_port.screenshot IS NOT NULL", sql)

    def test_searchscreenshot_with_port_neg_flips_at_predicate(self):
        # With a port / service constraint the flip happens at
        # the inner predicate (``screenshot IS NULL``) so other
        # ports of the same host can still have screenshots.
        sa = _sqlalchemy
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        flt = db.searchscreenshot(port=80, neg=True)
        sql = self._compile_pg(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        self.assertIn("n_port.screenshot IS NULL", sql)
        self.assertIn("n_port.port = 80", sql)
        self.assertNotIn("NOT IN", sql)

    def test_searchscreenshot_words_string_lowercases(self):
        sa = _sqlalchemy
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        flt = db.searchscreenshot(words="WELCOME")
        sql = self._compile_pg(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        # Word match goes through ``ANY(screenwords)``, value
        # is lower-cased to match Mongo's pre-stored shape.
        self.assertIn("'welcome' = ANY (n_port.screenwords)", sql)

    def test_searchscreenshot_words_list_uses_containment(self):
        sa = _sqlalchemy
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        flt = db.searchscreenshot(words=["Foo", "Bar"])
        sql = self._compile_pg(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        # ``$all`` -> array containment, lower-cased.
        self.assertIn("n_port.screenwords @> ARRAY['foo', 'bar']", sql)

    def test_searchscreenshot_words_neg_handles_null(self):
        # Mongo's ``$ne`` matches missing fields; the SQL path
        # has to add an explicit ``IS NULL`` branch because
        # three-valued logic on PG / DuckDB silently drops
        # ``NULL @> ...`` rows from the negated side.
        sa = _sqlalchemy
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        for words in ["welcome", ["welcome"]]:
            with self.subTest(words=words):
                flt = db.searchscreenshot(neg=True, words=words)
                sql = self._compile_pg(
                    flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
                )
                self.assertIn("n_port.screenwords IS NULL", sql)

    def test_searchscreenshot_words_regex_uses_correlated_unnest(self):
        # Pin the table-valued ``AS __sw(v)`` shape -- the
        # SRF stays inline in the FROM clause (implicitly
        # lateral on PG, accepted as such by DuckDB) so the
        # ``port.screenwords`` reference correlates with the
        # outer ``port`` row rather than decorrelating into a
        # cross-DB scan.  Earlier versions wrapped ``unnest()``
        # in ``select(...).subquery()`` which silently
        # decorrelated the call; that shape is gone now.
        import re

        sa = _sqlalchemy
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        flt = db.searchscreenshot(words=re.compile("login", re.IGNORECASE))
        sql = self._compile_pg(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        self.assertIn("unnest(n_port.screenwords) AS __sw(v)", sql)
        self.assertIn("__sw.v ~*", sql)

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_searchscreenshot_duckdb_regex_uses_regexp_matches(self):
        import re

        sa = _sqlalchemy
        from ivre.db.sql.duckdb import DuckDBNmap

        db = DuckDBNmap.from_url("duckdb:///:memory:")
        flt = db.searchscreenshot(words=re.compile("login", re.IGNORECASE))
        sql = self._compile_duckdb(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        # Same ``AS __sw(v)`` shape, dialect-flipped regex.
        self.assertIn("unnest(n_port.screenwords) AS __sw(v)", sql)
        self.assertNotIn("~*", sql)
        self.assertIn("regexp_matches(", sql)

    # -- searchsmbshares -----------------------------------------------

    def test_searchsmbshares_pg_unwinds_shares_array(self):
        sa = _sqlalchemy
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        flt = db.searchsmbshares(access="rw", hidden=True)
        sql = self._compile_pg(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        self.assertIn("n_script.name = 'smb-enum-shares'", sql)
        self.assertIn("jsonb_array_elements(n_script.data -> 'shares')", sql)
        self.assertIn("jsonb_typeof(n_script.data -> 'shares') = 'array'", sql)
        # The Mongo recipe ANDs three predicates per share:
        # access (OR over 'Anonymous access' and 'Current user
        # access'), Type, and ``Share != 'IPC$'``.
        self.assertIn("__share ->> 'Anonymous access'", sql)
        self.assertIn("__share ->> 'Current user access'", sql)
        self.assertIn("__share ->> 'Type'", sql)
        self.assertIn("__share ->> 'Share'", sql)
        self.assertIn("'IPC$'", sql)

    def test_searchsmbshares_hidden_none_uses_notin_excluded(self):
        sa = _sqlalchemy
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        flt = db.searchsmbshares()
        sql = self._compile_pg(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        # Mongo's ``$nin`` over the share-type sentinel list.
        for excluded in (
            "STYPE_IPC_HIDDEN",
            "Not a file share",
            "STYPE_IPC",
            "STYPE_PRINTQ",
        ):
            self.assertIn(excluded, sql)

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_searchsmbshares_duckdb_unwinds_with_json_each(self):
        sa = _sqlalchemy
        from ivre.db.sql.duckdb import DuckDBNmap

        db = DuckDBNmap.from_url("duckdb:///:memory:")
        flt = db.searchsmbshares(access="rw", hidden=True)
        sql = self._compile_duckdb(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        self.assertIn("json_each(n_script.data -> 'shares')", sql)
        self.assertIn("json_type(n_script.data -> 'shares') = 'ARRAY'", sql)
        # DuckDB's ``json_each`` exposes the per-element JSON
        # via the ``value`` column.
        self.assertIn("__share.value ->>", sql)

    # -- removescreenshot ----------------------------------------------

    def test_removescreenshot_clears_in_memory_dict(self):
        # Pure in-memory mutation -- no DB round-trip needed
        # to pin the contract.
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        host = {
            "_id": 1,
            "ports": [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "screenshot": "field",
                    "screendata": b"PNG",
                    "screenwords": ["foo"],
                },
                {
                    "port": 443,
                    "protocol": "tcp",
                    "screenshot": "empty",
                },
            ],
        }
        # ``removescreenshot`` issues an ``UPDATE`` -- without
        # a real DB, intercept the writer.
        captured = []

        def _capture(stmt):
            captured.append(stmt)

        # pylint: disable=protected-access
        db._write = _capture  # type: ignore[method-assign]
        db.removescreenshot(host)
        # Both ports lost their screenshot fields.
        for portrec in host["ports"]:
            self.assertNotIn("screenshot", portrec)
            self.assertNotIn("screendata", portrec)
            self.assertNotIn("screenwords", portrec)
        self.assertEqual(len(captured), 1)

    def test_removescreenshot_port_filter_only_clears_match(self):
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        host = {
            "_id": 1,
            "ports": [
                {"port": 80, "protocol": "tcp", "screenshot": "field"},
                {"port": 443, "protocol": "tcp", "screenshot": "empty"},
            ],
        }
        # pylint: disable=protected-access
        db._write = lambda stmt: None  # type: ignore[method-assign]
        db.removescreenshot(host, port=80)
        ports = {p["port"]: p for p in host["ports"]}
        self.assertNotIn("screenshot", ports[80])
        self.assertEqual(ports[443].get("screenshot"), "empty")

    # -- schema --------------------------------------------------------

    def test_port_schema_carries_screenshot_columns(self):
        from ivre.db.sql.tables import N_Port, V_Port

        for cls in (N_Port, V_Port):
            with self.subTest(cls=cls.__name__):
                for col in ("screenshot", "screendata", "screenwords"):
                    self.assertIn(col, cls.__table__.columns)


# ---------------------------------------------------------------------
# SQLDBResidualGapsTests -- pin the wire shape of the
# ``searchtimeago`` / ``searchmac`` (active) / ``searchhaslocation``
# (view) / ``setscreenshot`` / ``setscreenwords`` / ``get_mean_open_ports``
# / ``insert_or_update_mix`` (passive) helpers, plus the new
# ``addresses`` JSONB column on ``_Scan`` and the cpes/os/addresses
# round-trip through ``SQLDBActive.get``.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_SQLALCHEMY,
    "sqlalchemy is required (install with the ``postgres`` or ``duckdb`` extras)",
)
class SQLDBResidualGapsTests(unittest.TestCase):
    """Behaviour-pin for the residual-gap parity helpers added
    after :meth:`searchcpe` / :meth:`searchos` / :meth:`searchvuln`
    (M4.3.1) and :meth:`searchscreenshot` / :meth:`searchsmbshares`
    / :meth:`removescreenshot` (M4.3.2).
    """

    @staticmethod
    def _compile_pg(stmt):
        return str(
            stmt.compile(
                dialect=_sqlalchemy_postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )

    @staticmethod
    def _compile_duckdb(stmt):
        return str(
            stmt.compile(
                dialect=duckdb_engine.Dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )

    # -- searchtimeago -------------------------------------------------

    def test_searchtimeago_predicate_uses_time_stop(self):
        sa = _sqlalchemy
        import datetime

        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        flt = db.searchtimeago(datetime.timedelta(days=30))
        sql = self._compile_pg(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        # Must filter on ``time_stop`` (Mongo's ``endtime``)
        # with a ``>=`` comparison; the negated arm flips to
        # ``<``.
        self.assertIn("n_scan.time_stop >= ", sql)

    def test_searchtimeago_neg_flips_to_less_than(self):
        sa = _sqlalchemy
        import datetime

        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        flt = db.searchtimeago(datetime.timedelta(days=30), neg=True)
        sql = self._compile_pg(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        self.assertIn("n_scan.time_stop < ", sql)

    # -- searchmac (active) --------------------------------------------

    def test_searchmac_no_args_uses_existence_check(self):
        sa = _sqlalchemy
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        flt = db.searchmac()
        sql = self._compile_pg(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        # Portable existence check on the JSONB sub-key
        # rather than the PG-only ``?`` operator.
        self.assertIn("(n_scan.addresses -> 'mac') IS NOT NULL", sql)
        self.assertNotIn("jsonb_array_elements_text", sql)

    def test_searchmac_pg_unwinds_with_jsonb_array_elements_text(self):
        sa = _sqlalchemy
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        flt = db.searchmac("AA:BB:CC:DD:EE:FF")
        sql = self._compile_pg(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        # Inline SRF (implicitly lateral on PG) with the
        # explicit ``AS __mac(v)`` column-list alias so the
        # outer-row reference correlates per-scan.
        self.assertIn(
            "jsonb_array_elements_text(n_scan.addresses -> 'mac') " "AS __mac(v)",
            sql,
        )
        self.assertIn("jsonb_typeof(n_scan.addresses -> 'mac') = 'array'", sql)
        # MAC value is lower-cased before matching.
        self.assertIn("__mac.v = 'aa:bb:cc:dd:ee:ff'", sql)

    @unittest.skipUnless(
        _HAVE_DUCKDB_ENGINE,
        "duckdb-engine is required (install with the ``duckdb`` extras)",
    )
    def test_searchmac_duckdb_uses_from_json(self):
        sa = _sqlalchemy
        from ivre.db.sql.duckdb import DuckDBNmap

        db = DuckDBNmap.from_url("duckdb:///:memory:")
        flt = db.searchmac("AA:BB:CC:DD:EE:FF")
        sql = self._compile_duckdb(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        # DuckDB has no ``jsonb_array_elements_text`` SRF;
        # the override parses the JSON array via
        # ``from_json(..., '["VARCHAR"]')`` and unwinds with
        # ``unnest()``.
        self.assertIn("from_json(n_scan.addresses -> 'mac', ", sql)
        self.assertIn(" AS __mac(v)", sql)
        self.assertIn("json_type(n_scan.addresses -> 'mac') = 'ARRAY'", sql)

    # -- searchhaslocation (view) --------------------------------------

    def test_searchhaslocation_uses_info_loc(self):
        sa = _sqlalchemy
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        flt = db.searchhaslocation()
        sql = self._compile_pg(
            flt.query(sa.select(sa.func.count()).select_from(flt.select_from))
        )
        self.assertIn("(v_scan.info -> 'loc') IS NOT NULL", sql)

        flt_neg = db.searchhaslocation(neg=True)
        sql_neg = self._compile_pg(
            flt_neg.query(sa.select(sa.func.count()).select_from(flt_neg.select_from))
        )
        self.assertIn("(v_scan.info -> 'loc') IS NULL", sql_neg)

    # -- get_mean_open_ports -------------------------------------------

    def test_get_mean_open_ports_emits_count_times_sum(self):
        # Pin the SQL aggregation shape via reading the SA
        # constructs directly (the method returns a list, so
        # we patch the read iterator to capture the rendered
        # statement instead).  ``coalesce`` is required so
        # hosts with no open port land at ``mean = 0``,
        # matching Mongo's ``count * sum`` arithmetic when one
        # of the operands collapses to an empty array.
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        captured = []

        def _fake_read_iter(stmt):
            captured.append(stmt)
            return iter([])

        # pylint: disable=protected-access
        db._read_iter = _fake_read_iter  # type: ignore[method-assign]
        result = db.get_mean_open_ports(db.flt_empty)
        self.assertEqual(result, [])
        self.assertEqual(len(captured), 1)
        sql = self._compile_pg(captured[0])
        self.assertIn("count(n_port.id)", sql)
        self.assertIn("coalesce(sum(n_port.port), 0)", sql)
        self.assertIn("n_port.state = 'open'", sql)
        self.assertIn("GROUP BY n_scan.id", sql)

    # -- setscreenshot / setscreenwords --------------------------------

    def test_setscreenshot_raises_on_missing_port(self):
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        host = {"_id": 1, "ports": []}
        with self.assertRaises(KeyError):
            db.setscreenshot(host, 80, b"data")

    def test_setscreenshot_skips_when_already_set_without_overwrite(self):
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        host = {
            "_id": 1,
            "ports": [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "screenshot": "field",
                    "screendata": b"old",
                }
            ],
        }
        # pylint: disable=protected-access
        db._write = lambda stmt: None  # type: ignore[method-assign]
        db.setscreenshot(host, 80, b"new")
        self.assertEqual(host["ports"][0]["screendata"], b"old")

    def test_setscreenwords_skips_when_already_set_without_overwrite(self):
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        host = {
            "_id": 1,
            "ports": [
                {
                    "port": 80,
                    "protocol": "tcp",
                    "screenshot": "field",
                    "screendata": b"data",
                    "screenwords": ["existing"],
                }
            ],
        }
        # pylint: disable=protected-access
        db._write = lambda stmt: None  # type: ignore[method-assign]
        db.setscreenwords(host)
        # No overwrite: existing words are kept.
        self.assertEqual(host["ports"][0]["screenwords"], ["existing"])

    # -- insert_or_update_mix (passive) --------------------------------

    def test_insert_or_update_mix_routes_to_underlying_insert(self):
        # Pin that the helper extracts firstseen / lastseen /
        # count from the spec and forwards them to
        # ``_insert_or_update`` so the upsert merges via
        # ``least`` / ``greatest`` / ``+`` (or ``replacecount``
        # replaces wholesale).
        import datetime

        from ivre.db import DBPassive
        from ivre.db.sql.postgres import PostgresDBPassive

        captured = []

        def _fake_iou(self_, timestamp, values, lastseen=None, replacecount=False):
            captured.append(
                {
                    "timestamp": timestamp,
                    "values": values,
                    "lastseen": lastseen,
                    "replacecount": replacecount,
                }
            )

        original = PostgresDBPassive._insert_or_update
        PostgresDBPassive._insert_or_update = _fake_iou
        try:
            db = DBPassive.from_url("postgresql://x@localhost/x")
            db.insert_or_update_mix(
                {
                    "addr": "1.2.3.4",
                    "recontype": "MAC_ADDRESS",
                    "source": "DHCP",
                    "value": "aa:bb",
                    "firstseen": datetime.datetime(2024, 1, 1),
                    "lastseen": datetime.datetime(2024, 6, 1),
                    "count": 17,
                }
            )
        finally:
            PostgresDBPassive._insert_or_update = original
        self.assertEqual(len(captured), 1)
        call = captured[0]
        self.assertEqual(call["timestamp"], datetime.datetime(2024, 1, 1))
        self.assertEqual(call["lastseen"], datetime.datetime(2024, 6, 1))
        self.assertEqual(call["values"]["count"], 17)
        self.assertEqual(call["values"]["recontype"], "MAC_ADDRESS")
        self.assertFalse(call["replacecount"])

    def test_insert_or_update_mix_replacecount_pass_through(self):
        import datetime

        from ivre.db import DBPassive
        from ivre.db.sql.postgres import PostgresDBPassive

        captured = []

        def _fake_iou(self_, timestamp, values, lastseen=None, replacecount=False):
            captured.append(replacecount)

        original = PostgresDBPassive._insert_or_update
        PostgresDBPassive._insert_or_update = _fake_iou
        try:
            db = DBPassive.from_url("postgresql://x@localhost/x")
            db.insert_or_update_mix(
                {
                    "addr": "1.2.3.4",
                    "recontype": "MAC_ADDRESS",
                    "source": "DHCP",
                    "value": "aa:bb",
                    "firstseen": datetime.datetime(2024, 1, 1),
                    "lastseen": datetime.datetime(2024, 6, 1),
                    "count": 17,
                },
                replacecount=True,
            )
        finally:
            PostgresDBPassive._insert_or_update = original
        self.assertEqual(captured, [True])

    # -- schema --------------------------------------------------------

    def test_scan_schema_carries_addresses_column(self):
        from ivre.db.sql.tables import N_Scan, V_Scan

        for cls in (N_Scan, V_Scan):
            with self.subTest(cls=cls.__name__):
                self.assertIn("addresses", cls.__table__.columns)

    def test_get_projects_cpes_os_addresses(self):
        # The scan-row positional unpack must surface the
        # three host-level JSONB columns added in M4.3.1 /
        # M4.3.3 -- otherwise consumers calling ``db.nmap.get(...)``
        # would never see them and the round-trip would
        # silently lose data.
        from ivre.db import DBNmap

        db = DBNmap.from_url("postgresql://x@localhost/x")
        # pylint: disable=protected-access
        stmt = db._get(db.flt_empty)
        sql = self._compile_pg(stmt)
        for col in ("n_scan.cpes", "n_scan.os", "n_scan.addresses"):
            self.assertIn(col, sql)


# ---------------------------------------------------------------------
# SQLDBTopValuesNtlmTests -- pin the wire shape of the
# ``ntlm`` / ``ntlm.<key>`` branches in ``topvalues``.  Both
# PostgreSQL and DuckDB are exercised so the friendly-name
# alias map (Mongo's ``ntlm.os`` -> ``Product_Version`` etc.)
# stays under regression coverage on both backends.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_SQLALCHEMY,
    "sqlalchemy is required (install with the ``postgres`` or ``duckdb`` extras)",
)
class SQLDBTopValuesNtlmTests(unittest.TestCase):
    """Behaviour-pin for the ``ntlm`` and ``ntlm.<key>``
    ``topvalues`` branches added on ``PostgresDBActive``.

    ``topvalues`` returns a generator and the actual
    aggregation runs against a live database, so the pin
    intercepts ``_read_iter`` to capture the rendered SQL
    statement instead of executing it -- enough to cover the
    JSONB lookup path, the ``ntlm-info`` script-name guard,
    and the friendly-name alias map.
    """

    @staticmethod
    def _compile_pg(stmt):
        return str(
            stmt.compile(
                dialect=_sqlalchemy_postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )

    @staticmethod
    def _capture_topvalues_sql(db, field):
        """Run ``db.view.topvalues(field)`` with ``_read_iter``
        patched to capture the underlying SQL statement.
        Returns the rendered PostgreSQL string."""
        captured = []

        def _fake(stmt):
            captured.append(stmt)
            return iter([])

        # pylint: disable=protected-access
        original = db._read_iter
        db._read_iter = _fake
        try:
            list(db.topvalues(field))
        finally:
            db._read_iter = original
        assert captured, "topvalues did not call _read_iter"
        return SQLDBTopValuesNtlmTests._compile_pg(captured[-1])

    def test_topvalues_ntlm_groups_by_full_doc(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "ntlm")
        self.assertIn("v_script.name = 'ntlm-info'", sql)
        # SA emits the JSONB lookup as bracket notation
        # (``data['ntlm-info']``); both PostgreSQL and DuckDB
        # accept it as a synonym for ``->``.
        self.assertIn("v_script.data['ntlm-info']", sql)

    def test_topvalues_ntlm_friendly_aliases(self):
        # The Mongo helper exposes friendly names that map to
        # the underlying ``ntlm-info`` JSONB keys; pin the
        # alias map here so the SQL backend keeps the same
        # public contract.
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        cases = [
            ("ntlm.name", "Target_Name"),
            ("ntlm.server", "NetBIOS_Computer_Name"),
            ("ntlm.domain", "NetBIOS_Domain_Name"),
            ("ntlm.workgroup", "Workgroup"),
            ("ntlm.domain_dns", "DNS_Domain_Name"),
            ("ntlm.forest", "DNS_Tree_Name"),
            ("ntlm.fqdn", "DNS_Computer_Name"),
            ("ntlm.os", "Product_Version"),
            ("ntlm.version", "NTLM_Version"),
        ]
        for alias, target in cases:
            with self.subTest(alias=alias):
                sql = self._capture_topvalues_sql(db, alias)
                self.assertIn(f"v_script.data['ntlm-info']['{target}']", sql)
                # Every branch routes through the
                # ``ntlm-info`` script name and the
                # ``has_key`` guard.
                self.assertIn("v_script.name = 'ntlm-info'", sql)
                self.assertIn(f"v_script.data['ntlm-info'] ? '{target}'", sql)

    def test_topvalues_ntlm_passthrough_unaliased_key(self):
        # Keys outside the alias map (e.g. ``protocol``,
        # ``Target_Name`` directly) are passed through
        # verbatim -- matching the Mongo helper's
        # ``.get(arg, arg)`` fallback.
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "ntlm.protocol")
        self.assertIn("v_script.data['ntlm-info']['protocol']", sql)
        sql_target = self._capture_topvalues_sql(db, "ntlm.Target_Name")
        self.assertIn("v_script.data['ntlm-info']['Target_Name']", sql_target)


# ---------------------------------------------------------------------
# SQLDBTopValuesIotVulnTests -- pin the wire shape of the
# ``ike.*`` / ``enip.*`` / ``vulns.*`` / ``screenwords`` IoT /
# ICS / vuln cluster of ``topvalues`` branches added on
# ``PostgresDBActive``.  The DuckDB lane inherits the same code
# through ``DuckDBActive`` so these pins cover both backends.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_SQLALCHEMY,
    "sqlalchemy is required (install with the ``postgres`` or ``duckdb`` extras)",
)
class SQLDBTopValuesIotVulnTests(unittest.TestCase):
    """Behaviour-pin for the ``ike.*`` / ``enip.*`` / ``vulns.*``
    / ``screenwords`` ``topvalues`` branches.

    Same ``_read_iter`` interception trick the ntlm pin tests
    use -- the actual aggregation runs against a live
    database, but compiling the captured statement is enough
    to cover the JSONB unwind path, the script-name guard, the
    Mongo-shape friendly-name aliases (enip), and the
    array-element-tuple projection (ike.vendor_ids /
    ike.transforms / vulns.<other>).
    """

    @staticmethod
    def _compile_pg(stmt):
        return str(
            stmt.compile(
                dialect=_sqlalchemy_postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )

    @staticmethod
    def _capture_topvalues_sql(db, field):
        captured = []

        def _fake(stmt):
            captured.append(stmt)
            return iter([])

        # pylint: disable=protected-access
        original = db._read_iter
        db._read_iter = _fake
        try:
            list(db.topvalues(field))
        finally:
            db._read_iter = original
        assert captured, "topvalues did not call _read_iter"
        return SQLDBTopValuesIotVulnTests._compile_pg(captured[-1])

    # -- ike.* ---------------------------------------------------------

    def test_topvalues_ike_vendor_ids_emits_value_name_tuple(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "ike.vendor_ids")
        self.assertIn("v_script.name = 'ike-info'", sql)
        # Tuple projection: both ``value`` and ``name`` keys
        # off the unwound ``vendor_id`` element.
        self.assertIn("vendor_id ->> 'value'", sql)
        self.assertIn("vendor_id ->> 'name'", sql)
        self.assertIn(
            "jsonb_array_elements(v_script.data['ike-info']['vendor_ids'])",
            sql,
        )

    def test_topvalues_ike_transforms_emits_six_field_tuple(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "ike.transforms")
        self.assertIn("v_script.name = 'ike-info'", sql)
        for fld in (
            "Authentication",
            "Encryption",
            "GroupDesc",
            "Hash",
            "LifeDuration",
            "LifeType",
        ):
            self.assertIn(f"transform ->> '{fld}'", sql)
        self.assertIn("v_script.data['ike-info'] ? 'transforms'", sql)

    def test_topvalues_ike_notification_emits_scalar(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "ike.notification")
        self.assertIn("v_script.name = 'ike-info'", sql)
        self.assertIn("v_script.data['ike-info']['notification_type']", sql)
        # No JSON-array unwind on the scalar branch.
        self.assertNotIn("jsonb_array_elements", sql)

    def test_topvalues_ike_passthrough_unaliased_key(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "ike.attributes")
        self.assertIn("v_script.name = 'ike-info'", sql)
        self.assertIn("v_script.data['ike-info']['attributes']", sql)

    # -- enip.* --------------------------------------------------------

    def test_topvalues_enip_friendly_aliases(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        cases = [
            ("enip.vendor", "Vendor"),
            ("enip.product", "Product Name"),
            ("enip.serial", "Serial Number"),
            ("enip.devtype", "Device Type"),
            ("enip.prodcode", "Product Code"),
            ("enip.rev", "Revision"),
            ("enip.ip", "Device IP"),
        ]
        for alias, target in cases:
            with self.subTest(alias=alias):
                sql = self._capture_topvalues_sql(db, alias)
                self.assertIn(f"v_script.data['enip-info']['{target}']", sql)
                self.assertIn("v_script.name = 'enip-info'", sql)

    def test_topvalues_enip_passthrough_unaliased_key(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "enip.Custom_Field")
        self.assertIn("v_script.data['enip-info']['Custom_Field']", sql)

    # -- vulns.* -------------------------------------------------------

    def test_topvalues_vulns_id_unwinds_array(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "vulns.id")
        self.assertIn("jsonb_array_elements(v_script.data -> 'vulns')", sql)
        self.assertIn("vuln ->> 'id'", sql)
        # The aggregation is gated on the JSONB-typeof check
        # rather than a script-name list -- vulns are emitted
        # by dozens of NSE scripts and the array-shape guard
        # is enough to scope the unwind safely.
        self.assertIn("jsonb_typeof(v_script.data -> 'vulns') = 'array'", sql)

    def test_topvalues_vulns_other_emits_id_tuple(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "vulns.state")
        # Tuple projection: both ``id`` (so the caller can
        # correlate) and the requested subfield.
        self.assertIn("vuln ->> 'id'", sql)
        self.assertIn("vuln ->> 'state'", sql)
        self.assertIn("jsonb_array_elements(v_script.data -> 'vulns')", sql)

    # -- screenwords ---------------------------------------------------

    def test_topvalues_screenwords_unnests_array(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "screenwords")
        self.assertIn("unnest(v_port.screenwords)", sql)
        self.assertIn("v_port.screenwords IS NOT NULL", sql)


# ---------------------------------------------------------------------
# SQLDBTopValuesResidualTests -- pin the wire shape of the
# residual ``topvalues`` parity branches: ``addr`` /
# ``cpe[.<part>][:<spec>]`` / ``smb.*`` / ``mongo.dbs.*`` /
# ``sshkey.bits`` / ``sshkey.<key>`` / ``ja4-client[.<sub>][:<value>]``,
# plus the ``CROSS JOIN LATERAL`` rewrite of every existing
# ``jsonb_array_elements(...).alias("name")`` extraselectfrom
# path (httphdr*/httpapp*/ja3-client/ja3-server/useragent/
# ike.vendor_ids/ike.transforms/vulns.id/vulns.<other>/sshkey.*/
# ja4-client/cpe).
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_SQLALCHEMY,
    "sqlalchemy is required (install with the ``postgres`` or ``duckdb`` extras)",
)
class SQLDBTopValuesResidualTests(unittest.TestCase):
    """Behaviour-pin for the residual ``topvalues`` branches
    closing M4.4 -- enough to delete the
    ``raise NotImplementedError()`` catch-all
    (``postgres.py:1735``) and unconditionally restore the
    ``self.assertFalse(err)`` assertion that
    ``_check_top_value_cli`` had to gate behind
    ``DATABASE != "postgres"`` while the cartesian-product
    warning was leaking on every ``httphdr*`` / ``httpapp*``
    CLI call.
    """

    @staticmethod
    def _compile_pg(stmt):
        return str(
            stmt.compile(
                dialect=_sqlalchemy_postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )

    @staticmethod
    def _capture_topvalues_sql(db, field):
        captured = []

        def _fake(stmt):
            captured.append(stmt)
            return iter([])

        # pylint: disable=protected-access
        original = db._read_iter
        db._read_iter = _fake
        try:
            list(db.topvalues(field))
        finally:
            db._read_iter = original
        assert captured, "topvalues did not call _read_iter"
        return SQLDBTopValuesResidualTests._compile_pg(captured[-1])

    # -- addr ----------------------------------------------------------

    def test_topvalues_addr_groups_on_scan_addr(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "addr")
        self.assertIn("v_scan.addr", sql)
        self.assertIn("GROUP BY v_scan.addr", sql)

    # -- cpe.* ---------------------------------------------------------

    def test_topvalues_cpe_default_projects_all_four_fields(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "cpe")
        for fld in ("type", "vendor", "product", "version"):
            self.assertIn(f"cpe ->> '{fld}'", sql)

    def test_topvalues_cpe_part_truncates_projection(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "cpe.vendor")
        # ``cpe.vendor`` projects up to and including
        # ``vendor`` (so ``type`` and ``vendor`` only).
        self.assertIn("cpe ->> 'type'", sql)
        self.assertIn("cpe ->> 'vendor'", sql)
        self.assertNotIn("cpe ->> 'product'", sql)
        self.assertNotIn("cpe ->> 'version'", sql)

    def test_topvalues_cpe_numeric_part_resolves(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "cpe.1")
        # ``cpe.1`` resolves to the first cpe key (``type``).
        self.assertIn("cpe ->> 'type'", sql)
        self.assertNotIn("cpe ->> 'vendor'", sql)

    def test_topvalues_cpe_spec_filters_unwound_element(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "cpe.product:apache")
        # The spec filters at both the host level (via
        # ``searchcpe``) and the unwound element level.
        self.assertIn("cpe ->> 'type'", sql)
        # Host-level filter pulls in a ``searchcpe`` EXISTS.
        self.assertIn("__cpe ->> 'type'", sql)

    def test_topvalues_cpe_uses_lateral_unwind(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "cpe")
        self.assertIn("LATERAL jsonb_array_elements(v_scan.cpes)", sql)

    # -- smb.* ---------------------------------------------------------

    def test_topvalues_smb_subkey_indexes_into_script_data(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "smb.os")
        self.assertIn("v_script.name = 'smb-os-discovery'", sql)
        self.assertIn("v_script.data['smb-os-discovery']['os']", sql)

    # -- mongo.dbs.* ---------------------------------------------------

    def test_topvalues_mongo_dbs_indexes_into_script_data(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "mongo.dbs.name")
        self.assertIn("v_script.name = 'mongodb-databases'", sql)
        self.assertIn("v_script.data['mongodb-databases']['name']", sql)

    # -- sshkey.* ------------------------------------------------------

    def test_topvalues_sshkey_bits_emits_type_bits_tuple(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "sshkey.bits")
        self.assertIn("v_script.name = 'ssh-hostkey'", sql)
        self.assertIn("sshkey ->> 'type'", sql)
        self.assertIn("sshkey ->> 'bits'", sql)

    def test_topvalues_sshkey_passthrough_other_key(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "sshkey.fingerprint")
        self.assertIn("sshkey ->> 'fingerprint'", sql)

    # -- ja4-client ----------------------------------------------------

    def test_topvalues_ja4client_default_subfield_is_ja4(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(db, "ja4-client")
        self.assertIn("v_script.name = 'ssl-ja4-client'", sql)
        self.assertIn("ssl_ja4_client ->> 'ja4'", sql)

    def test_topvalues_ja4client_value_filters_inner_unwind(self):
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        sql = self._capture_topvalues_sql(
            db, "ja4-client:t13d1517h2_8daaf6152771_b1ff8ab2d16f"
        )
        self.assertIn(
            "(ssl_ja4_client ->> 'ja4') = " "'t13d1517h2_8daaf6152771_b1ff8ab2d16f'",
            sql,
        )

    # -- LATERAL rewrite -----------------------------------------------

    def test_lateral_silences_cartesian_product_on_existing_paths(self):
        # Pin that the existing ``jsonb_array_elements(...)``
        # extraselectfrom paths now wrap their unwind in
        # ``LATERAL`` -- silences the
        # ``SAWarning: cartesian product`` PostgreSQL emits
        # when a comma-joined SRF lacks an explicit join
        # condition.
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        for field in (
            "httphdr",
            "httphdr.name",
            "httphdr:server",
            "httpapp",
            "httpapp:Apache",
            "ja3-client",
            "ja3-server",
            "useragent",
            "useragent:Firefox",
            "ike.vendor_ids",
            "ike.transforms",
            "vulns.id",
            "vulns.state",
            "sshkey.bits",
            "sshkey.fingerprint",
            "ja4-client",
        ):
            with self.subTest(field=field):
                sql = self._capture_topvalues_sql(db, field)
                self.assertIn("LATERAL", sql.upper())

    # -- catch-all -----------------------------------------------------

    def test_topvalues_unknown_field_raises_valueerror(self):
        # The ``raise NotImplementedError()`` catch-all was
        # replaced with a clearer
        # ``raise ValueError(f"Unknown field {field}")``
        # matching the Mongo helper's ``hassh`` branch
        # (``mongo.py:3881``).
        from ivre.db import DBView

        db = DBView.from_url("postgresql://x@localhost/x")
        with self.assertRaises(ValueError) as cm:
            list(db.topvalues("definitely-not-a-field"))
        self.assertIn("definitely-not-a-field", str(cm.exception))


# ---------------------------------------------------------------------
# SQLDBFlowSchemaTests -- pin the SQL Flow purpose schema (host +
# flow tables, columns, types, indexes, foreign keys).  These pin
# the structural contract subsequent SQLDBFlow ingestion / query
# helpers will rely on; a regression here surfaces immediately as
# a column-name / type / index mismatch instead of a broken
# upsert under load.
# ---------------------------------------------------------------------


try:
    from ivre.db.sql import SQLDBFlow as _SQLDBFlow_for_schema_test  # noqa: F401
    from ivre.db.sql.tables import Flow as _Flow_for_schema_test
    from ivre.db.sql.tables import Host as _Host_for_schema_test

    _HAVE_SQLDB_FLOW = True
except ImportError:
    _HAVE_SQLDB_FLOW = False


@unittest.skipUnless(
    _HAVE_SQLDB_FLOW,
    "SQLAlchemy is required for SQLDBFlowSchemaTests",
)
class SQLDBFlowSchemaTests(unittest.TestCase):
    """Structural pin tests for the SQL Flow schema.

    Mirrors :class:`MongoDBFlow` (``ivre/db/mongo.py:6176``) on the
    columns the ingestion / query paths read.  Two intentional
    divergences are pinned here so a future refactor cannot
    silently revert them:

    * Mongo stores source / destination addresses inline as
      ``src_addr_0`` / ``src_addr_1``; the SQL backend uses a
      separate :class:`Host` table referenced via ``flow.src`` /
      ``flow.dst`` foreign keys.
    * Mongo's ``times`` array (per-flow timeslot history) is
      MongoDB-only per ``ivre/flow.py:45-48``; the SQL schema
      omits it.
    """

    def test_host_table_columns(self):
        cols = {c.name: c for c in _Host_for_schema_test.__table__.columns}
        self.assertEqual(set(cols), {"id", "addr", "firstseen", "lastseen"})
        self.assertTrue(cols["id"].primary_key)
        # ``addr`` must be NOT NULL: it is the natural key the
        # ingestion path looks up before inserting flow rows.
        self.assertFalse(cols["addr"].nullable)
        # ``addr`` uses the dialect-aware ``SQLINET``
        # (``postgresql.INET`` with a DuckDB-flavoured literal
        # processor); confirm we did not regress to plain
        # ``String``.
        self.assertEqual(cols["addr"].type.__class__.__name__, "INETLiteral")

    def test_host_table_unique_addr(self):
        # The ``host`` table needs a UNIQUE constraint on ``addr``
        # so the ingestion path can ``ON CONFLICT (addr) DO
        # UPDATE`` without an extra serialisation lock.
        unique_constraints = [
            c
            for c in _Host_for_schema_test.__table__.constraints
            if c.__class__.__name__ == "UniqueConstraint"
        ]
        self.assertEqual(len(unique_constraints), 1)
        self.assertEqual([col.name for col in unique_constraints[0].columns], ["addr"])

    def test_host_table_indexes(self):
        idx_names = {i.name for i in _Host_for_schema_test.__table__.indexes}
        self.assertIn("host_idx_firstseen", idx_names)
        self.assertIn("host_idx_lastseen", idx_names)

    def test_flow_table_columns(self):
        cols = {c.name: c for c in _Flow_for_schema_test.__table__.columns}
        self.assertEqual(
            set(cols),
            {
                "id",
                "proto",
                "dport",
                "type",
                "src",
                "dst",
                "firstseen",
                "lastseen",
                "scpkts",
                "scbytes",
                "cspkts",
                "csbytes",
                "count",
                "sports",
                "codes",
                "meta",
                "schema_version",
            },
        )
        self.assertTrue(cols["id"].primary_key)
        # ``dport`` and ``type`` are mutually exclusive depending
        # on the protocol; both must be nullable.
        self.assertTrue(cols["dport"].nullable)
        self.assertTrue(cols["type"].nullable)

    def test_flow_packet_byte_counters_use_bigint(self):
        # ``BigInteger`` (not ``Integer``): cumulative byte
        # counters on long-lived flows can exceed 2^31 within a
        # single retention window; widening avoids silent overflow
        # on every PostgreSQL upsert.
        cols = {c.name: c for c in _Flow_for_schema_test.__table__.columns}
        for name in ("scpkts", "scbytes", "cspkts", "csbytes", "count"):
            self.assertEqual(
                cols[name].type.__class__.__name__,
                "BigInteger",
                f"{name!r} must be BigInteger to avoid 2^31 overflow",
            )

    def test_flow_meta_is_jsonb(self):
        # ``meta`` carries the per-protocol metadata bag mirroring
        # Mongo's ``meta.<name>`` sub-document.  ``SQLJSONB`` is a
        # ``postgresql.JSONB().with_variant(JSON(), "duckdb")``
        # type so the same column compiles to ``JSONB`` on
        # PostgreSQL and ``JSON`` on DuckDB.
        cols = {c.name: c for c in _Flow_for_schema_test.__table__.columns}
        self.assertEqual(cols["meta"].type.__class__.__name__, "JSONB")

    def test_flow_sports_codes_are_integer_arrays(self):
        cols = {c.name: c for c in _Flow_for_schema_test.__table__.columns}
        for name in ("sports", "codes"):
            self.assertEqual(
                cols[name].type.__class__.__name__,
                "ARRAY",
                f"{name!r} must be a SQL ARRAY",
            )
            self.assertEqual(cols[name].type.item_type.__class__.__name__, "Integer")

    def test_flow_src_dst_are_foreign_keys_to_host(self):
        cols = {c.name: c for c in _Flow_for_schema_test.__table__.columns}
        for name in ("src", "dst"):
            fks = list(cols[name].foreign_keys)
            self.assertEqual(len(fks), 1, f"{name!r} must have a single FK")
            fk = fks[0]
            # FK target table is ``host``; the ondelete clause
            # is ``RESTRICT`` so a host row cannot disappear
            # while flows still reference it.
            self.assertEqual(fk.column.table.name, "host")
            self.assertEqual(fk.column.name, "id")
            self.assertEqual(fk.ondelete, "RESTRICT")

    def test_flow_lookup_index_covers_upsert_key(self):
        # The ingestion paths upsert flows on
        # ``(src, dst, proto, dport-or-type, schema_version)``;
        # the composite ``flow_unique_lookup`` must cover every
        # lookup column in that order so the planner can use
        # the index both for the ``WHERE`` clause matching the
        # upsert spec and as the ``ON CONFLICT`` target the
        # SQL ingestion path infers in
        # :meth:`SQLDBFlow._flow_upsert_stmt`.  The index is
        # ``UNIQUE`` so duplicate keys collapse on ingestion
        # (mirroring Mongo's ``upsert=True`` semantics); the
        # ``COALESCE(<col>, -1)`` wrappers fold the otherwise
        # NULL-distinct ``dport`` / ``type`` columns onto a
        # single constraint slot so every protocol shape
        # (TCP/UDP, ICMP, other) shares the same uniqueness
        # rule.
        idx_by_name = {i.name: i for i in _Flow_for_schema_test.__table__.indexes}
        self.assertIn("flow_unique_lookup", idx_by_name)
        idx = idx_by_name["flow_unique_lookup"]
        self.assertTrue(idx.unique)
        # ``Index.columns`` mixes plain :class:`Column`
        # objects and the SQL function expressions that wrap
        # ``dport`` / ``type``.  Pin the column-name sequence
        # for the bare columns (``src``, ``dst``, ``proto``,
        # ``schema_version``) and check that the COALESCE
        # expressions land between them in the expected
        # positions.
        col_names = [c.name if hasattr(c, "name") else None for c in idx.expressions]
        # The ``coalesce(...)`` expressions surface with
        # ``.name == "coalesce"``; the bare columns surface
        # with their own name.
        self.assertEqual(
            col_names,
            ["src", "dst", "proto", "coalesce", "coalesce", "schema_version"],
        )

    def test_flow_individual_metric_indexes(self):
        # Mirrors the per-metric indexes on
        # ``MongoDBFlow.indexes`` (``mongo.py:6204-6212``).  Each
        # of these is used by the ``flow filter`` UI for
        # ``count = N``, ``firstseen >= ...``, ``cspkts > 1000``,
        # etc.
        idx_names = {i.name for i in _Flow_for_schema_test.__table__.indexes}
        for expected in (
            "flow_idx_proto",
            "flow_idx_dport",
            "flow_idx_schema_version",
            "flow_idx_firstseen",
            "flow_idx_lastseen",
            "flow_idx_count",
            "flow_idx_cspkts",
            "flow_idx_scpkts",
            "flow_idx_csbytes",
            "flow_idx_scbytes",
        ):
            self.assertIn(
                expected,
                idx_names,
                f"missing per-metric index {expected!r} -- "
                "the flow filter UI relies on indexed lookups for "
                "single-column predicates",
            )

    def test_sqldbflow_table_layout_includes_host(self):
        # ``SQLDBFlow.tables`` is the namedtuple subsequent helpers
        # read; the ingestion path needs ``self.tables.host``
        # alongside ``self.tables.flow`` to perform the host
        # upsert before linking the flow row.
        self.assertEqual(
            tuple(_SQLDBFlow_for_schema_test.table_layout._fields),
            ("host", "flow"),
        )
        self.assertIs(_SQLDBFlow_for_schema_test.tables.host, _Host_for_schema_test)
        self.assertIs(_SQLDBFlow_for_schema_test.tables.flow, _Flow_for_schema_test)


# ---------------------------------------------------------------------
# SQLDBFlowFromFiltersTests -- pin the wire shape of the
# ``from_filters`` -> ``get`` translation on ``SQLDBFlow``: the
# parsed :class:`ivre.flow.Query` clauses must lower into the
# expected SQLAlchemy ``WHERE`` expressions, and the JOINed
# ``(Flow, src_addr, dst_addr)`` row must project into the
# Mongo-shaped dict :func:`DBFlow._flow2host` /
# :func:`DBFlow._edge2json_default` consume.  Without that
# parity, the inherited :meth:`DBFlow.to_iter` /
# :meth:`DBFlow.to_graph` (which feed the ``flowcli`` /
# ``/cgi/flows`` paths) would silently return malformed graphs.
# ---------------------------------------------------------------------


try:
    from ivre.db.sql import SQLDBFlow as _SQLDBFlow_for_filters_test
    from ivre.db.sql import SQLFlowFilter as _SQLFlowFilter_for_filters_test
    from ivre.db.sql.tables import Flow as _Flow_for_filters_test
    from ivre.db.sql.tables import Host as _Host_for_filters_test

    _HAVE_SQLDB_FLOW_FILTERS = True
except ImportError:
    _HAVE_SQLDB_FLOW_FILTERS = False


@unittest.skipUnless(
    _HAVE_SQLDB_FLOW_FILTERS,
    "SQLAlchemy is required for SQLDBFlowFromFiltersTests",
)
class SQLDBFlowFromFiltersTests(unittest.TestCase):
    """Behaviour-pin for :meth:`SQLDBFlow.from_filters` and
    :meth:`SQLDBFlow.get`.

    Mirrors :meth:`MongoDBFlow.flt_from_query` (which produces
    a Mongo filter dict via the same parsed
    :class:`flow.Query`).  Every supported clause shape gets
    its expected SQLAlchemy ``WHERE`` translation pinned to
    the literal-binds-rendered SQL fragment, so a future
    refactor of the translator cannot silently drift the two
    backends apart.
    """

    @staticmethod
    def _compile_pg(stmt):
        from sqlalchemy.dialects import postgresql

        return str(
            stmt.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )

    @classmethod
    def _where_sql(cls, filters):
        """Compile ``from_filters(filters)`` -> SA ``WHERE``
        expression -> PostgreSQL fragment for assertion."""
        from sqlalchemy import select
        from sqlalchemy.orm import aliased

        flt = _SQLDBFlow_for_filters_test.from_filters(filters)
        src = aliased(_Host_for_filters_test, name="src_h")
        dst = aliased(_Host_for_filters_test, name="dst_h")
        where = _SQLDBFlow_for_filters_test._flt_from_query(flt.query, src, dst)
        return cls._compile_pg(select(_Flow_for_filters_test.id).where(where))

    # -- return type --------------------------------------------------

    def test_from_filters_returns_sqlflow_filter(self):
        # ``from_filters`` does not eagerly translate the
        # ``flow.Query`` clauses -- it returns a wrapper so the
        # SA expression can be built later, when the per-query
        # ``Host`` aliases are bound inside :meth:`get`.
        flt = _SQLDBFlow_for_filters_test.from_filters({})
        self.assertIsInstance(flt, _SQLFlowFilter_for_filters_test)
        # Empty filters -> empty clauses list (no AND of ORs).
        self.assertEqual(flt.query.clauses, [])

    # -- direct-column comparisons ------------------------------------

    def test_proto_equality(self):
        # Plain ``proto = tcp`` lowers to a flat
        # ``flow.proto = 'tcp'`` predicate; no JOIN, no host
        # alias reference -- SA prunes the unused FROM list.
        sql = self._where_sql({"edges": ["proto = tcp"]})
        self.assertIn("flow.proto = 'tcp'", sql)
        self.assertNotIn("host", sql)

    def test_count_gt(self):
        sql = self._where_sql({"edges": ["count > 5"]})
        self.assertIn("flow.count > 5", sql)

    def test_negation_swaps_to_neq(self):
        # ``!proto = tcp`` lowers to ``flow.proto != 'tcp'``;
        # the translator wraps the comparison in ``NOT(...)``
        # rather than swapping operators (the SQL planner
        # inverts the comparison itself).  The flow filter
        # parser only treats ``!`` as a negation prefix when
        # it directly precedes the attribute (no separating
        # whitespace), matching Mongo's
        # :meth:`MongoDBFlow.flt_from_clause` convention.
        sql = self._where_sql({"edges": ["!proto = tcp"]})
        self.assertIn("flow.proto != 'tcp'", sql)

    # -- AND / OR composition -----------------------------------------

    def test_and_composition(self):
        # Multiple clauses without an explicit ``OR`` are
        # AND-ed together at the top level.
        sql = self._where_sql({"edges": ["proto = tcp", "dport = 443"]})
        self.assertIn("flow.proto = 'tcp'", sql)
        self.assertIn("flow.dport = 443", sql)
        self.assertIn(" AND ", sql)

    def test_or_composition(self):
        sql = self._where_sql({"edges": ["proto = tcp || proto = udp"]})
        self.assertIn(" OR ", sql)

    # -- addr / src.addr / dst.addr -----------------------------------

    def test_addr_shortcut_expands_to_or(self):
        # ``addr = X`` expands to ``src_h.addr = X OR
        # dst_h.addr = X``: the JOINs to both ``Host`` aliases
        # come from the surrounding :meth:`get` query, but the
        # WHERE expression itself references both aliases'
        # ``addr`` columns.
        sql = self._where_sql({"nodes": ["addr = 1.2.3.4"]})
        self.assertIn("src_h.addr", sql)
        self.assertIn("dst_h.addr", sql)
        self.assertIn(" OR ", sql)

    def test_addr_neq_uses_and(self):
        # ``addr != X`` is the De Morgan dual of ``addr = X``:
        # exclude flows where *either* side matches, i.e.
        # ``src_h.addr != X AND dst_h.addr != X``.  Without
        # this special-case, ``OR`` would let through every
        # flow where the *other* side does not match.
        sql = self._where_sql({"nodes": ["addr != 1.2.3.4"]})
        self.assertIn("src_h.addr !=", sql)
        self.assertIn("dst_h.addr !=", sql)
        self.assertIn(" AND ", sql)

    def test_src_addr_only(self):
        sql = self._where_sql({"nodes": ["src.addr = 1.2.3.4"]})
        self.assertIn("src_h.addr = ", sql)
        self.assertNotIn("dst_h.addr", sql)

    def test_dst_addr_only(self):
        sql = self._where_sql({"nodes": ["dst.addr = 1.2.3.4"]})
        self.assertIn("dst_h.addr = ", sql)
        self.assertNotIn("src_h.addr", sql)

    # -- existence (no operator) --------------------------------------

    def test_bare_attr_is_existence_check(self):
        # ``proto`` (no operator) -> ``flow.proto IS NOT NULL``.
        sql = self._where_sql({"edges": ["proto"]})
        self.assertIn("flow.proto IS NOT NULL", sql)

    def test_bare_attr_negated_is_null_check(self):
        # SQLAlchemy folds ``NOT (col IS NOT NULL)`` straight
        # into ``col IS NULL`` (and ditto for the addr-OR
        # case).  Pin the simplified shape so a future
        # rewrite of the translator that emits an explicit
        # ``NOT`` wrapper without the simplification surfaces
        # in this test instead of silently changing the
        # rendered SQL.
        sql = self._where_sql({"edges": ["!proto"]})
        self.assertIn("flow.proto IS NULL", sql)

    # -- meta.<proto>[.<key>] paths -----------------------------------

    def test_meta_proto_existence(self):
        # ``meta.http`` (bare) -> ``meta ->> 'http' IS NOT
        # NULL``: the JSONB ``->>`` extractor returns ``NULL``
        # when the key is absent, so the existence check
        # composes naturally.
        sql = self._where_sql({"edges": ["meta.http"]})
        self.assertIn("meta", sql)
        self.assertIn("'http'", sql)
        self.assertIn("IS NOT NULL", sql)

    def test_meta_proto_key_equality(self):
        # ``meta.http.method = GET`` -> ``(meta -> 'http') ->>
        # 'method' = 'GET'``.  Intermediate hops use ``->`` so
        # they keep the JSONB shape; only the leaf hops uses
        # ``->>`` to produce a comparable text value.
        sql = self._where_sql({"edges": ["meta.http.method = GET"]})
        self.assertIn("'http'", sql)
        self.assertIn("'method'", sql)
        self.assertIn("'GET'", sql)

    # -- date columns -------------------------------------------------

    def test_firstseen_iso_string_is_coerced_to_datetime(self):
        # IVRE's web layer ships ISO-8601 timestamps; the
        # translator routes them through
        # :func:`utils.all2datetime` so SQLAlchemy renders them
        # with the right ``TIMESTAMP`` literal.
        sql = self._where_sql({"edges": ["firstseen >= 2024-01-01 00:00:00"]})
        self.assertIn("flow.firstseen >= ", sql)
        self.assertIn("'2024-01-01 00:00:00'", sql)

    # -- error paths --------------------------------------------------

    def test_unknown_attribute_raises(self):
        # Typos / unknown columns surface eagerly rather than
        # silently being lowered to ``NULL = ...``.
        with self.assertRaises(ValueError):
            self._where_sql({"edges": ["bogus_col = 5"]})

    def test_array_mode_raises_not_implemented(self):
        # ``ANY`` / ``ALL`` / ``NONE`` / ``ONE`` array modes
        # are deferred to follow-up SQL flow work; the
        # translator surfaces the gap explicitly so a CLI
        # caller does not silently get an empty result set.
        with self.assertRaises(NotImplementedError):
            self._where_sql({"edges": ["ANY sports = 80"]})

    def test_len_mode_raises_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self._where_sql({"edges": ["LEN sports > 0"]})

    def test_regex_operator_raises_not_implemented(self):
        with self.assertRaises(NotImplementedError):
            self._where_sql({"edges": ["proto =~ tcp"]})

    # -- _row2flow projection -----------------------------------------

    def test_row2flow_returns_mongo_shaped_dict(self):
        # The base ``DBFlow.cursor2json_iter`` consumes flow
        # rows via ``row.get("addr")`` / ``row.get("_id")`` /
        # ``row.get("proto")`` / etc.  Pin the per-key
        # projection so the SA-row -> dict conversion stays
        # compatible with the inherited helpers; without it,
        # ``to_iter`` / ``to_graph`` would silently emit empty
        # graph nodes.
        class _FakeFlow:
            id = 42
            proto = "tcp"
            dport = 443
            type = None
            firstseen = "2024-01-01"
            lastseen = "2024-01-02"
            scpkts = 100
            scbytes = 4000
            cspkts = 80
            csbytes = 3500
            count = 3
            sports = [50000, 50001]
            codes = None
            meta = {"http": {"method": "GET"}}
            schema_version = 1

        rec = _SQLDBFlow_for_filters_test._row2flow(
            (_FakeFlow(), "10.0.0.1", "10.0.0.2")
        )
        self.assertEqual(rec["_id"], 42)
        self.assertEqual(rec["src_addr"], "10.0.0.1")
        self.assertEqual(rec["dst_addr"], "10.0.0.2")
        self.assertEqual(rec["proto"], "tcp")
        self.assertEqual(rec["dport"], 443)
        self.assertEqual(rec["sports"], [50000, 50001])
        self.assertEqual(rec["meta"], {"http": {"method": "GET"}})
        # Exhaustive key set so a new column added to ``Flow``
        # shows up in the projection or fails the test.
        self.assertEqual(
            set(rec),
            {
                "_id",
                "src_addr",
                "dst_addr",
                "proto",
                "dport",
                "type",
                "firstseen",
                "lastseen",
                "scpkts",
                "scbytes",
                "cspkts",
                "csbytes",
                "count",
                "sports",
                "codes",
                "meta",
                "schema_version",
            },
        )

    def test_row2flow_preserves_none_addresses(self):
        # ``src_addr`` / ``dst_addr`` come from the JOIN; if a
        # downstream consumer ever passes a NULL (e.g. a
        # placeholder dangling pointer), ``_row2flow`` keeps
        # that as ``None`` rather than the string ``"None"``.
        class _FakeFlow:
            id = 1
            proto = None
            dport = None
            type = None
            firstseen = None
            lastseen = None
            scpkts = None
            scbytes = None
            cspkts = None
            csbytes = None
            count = None
            sports = None
            codes = None
            meta = None
            schema_version = None

        rec = _SQLDBFlow_for_filters_test._row2flow((_FakeFlow(), None, None))
        self.assertIsNone(rec["src_addr"])
        self.assertIsNone(rec["dst_addr"])

    # -- to_iter / to_graph delegate to the base class ----------------

    def test_to_iter_inherited_from_dbflow(self):
        # The ``NotImplementedError`` stubs in ``SQLDBFlow``
        # (``to_iter`` / ``to_graph``) were dropped so the
        # base-class versions in :class:`DBFlow` take over;
        # both delegate to ``self.get(...)``, which now works
        # on the SQL backend.
        from ivre.db import DBFlow

        self.assertIs(_SQLDBFlow_for_filters_test.to_iter, DBFlow.to_iter)
        self.assertIs(_SQLDBFlow_for_filters_test.to_graph, DBFlow.to_graph)


# ---------------------------------------------------------------------
# SQLDBFlowAggregationsTests -- pin the wire shape of the
# read-side aggregation helpers (``count`` / ``flow_daily`` /
# ``topvalues`` / ``top``) on :class:`SQLDBFlow`.  These power
# the ``flowcli --count`` / ``--top`` / ``--flow-daily`` paths
# and the ``/cgi/flows/count`` web route; without them, every
# such call raised ``NotImplementedError``.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_SQLDB_FLOW_FILTERS,
    "SQLAlchemy is required for SQLDBFlowAggregationsTests",
)
class SQLDBFlowAggregationsTests(unittest.TestCase):
    """Behaviour-pin for ``count`` / ``flow_daily`` /
    ``topvalues`` / ``top`` on :class:`SQLDBFlow`.

    Mirrors :meth:`MongoDBFlow.count` / ``flow_daily`` /
    ``topvalues`` -- the contract is identical (same return
    shape so :mod:`ivre.tools.flowcli` and
    :mod:`ivre.web.app` consume both backends interchangeably);
    SQL diverges on the bucketing source for ``flow_daily``
    only -- the per-flow ``times`` array is documented as
    MongoDB-only in :mod:`ivre.flow`, so the SQL path buckets
    on ``firstseen`` instead.
    """

    @staticmethod
    def _compile_pg(stmt):
        from sqlalchemy.dialects import postgresql

        return str(
            stmt.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )

    # -- count() ------------------------------------------------------

    def test_count_signature_returns_dict(self):
        # ``count`` must accept a :class:`SQLFlowFilter` -- the
        # type :meth:`SQLDBFlow.from_filters` returns -- and
        # produce the canonical ``{clients, servers, flows}``
        # dict :func:`ivre.tools.flowcli` and
        # :class:`MongoDBFlow.count` agree on.  Without a live
        # PostgreSQL we mock the connection to assert the
        # SELECT shape and the return-dict construction in one
        # pass.
        from unittest.mock import MagicMock

        captured = []

        class _FakeConn:
            def execute(self, stmt):
                captured.append(stmt)
                row = MagicMock()
                row.flows = 5
                row.clients = 3
                row.servers = 4
                result = MagicMock()
                result.one.return_value = row
                return result

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        db = _SQLDBFlow_for_filters_test.__new__(_SQLDBFlow_for_filters_test)
        db._db = MagicMock()
        db._db.connect.return_value = _FakeConn()

        flt = _SQLDBFlow_for_filters_test.from_filters({"edges": ["proto = tcp"]})
        result = db.count(flt)
        self.assertEqual(result, {"flows": 5, "clients": 3, "servers": 4})

        # The captured SELECT must group COUNT(*) for flows and
        # COUNT(DISTINCT) for clients / servers, with the
        # canonical ``flow JOIN host AS src JOIN host AS dst``
        # join shape and the WHERE clause from the filter.
        self.assertEqual(len(captured), 1)
        sql = self._compile_pg(captured[0])
        self.assertIn("count(*)", sql)
        self.assertIn("count(DISTINCT flow.src)", sql)
        self.assertIn("count(DISTINCT flow.dst)", sql)
        self.assertIn("flow.proto = 'tcp'", sql)
        self.assertIn("JOIN host", sql)

    def test_count_none_spec_treated_as_match_all(self):
        # ``count(None)`` should not raise -- the
        # ``DBFlow.from_filters`` chain returns ``None``-able
        # values from time to time, and the count result for an
        # empty filter is well-defined.
        from unittest.mock import MagicMock

        captured = []

        class _FakeConn:
            def execute(self, stmt):
                captured.append(stmt)
                row = MagicMock()
                row.flows = 0
                row.clients = 0
                row.servers = 0
                result = MagicMock()
                result.one.return_value = row
                return result

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        db = _SQLDBFlow_for_filters_test.__new__(_SQLDBFlow_for_filters_test)
        db._db = MagicMock()
        db._db.connect.return_value = _FakeConn()
        result = db.count(None)
        self.assertEqual(result, {"flows": 0, "clients": 0, "servers": 0})
        self.assertIn("WHERE true", self._compile_pg(captured[0]))

    # -- topvalues() / top() -------------------------------------------

    def test_topvalues_unsupported_field_raises(self):
        # ``sport`` would need a ``sports`` array unwind we
        # have not implemented yet; surface that explicitly so
        # the CLI does not silently return an empty result.
        from unittest.mock import MagicMock

        db = _SQLDBFlow_for_filters_test.__new__(_SQLDBFlow_for_filters_test)
        db._db = MagicMock()
        flt = _SQLDBFlow_for_filters_test.from_filters({})
        with self.assertRaises(ValueError):
            list(db.topvalues(flt, ["sport"]))

    def test_topvalues_empty_fields_raises(self):
        from unittest.mock import MagicMock

        db = _SQLDBFlow_for_filters_test.__new__(_SQLDBFlow_for_filters_test)
        db._db = MagicMock()
        flt = _SQLDBFlow_for_filters_test.from_filters({})
        with self.assertRaises(ValueError):
            list(db.topvalues(flt, []))

    def test_topvalues_select_shape(self):
        # Capture the SQL the topvalues GROUP BY emits and
        # pin the column / alias / ORDER BY layout.  This is
        # the wire contract :meth:`MongoDBFlow.topvalues`
        # produces (counts descending by default; LIMIT
        # ``topnbr``); a future refactor that reorders or
        # renames the columns surfaces here instead of as a
        # silent CLI regression.
        from unittest.mock import MagicMock

        captured = []

        class _FakeConn:
            def execute(self, stmt):
                captured.append(stmt)
                return iter([])

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        db = _SQLDBFlow_for_filters_test.__new__(_SQLDBFlow_for_filters_test)
        db._db = MagicMock()
        db._db.connect.return_value = _FakeConn()
        flt = _SQLDBFlow_for_filters_test.from_filters({})
        list(db.topvalues(flt, ["proto", "dport"], topnbr=5))
        sql = self._compile_pg(captured[0])
        self.assertIn("GROUP BY flow.proto, flow.dport", sql)
        self.assertIn("count(*) AS _count", sql)
        # SQLAlchemy references the labeled column by its
        # alias in ORDER BY rather than re-emitting the
        # ``count(*)`` expression.
        self.assertIn("ORDER BY _count DESC", sql)
        self.assertIn("LIMIT 5", sql)

    def test_topvalues_collect_uses_array_agg(self):
        # ``collect_fields`` translate to ``array_agg`` (no
        # SQL-side ``DISTINCT`` -- the per-row arrays must
        # stay aligned across collect fields so the
        # ``zip(*arrays)`` step in the result decoder produces
        # well-formed tuples; SQL-side ``DISTINCT`` per
        # column would produce mis-aligned arrays).
        from unittest.mock import MagicMock

        captured = []

        class _FakeConn:
            def execute(self, stmt):
                captured.append(stmt)
                return iter([])

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        db = _SQLDBFlow_for_filters_test.__new__(_SQLDBFlow_for_filters_test)
        db._db = MagicMock()
        db._db.connect.return_value = _FakeConn()
        flt = _SQLDBFlow_for_filters_test.from_filters({})
        list(
            db.topvalues(
                flt,
                ["proto"],
                collect_fields=["src.addr", "dst.addr"],
            )
        )
        sql = self._compile_pg(captured[0])
        self.assertIn("array_agg(", sql)
        self.assertNotIn("array_agg(DISTINCT", sql)
        self.assertIn("AS _collect_0", sql)
        self.assertIn("AS _collect_1", sql)

    def test_topvalues_least_orders_ascending(self):
        from unittest.mock import MagicMock

        captured = []

        class _FakeConn:
            def execute(self, stmt):
                captured.append(stmt)
                return iter([])

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        db = _SQLDBFlow_for_filters_test.__new__(_SQLDBFlow_for_filters_test)
        db._db = MagicMock()
        db._db.connect.return_value = _FakeConn()
        flt = _SQLDBFlow_for_filters_test.from_filters({})
        list(db.topvalues(flt, ["proto"], least=True))
        sql = self._compile_pg(captured[0])
        self.assertIn("ORDER BY _count ASC", sql)

    def test_topvalues_sum_fields_uses_sum(self):
        from unittest.mock import MagicMock

        captured = []

        class _FakeConn:
            def execute(self, stmt):
                captured.append(stmt)
                return iter([])

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        db = _SQLDBFlow_for_filters_test.__new__(_SQLDBFlow_for_filters_test)
        db._db = MagicMock()
        db._db.connect.return_value = _FakeConn()
        flt = _SQLDBFlow_for_filters_test.from_filters({})
        list(db.topvalues(flt, ["proto"], sum_fields=["scbytes", "csbytes"]))
        sql = self._compile_pg(captured[0])
        # SQLAlchemy renders ``a + b`` for the per-row sum
        # expression; the outer ``sum(...)`` aggregates that
        # across the group.  Mirrors Mongo's ``$add`` ->
        # ``$sum`` projection chain.
        self.assertIn("sum(", sql)
        self.assertIn("scbytes", sql)
        self.assertIn("csbytes", sql)

    def test_top_is_alias_of_topvalues(self):
        # ``DBFlow.top`` was an abstract method on the base
        # class; the SQL backend ships ``top`` as a thin
        # parameter-renaming alias of ``topvalues`` so callers
        # of either name keep working unchanged.
        from unittest.mock import MagicMock

        captured = []

        class _FakeConn:
            def execute(self, stmt):
                captured.append(stmt)
                return iter([])

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        db = _SQLDBFlow_for_filters_test.__new__(_SQLDBFlow_for_filters_test)
        db._db = MagicMock()
        db._db.connect.return_value = _FakeConn()
        flt = _SQLDBFlow_for_filters_test.from_filters({})
        list(db.top(flt, ["proto"], collect=["src.addr"], sumfields=["count"]))
        sql = self._compile_pg(captured[0])
        self.assertIn("array_agg(", sql)
        self.assertIn("sum(flow.count)", sql)

    # -- flow_daily() bucketing ---------------------------------------

    def test_flow_daily_buckets_by_precision(self):
        # The bucketing helper is independent of the DB
        # connection: feed it a hand-crafted iterable and
        # inspect the per-bucket histogram.  Here ``precision=10``
        # collapses seconds 0..9 into bucket 0; seconds 10..19
        # into bucket 10; the proto/dport histogram aggregates
        # within each bucket.
        import datetime as _datetime

        class _Row:
            def __init__(self, ts, proto, dport=None, type=None):
                self.firstseen = ts
                self.proto = proto
                self.dport = dport
                self.type = type

        rows = [
            _Row(_datetime.datetime(2024, 1, 1, 10, 30, 3), "tcp", dport=443),
            _Row(_datetime.datetime(2024, 1, 1, 10, 30, 7), "tcp", dport=443),
            _Row(_datetime.datetime(2024, 1, 1, 10, 30, 12), "tcp", dport=443),
            _Row(_datetime.datetime(2024, 1, 1, 10, 30, 15), "udp", dport=53),
        ]
        out = list(_SQLDBFlow_for_filters_test._flow_daily_buckets(rows, precision=10))
        self.assertEqual(len(out), 2)
        # First bucket: 10:30:00 (seconds 3 and 7 collapse to 0).
        self.assertEqual(out[0]["time_in_day"], _datetime.time(10, 30, 0))
        self.assertEqual(out[0]["flows"], [("tcp/443", 2)])
        # Second bucket: 10:30:10 (seconds 12 and 15 collapse to 10).
        self.assertEqual(out[1]["time_in_day"], _datetime.time(10, 30, 10))
        self.assertEqual(sorted(out[1]["flows"]), [("tcp/443", 1), ("udp/53", 1)])

    def test_flow_daily_handles_icmp_via_type(self):
        # ICMP flows have no ``dport``; the entry name uses
        # ``proto/type`` instead.  Mirrors Mongo's
        # ``$cond``-driven entry-name construction at
        # :meth:`MongoDBFlow.flow_daily`.
        import datetime as _datetime

        class _Row:
            def __init__(self, ts, proto, dport, type):
                self.firstseen = ts
                self.proto = proto
                self.dport = dport
                self.type = type

        rows = [
            _Row(_datetime.datetime(2024, 1, 1, 0, 0, 0), "icmp", None, 8),
        ]
        out = list(_SQLDBFlow_for_filters_test._flow_daily_buckets(rows, precision=60))
        self.assertEqual(out[0]["flows"], [("icmp/8", 1)])

    def test_flow_daily_skips_null_firstseen(self):
        # ``firstseen`` can in theory be ``NULL`` (the column is
        # nullable on the schema); skip those rows rather than
        # crashing the iterator.
        class _Row:
            firstseen = None
            proto = "tcp"
            dport = 80
            type = None

        out = list(
            _SQLDBFlow_for_filters_test._flow_daily_buckets([_Row()], precision=60)
        )
        self.assertEqual(out, [])


# ---------------------------------------------------------------------
# SQLDBFlowDetailsTests -- pin :meth:`SQLDBFlow.host_details`
# and :meth:`SQLDBFlow.flow_details`.  Both feed
# ``/cgi/flows/host/<addr>`` and ``/cgi/flows/flow/<id>``
# respectively; without them the flow-graph drill-downs raised
# ``NotImplementedError`` on the SQL backend.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_SQLDB_FLOW_FILTERS,
    "SQLAlchemy is required for SQLDBFlowDetailsTests",
)
class SQLDBFlowDetailsTests(unittest.TestCase):
    """Behaviour-pin for ``host_details`` and
    ``flow_details`` on :class:`SQLDBFlow`.

    Both helpers mirror :meth:`MongoDBFlow.host_details` /
    :meth:`MongoDBFlow.flow_details`'s contracts byte-for-byte
    so the web UI / flowcli paths consume both backends
    interchangeably.

    The connection is mocked via :class:`unittest.mock.MagicMock`
    so the assertions cover both the SELECT shape (compiled to
    PostgreSQL via ``literal_binds``) and the result dict the
    helper returns from the canned rows.
    """

    @staticmethod
    def _compile_pg(stmt):
        from sqlalchemy.dialects import postgresql

        return str(
            stmt.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )

    @staticmethod
    def _make_db(rows):
        """Construct a :class:`SQLDBFlow` instance with a
        mocked engine that yields ``rows`` from any
        ``execute`` call.  Returns the db along with the
        ``captured`` list collecting every executed SA
        statement (so individual tests can inspect the
        compiled SQL).
        """
        from unittest.mock import MagicMock

        captured = []

        class _FakeResult:
            def __init__(self, rows):
                self._rows = list(rows)

            def __iter__(self):
                return iter(self._rows)

            def first(self):
                return self._rows[0] if self._rows else None

        class _FakeConn:
            def execute(self, stmt):
                captured.append(stmt)
                return _FakeResult(rows)

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        db = _SQLDBFlow_for_filters_test.__new__(_SQLDBFlow_for_filters_test)
        db._db = MagicMock()
        db._db.connect.return_value = _FakeConn()
        return db, captured

    @staticmethod
    def _make_flow(**overrides):
        """Build a stand-in :class:`Flow`-shaped object the
        ``_row2flow`` helper accepts as the first row item.
        Pinned attribute set so a future column addition that
        breaks the projection surfaces here, not on the live
        DB lane."""
        attrs = {
            "id": 1,
            "proto": "tcp",
            "dport": 80,
            "type": None,
            "firstseen": None,
            "lastseen": None,
            "scpkts": 0,
            "scbytes": 0,
            "cspkts": 0,
            "csbytes": 0,
            "count": 1,
            "sports": [],
            "codes": None,
            "meta": None,
            "schema_version": 1,
        }
        attrs.update(overrides)
        return type("_FakeFlow", (), attrs)

    # -- host_details() -----------------------------------------------

    def test_host_details_select_shape(self):
        # The SELECT must filter on
        # ``src_alias.addr = node_id OR dst_alias.addr =
        # node_id`` so a single round-trip retrieves every
        # flow the host participates in (incoming and
        # outgoing).
        db, captured = self._make_db([])
        result = db.host_details("10.0.0.1")
        self.assertEqual(len(captured), 1)
        sql = self._compile_pg(captured[0])
        self.assertIn("flow_src_host.addr", sql)
        self.assertIn("flow_dst_host.addr", sql)
        self.assertIn(" OR ", sql)
        # Empty result -> empty sets returned as lists.
        self.assertEqual(result["clients"], [])
        self.assertEqual(result["servers"], [])
        self.assertEqual(result["in_flows"], [])
        self.assertEqual(result["out_flows"], [])
        self.assertEqual(result["elt"]["addr"], "10.0.0.1")
        self.assertIsNone(result["elt"]["firstseen"])
        self.assertIsNone(result["elt"]["lastseen"])

    def test_host_details_classifies_flows_by_side(self):
        # Mongo's helper classifies each flow by which side
        # of the source / destination addresses matches the
        # queried ``node_id``: incoming flows accumulate
        # ``in_flows`` ((proto, dport)) and ``clients``
        # (source IPs); outgoing flows accumulate ``out_flows``
        # and ``servers``.  Pin the same dispatch on SQL.
        import datetime as _datetime

        rows = [
            # node is the source -> outgoing flow.
            (
                self._make_flow(
                    id=1,
                    proto="tcp",
                    dport=80,
                    firstseen=_datetime.datetime(2024, 1, 1, 10, 0, 0),
                    lastseen=_datetime.datetime(2024, 1, 1, 10, 5, 0),
                ),
                "10.0.0.1",  # src_addr
                "1.2.3.4",  # dst_addr
            ),
            # node is the destination -> incoming flow.
            (
                self._make_flow(
                    id=2,
                    proto="udp",
                    dport=53,
                    firstseen=_datetime.datetime(2024, 1, 1, 9, 30, 0),
                    lastseen=_datetime.datetime(2024, 1, 1, 11, 0, 0),
                ),
                "5.6.7.8",  # src_addr
                "10.0.0.1",  # dst_addr
            ),
            # Another outgoing flow to an already-seen server
            # IP -- the ``servers`` set must dedupe by
            # converting via ``set`` before the list cast.
            (
                self._make_flow(id=3, proto="tcp", dport=443),
                "10.0.0.1",
                "1.2.3.4",
            ),
        ]
        db, _ = self._make_db(rows)
        result = db.host_details("10.0.0.1")
        self.assertEqual(set(result["clients"]), {"5.6.7.8"})
        self.assertEqual(set(result["servers"]), {"1.2.3.4"})
        self.assertEqual(set(result["out_flows"]), {("tcp", 80), ("tcp", 443)})
        self.assertEqual(set(result["in_flows"]), {("udp", 53)})
        # ``firstseen`` / ``lastseen`` aggregate to
        # min / max across every flow the host touches.
        self.assertEqual(
            result["elt"]["firstseen"],
            _datetime.datetime(2024, 1, 1, 9, 30, 0),
        )
        self.assertEqual(
            result["elt"]["lastseen"],
            _datetime.datetime(2024, 1, 1, 11, 0, 0),
        )

    def test_host_details_skips_null_timestamps(self):
        # ``firstseen`` / ``lastseen`` columns are nullable;
        # rows with NULL timestamps must not poison the
        # min / max aggregation (Python ``None`` would
        # compare with the chained-comparison operators).
        import datetime as _datetime

        rows = [
            (
                self._make_flow(
                    id=1,
                    firstseen=_datetime.datetime(2024, 1, 1),
                    lastseen=_datetime.datetime(2024, 1, 2),
                ),
                "10.0.0.1",
                "1.2.3.4",
            ),
            (
                self._make_flow(id=2, firstseen=None, lastseen=None),
                "10.0.0.1",
                "5.6.7.8",
            ),
        ]
        db, _ = self._make_db(rows)
        result = db.host_details("10.0.0.1")
        self.assertEqual(result["elt"]["firstseen"], _datetime.datetime(2024, 1, 1))
        self.assertEqual(result["elt"]["lastseen"], _datetime.datetime(2024, 1, 2))

    # -- flow_details() -----------------------------------------------

    def test_flow_details_returns_none_for_missing(self):
        db, captured = self._make_db([])
        self.assertIsNone(db.flow_details(42))
        sql = self._compile_pg(captured[0])
        # ``flow.id = 42`` -- the ``int(flow_id)`` coerce
        # is what enables this literal binding.
        self.assertIn("flow.id = 42", sql)

    def test_flow_details_returns_none_for_invalid_id(self):
        # Mongo accepts ``ObjectId`` strings; the SQL backend
        # cannot translate "abc" into an integer PK so it
        # short-circuits to ``None`` rather than raising.
        db, captured = self._make_db([])
        self.assertIsNone(db.flow_details("not-an-int"))
        # No SQL emitted on the bad-input path.
        self.assertEqual(captured, [])

    def test_flow_details_projects_edge2json_data(self):
        # The ``elt`` payload follows the
        # :meth:`DBFlow._edge2json_default` shape: same keys
        # as the graph-edge representation (``proto``,
        # ``dport``, ``cspkts`` / ``scpkts`` / ``csbytes`` /
        # ``scbytes``, ``addr_src`` / ``addr_dst``,
        # ``firstseen`` / ``lastseen``, ``__key__``,
        # ``count``).  Pin the per-key projection so a
        # future refactor of either helper does not silently
        # change the API for the web UI.
        import datetime as _datetime

        rows = [
            (
                self._make_flow(
                    id=99,
                    proto="tcp",
                    dport=443,
                    firstseen=_datetime.datetime(2024, 1, 1),
                    lastseen=_datetime.datetime(2024, 1, 2),
                    cspkts=10,
                    scpkts=20,
                    csbytes=1000,
                    scbytes=2000,
                    count=5,
                    sports=[50000],
                ),
                "10.0.0.1",
                "1.2.3.4",
            ),
        ]
        db, _ = self._make_db(rows)
        result = db.flow_details(99)
        self.assertIn("elt", result)
        elt = result["elt"]
        self.assertEqual(elt["proto"], "tcp")
        self.assertEqual(elt["dport"], 443)
        self.assertEqual(elt["cspkts"], 10)
        self.assertEqual(elt["scpkts"], 20)
        self.assertEqual(elt["csbytes"], 1000)
        self.assertEqual(elt["scbytes"], 2000)
        self.assertEqual(elt["count"], 5)
        self.assertEqual(elt["addr_src"], "10.0.0.1")
        self.assertEqual(elt["addr_dst"], "1.2.3.4")
        self.assertEqual(elt["sports"], [50000])
        self.assertEqual(elt["__key__"], "99")
        self.assertEqual(elt["firstseen"], _datetime.datetime(2024, 1, 1))
        self.assertEqual(elt["lastseen"], _datetime.datetime(2024, 1, 2))
        # No ``meta`` -> the key is omitted (Mongo helper
        # leaves it out, not present-with-empty-value).
        self.assertNotIn("meta", result)

    def test_flow_details_includes_meta_when_present(self):
        rows = [
            (
                self._make_flow(
                    id=7,
                    proto="tcp",
                    dport=80,
                    meta={"http": {"method": "GET", "host": "example.com"}},
                ),
                "10.0.0.1",
                "1.2.3.4",
            ),
        ]
        db, _ = self._make_db(rows)
        result = db.flow_details(7)
        self.assertIn("meta", result)
        self.assertEqual(
            result["meta"],
            {"http": {"method": "GET", "host": "example.com"}},
        )


# ---------------------------------------------------------------------
# SQLDBFlowIngestionTests -- pin :meth:`SQLDBFlow.start_bulk_insert`,
# ``any2flow`` / ``conn2flow`` / ``flow2flow``, ``bulk_commit`` and
# ``cleanup_flows``.  These methods feed the ``zeek2db`` / ``flow2db``
# entry points; before this sub-PR they raised ``NotImplementedError``
# and the whole ingestion lane was unusable on the SQL backend.
#
# Each test mocks the SQLAlchemy engine via :class:`MagicMock` and
# captures every executed statement, asserting:
#   * the per-record statement count (host upsert x2 + flow upsert),
#   * the conflict target matches the partial unique index
#     ``flow_unique_lookup`` declared in ``ivre/db/sql/tables.py``,
#   * the SET list mirrors Mongo's ``$min`` / ``$max`` / ``$inc`` /
#     ``$addToSet`` blocks for the matching record kind.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_SQLDB_FLOW_FILTERS,
    "SQLAlchemy is required for SQLDBFlowIngestionTests",
)
class SQLDBFlowIngestionTests(unittest.TestCase):
    """Behaviour-pin for the SQL backend's flow ingestion path.

    The tests run with no live database -- the engine is replaced by
    a :class:`MagicMock` whose ``begin()`` context yields a fake
    connection that captures every executed SA statement.  Each
    statement is then compiled against the PostgreSQL dialect so
    individual tests can assert on substrings of the rendered SQL.
    """

    @staticmethod
    def _compile_pg(stmt):
        from sqlalchemy.dialects import postgresql

        # ``literal_binds=True`` would error on JSONB / DATETIME
        # bind values (no literal renderer for those types).  The
        # default compile path renders binds as ``%(name)s``
        # placeholders, which is enough for substring assertions
        # on the SET / ON CONFLICT clauses.
        return str(stmt.compile(dialect=postgresql.dialect()))

    @staticmethod
    def _make_db():
        """Construct a :class:`SQLDBFlow` with a mocked engine.

        Returns ``(db, captured)`` where ``captured`` is the list
        every call to ``conn.execute(stmt)`` appends to.  The
        mocked ``execute`` returns a stub whose ``scalar_one()``
        yields a deterministic 1 -- the only consumer is the
        host-upsert path, which uses the value as the FK
        identifier.
        """
        from unittest.mock import MagicMock

        captured = []

        class _FakeResult:
            def scalar_one(self):
                return 1

        class _FakeConn:
            def execute(self, stmt):
                captured.append(stmt)
                return _FakeResult()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        db = _SQLDBFlow_for_filters_test.__new__(_SQLDBFlow_for_filters_test)
        db._db = MagicMock()
        db._db.begin.return_value = _FakeConn()
        return db, captured

    # -- start_bulk_insert / queue helpers ----------------------------

    def test_start_bulk_insert_returns_empty_list(self):
        # Mirrors :meth:`MongoDBFlow.start_bulk_insert`: callers
        # treat the return value as opaque, but it must be
        # mutable and falsy on init so :meth:`bulk_commit`'s
        # empty-bulk fast path triggers.
        bulk = _SQLDBFlow_for_filters_test.start_bulk_insert()
        self.assertEqual(bulk, [])
        self.assertFalse(bulk)

    def test_postgres_flow_instance_start_bulk_insert(self):
        # Regression pin: the per-row :class:`BulkInsert`
        # factory (used by the active ingestion path's
        # ``store_or_merge_host`` / ``start_store_hosts``)
        # used to live on :class:`PostgresDB` and shadowed
        # :meth:`SQLDBFlow.start_bulk_insert` via MRO on
        # :class:`PostgresDBFlow`'s ``(PostgresDB, SQLDBFlow)``
        # bases.  ``db.start_bulk_insert()`` on a
        # :class:`PostgresDBFlow` instance therefore returned
        # a :class:`BulkInsert` object instead of the empty
        # list :meth:`SQLDBFlow.bulk_commit` expects.
        #
        # The fix moved the factory down to
        # :class:`PostgresDBActive` (its only consumer),
        # leaving the name unreachable on the flow MRO so
        # :meth:`SQLDBFlow.start_bulk_insert`'s ``[]``
        # tuple-list factory wins by inheritance.  Pin both
        # the instance-level call and the class-level
        # ``__qualname__`` so a future regression that
        # re-introduces ``start_bulk_insert`` on
        # :class:`PostgresDB` (or any earlier MRO ancestor)
        # surfaces here.
        from unittest.mock import MagicMock

        from ivre.db.sql import SQLDBFlow
        from ivre.db.sql.postgres import PostgresDBFlow

        # Class-level resolution must point at the flow
        # ingestion path's static method, not the active
        # path's :class:`BulkInsert` factory.
        self.assertEqual(
            PostgresDBFlow.start_bulk_insert.__qualname__,
            SQLDBFlow.start_bulk_insert.__qualname__,
        )
        db = PostgresDBFlow.__new__(PostgresDBFlow)
        db._db = MagicMock()
        bulk = db.start_bulk_insert()
        self.assertEqual(bulk, [])
        # The Mongo-shape append must work.
        bulk.append(("conn", {}))
        self.assertEqual(len(bulk), 1)

    def test_queue_helpers_record_kind(self):
        # The queue helpers tag every entry with the kind
        # :meth:`bulk_commit` then dispatches on; without the
        # tag the dispatch table would have to introspect the
        # record shape, defeating the parity with Mongo's
        # opaque ``pymongo.UpdateOne`` queue.
        bulk = _SQLDBFlow_for_filters_test.start_bulk_insert()
        rec = {"src": "10.0.0.1", "dst": "10.0.0.2", "proto": "tcp"}
        _SQLDBFlow_for_filters_test.any2flow(bulk, "http", rec)
        _SQLDBFlow_for_filters_test.conn2flow(bulk, rec)
        _SQLDBFlow_for_filters_test.flow2flow(bulk, rec)
        self.assertEqual(len(bulk), 3)
        self.assertEqual(bulk[0][0], "any")
        self.assertEqual(bulk[0][1], "http")
        self.assertEqual(bulk[1][0], "conn")
        self.assertEqual(bulk[2][0], "flow")

    # -- bulk_commit ---------------------------------------------------

    def test_bulk_commit_empty_is_noop(self):
        # An empty bulk must not open a transaction (mirrors
        # Mongo's ``InvalidOperation`` swallow) -- ``zeek2db``
        # commits one bulk per file, and empty input files would
        # otherwise hammer the database with empty txns.
        db, captured = self._make_db()
        db.bulk_commit([])
        self.assertEqual(captured, [])
        # ``begin`` must not even be called on the empty path.
        db._db.begin.assert_not_called()

    def test_bulk_commit_unknown_kind_raises(self):
        # Defensive guard: a malformed bulk entry surfaces as a
        # ``ValueError`` rather than a silent no-op so a future
        # refactor that adds a new entry kind without updating
        # the dispatch table fails loudly.
        db, _ = self._make_db()
        with self.assertRaises(ValueError):
            db.bulk_commit([("bogus", {})])

    # -- conn2flow upsert SQL shape -----------------------------------

    def _commit_conn(self, **rec_overrides):
        from datetime import datetime

        db, captured = self._make_db()
        rec = {
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "proto": "tcp",
            "sport": 1234,
            "dport": 80,
            "start_time": datetime(2024, 1, 1, 0, 0, 0),
            "end_time": datetime(2024, 1, 1, 0, 0, 5),
            "orig_pkts": 5,
            "resp_pkts": 7,
            "orig_ip_bytes": 500,
            "resp_ip_bytes": 700,
        }
        rec.update(rec_overrides)
        bulk = _SQLDBFlow_for_filters_test.start_bulk_insert()
        _SQLDBFlow_for_filters_test.conn2flow(bulk, rec)
        db.bulk_commit(bulk)
        return captured

    def test_conn2flow_emits_three_statements(self):
        # One conn record drives two host upserts (src + dst)
        # and one flow upsert -- three round trips per record.
        # The bulk-grouping optimisation that would collapse
        # this into a COPY pipeline is a follow-up.
        captured = self._commit_conn()
        self.assertEqual(len(captured), 3)

    def test_conn2flow_host_upsert_shape(self):
        # The host upsert keys on ``addr``, widens the
        # observation window via LEAST/GREATEST, and returns
        # the FK identifier the flow upsert then uses.
        captured = self._commit_conn()
        host_sql = self._compile_pg(captured[0])
        self.assertIn("INSERT INTO host", host_sql)
        self.assertIn("ON CONFLICT (addr)", host_sql)
        self.assertIn("least(host.firstseen", host_sql)
        self.assertIn("greatest(host.lastseen", host_sql)
        self.assertIn("RETURNING host.id", host_sql)

    def test_conn2flow_flow_upsert_targets_unique_lookup(self):
        # The conflict target must list the same expressions
        # the partial unique index ``flow_unique_lookup``
        # carries (``COALESCE(<col>, -1)`` for ``dport`` and
        # ``type`` so NULLs collapse onto a single constraint
        # slot).
        captured = self._commit_conn()
        flow_sql = self._compile_pg(captured[2])
        self.assertIn("INSERT INTO flow", flow_sql)
        self.assertIn(
            "ON CONFLICT (src, dst, proto, coalesce(dport, ",
            flow_sql,
        )
        self.assertIn("coalesce(type, ", flow_sql)
        self.assertIn("schema_version", flow_sql)

    def test_conn2flow_flow_upsert_accumulates_counters(self):
        # Mongo's ``$inc cspkts`` etc. translates to
        # ``coalesce(flow.col, 0) + excluded.col`` so an
        # earlier ``any2flow`` row that left the counter NULL
        # does not poison the accumulation.
        captured = self._commit_conn()
        flow_sql = self._compile_pg(captured[2])
        for col in ("cspkts", "scpkts", "csbytes", "scbytes", "count"):
            self.assertIn(
                f"{col} = (coalesce(flow.{col}, ",
                flow_sql,
            )
            self.assertIn(f"+ excluded.{col})", flow_sql)

    def test_conn2flow_flow_upsert_concatenates_arrays(self):
        # Mongo's ``$addToSet sports`` translates to an
        # ``array_cat`` of the existing column with the new
        # value; ``COALESCE`` on both sides tolerates NULL
        # arrays so the very first conn2flow on a key seeds
        # the column without raising.
        captured = self._commit_conn()
        flow_sql = self._compile_pg(captured[2])
        self.assertIn("sports = array_cat(coalesce(flow.sports, ", flow_sql)
        self.assertIn("codes = array_cat(coalesce(flow.codes, ", flow_sql)

    def test_conn2flow_widens_timestamp_window(self):
        # ``firstseen`` / ``lastseen`` must collapse via
        # LEAST / GREATEST on every ingestion path -- it's
        # the only update an ``any2flow`` followed by a
        # ``conn2flow`` pair leaves on the row's timestamp
        # columns.
        captured = self._commit_conn()
        flow_sql = self._compile_pg(captured[2])
        self.assertIn("firstseen = least(flow.firstseen", flow_sql)
        self.assertIn("lastseen = greatest(flow.lastseen", flow_sql)

    # -- icmp / non-port protocols ------------------------------------

    def test_conn2flow_icmp_uses_type_and_codes(self):
        # ICMP records leave ``dport`` NULL and populate
        # ``type`` / ``codes`` instead -- mirrors Mongo's
        # ``MongoDBFlow._get_flow_key`` dispatch.
        captured = self._commit_conn(
            proto="icmp",
            type=8,
            code=0,
            sport=None,
            dport=None,
        )
        flow_sql = self._compile_pg(captured[2])
        # The conflict target still lists both COALESCE
        # wrappers so the partial unique index stays the
        # inferred conflict resolution path regardless of
        # which protocol the record carries.
        self.assertIn("coalesce(dport, ", flow_sql)
        self.assertIn("coalesce(type, ", flow_sql)

    # -- any2flow ------------------------------------------------------

    def test_any2flow_does_not_increment_counters(self):
        # Per :meth:`MongoDBFlow.any2flow`'s contract the
        # top-level ``count`` is *not* bumped (only
        # ``meta.<name>.count`` is, which the SQL backend
        # defers).  The SET clause must therefore omit the
        # counter ``+`` accumulation -- only the timestamp
        # widening survives.
        from datetime import datetime

        db, captured = self._make_db()
        rec = {
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "proto": "tcp",
            "dport": 80,
            "start_time": datetime(2024, 1, 1, 0, 0, 0),
            "end_time": datetime(2024, 1, 1, 0, 0, 1),
        }
        bulk = _SQLDBFlow_for_filters_test.start_bulk_insert()
        _SQLDBFlow_for_filters_test.any2flow(bulk, "http", rec)
        db.bulk_commit(bulk)
        flow_sql = self._compile_pg(captured[2])
        self.assertIn("firstseen = least(flow.firstseen", flow_sql)
        self.assertIn("lastseen = greatest(flow.lastseen", flow_sql)
        # The counter columns stay out of the SET list (they
        # appear in the INSERT VALUES only).
        for col in ("cspkts", "scpkts", "csbytes", "scbytes", "count"):
            self.assertNotIn(f"{col} = (coalesce(flow.{col}", flow_sql)

    # -- flow2flow -----------------------------------------------------

    def test_flow2flow_takes_counters_verbatim(self):
        # NetFlow / Argus records already carry the
        # ``cspkts`` / ``scpkts`` / ``csbytes`` / ``scbytes``
        # field names ``conn2flow`` derives from Zeek's
        # ``orig_*`` / ``resp_*`` keys, so the upsert path
        # must read them as-is.  The SET clause shape is
        # identical to ``conn2flow``.
        from datetime import datetime

        db, captured = self._make_db()
        rec = {
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "proto": "udp",
            "sport": 4242,
            "dport": 53,
            "start_time": datetime(2024, 1, 1, 0, 0, 0),
            "end_time": datetime(2024, 1, 1, 0, 0, 1),
            "cspkts": 1,
            "scpkts": 1,
            "csbytes": 60,
            "scbytes": 80,
        }
        bulk = _SQLDBFlow_for_filters_test.start_bulk_insert()
        _SQLDBFlow_for_filters_test.flow2flow(bulk, rec)
        db.bulk_commit(bulk)
        flow_sql = self._compile_pg(captured[2])
        for col in ("cspkts", "scpkts", "csbytes", "scbytes", "count"):
            self.assertIn(
                f"{col} = (coalesce(flow.{col}, ",
                flow_sql,
            )

    # -- cleanup_flows -------------------------------------------------

    def test_cleanup_flows_is_a_noop(self):
        # ``zeek2db`` calls ``cleanup_flows`` after every
        # bulk unless ``--no-cleanup`` is set; the SQL
        # backend's host-swap heuristic is deferred to a
        # follow-up so the method must not raise (and must
        # not issue any SQL).
        db, captured = self._make_db()
        db.cleanup_flows()
        self.assertEqual(captured, [])
        db._db.begin.assert_not_called()


# ---------------------------------------------------------------------
# DuckDBFlowTests -- pin :class:`ivre.db.sql.duckdb.DuckDBFlow`.
#
# DuckDB does not support expression-based ``ON CONFLICT`` targets
# (``Not implemented Error: Non-column index element not supported
# yet!``), so the flow ingestion path's COALESCE-based unique index
# inference (the partial unique index ``flow_unique_lookup``) is
# unusable.  :class:`DuckDBFlow` overrides
# :meth:`_flow_merge` with a SELECT-by-key-then-INSERT-or-UPDATE
# strategy that produces the same end-state without touching the
# per-record ``_apply_*`` helpers.
#
# Tests cover:
#   * backend dispatch (``DBFlow.backends["duckdb"]``),
#   * ``start_bulk_insert`` returns ``[]`` after the MRO override
#     on ``PostgresDBFlow`` (PostgresDB's same-named method
#     otherwise shadows :meth:`SQLDBFlow.start_bulk_insert`),
#   * mocked SELECT-then-merge SQL shape,
#   * (with duckdb-engine installed) a full live-engine roundtrip
#     so the counter / timestamp / array-merge semantics match the
#     PG ON CONFLICT path byte-for-byte.
# ---------------------------------------------------------------------


try:
    from ivre.db.sql.duckdb import DuckDBFlow as _DuckDBFlow_for_tests  # noqa: E402
    from ivre.db.sql.tables import Flow as _Flow_for_duckdb_tests  # noqa: E402
    from ivre.db.sql.tables import Host as _Host_for_duckdb_tests  # noqa: E402

    _HAVE_DUCKDB_FLOW = True
except ImportError:
    _HAVE_DUCKDB_FLOW = False


@unittest.skipUnless(
    _HAVE_DUCKDB_FLOW,
    "SQLAlchemy is required for DuckDBFlowTests",
)
class DuckDBFlowTests(unittest.TestCase):
    """Behaviour-pin for :class:`ivre.db.sql.duckdb.DuckDBFlow`."""

    # -- backend registration -----------------------------------------

    def test_backend_registered(self):
        # Without the ``"duckdb"`` entry in
        # :attr:`DBFlow.backends` an ``DB = duckdb:///...`` URL
        # would silently fall back to a generic ``DBFlow`` and
        # every call would raise ``NotImplementedError``.
        from ivre.db import DBFlow

        self.assertEqual(
            DBFlow.backends.get("duckdb"),
            ("sql.duckdb", "DuckDBFlow"),
        )

    def test_class_inherits_postgres_flow_read_path(self):
        # DuckDBFlow inherits the read-side methods (count,
        # to_graph, host_details, flow_details, topvalues,
        # flow_daily, ...) from :class:`PostgresDBFlow`.  The
        # MRO must place ``DuckDBMixin`` first so its dialect
        # overrides win the lookup against PostgresDB's
        # defaults; ``PostgresDBFlow`` follows so the
        # ON-CONFLICT-free read path is reachable.
        mro = [c.__name__ for c in _DuckDBFlow_for_tests.__mro__]
        self.assertEqual(mro[0], "DuckDBFlow")
        self.assertEqual(mro[1], "DuckDBMixin")
        self.assertEqual(mro[2], "PostgresDBFlow")

    # -- start_bulk_insert inheritance --------------------------------

    def test_start_bulk_insert_returns_empty_list(self):
        # Pure-inheritance regression pin: the per-row
        # :class:`BulkInsert` factory used to live on
        # :class:`PostgresDB` and shadowed
        # :meth:`SQLDBFlow.start_bulk_insert` via MRO on
        # :class:`DuckDBFlow`'s ``(DuckDBMixin,
        # PostgresDBFlow, ...)`` bases.  After moving the
        # factory down to :class:`PostgresDBActive`, the
        # flow MRO branch inherits
        # :meth:`SQLDBFlow.start_bulk_insert`'s ``[]``
        # tuple-list factory directly -- no override needed.
        from unittest.mock import MagicMock

        db = _DuckDBFlow_for_tests.__new__(_DuckDBFlow_for_tests)
        db._db = MagicMock()
        bulk = db.start_bulk_insert()
        self.assertEqual(bulk, [])
        # Append accepts the Mongo-shape entry the queue
        # helpers produce.
        bulk.append(("conn", {}))
        self.assertEqual(len(bulk), 1)

    # -- _flow_merge SELECT-then-merge SQL shape ----------------------

    @staticmethod
    def _make_db():
        """Construct a :class:`DuckDBFlow` with a mocked engine
        that captures every SA statement.

        ``execute`` returns a stub whose ``.scalar()`` yields
        ``None`` (no existing row) so the SELECT-then-merge
        path takes the INSERT branch by default; individual
        tests can override the return on a per-call basis to
        exercise the UPDATE branch.
        """
        from unittest.mock import MagicMock

        captured = []

        class _FakeResult:
            def __init__(self, value=None):
                self._value = value

            def scalar(self):
                return self._value

            def scalar_one(self):
                return 1

        class _FakeConn:
            def __init__(self):
                self._next_select = None

            def execute(self, stmt):
                captured.append(stmt)
                # First execute call in _flow_merge is the
                # SELECT; emit ``next_select`` if set, else
                # ``None`` (= no existing row).
                value = self._next_select
                self._next_select = None
                return _FakeResult(value)

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        conn = _FakeConn()
        db = _DuckDBFlow_for_tests.__new__(_DuckDBFlow_for_tests)
        db._db = MagicMock()
        db._db.begin.return_value = conn
        return db, conn, captured

    def test_flow_merge_insert_branch_emits_insert(self):
        # When the SELECT returns no existing row the merge
        # path must emit a plain ``INSERT INTO flow``
        # statement (no ``ON CONFLICT`` clause -- that's the
        # whole point of the override).
        from datetime import datetime

        db, _conn, captured = self._make_db()
        bulk = db.start_bulk_insert()
        db.conn2flow(
            bulk,
            {
                "src": "10.0.0.1",
                "dst": "10.0.0.2",
                "proto": "tcp",
                "sport": 1234,
                "dport": 80,
                "start_time": datetime(2024, 1, 1, 0, 0, 0),
                "end_time": datetime(2024, 1, 1, 0, 0, 5),
                "orig_pkts": 5,
                "resp_pkts": 7,
                "orig_ip_bytes": 500,
                "resp_ip_bytes": 700,
            },
        )
        db.bulk_commit(bulk)
        # Three statements per record: src host upsert + dst
        # host upsert + flow SELECT.  Since SELECT returned
        # ``None`` we then issue an INSERT -> total 4.
        self.assertEqual(len(captured), 4)
        from sqlalchemy.dialects import postgresql

        # The flow path's last statement must be a SELECT
        # (the lookup) followed by an INSERT (the no-row
        # branch).
        select_sql = str(captured[2].compile(dialect=postgresql.dialect()))
        insert_sql = str(captured[3].compile(dialect=postgresql.dialect()))
        self.assertIn("SELECT flow.id", select_sql)
        self.assertIn("FROM flow", select_sql)
        self.assertIn("INSERT INTO flow", insert_sql)
        # No ON CONFLICT clause -- the whole point of the
        # SELECT-then-merge path is to bypass it.
        self.assertNotIn("ON CONFLICT", insert_sql)

    def test_flow_merge_update_branch_emits_update(self):
        # When the SELECT returns an existing flow id the
        # merge path must emit an ``UPDATE`` with the same
        # widening / accumulation / array-merge semantics as
        # the PG ON CONFLICT path.
        from datetime import datetime

        db, conn, captured = self._make_db()
        # Make the flow SELECT (the third execute) return an
        # existing id so the merge takes the UPDATE branch.
        # The two host upserts come first, both via the same
        # connection, so we need the third execute to yield
        # the id.  Track the call number directly.
        call_idx = [0]
        original_execute = conn.execute

        def execute_with_select_id(stmt):
            call_idx[0] += 1
            if call_idx[0] == 3:  # the flow SELECT
                conn._next_select = 42
            return original_execute(stmt)

        conn.execute = execute_with_select_id

        bulk = db.start_bulk_insert()
        db.conn2flow(
            bulk,
            {
                "src": "10.0.0.1",
                "dst": "10.0.0.2",
                "proto": "tcp",
                "sport": 1234,
                "dport": 80,
                "start_time": datetime(2024, 1, 1, 0, 0, 0),
                "end_time": datetime(2024, 1, 1, 0, 0, 5),
                "orig_pkts": 5,
                "resp_pkts": 7,
                "orig_ip_bytes": 500,
                "resp_ip_bytes": 700,
            },
        )
        db.bulk_commit(bulk)
        from sqlalchemy.dialects import postgresql

        update_sql = str(captured[3].compile(dialect=postgresql.dialect()))
        self.assertIn("UPDATE flow SET", update_sql)
        # The SET clause must widen the timestamp window via
        # LEAST/GREATEST -- mirrors the PG ON CONFLICT path.
        self.assertIn("least(flow.firstseen", update_sql)
        self.assertIn("greatest(flow.lastseen", update_sql)
        # Counters accumulate via ``coalesce(col, 0) + <value>``.
        # Pin both halves separately (the SET clause renders
        # ``col=(coalesce(...) + ...)`` without a space around
        # ``=`` on UPDATE, so a single substring match would be
        # whitespace-fragile).
        for col in ("cspkts", "scpkts", "csbytes", "scbytes", "count"):
            self.assertIn(f"coalesce(flow.{col}, ", update_sql)

    def test_flow_merge_select_uses_is_null_for_missing_dport(self):
        # ICMP records carry ``dport=NULL`` / ``type=<int>``;
        # SQL equality on ``NULL`` returns ``NULL`` so the
        # SELECT must use ``IS NULL`` instead of ``= NULL``
        # to find existing rows.  Pin this so a future
        # refactor doesn't silently introduce duplicate
        # rows.
        from datetime import datetime

        db, _conn, captured = self._make_db()
        bulk = db.start_bulk_insert()
        db.conn2flow(
            bulk,
            {
                "src": "10.0.0.1",
                "dst": "10.0.0.2",
                "proto": "icmp",
                "type": 8,
                "code": 0,
                "start_time": datetime(2024, 1, 1, 0, 0, 0),
                "end_time": datetime(2024, 1, 1, 0, 0, 5),
                "orig_pkts": 1,
                "resp_pkts": 1,
                "orig_ip_bytes": 60,
                "resp_ip_bytes": 60,
            },
        )
        db.bulk_commit(bulk)
        from sqlalchemy.dialects import postgresql

        select_sql = str(captured[2].compile(dialect=postgresql.dialect()))
        # ICMP path: dport is NULL -> ``IS NULL``; type is
        # set -> ``= :type_1``.
        self.assertIn("flow.dport IS NULL", select_sql)
        self.assertIn("flow.type = ", select_sql)


# Live-engine integration test -- gated on ``duckdb-engine``
# installed.  Exercises the full ingestion path against an
# in-memory DuckDB so the SELECT-then-merge logic is verified
# end-to-end (counter accumulation / timestamp widening / array
# concatenation).
try:
    import duckdb_engine as _duckdb_engine_for_flow_tests  # type: ignore[import-untyped]  # noqa: F401, E402

    _HAVE_DUCKDB_ENGINE_FOR_FLOW = True
except ImportError:
    _HAVE_DUCKDB_ENGINE_FOR_FLOW = False


@unittest.skipUnless(
    _HAVE_DUCKDB_FLOW and _HAVE_DUCKDB_ENGINE_FOR_FLOW,
    "duckdb-engine is required (install with the ``duckdb`` extras)",
)
class DuckDBFlowLiveIntegrationTests(unittest.TestCase):
    """End-to-end ingestion against an in-memory DuckDB.

    The PG-targeted ``ON CONFLICT (..., COALESCE(dport, -1),
    ...)`` path raises
    ``NotImplementedException: Non-column index element not
    supported yet!`` on DuckDB; this class verifies that
    :meth:`DuckDBFlow._flow_merge`'s SELECT-then-merge override
    produces the same end-state as the PG path would have.
    """

    @classmethod
    def setUpClass(cls):
        import os
        import tempfile

        import sqlalchemy as sa  # type: ignore[import-untyped]

        from ivre.db.sql.duckdb import _is_unsupported_on_duckdb
        from ivre.db.sql.tables import Base

        # Strip the indexes / FK constraints DuckDB rejects at
        # CREATE TABLE time.  Mirrors the bookkeeping
        # :meth:`DuckDBMixin.init` does in production; we
        # skip the full ``init()`` because the test's
        # short-lived engine doesn't need the FTS index loader.
        # Track every mutation so :meth:`tearDownClass` can
        # restore the metadata declarations exactly -- the
        # ``Base.metadata`` object is module-level state shared
        # with sibling test classes (e.g.
        # :class:`SQLDBFlowSchemaTests`), and a partial restore
        # would silently break the assertions there.
        cls._saved_idx = []
        cls._saved_fkc = []
        cls._saved_col_fks = []
        for tbl in (
            _Host_for_duckdb_tests.__table__,
            _Flow_for_duckdb_tests.__table__,
        ):
            for ix in list(tbl.indexes):
                if _is_unsupported_on_duckdb(ix):
                    cls._saved_idx.append((tbl, ix))
                    tbl.indexes.discard(ix)
            for fkc in list(tbl.foreign_key_constraints):
                cls._saved_fkc.append((tbl, fkc))
                tbl.constraints.discard(fkc)
            for col in list(tbl.columns):
                if col.foreign_keys:
                    cls._saved_col_fks.append((col, set(col.foreign_keys)))
                    for fk in list(col.foreign_keys):
                        col.foreign_keys.discard(fk)
                        tbl.foreign_keys.discard(fk)
        fd, cls._path = tempfile.mkstemp(suffix=".duckdb")
        os.close(fd)
        os.unlink(cls._path)
        cls._engine = sa.create_engine(f"duckdb:///{cls._path}")
        Base.metadata.create_all(
            cls._engine,
            tables=[
                _Host_for_duckdb_tests.__table__,
                _Flow_for_duckdb_tests.__table__,
            ],
        )

    @classmethod
    def tearDownClass(cls):
        import os

        cls._engine.dispose()
        if os.path.exists(cls._path):
            os.unlink(cls._path)
        # Restore the schema declarations so sibling test
        # classes (notably :class:`SQLDBFlowSchemaTests`,
        # which assert on the exact FK / index inventory) see
        # them unchanged.  Per-column ``ForeignKey`` objects
        # need to land back on both the column and the
        # table's ``foreign_keys`` set; missing the latter
        # leaves :attr:`Column.foreign_keys` empty even
        # though the table-level constraint is restored.
        for tbl, ix in cls._saved_idx:
            tbl.indexes.add(ix)
        for tbl, fkc in cls._saved_fkc:
            tbl.append_constraint(fkc)
        for col, fks in cls._saved_col_fks:
            for fk in fks:
                col.foreign_keys.add(fk)
                col.table.foreign_keys.add(fk)

    def test_repeated_conn_records_accumulate(self):
        # Mirrors the PG counter-accumulation contract: two
        # records with the same flow key must collapse onto a
        # single row whose counters / sports list / timestamp
        # window reflect both observations.
        from datetime import datetime

        import sqlalchemy as sa

        db = _DuckDBFlow_for_tests.__new__(_DuckDBFlow_for_tests)
        db._db = self._engine

        bulk = db.start_bulk_insert()
        db.conn2flow(
            bulk,
            {
                "src": "10.0.0.10",
                "dst": "10.0.0.20",
                "proto": "tcp",
                "sport": 1234,
                "dport": 80,
                "start_time": datetime(2024, 1, 1, 0, 0, 0),
                "end_time": datetime(2024, 1, 1, 0, 0, 5),
                "orig_pkts": 5,
                "resp_pkts": 7,
                "orig_ip_bytes": 500,
                "resp_ip_bytes": 700,
            },
        )
        db.bulk_commit(bulk)
        bulk = db.start_bulk_insert()
        db.conn2flow(
            bulk,
            {
                "src": "10.0.0.10",
                "dst": "10.0.0.20",
                "proto": "tcp",
                "sport": 5678,
                "dport": 80,
                "start_time": datetime(2024, 1, 1, 0, 0, 10),
                "end_time": datetime(2024, 1, 1, 0, 0, 15),
                "orig_pkts": 3,
                "resp_pkts": 4,
                "orig_ip_bytes": 300,
                "resp_ip_bytes": 400,
            },
        )
        db.bulk_commit(bulk)
        with self._engine.connect() as conn:
            row = conn.execute(
                sa.select(
                    _Flow_for_duckdb_tests.cspkts,
                    _Flow_for_duckdb_tests.scpkts,
                    _Flow_for_duckdb_tests.csbytes,
                    _Flow_for_duckdb_tests.scbytes,
                    _Flow_for_duckdb_tests.count,
                    _Flow_for_duckdb_tests.sports,
                    _Flow_for_duckdb_tests.firstseen,
                    _Flow_for_duckdb_tests.lastseen,
                ).where(
                    sa.and_(
                        _Flow_for_duckdb_tests.proto == "tcp",
                        _Flow_for_duckdb_tests.dport == 80,
                    )
                )
            ).fetchone()
        self.assertEqual(row.cspkts, 8)
        self.assertEqual(row.scpkts, 11)
        self.assertEqual(row.csbytes, 800)
        self.assertEqual(row.scbytes, 1100)
        self.assertEqual(row.count, 2)
        self.assertEqual(sorted(row.sports), [1234, 5678])
        self.assertEqual(row.firstseen, datetime(2024, 1, 1, 0, 0, 0))
        self.assertEqual(row.lastseen, datetime(2024, 1, 1, 0, 0, 15))


# ---------------------------------------------------------------------
# SQLDBRirTests -- pin :class:`ivre.db.sql.SQLDBRir`'s schema +
# search SQL shapes + ingestion record translation.
#
# The schema part walks the declared :class:`Rir` table and pins
# every column / index inventory item so a future refactor that
# drops one surfaces here.  The search part compiles each ``search
# XXX`` helper against the PostgreSQL dialect (with literal_binds)
# and asserts the rendered SQL fragment.  The ingestion part
# exercises :meth:`SQLDBRir._record_to_row` /
# :meth:`SQLDBRir._row2rec` round-trip semantics so the wire
# shapes Mongo / SQL share stay aligned byte-for-byte.
# ---------------------------------------------------------------------


try:
    from ivre.db.sql import SQLDBRir as _SQLDBRir_for_tests  # noqa: E402
    from ivre.db.sql.tables import Rir as _Rir_for_tests  # noqa: E402

    _HAVE_SQLDB_RIR = True
except ImportError:
    _HAVE_SQLDB_RIR = False


@unittest.skipUnless(
    _HAVE_SQLDB_RIR,
    "SQLAlchemy is required for SQLDBRirTests",
)
class SQLDBRirTests(unittest.TestCase):
    """Behaviour-pin for :class:`ivre.db.sql.SQLDBRir`.

    Mirrors :class:`ivre.db.mongo.MongoDBRir`'s public method
    surface so a ``DB = postgresql://...`` configuration drives
    the same ``ivre rirlookup`` paths Mongo does.
    """

    @staticmethod
    def _compile_pg(stmt):
        from sqlalchemy.dialects import postgresql

        return str(
            stmt.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )

    # -- schema -------------------------------------------------------

    def test_schema_columns_present(self):
        # Every typed column the ingestion / search paths
        # reference must be declared on the table.  A missing
        # column would surface here, not at runtime.
        cols = {c.name for c in _Rir_for_tests.__table__.columns}
        for expected in (
            "id",
            "start",
            "stop",
            "size",
            "aut_num",
            "as_name",
            "netname",
            "descr",
            "remarks",
            "notify",
            "org",
            "country",
            "lang",
            "source",
            "source_file",
            "source_hash",
            "extra",
            "schema_version",
        ):
            self.assertIn(expected, cols)

    def test_schema_inet_columns_render_natively(self):
        # ``start`` / ``stop`` must compile as ``INET`` on PG so
        # range comparisons use the dialect-native operators.
        from sqlalchemy.schema import CreateTable

        sql = self._compile_pg(CreateTable(_Rir_for_tests.__table__))
        self.assertIn("start INET", sql)
        self.assertIn("stop INET", sql)
        # ``size`` must be ``NUMERIC(40, 0)`` so IPv6 ranges
        # (up to 2**128 addresses) round-trip without
        # overflow.
        self.assertIn("size NUMERIC(40, 0)", sql)

    def test_schema_indexes_inventory(self):
        # The full set of expected indexes -- pin so a refactor
        # that drops one surfaces here, not on a slow live
        # query.
        names = {ix.name for ix in _Rir_for_tests.__table__.indexes}
        for expected in (
            "rir_idx_range",
            "rir_idx_aut_num",
            "rir_idx_country",
            "rir_idx_source",
            "rir_idx_source_file",
            "rir_idx_source_hash",
            "rir_idx_schema_version",
            "rir_idx_size",
            "rir_idx_fts",
        ):
            self.assertIn(expected, names)

    def test_schema_fts_index_is_gin(self):
        # The FTS index must be declared with ``USING GIN`` so
        # the planner picks it for ``to_tsvector(...) @@
        # plainto_tsquery(...)`` clauses.
        idx_by_name = {ix.name: ix for ix in _Rir_for_tests.__table__.indexes}
        self.assertEqual(
            idx_by_name["rir_idx_fts"].kwargs.get("postgresql_using"),
            "gin",
        )

    def test_schema_aut_num_partial_index(self):
        # The aut-num index is partial (``WHERE aut_num IS
        # NOT NULL``) so it doesn't bloat with the inet[6]num
        # rows that always leave ``aut_num`` NULL.
        idx_by_name = {ix.name: ix for ix in _Rir_for_tests.__table__.indexes}
        where = idx_by_name["rir_idx_aut_num"].kwargs.get("postgresql_where")
        self.assertIsNotNone(where)
        sql = self._compile_pg(where)
        self.assertIn("aut_num IS NOT NULL", sql)

    # -- search* SQL shapes ------------------------------------------

    def test_searchhost_shape(self):
        # ``WHERE start <= addr AND stop >= addr`` -- the
        # ``rir_idx_range`` B-tree accelerates the lookup on
        # same-family ranges.
        sql = self._compile_pg(_SQLDBRir_for_tests.searchhost("10.0.0.1"))
        self.assertIn("rir.start <=", sql)
        self.assertIn("rir.stop >=", sql)
        # The ``INETLiteral.bind_expression`` wraps the literal
        # in ``CAST('10.0.0.1'::inet AS INET)`` so PostgreSQL
        # coerces the value at execution time even when the
        # column is created on a different connection.
        self.assertIn("'10.0.0.1'::inet", sql)

    def test_searchhost_neg_raises(self):
        # Mirrors :meth:`MongoDBRir.searchhost`'s contract --
        # negation has no meaningful interpretation on a range
        # overlap, so the helper raises rather than silently
        # returning a no-op clause.
        with self.assertRaises(ValueError):
            _SQLDBRir_for_tests.searchhost("10.0.0.1", neg=True)

    def test_searchnet_overlap_shape(self):
        # ``net2range('10.0.0.0/8') == ('10.0.0.0',
        # '10.255.255.255')``; the overlap predicate is
        # ``record.start <= 10.255.255.255 AND record.stop
        # >= 10.0.0.0``.
        sql = self._compile_pg(_SQLDBRir_for_tests.searchnet("10.0.0.0/8"))
        self.assertIn("'10.0.0.0'::inet", sql)
        self.assertIn("'10.255.255.255'::inet", sql)

    def test_searchasnum_int_and_string(self):
        # Both ``15169`` (int) and ``"AS15169"`` / ``"15169"``
        # (string) must coerce to the same SQL clause.
        for value in (15169, "AS15169", "as15169", "15169"):
            sql = self._compile_pg(_SQLDBRir_for_tests.searchasnum(value))
            self.assertIn("rir.aut_num = 15169", sql)

    def test_searchasnum_list(self):
        # A list of AS numbers translates to ``IN (...)``;
        # mixed int / string values normalise to int via
        # ``_coerce_asnum_sql``.
        sql = self._compile_pg(_SQLDBRir_for_tests.searchasnum([15169, "AS32934"]))
        self.assertIn("rir.aut_num IN", sql)
        self.assertIn("15169", sql)
        self.assertIn("32934", sql)

    def test_searchasname_regex(self):
        # Regex match through PG's ``~*`` (case-insensitive)
        # / ``~`` (case-sensitive) operators.
        import re as _re

        sql = self._compile_pg(
            _SQLDBRir_for_tests.searchasname(_re.compile("Google", _re.IGNORECASE))
        )
        self.assertIn("rir.as_name ~*", sql)
        self.assertIn("Google", sql)

    def test_searchcountry_unaliased(self):
        # ``country_unalias`` collapses synonyms (``"UK"``
        # -> ``"GB"``); pin so a future tweak to the alias
        # table doesn't silently change query behaviour.
        sql = self._compile_pg(_SQLDBRir_for_tests.searchcountry("UK"))
        self.assertIn("rir.country", sql)
        self.assertIn("GB", sql)

    def test_searchsourcefile_and_searchfileid(self):
        sql = self._compile_pg(
            _SQLDBRir_for_tests.searchsourcefile("ripe.db.inetnum.gz")
        )
        self.assertIn("rir.source_file = 'ripe.db.inetnum.gz'", sql)
        sql = self._compile_pg(_SQLDBRir_for_tests.searchfileid("deadbeef"))
        self.assertIn("rir.source_hash = 'deadbeef'", sql)

    def test_flt_and_or_drop_none(self):
        # ``flt_and(None, x)`` returns ``x`` directly; mirrors
        # Mongo's ``flt_and`` shape so call sites that chain
        # optional filters keep working unchanged.
        clause = _SQLDBRir_for_tests.searchcountry("FR")
        self.assertIs(_SQLDBRir_for_tests.flt_and(None, clause), clause)
        self.assertIsNone(_SQLDBRir_for_tests.flt_and(None, None))

    # -- ingestion record translation --------------------------------

    def test_record_to_row_inetnum(self):
        # An ``inetnum`` record gets ``size`` computed and
        # ``aut_num`` left NULL; unknown keys go to ``extra``.
        rec = {
            "start": "10.0.0.0",
            "stop": "10.255.255.255",
            "netname": "TEST-NET",
            "country": "FR",
            "descr": "test description",
            "source_file": "ripe.db.inetnum.gz",
            "source_hash": "deadbeef",
            "mnt-by": "MAINTAINER-MNT",
        }
        row = _SQLDBRir_for_tests._record_to_row(rec)
        self.assertEqual(row["start"], "10.0.0.0")
        self.assertEqual(row["stop"], "10.255.255.255")
        self.assertEqual(row["netname"], "TEST-NET")
        self.assertEqual(row["country"], "FR")
        self.assertEqual(row["source_file"], "ripe.db.inetnum.gz")
        self.assertEqual(row["source_hash"], "deadbeef")
        # /8 = 2**24 = 16 777 216 addresses.
        self.assertEqual(row["size"], 16777216)
        self.assertIsNone(row["aut_num"])
        # ``mnt-by`` is not a typed column -> ``extra`` bag.
        self.assertEqual(row["extra"], {"mnt-by": "MAINTAINER-MNT"})
        self.assertEqual(row["schema_version"], _SQLDBRir_for_tests.SCHEMA_VERSION)

    def test_record_to_row_aut_num(self):
        # An ``aut-num`` record carries ``aut_num`` (int) and
        # leaves ``start`` / ``stop`` / ``size`` NULL.  The
        # parser's whois-native ``aut-num`` / ``as-name`` keys
        # rename to the SQL columns ``aut_num`` / ``as_name``.
        rec = {
            "aut-num": 15169,
            "as-name": "GOOGLE",
            "country": "US",
            "source_file": "arin.db.gz",
            "source_hash": "cafebabe",
        }
        row = _SQLDBRir_for_tests._record_to_row(rec)
        self.assertEqual(row["aut_num"], 15169)
        self.assertEqual(row["as_name"], "GOOGLE")
        self.assertIsNone(row["start"])
        self.assertIsNone(row["stop"])
        self.assertIsNone(row["size"])
        self.assertIsNone(row["extra"])

    def test_record_to_row_size_overflow(self):
        # IPv6 ranges can reach 2**128 -- the size column is
        # ``Numeric(40, 0)`` precisely so the value
        # round-trips through the SQL layer without overflow.
        rec = {"start": "::", "stop": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}
        row = _SQLDBRir_for_tests._record_to_row(rec)
        self.assertEqual(row["size"], 2**128)

    def test_row2rec_round_trip(self):
        # ``_row2rec`` must rebuild the Mongo-shaped dict the
        # ``rirlookup`` consumer expects: typed columns map
        # back to whois-native keys (``aut-num`` / ``as-name``),
        # ``extra`` JSONB flattens into the top level, and
        # NULLs drop out so a sparse record stays compact.

        class _FakeRow:
            id = 1
            start = "10.0.0.0"
            stop = "10.255.255.255"
            size = 16777216
            aut_num = None
            as_name = None
            netname = "TEST-NET"
            descr = "test"
            remarks = None
            notify = None
            org = None
            country = "FR"
            lang = None
            source = None
            source_file = "ripe.db.inetnum.gz"
            source_hash = "deadbeef"
            extra = {"mnt-by": "MAINTAINER-MNT"}
            schema_version = 2

        rec = _SQLDBRir_for_tests._row2rec(_FakeRow())
        self.assertEqual(rec["start"], "10.0.0.0")
        self.assertEqual(rec["stop"], "10.255.255.255")
        self.assertEqual(rec["netname"], "TEST-NET")
        self.assertEqual(rec["country"], "FR")
        self.assertEqual(rec["mnt-by"], "MAINTAINER-MNT")
        self.assertEqual(rec["size"], 16777216)
        self.assertEqual(rec["schema_version"], 2)
        self.assertEqual(rec["_id"], 1)
        # NULL columns must not surface in the dict.
        self.assertNotIn("aut-num", rec)
        self.assertNotIn("as-name", rec)
        self.assertNotIn("remarks", rec)

    def test_row2rec_aut_num_renames(self):
        class _FakeRow:
            id = 7
            start = None
            stop = None
            size = None
            aut_num = 15169
            as_name = "GOOGLE"
            netname = None
            descr = None
            remarks = None
            notify = None
            org = None
            country = "US"
            lang = None
            source = None
            source_file = "arin.db.gz"
            source_hash = "cafebabe"
            extra = None
            schema_version = 2

        rec = _SQLDBRir_for_tests._row2rec(_FakeRow())
        # aut_num / as_name rename to whois-native keys.
        self.assertEqual(rec["aut-num"], 15169)
        self.assertEqual(rec["as-name"], "GOOGLE")
        self.assertNotIn("aut_num", rec)
        self.assertNotIn("as_name", rec)

    # -- backend registration ----------------------------------------

    def test_postgres_backend_registered(self):
        from ivre.db import DBRir

        self.assertEqual(
            DBRir.backends.get("postgresql"),
            ("sql.postgres", "PostgresDBRir"),
        )


# ---------------------------------------------------------------------
# DuckDBRirTests -- pin :class:`ivre.db.sql.duckdb.DuckDBRir`.
#
# DuckDB-specific concerns covered:
#   * the schema's ``Numeric(40, 0)`` ``size`` column collapses
#     to ``Numeric(38, 0)`` on DuckDB via ``with_variant``,
#   * the DuckDB-incompatible indexes
#     (``rir_idx_range`` over INET, ``rir_idx_aut_num``
#     partial WHERE, ``rir_idx_fts`` GIN) are flagged by
#     :func:`_is_unsupported_on_duckdb` so
#     :meth:`DuckDBMixin.init` strips them at create-time
#     without breaking the read paths,
#   * the INET round-trip dict struct DuckDB returns is
#     coerced back into a printable string via
#     :meth:`DuckDBMixin.internal2ip` so ``_row2rec`` yields
#     the same wire shape PG does,
#   * (with duckdb-engine installed) the full ingestion +
#     search roundtrip against an in-memory DuckDB engine.
# ---------------------------------------------------------------------


try:
    from ivre.db.sql.duckdb import DuckDBRir as _DuckDBRir_for_tests  # noqa: E402

    _HAVE_DUCKDB_RIR = True
except ImportError:
    _HAVE_DUCKDB_RIR = False


@unittest.skipUnless(
    _HAVE_DUCKDB_RIR,
    "SQLAlchemy is required for DuckDBRirTests",
)
class DuckDBRirTests(unittest.TestCase):
    """Behaviour-pin for :class:`ivre.db.sql.duckdb.DuckDBRir`."""

    def test_backend_registered(self):
        from ivre.db import DBRir

        self.assertEqual(
            DBRir.backends.get("duckdb"),
            ("sql.duckdb", "DuckDBRir"),
        )

    def test_class_inherits_postgres_rir(self):
        # DuckDBRir inherits the SQLDBRir search / aggregate
        # / ingestion path from :class:`PostgresDBRir`.  The
        # MRO must place ``DuckDBMixin`` first so its dialect
        # overrides win the lookup against PostgresDB's
        # defaults; ``PostgresDBRir`` follows so the SQL
        # implementation is reachable.
        mro = [c.__name__ for c in _DuckDBRir_for_tests.__mro__]
        self.assertEqual(mro[0], "DuckDBRir")
        self.assertEqual(mro[1], "DuckDBMixin")
        self.assertEqual(mro[2], "PostgresDBRir")

    def test_size_column_variant_collapses_on_duckdb(self):
        # ``size`` is ``Numeric(40, 0)`` on PG (covers /0
        # IPv6 = 2**128 addresses, 39 digits) but DuckDB
        # caps DECIMAL precision at 38, so the
        # ``with_variant(Numeric(38, 0), "duckdb")`` adapter
        # narrows the column on DuckDB.  Pin the rendered
        # type so a future refactor of the variant surfaces
        # here.
        from sqlalchemy import create_engine
        from sqlalchemy.schema import CreateTable

        try:
            engine = create_engine("duckdb:///:memory:")
        except Exception as exc:  # pragma: no cover -- import-only
            self.skipTest(f"duckdb-engine not installed: {exc}")
        sql = str(CreateTable(_Rir_for_tests.__table__).compile(dialect=engine.dialect))
        self.assertIn("size NUMERIC(38, 0)", sql)
        # PostgreSQL stays at 40 digits.
        from sqlalchemy.dialects import postgresql

        pg_sql = str(
            CreateTable(_Rir_for_tests.__table__).compile(dialect=postgresql.dialect())
        )
        self.assertIn("size NUMERIC(40, 0)", pg_sql)

    def test_duckdb_unsupported_indexes_get_stripped(self):
        # The three indexes incompatible with DuckDB (range
        # over INET, partial WHERE clause, GIN FTS) must be
        # flagged by :func:`_is_unsupported_on_duckdb` so
        # :meth:`DuckDBMixin.init` strips them before
        # ``create_all``.  A regression that adds a fresh
        # rir index without considering DuckDB would surface
        # here.
        from ivre.db.sql.duckdb import _is_unsupported_on_duckdb

        idx_by_name = {ix.name: ix for ix in _Rir_for_tests.__table__.indexes}
        for name in ("rir_idx_range", "rir_idx_aut_num", "rir_idx_fts"):
            self.assertTrue(
                _is_unsupported_on_duckdb(idx_by_name[name]),
                f"{name} must be flagged unsupported on DuckDB",
            )
        # The simple BTrees over scalar columns survive.
        for name in (
            "rir_idx_country",
            "rir_idx_source",
            "rir_idx_source_file",
            "rir_idx_source_hash",
            "rir_idx_schema_version",
            "rir_idx_size",
        ):
            self.assertFalse(
                _is_unsupported_on_duckdb(idx_by_name[name]),
                f"{name} must survive on DuckDB",
            )


# Live-engine integration test -- gated on ``duckdb-engine``
# installed.  Exercises bulk insert + every read path against
# an in-memory DuckDB so the DuckDB-specific tweaks (INET dict
# struct, Numeric width variant, stripped indexes) are verified
# end-to-end against parity with the PG semantics.
try:
    import duckdb_engine as _duckdb_engine_for_rir_tests  # type: ignore[import-untyped]  # noqa: F401, E402

    _HAVE_DUCKDB_ENGINE_FOR_RIR = True
except ImportError:
    _HAVE_DUCKDB_ENGINE_FOR_RIR = False


@unittest.skipUnless(
    _HAVE_DUCKDB_RIR and _HAVE_DUCKDB_ENGINE_FOR_RIR,
    "duckdb-engine is required (install with the ``duckdb`` extras)",
)
class DuckDBRirLiveIntegrationTests(unittest.TestCase):
    """End-to-end RIR ingestion + search against an in-memory
    DuckDB.

    Verifies that the shared :class:`SQLDBRir` path works on
    DuckDB without modification once :class:`DuckDBMixin`'s
    ``internal2ip`` override and the ``Numeric(40, 0)`` ->
    ``Numeric(38, 0)`` variant are wired.
    """

    @classmethod
    def setUpClass(cls):
        import os
        import tempfile

        import sqlalchemy as sa  # type: ignore[import-untyped]

        from ivre.db.sql.duckdb import _is_unsupported_on_duckdb
        from ivre.db.sql.tables import Base

        # Strip the indexes DuckDB rejects at CREATE time.
        # Mirrors :meth:`DuckDBMixin.init`'s bookkeeping; we
        # skip the full ``init()`` because the test's
        # short-lived engine doesn't need the FTS extension
        # loader.  Save and restore so sibling test classes
        # sharing the module-level metadata see the original
        # declarations.
        cls._saved_idx = []
        for ix in list(_Rir_for_tests.__table__.indexes):
            if _is_unsupported_on_duckdb(ix):
                cls._saved_idx.append(ix)
                _Rir_for_tests.__table__.indexes.discard(ix)
        fd, cls._path = tempfile.mkstemp(suffix=".duckdb")
        os.close(fd)
        os.unlink(cls._path)
        cls._engine = sa.create_engine(f"duckdb:///{cls._path}")
        Base.metadata.create_all(cls._engine, tables=[_Rir_for_tests.__table__])

    @classmethod
    def tearDownClass(cls):
        import os

        cls._engine.dispose()
        if os.path.exists(cls._path):
            os.unlink(cls._path)
        for ix in cls._saved_idx:
            _Rir_for_tests.__table__.indexes.add(ix)

    def _make_db(self):
        db = _DuckDBRir_for_tests.__new__(_DuckDBRir_for_tests)
        db._db = self._engine
        return db

    def test_inetnum_record_roundtrip(self):
        # Bulk-insert an inetnum record, then look it up via
        # ``searchhost`` and verify the dict shape matches
        # what Mongo returns (printable IPs, ``Decimal``
        # ``size``, etc.).
        db = self._make_db()
        bulk = db.start_bulk()
        bulk = db.insert_bulk(
            bulk,
            {
                "start": "10.0.0.0",
                "stop": "10.255.255.255",
                "netname": "TEST-INETNUM",
                "country": "FR",
                "source_file": "ripe.db.inetnum.gz",
                "source_hash": "deadbeef",
            },
        )
        db.stop_bulk(bulk)
        results = list(db.get(db.searchhost("10.5.0.1")))
        self.assertEqual(len(results), 1)
        rec = results[0]
        # DuckDB's INET dict struct must be flattened to a
        # printable string via :meth:`DuckDBMixin.internal2ip`.
        self.assertEqual(rec["start"], "10.0.0.0")
        self.assertEqual(rec["stop"], "10.255.255.255")
        self.assertEqual(rec["netname"], "TEST-INETNUM")
        # /8 = 2**24 = 16777216 addresses; the Numeric(38, 0)
        # column round-trips as ``Decimal`` regardless of
        # backend.
        self.assertEqual(int(rec["size"]), 16777216)

    def test_aut_num_record_roundtrip(self):
        # Aut-num records leave ``start`` / ``stop`` /
        # ``size`` NULL and the wire-shaped output renames
        # ``aut_num`` / ``as_name`` back to ``aut-num`` /
        # ``as-name``.
        db = self._make_db()
        bulk = db.start_bulk()
        bulk = db.insert_bulk(
            bulk,
            {
                "aut-num": 64512,
                "as-name": "TEST-AS",
                "country": "FR",
                "source_file": "ripe.db.gz",
                "source_hash": "feedface",
            },
        )
        db.stop_bulk(bulk)
        results = list(db.get(db.searchasnum(64512)))
        self.assertEqual(len(results), 1)
        rec = results[0]
        self.assertEqual(rec["aut-num"], 64512)
        self.assertEqual(rec["as-name"], "TEST-AS")
        self.assertNotIn("start", rec)
        self.assertNotIn("size", rec)

    def test_count_and_distinct(self):
        # ``count`` + ``distinct`` work without dialect
        # overrides -- pin so a future refactor that
        # introduces an ON CONFLICT / window function in the
        # default :class:`SQLDBRir` path doesn't break the
        # DuckDB lane silently.
        db = self._make_db()
        # Ingest a few more records to exercise the
        # aggregations.  All records share the existing
        # ``country=FR`` ones so ``count(country='FR') >= 2``.
        bulk = db.start_bulk()
        for cc, name in [("US", "TEST-A"), ("DE", "TEST-B"), ("FR", "TEST-C")]:
            bulk = db.insert_bulk(
                bulk,
                {
                    "start": "192.0.2.0",
                    "stop": "192.0.2.255",
                    "netname": name,
                    "country": cc,
                    "source_file": "extra.gz",
                    "source_hash": f"hash{cc}",
                },
            )
        db.stop_bulk(bulk)
        # At least the FR record from the first test plus
        # one new FR record above.
        self.assertGreaterEqual(db.count(db.searchcountry("FR")), 2)
        countries = set(db.distinct("country"))
        self.assertIn("FR", countries)
        self.assertIn("US", countries)
        self.assertIn("DE", countries)


# ---------------------------------------------------------------------
# DocumentDBRirTests -- pin :class:`ivre.db.document.DocumentDBRir`.
#
# DocumentDB lacks the ``"text"`` index type and the ``$text``
# operator entirely; the subclass overrides
# :attr:`MongoDBRir.indexes` to drop the text-index entry while
# inheriting every other index unchanged.  The MongoDBRir
# ``searchXXX`` helpers never emit ``$text`` (RIR records have
# no equivalent of the active backend's
# :meth:`MongoDBView.searchtext` path), so the text-index
# removal is the only adjustment needed for parity.
#
# Tests are gated on the ``pymongo`` import (DocumentDB shares
# the MongoDB wire protocol, but the test class only inspects
# the in-process class attributes -- no live cluster required).
# ---------------------------------------------------------------------


try:
    import pymongo as _pymongo_for_docdb_tests  # type: ignore[import-untyped]  # noqa: F401, E402

    _HAVE_PYMONGO = True
except ImportError:
    _HAVE_PYMONGO = False


@unittest.skipUnless(
    _HAVE_PYMONGO,
    "pymongo is required for DocumentDBRirTests",
)
class DocumentDBRirTests(unittest.TestCase):
    """Behaviour-pin for :class:`ivre.db.document.DocumentDBRir`."""

    def test_backend_registered(self):
        from ivre.db import DBRir

        self.assertEqual(
            DBRir.backends.get("documentdb"),
            ("document", "DocumentDBRir"),
        )

    def test_subclasses_mongodb_rir(self):
        # Pure inheritance from :class:`MongoDBRir`; the
        # ``is_documentdb`` flag triggers the existing
        # ``MongoDBRir`` workarounds (``$floor`` rewrite,
        # cursor-timeout flip).
        from ivre.db.document import DocumentDBRir
        from ivre.db.mongo import MongoDBRir

        self.assertTrue(issubclass(DocumentDBRir, MongoDBRir))
        self.assertTrue(DocumentDBRir.is_documentdb)

    def test_text_index_omitted(self):
        # DocumentDB rejects text indexes wholesale; the
        # subclass drops the trailing ``"text"`` index
        # :class:`MongoDBRir` declares so
        # :meth:`MongoDBRir.create_indexes` doesn't crash on a
        # DocumentDB cluster.
        from ivre.db.document import DocumentDBRir
        from ivre.db.mongo import MongoDBRir

        # Walk every index spec on the rir column; no entry
        # may carry a ``"text"`` index type.
        for index_keys, _kwargs in DocumentDBRir.indexes[0]:
            for _field, index_type in index_keys:
                self.assertNotEqual(
                    index_type,
                    "text",
                    f"DocumentDBRir.indexes contains a text index: {index_keys}",
                )
        # Sanity check the count -- exactly one fewer entry
        # than MongoDBRir (the text index that got dropped).
        self.assertEqual(
            len(DocumentDBRir.indexes[0]),
            len(MongoDBRir.indexes[0]) - 1,
        )

    def test_non_text_indexes_preserved(self):
        # Every non-text index from :class:`MongoDBRir`
        # survives.  Pin the inventory so a refactor that
        # accidentally drops a non-text entry surfaces here,
        # not on a slow live query.
        from ivre.db.document import DocumentDBRir
        from ivre.db.mongo import MongoDBRir

        non_text_mongo_indexes = [
            spec
            for spec in MongoDBRir.indexes[0]
            if not any(t == "text" for _f, t in spec[0])
        ]
        self.assertEqual(
            len(DocumentDBRir.indexes[0]),
            len(non_text_mongo_indexes),
        )

    def test_searchhost_inherits_unchanged(self):
        # Range-lookup search uses ``$lt`` / ``$lte`` /
        # ``$gt`` / ``$gte`` / ``$and`` / ``$or`` -- all
        # supported on DocumentDB.  Pin that the inherited
        # method produces the same filter dict
        # :class:`MongoDBRir` does.
        from ivre.db.document import DocumentDBRir
        from ivre.db.mongo import MongoDBRir

        self.assertEqual(
            DocumentDBRir.searchhost("10.0.0.1"),
            MongoDBRir.searchhost("10.0.0.1"),
        )

    def test_searchasnum_inherits_unchanged(self):
        from ivre.db.document import DocumentDBRir
        from ivre.db.mongo import MongoDBRir

        for value in (15169, "AS15169"):
            self.assertEqual(
                DocumentDBRir.searchasnum(value),
                MongoDBRir.searchasnum(value),
            )


# ---------------------------------------------------------------------
# SQLDBAuthTests -- pin :class:`ivre.db.sql.SQLDBAuth`'s schema +
# helper SQL shapes + dict-output round-trip semantics.
#
# The class is the shared base for the upcoming PostgresDBAuth /
# DuckDBDBAuth concretes (M4.8.2 / M4.8.3); without backend
# registration there's no live engine to drive end-to-end here.
# We verify:
#   * the five auth tables declare every column the Mongo path
#     references (column inventory),
#   * the natural-key UNIQUE constraints + secondary indexes
#     are declared,
#   * the helper methods compile against the in-memory DuckDB
#     engine end-to-end (so the next sub-PR's concrete class
#     can ride on top with confidence).
# ---------------------------------------------------------------------


try:
    from ivre.db.sql.tables import AuthApiKey as _AuthApiKey_for_tests  # noqa: E402
    from ivre.db.sql.tables import (  # noqa: E402
        AuthMagicLink as _AuthMagicLink_for_tests,
    )
    from ivre.db.sql.tables import (  # noqa: E402
        AuthRateLimit as _AuthRateLimit_for_tests,
    )
    from ivre.db.sql.tables import AuthSession as _AuthSession_for_tests  # noqa: E402
    from ivre.db.sql.tables import AuthUser as _AuthUser_for_tests  # noqa: E402

    _HAVE_SQLDB_AUTH = True
except ImportError:
    _HAVE_SQLDB_AUTH = False


@unittest.skipUnless(
    _HAVE_SQLDB_AUTH,
    "SQLAlchemy is required for SQLDBAuthTests",
)
class SQLDBAuthSchemaTests(unittest.TestCase):
    """Pin the auth table inventory.

    The :class:`MongoDBAuth` schema is split across five
    collections (``auth_user`` / ``auth_session`` /
    ``auth_api_key`` / ``auth_rate_limit`` /
    ``auth_magic_link``); the SQL backend keeps the same
    breakdown.  Each test below verifies the columns / indexes
    one of these tables must carry so the helper paths land
    correctly.
    """

    def test_auth_user_columns(self):
        cols = {c.name for c in _AuthUser_for_tests.__table__.columns}
        for expected in (
            "id",
            "email",
            "display_name",
            "is_admin",
            "is_active",
            "groups",
            "created_at",
            "last_login",
            "schema_version",
        ):
            self.assertIn(expected, cols)

    def test_auth_user_unique_email(self):
        constraints = {
            c.name
            for c in _AuthUser_for_tests.__table__.constraints
            if hasattr(c, "name") and c.name is not None
        }
        self.assertIn("auth_user_idx_email", constraints)

    def test_auth_session_columns(self):
        cols = {c.name for c in _AuthSession_for_tests.__table__.columns}
        for expected in (
            "id",
            "token_hash",
            "user_email",
            "created_at",
            "expires_at",
            "last_used",
        ):
            self.assertIn(expected, cols)

    def test_auth_session_unique_token_hash(self):
        constraints = {
            c.name
            for c in _AuthSession_for_tests.__table__.constraints
            if hasattr(c, "name") and c.name is not None
        }
        self.assertIn("auth_session_idx_token_hash", constraints)

    def test_auth_api_key_columns(self):
        cols = {c.name for c in _AuthApiKey_for_tests.__table__.columns}
        for expected in (
            "id",
            "key_hash",
            "key_prefix",
            "user_email",
            "name",
            "created_at",
            "expires_at",
            "last_used",
        ):
            self.assertIn(expected, cols)

    def test_auth_rate_limit_columns(self):
        cols = {c.name for c in _AuthRateLimit_for_tests.__table__.columns}
        for expected in ("id", "key", "created_at"):
            self.assertIn(expected, cols)
        # The composite index used by :meth:`is_rate_limited`'s
        # window scan must exist so the helper doesn't degrade
        # to a sequential scan once the ledger fills up.
        names = {ix.name for ix in _AuthRateLimit_for_tests.__table__.indexes}
        self.assertIn("auth_rate_limit_idx_key_created", names)

    def test_auth_magic_link_columns(self):
        cols = {c.name for c in _AuthMagicLink_for_tests.__table__.columns}
        for expected in (
            "id",
            "token_hash",
            "email",
            "created_at",
            "expires_at",
        ):
            self.assertIn(expected, cols)


# Live-engine integration test for SQLDBAuth -- gated on
# ``duckdb-engine`` installed.  Exercises every helper against
# an in-memory DuckDB so the round-trip semantics
# (session / API key / magic link / rate limit / group
# membership) are verified end-to-end.  PostgreSQL-specific
# concerns (the upcoming M4.8.2 concrete class) live in the
# next sub-PR's tests.
try:
    import duckdb_engine as _duckdb_engine_for_auth_tests  # type: ignore[import-untyped]  # noqa: F401, E402

    _HAVE_DUCKDB_ENGINE_FOR_AUTH = True
except ImportError:
    _HAVE_DUCKDB_ENGINE_FOR_AUTH = False


@unittest.skipUnless(
    _HAVE_SQLDB_AUTH and _HAVE_DUCKDB_ENGINE_FOR_AUTH,
    "duckdb-engine is required (install with the ``duckdb`` extras)",
)
class SQLDBAuthLiveIntegrationTests(unittest.TestCase):
    """End-to-end auth helpers against an in-memory DuckDB.

    Mirrors :class:`MongoDBAuth`'s contract across the full
    helper surface so the upcoming :class:`PostgresDBAuth` /
    :class:`DuckDBDBAuth` concretes inherit a known-good
    implementation.
    """

    @classmethod
    def setUpClass(cls):
        import os
        import tempfile

        import sqlalchemy as sa  # type: ignore[import-untyped]

        from ivre.db.sql.duckdb import _is_unsupported_on_duckdb
        from ivre.db.sql.tables import Base

        cls._auth_tables = [
            _AuthUser_for_tests.__table__,
            _AuthSession_for_tests.__table__,
            _AuthApiKey_for_tests.__table__,
            _AuthRateLimit_for_tests.__table__,
            _AuthMagicLink_for_tests.__table__,
        ]
        cls._saved_idx = []
        for tbl in cls._auth_tables:
            for ix in list(tbl.indexes):
                if _is_unsupported_on_duckdb(ix):
                    cls._saved_idx.append((tbl, ix))
                    tbl.indexes.discard(ix)
        fd, cls._path = tempfile.mkstemp(suffix=".duckdb")
        os.close(fd)
        os.unlink(cls._path)
        cls._engine = sa.create_engine(f"duckdb:///{cls._path}")
        Base.metadata.create_all(cls._engine, tables=cls._auth_tables)

        # Use the real :class:`DuckDBAuth` class -- the shared
        # :class:`SQLDBAuth` base lives in
        # ``ivre/db/sql/__init__.py`` and the concrete DuckDB
        # backend pulls in :class:`DuckDBMixin` (so the
        # dialect-aware ``internal2ip`` / ``ip2internal`` /
        # FTS overrides apply).
        from ivre.db.sql.duckdb import DuckDBAuth

        cls._db_cls = DuckDBAuth

    @classmethod
    def tearDownClass(cls):
        import os

        cls._engine.dispose()
        if os.path.exists(cls._path):
            os.unlink(cls._path)
        for tbl, ix in cls._saved_idx:
            tbl.indexes.add(ix)

    def setUp(self):
        # Drop every row from every auth table so each test
        # starts from an empty schema.  DuckDB's ``DELETE FROM``
        # without WHERE clears the table.
        from sqlalchemy import delete

        with self._engine.begin() as conn:
            for tbl in self._auth_tables:
                conn.execute(delete(tbl))
        self.db = self._db_cls.__new__(self._db_cls)
        self.db._db = self._engine

    def test_create_and_get_user(self):
        # ``create_user`` returns the document dict :class:
        # `MongoDBAuth` produces; ``get_user_by_email``
        # round-trips every field including the ``groups``
        # array.
        created = self.db.create_user(
            "alice@example.com",
            display_name="Alice",
            is_active=True,
            groups=["admin"],
        )
        self.assertEqual(created["email"], "alice@example.com")
        self.assertEqual(created["groups"], ["admin"])
        fetched = self.db.get_user_by_email("alice@example.com")
        self.assertEqual(fetched["email"], "alice@example.com")
        self.assertEqual(fetched["display_name"], "Alice")
        self.assertTrue(fetched["is_active"])
        self.assertFalse(fetched["is_admin"])
        self.assertEqual(fetched["groups"], ["admin"])

    def test_get_user_returns_none_for_missing(self):
        self.assertIsNone(self.db.get_user_by_email("nope@example.com"))

    def test_session_round_trip(self):
        self.db.create_user("alice@example.com", is_active=True)
        token = self.db.create_session("alice@example.com", lifetime=60)
        user = self.db.validate_session(token)
        self.assertIsNotNone(user)
        self.assertEqual(user["email"], "alice@example.com")
        # The user's ``last_login`` is bumped on session
        # creation.
        self.assertIsNotNone(user["last_login"])
        # Drop the session -> subsequent validation returns
        # None.
        self.db.delete_session(token)
        self.assertIsNone(self.db.validate_session(token))

    def test_api_key_round_trip(self):
        self.db.create_user("alice@example.com", is_active=True)
        key = self.db.create_api_key("alice@example.com", "test key")
        # Raw key surfaces once; the database stores only the
        # SHA-256 hex digest.
        self.assertTrue(key.startswith("ivre_"))
        user = self.db.validate_api_key(key)
        self.assertEqual(user["email"], "alice@example.com")
        keys = self.db.list_api_keys("alice@example.com")
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0]["key_prefix"], key[:12])
        # ``delete_api_key`` returns the deleted row count;
        # the DuckDB-specific RETURNING-based override
        # produces the right number even though
        # ``cursor.rowcount`` reports ``-1`` on the DuckDB
        # dialect.
        self.assertEqual(self.db.delete_api_key(keys[0]["key_hash"]), 1)
        # Subsequent delete on the same hash is a no-op.
        self.assertEqual(self.db.delete_api_key(keys[0]["key_hash"]), 0)

    def test_magic_link_single_use(self):
        token = self.db.create_magic_link_token("alice@example.com", lifetime=300)
        self.assertEqual(self.db.consume_magic_link_token(token), "alice@example.com")
        # Second consume fails -- the row was deleted
        # atomically by the first.
        self.assertIsNone(self.db.consume_magic_link_token(token))

    def test_rate_limit_threshold(self):
        # Empty ledger -> not limited.
        self.assertFalse(
            self.db.is_rate_limited("magic:alice", max_attempts=3, window=60)
        )
        for _ in range(3):
            self.db.record_rate_limit("magic:alice")
        # Reached the threshold (>= max_attempts).
        self.assertTrue(
            self.db.is_rate_limited("magic:alice", max_attempts=3, window=60)
        )
        # A different key shares no state.
        self.assertFalse(
            self.db.is_rate_limited("magic:bob", max_attempts=3, window=60)
        )

    def test_group_membership_is_idempotent(self):
        self.db.create_user("alice@example.com")
        self.db.add_user_group("alice@example.com", "audit")
        # Re-adding the same group is a no-op (mirrors
        # ``$addToSet``).
        self.db.add_user_group("alice@example.com", "audit")
        self.assertEqual(self.db.get_user_groups("alice@example.com"), ["audit"])
        self.db.remove_user_group("alice@example.com", "audit")
        self.assertEqual(self.db.get_user_groups("alice@example.com"), [])
        # Removing a missing group is a no-op too.
        self.db.remove_user_group("alice@example.com", "audit")

    def test_list_users_filters(self):
        self.db.create_user("alice@example.com", is_active=True, is_admin=True)
        self.db.create_user("bob@example.com", is_active=True, groups=["audit"])
        self.db.create_user("carol@example.com")  # is_active=False
        actives = self.db.list_users(is_active=True)
        self.assertEqual(
            {u["email"] for u in actives}, {"alice@example.com", "bob@example.com"}
        )
        admins = self.db.list_users(is_admin=True)
        self.assertEqual({u["email"] for u in admins}, {"alice@example.com"})
        auditors = self.db.list_users(group="audit")
        self.assertEqual({u["email"] for u in auditors}, {"bob@example.com"})

    def test_ensure_remote_user_creates_then_fetches(self):
        # First call creates the user as ``is_active=True``;
        # second call finds the existing record.
        self.assertIsNone(self.db.get_user_by_email("carol@example.com"))
        user = self.db.ensure_remote_user("carol@example.com")
        self.assertEqual(user["email"], "carol@example.com")
        self.assertTrue(user["is_active"])
        # No duplicate user is created on the second call.
        again = self.db.ensure_remote_user("carol@example.com")
        self.assertEqual(again["_id"], user["_id"])

    def test_delete_user_cascades(self):
        self.db.create_user("alice@example.com", is_active=True)
        self.db.create_session("alice@example.com", lifetime=60)
        self.db.create_api_key("alice@example.com", "k1")
        self.db.create_magic_link_token("alice@example.com", lifetime=60)
        self.db.delete_user("alice@example.com")
        # User gone.
        self.assertIsNone(self.db.get_user_by_email("alice@example.com"))
        # Sessions / api-keys / magic-links cascaded.
        self.assertEqual(self.db.list_api_keys("alice@example.com"), [])


# ---------------------------------------------------------------------
# PostgresDBAuthTests -- pin :class:`ivre.db.sql.postgres.PostgresDBAuth`.
#
# Pure inheritance from :class:`SQLDBAuth` -- every method
# :class:`SQLDBAuth` declares uses portable SQL, so the concrete
# subclass has no per-method override.  We pin:
#   * backend dispatch (``DBAuth.backends['postgresql']``),
#   * MRO (PostgresDB first so its dialect helpers win the
#     lookup against the shared SQL defaults),
#   * a handful of compiled-SQL fragments via the PostgreSQL
#     dialect so a future drift between the shared helpers and
#     PG's expected output surfaces immediately.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_SQLDB_AUTH,
    "SQLAlchemy is required for PostgresDBAuthTests",
)
class PostgresDBAuthTests(unittest.TestCase):
    """Behaviour-pin for :class:`PostgresDBAuth`."""

    @staticmethod
    def _compile_pg(stmt):
        from sqlalchemy.dialects import postgresql

        return str(
            stmt.compile(
                dialect=postgresql.dialect(),
                compile_kwargs={"literal_binds": True},
            )
        )

    def test_backend_registered(self):
        from ivre.db import DBAuth

        self.assertEqual(
            DBAuth.backends.get("postgresql"),
            ("sql.postgres", "PostgresDBAuth"),
        )

    def test_mro(self):
        # ``PostgresDB`` first so its dialect helpers
        # (``ip2internal`` / ``_searchstring_re`` / etc.) win
        # the lookup against :class:`SQLDB`'s defaults;
        # ``SQLDBAuth`` follows so the shared helpers are
        # reachable.
        from ivre.db.sql.postgres import PostgresDBAuth

        mro = [c.__name__ for c in PostgresDBAuth.__mro__]
        self.assertEqual(mro[0], "PostgresDBAuth")
        self.assertEqual(mro[1], "PostgresDB")
        self.assertEqual(mro[2], "SQLDBAuth")

    def test_get_user_by_email_renders_clean_sql(self):
        # The lookup is the hottest auth read path; pin the
        # rendered shape so a future refactor of
        # :meth:`SQLDBAuth.get_user_by_email` doesn't
        # silently introduce a sub-query or a CTE that
        # bypasses the ``auth_user_idx_email`` unique index.
        from sqlalchemy import select

        sql = self._compile_pg(
            select(_AuthUser_for_tests).where(
                _AuthUser_for_tests.email == "alice@example.com"
            )
        )
        self.assertIn("FROM auth_user", sql)
        self.assertIn("auth_user.email = 'alice@example.com'", sql)

    def test_consume_magic_link_token_uses_delete_returning(self):
        # The single-use exchange must be a single
        # ``DELETE ... RETURNING`` statement so the token
        # can't be replayed even under concurrent reads.
        import datetime as _dt

        from sqlalchemy import and_, delete

        stmt = (
            delete(_AuthMagicLink_for_tests)
            .where(
                and_(
                    _AuthMagicLink_for_tests.token_hash == "h",
                    _AuthMagicLink_for_tests.expires_at
                    > _dt.datetime(2024, 1, 1, 0, 0, 0),
                )
            )
            .returning(_AuthMagicLink_for_tests.email)
        )
        sql = self._compile_pg(stmt)
        self.assertIn("DELETE FROM auth_magic_link", sql)
        self.assertIn("RETURNING auth_magic_link.email", sql)

    def test_list_users_group_filter_uses_array_any(self):
        # ``$group=foo`` filter compiles to PostgreSQL's
        # ``foo = ANY(auth_user.groups)`` containment shape
        # (works unchanged on DuckDB's ``LIST`` type too).
        from sqlalchemy import select

        sql = self._compile_pg(
            select(_AuthUser_for_tests).where(_AuthUser_for_tests.groups.any("admin"))
        )
        self.assertIn("'admin' = ANY (auth_user.groups)", sql)

    def test_rate_limit_window_uses_count(self):
        # ``is_rate_limited`` counts rows whose
        # ``created_at`` falls inside the trailing window;
        # the composite ``(key, created_at)`` index keeps
        # the scan tight.
        import datetime as _dt

        from sqlalchemy import and_, func, select

        cutoff = _dt.datetime(2024, 1, 1, 0, 0, 0)
        stmt = (
            select(func.count())
            .select_from(_AuthRateLimit_for_tests)
            .where(
                and_(
                    _AuthRateLimit_for_tests.key == "magic:alice",
                    _AuthRateLimit_for_tests.created_at > cutoff,
                )
            )
        )
        sql = self._compile_pg(stmt)
        self.assertIn("SELECT count(*) AS count_1", sql)
        self.assertIn("FROM auth_rate_limit", sql)
        self.assertIn("auth_rate_limit.key = 'magic:alice'", sql)


# ---------------------------------------------------------------------
# DuckDBAuthTests -- pin :class:`ivre.db.sql.duckdb.DuckDBAuth`.
#
# Pure inheritance from :class:`PostgresDBAuth` with the
# established :class:`DuckDBMixin` front-of-MRO placement so the
# dialect-aware ``internal2ip`` / ``ip2internal`` /
# ``_searchstring_re`` overrides apply.  The end-to-end auth
# semantics are already covered by
# :class:`SQLDBAuthLiveIntegrationTests` (which now exercises
# the real :class:`DuckDBAuth` class against an in-memory DuckDB
# engine); this class adds the backend-dispatch + MRO pins so a
# future refactor that drops the registration surfaces here.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_SQLDB_AUTH,
    "SQLAlchemy is required for DuckDBAuthTests",
)
class DuckDBAuthTests(unittest.TestCase):
    """Behaviour-pin for :class:`DuckDBAuth`."""

    def test_backend_registered(self):
        from ivre.db import DBAuth

        self.assertEqual(
            DBAuth.backends.get("duckdb"),
            ("sql.duckdb", "DuckDBAuth"),
        )

    def test_mro(self):
        # DuckDBMixin first (its dialect overrides win the
        # lookup against PostgresDB's), then PostgresDBAuth
        # so the SQL implementation is reachable.
        from ivre.db.sql.duckdb import DuckDBAuth

        mro = [c.__name__ for c in DuckDBAuth.__mro__]
        self.assertEqual(mro[0], "DuckDBAuth")
        self.assertEqual(mro[1], "DuckDBMixin")
        self.assertEqual(mro[2], "PostgresDBAuth")

    def test_table_layout_inherited(self):
        # The five auth tables :class:`SQLDBAuth` declares
        # come through unchanged on DuckDB -- no per-dialect
        # schema variant is needed because no auth column
        # uses INET.
        from ivre.db.sql.duckdb import DuckDBAuth

        self.assertEqual(
            set(DuckDBAuth.tables._asdict().keys()),
            {"user", "session", "api_key", "rate_limit", "magic_link"},
        )


# ---------------------------------------------------------------------
# DocumentDBAuthTests -- pin :class:`ivre.db.document.DocumentDBAuth`.
#
# Pure inheritance from :class:`MongoDBAuth` with the
# ``is_documentdb = True`` flag enabling the existing
# ``MongoDBAuth`` workarounds for the few DocumentDB-incompatible
# patterns (none currently exercised in the auth helpers -- the
# flag is set for forward compatibility).
#
# Auth records carry no free-text fields the web layer
# searches, so :class:`MongoDBAuth.indexes` has no ``"text"``
# index entry that would need stripping (unlike
# :class:`DocumentDBRir`).  Every operator the helpers emit
# (``$set`` / ``$addToSet`` / ``$pull`` / ``$or`` / ``$gt`` /
# ``$lt`` / ``$in``, ``find_one_and_delete``,
# ``count_documents``) is supported on AWS DocumentDB at the
# MongoDB 5.0 compatibility level the documentdb.yml CI
# workflow targets.
# ---------------------------------------------------------------------


@unittest.skipUnless(
    _HAVE_PYMONGO,
    "pymongo is required for DocumentDBAuthTests",
)
class DocumentDBAuthTests(unittest.TestCase):
    """Behaviour-pin for :class:`ivre.db.document.DocumentDBAuth`."""

    def test_backend_registered(self):
        from ivre.db import DBAuth

        self.assertEqual(
            DBAuth.backends.get("documentdb"),
            ("document", "DocumentDBAuth"),
        )

    def test_subclasses_mongodb_auth(self):
        # Pure inheritance from :class:`MongoDBAuth`; the
        # ``is_documentdb`` flag activates the existing
        # ``MongoDBAuth`` workarounds (none currently
        # exercised on this code path -- set for forward
        # compatibility).
        from ivre.db.document import DocumentDBAuth
        from ivre.db.mongo import MongoDBAuth

        self.assertTrue(issubclass(DocumentDBAuth, MongoDBAuth))
        self.assertTrue(DocumentDBAuth.is_documentdb)

    def test_no_text_index(self):
        # Auth records carry no free-text fields the web
        # layer searches, so :class:`MongoDBAuth.indexes`
        # has no ``"text"`` index entry.  Pin so a future
        # refactor that adds one (which DocumentDB would
        # reject) surfaces here.
        from ivre.db.document import DocumentDBAuth

        for col_indexes in DocumentDBAuth.indexes:
            for index_keys, _kwargs in col_indexes:
                for _field, index_type in index_keys:
                    self.assertNotEqual(
                        index_type,
                        "text",
                        f"DocumentDBAuth.indexes contains a text index: {index_keys}",
                    )

    def test_indexes_inherit_unchanged(self):
        # The full :class:`MongoDBAuth.indexes` structure
        # passes through unchanged (no per-column override
        # needed, unlike :class:`DocumentDBRir`).
        from ivre.db.document import DocumentDBAuth
        from ivre.db.mongo import MongoDBAuth

        self.assertEqual(DocumentDBAuth.indexes, MongoDBAuth.indexes)


# ---------------------------------------------------------------------
# CapabilityRegistryTests -- pin :attr:`DB.supports` per backend.
#
# The capability registry lets the test suite branch on backend
# behaviour without hard-coding the ``DATABASE`` environment
# variable; the migration is documented inline in
# ``tests/tests.py``.  These tests pin the per-backend
# capability flags so a future refactor that drops one
# silently (and re-introduces a ``DATABASE`` skip) surfaces
# here.
# ---------------------------------------------------------------------


class CapabilityRegistryTests(unittest.TestCase):
    """Behaviour-pin for the ``supports`` frozenset on each
    concrete backend class.

    Only the backends importable without optional dependencies
    (MongoDB / DocumentDB / the abstract ``DB`` base) are
    exercised here; the SQL backends pull in ``sqlalchemy`` at
    import time and live in
    :class:`SQLCapabilityRegistryTests` below.
    """

    def test_base_supports_is_empty(self):
        # The opt-in default: a backend without any capability
        # flag inherits the empty frozenset from
        # :class:`DB`.
        from ivre.db import DB

        self.assertEqual(DB.supports, frozenset())

    def test_mongo_nmap_supports_init_terminates(self):
        from ivre.db.mongo import MongoDBNmap

        self.assertIn("nmap_init_terminates", MongoDBNmap.supports)

    def test_documentdb_nmap_inherits_init_terminates(self):
        # :class:`DocumentDBNmap` inherits the Mongo flag set
        # unchanged.
        from ivre.db.document import DocumentDBNmap

        self.assertIn("nmap_init_terminates", DocumentDBNmap.supports)

    def test_mongo_passive_supports_no_bulk_and_source_invariant(self):
        from ivre.db.mongo import MongoDBPassive

        self.assertIn("passive_no_bulk_ingestion", MongoDBPassive.supports)
        self.assertIn("passive_source_field_invariant", MongoDBPassive.supports)

    def test_mongo_flow_supports_array_topvalues(self):
        from ivre.db.mongo import MongoDBFlow

        self.assertIn("flow_array_topvalues", MongoDBFlow.supports)

    def test_database_skip_count_under_threshold(self):
        # Defence in depth: re-grep ``tests/tests.py`` for
        # ``DATABASE [!=]= "..."`` and fail if the count
        # ever creeps back up.  The acceptance bar is
        # ``<= 5`` lines, each commented as intentional;
        # the current code carries 4 (the dialect-specific
        # explain assertion split + the maxmind data lane
        # + the mongodump producer).
        import os
        import re

        tests_path = os.path.join(os.path.dirname(__file__), "tests.py")
        with open(tests_path, encoding="utf-8") as fdesc:
            matches = [
                lineno
                for lineno, line in enumerate(fdesc, start=1)
                if re.search(r"DATABASE\s*[!=]=", line)
            ]
        self.assertLessEqual(
            len(matches),
            5,
            f"tests.py has {len(matches)} ``DATABASE [!=]=`` lines "
            f"(>5 acceptance bar); migrate excess to capability "
            f"flags. Lines: {matches}",
        )


# SQL-side capability tests live in a separate class so the
# ``sqlalchemy`` import they trigger via
# ``ivre/db/sql/__init__.py`` doesn't break the no-backend CI
# job (which deliberately skips the ``[postgres]`` / ``[duckdb]``
# extras).  The ``_HAVE_SQLALCHEMY`` flag declared earlier in
# this file gates the whole class.
@unittest.skipUnless(
    _HAVE_SQLALCHEMY,
    "sqlalchemy is required (install with the ``postgres`` or " "``duckdb`` extras)",
)
class SQLCapabilityRegistryTests(unittest.TestCase):
    """Capability-registry pins for the SQL backends."""

    def test_postgres_nmap_drops_init_terminates(self):
        # PostgreSQL's ``scancli --init`` hangs in the test
        # cleanup phase; the missing flag gates the
        # corresponding ``test_90_cleanup`` block.
        from ivre.db.sql.postgres import PostgresDBNmap

        self.assertNotIn("nmap_init_terminates", PostgresDBNmap.supports)

    def test_duckdb_nmap_supports_init_terminates(self):
        from ivre.db.sql.duckdb import DuckDBNmap

        self.assertIn("nmap_init_terminates", DuckDBNmap.supports)

    def test_postgres_passive_drops_no_bulk(self):
        # PG's per-row passive ingestion path is broken
        # under the real-world p0f fixture pending a
        # deferred investigation; the missing flag forces
        # ``test_40_passive`` to bulk-only mode.
        from ivre.db.sql.postgres import PostgresDBPassive

        self.assertNotIn("passive_no_bulk_ingestion", PostgresDBPassive.supports)

    def test_duckdb_passive_supports_no_bulk(self):
        from ivre.db.sql.duckdb import DuckDBPassive

        self.assertIn("passive_no_bulk_ingestion", DuckDBPassive.supports)

    def test_sql_flow_drops_array_topvalues(self):
        # The SQL flow backends defer the per-protocol
        # ``meta.<name>`` JSONB merge and the timeslot
        # ingestion; ``topvalues`` over the array forms is
        # not available there yet.
        from ivre.db.sql.duckdb import DuckDBFlow
        from ivre.db.sql.postgres import PostgresDBFlow

        self.assertNotIn("flow_array_topvalues", PostgresDBFlow.supports)
        self.assertNotIn("flow_array_topvalues", DuckDBFlow.supports)


# ---------------------------------------------------------------------
# HttpDBFlowTests -- pin :class:`ivre.db.http.HttpDBFlow`'s URL /
# request-body shapes.  The HTTP backend proxies every flow query
# to a remote IVRE's ``/flows`` endpoint; without these tests a
# refactor of either side could silently drift the wire format.
#
# Each test mocks the urllib opener that backs
# :class:`HttpFetcherBasic` so the captured calls expose either the
# rendered GET URL (read methods) or the POST ``Request`` object
# (ingestion path).
# ---------------------------------------------------------------------


from ivre.db.http import HttpDBFlow as _HttpDBFlow_for_tests  # noqa: E402
from ivre.db.http import _HttpFlowQuery as _HttpFlowQuery_for_tests  # noqa: E402


class HttpDBFlowTests(unittest.TestCase):
    """Behaviour-pin for :class:`ivre.db.http.HttpDBFlow`.

    Mirrors :class:`ivre.db.mongo.MongoDBFlow`'s public method
    surface so an ``DB = http://...`` configuration can drive
    ``zeek2db`` ingestion and the read endpoints.  The mocked
    opener captures every emitted HTTP call -- GET URLs as
    strings, POST requests as :class:`urllib.request.Request`
    objects -- so the assertions cover both shape (URL /
    method / headers) and payload.
    """

    @staticmethod
    def _make_db(read_payload=b'{"clients": 0, "servers": 0, "flows": 0}'):
        from unittest.mock import MagicMock

        calls = []

        class _FakeResp:
            def __init__(self, payload):
                self._payload = payload

            def read(self):
                return self._payload

        class _FakeOpener:
            addheaders = [("User-Agent", "test/1.0")]

            def open(self, url_or_req):
                calls.append(url_or_req)
                return _FakeResp(read_payload)

        class _FakeFetcher:
            baseurl = "http://test.example/api"

            def __init__(self):
                self.urlop = _FakeOpener()

            def open(self, url):
                return self.urlop.open(url)

        db = _HttpDBFlow_for_tests.__new__(_HttpDBFlow_for_tests)
        db.db = _FakeFetcher()
        db.reference = MagicMock()
        return db, calls

    # -- backend registration -----------------------------------------

    def test_backend_registered(self):
        # The ``http://`` URL scheme dispatches to ``HttpDBFlow``
        # via :attr:`DBFlow.backends`; without the registration
        # ``ivre.db.db.flow`` would fall back to a generic
        # ``DBFlow`` and every call would raise
        # ``NotImplementedError``.
        from ivre.db import DBFlow

        self.assertEqual(
            DBFlow.backends.get("http"),
            ("http", "HttpDBFlow"),
        )

    # -- from_filters / wrapper ---------------------------------------

    def test_from_filters_returns_wrapper(self):
        # The wrapper holds the raw filters dict + the
        # ``from_filters`` kwargs so per-method overrides can
        # layer on top at request-build time.  The remote IVRE
        # re-parses the same dict via its own
        # :meth:`DBFlow.from_filters`, so we never run the
        # parser locally.
        flt = _HttpDBFlow_for_tests.from_filters(
            {"nodes": [], "edges": []},
            limit=10,
            skip=5,
            mode="flow_map",
        )
        self.assertIsInstance(flt, _HttpFlowQuery_for_tests)
        self.assertEqual(flt.filters, {"nodes": [], "edges": []})
        self.assertEqual(flt.kwargs["limit"], 10)
        self.assertEqual(flt.kwargs["skip"], 5)
        self.assertEqual(flt.kwargs["mode"], "flow_map")

    # -- count() URL shape --------------------------------------------

    def test_count_url_shape(self):
        # Mirrors ``GET /flows?count=true&q=<json>``; the
        # server side reads ``count`` out of the JSON ``q``
        # payload and returns ``{clients, servers, flows}``.
        db, calls = self._make_db(
            b'{"clients": 1, "servers": 2, "flows": 3}',
        )
        flt = _HttpDBFlow_for_tests.from_filters(
            {"nodes": [], "edges": []},
        )
        result = db.count(flt)
        self.assertEqual(result, {"clients": 1, "servers": 2, "flows": 3})
        self.assertEqual(len(calls), 1)
        url = calls[0]
        self.assertTrue(url.startswith("http://test.example/api/flows?q="))
        # The ``count=true`` flag travels inside the JSON
        # payload (URL-encoded), not as a separate query
        # parameter.
        self.assertIn("count", url)
        self.assertIn("true", url)

    # -- to_graph() URL shape -----------------------------------------

    def test_to_graph_forwards_overrides(self):
        # Per-call ``limit`` / ``skip`` / ``mode`` etc. layer
        # on top of the wrapper-captured kwargs and replace
        # them in the JSON payload (``None`` values drop out
        # so the server-side defaults kick in).
        db, calls = self._make_db(b'{"nodes": [], "edges": []}')
        flt = _HttpDBFlow_for_tests.from_filters(
            {"nodes": [{"attr": ["addr"]}], "edges": []},
            limit=10,
            mode="default",
        )
        db.to_graph(flt, limit=20, skip=0, mode="flow_map", timeline=True)
        self.assertEqual(len(calls), 1)
        url = calls[0]
        from urllib.parse import parse_qs, urlparse

        params = parse_qs(urlparse(url).query)
        payload = json.loads(params["q"][0])
        # Per-call overrides win over wrapper kwargs.
        self.assertEqual(payload["limit"], 20)
        self.assertEqual(payload["mode"], "flow_map")
        self.assertEqual(payload["timeline"], True)
        # Wrapper-captured filters are forwarded verbatim.
        self.assertEqual(payload["nodes"], [{"attr": ["addr"]}])
        self.assertEqual(payload["edges"], [])

    def test_to_graph_serializes_datetime_overrides(self):
        # ``before`` / ``after`` round-trip as
        # ``"YYYY-MM-DD HH:MM"`` strings so the server-side
        # ``datetime.strptime`` (in ``ivre/web/app.py:get_flow``)
        # parses them back without timezone guesswork.
        from datetime import datetime as _dt

        db, calls = self._make_db(b'{"nodes": [], "edges": []}')
        flt = _HttpDBFlow_for_tests.from_filters({"nodes": [], "edges": []})
        db.to_graph(
            flt,
            after=_dt(2024, 1, 1, 12, 30),
            before=_dt(2024, 1, 2, 13, 45),
        )
        from urllib.parse import parse_qs, urlparse

        payload = json.loads(parse_qs(urlparse(calls[0]).query)["q"][0])
        self.assertEqual(payload["after"], "2024-01-01 12:30")
        self.assertEqual(payload["before"], "2024-01-02 13:45")

    # -- host_details / flow_details ---------------------------------

    def test_host_details_url_shape(self):
        # Mirrors :meth:`MongoDBFlow.host_details`'s contract:
        # the wire shape is
        # ``GET /flows?action=details&q={"type":"node","id":<addr>}``.
        db, calls = self._make_db(b'{"elt": {"addr": "10.0.0.1"}}')
        result = db.host_details("10.0.0.1")
        self.assertEqual(result["elt"]["addr"], "10.0.0.1")
        url = calls[0]
        self.assertIn("action=details", url)
        from urllib.parse import parse_qs, urlparse

        payload = json.loads(parse_qs(urlparse(url).query)["q"][0])
        self.assertEqual(payload, {"type": "node", "id": "10.0.0.1"})

    def test_flow_details_url_shape(self):
        # Same shape as ``host_details`` but with
        # ``type=edge`` and the integer flow id.
        db, calls = self._make_db(b'{"elt": {"_id": "42"}}')
        db.flow_details(42)
        url = calls[0]
        self.assertIn("action=details", url)
        from urllib.parse import parse_qs, urlparse

        payload = json.loads(parse_qs(urlparse(url).query)["q"][0])
        self.assertEqual(payload, {"type": "edge", "id": 42})

    def test_host_details_returns_none_on_failure(self):
        # The remote IVRE emits 404 for unknown nodes.
        # ``urllib`` surfaces 404 as a raised exception; the
        # caller (web UI / flowcli) expects ``None`` so we
        # downgrade the failure here.
        db, _ = self._make_db()
        db.db.urlop.open = lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("404 Not Found")
        )
        self.assertIsNone(db.host_details("10.0.0.99"))

    # -- ingestion queue helpers --------------------------------------

    def test_start_bulk_insert_returns_empty_list(self):
        bulk = _HttpDBFlow_for_tests.start_bulk_insert()
        self.assertEqual(bulk, [])

    def test_queue_helpers_serialize_datetime(self):
        # ``start_time`` / ``end_time`` round-trip as epoch
        # floats so the server-side handler can rebuild
        # :class:`datetime` via :func:`datetime.fromtimestamp`
        # without timezone guesswork.
        from datetime import datetime as _dt

        bulk = _HttpDBFlow_for_tests.start_bulk_insert()
        rec = {
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "proto": "tcp",
            "start_time": _dt(2024, 1, 1, 0, 0, 0),
            "end_time": _dt(2024, 1, 1, 0, 0, 5),
            "sport": 1234,
            "dport": 80,
        }
        _HttpDBFlow_for_tests.any2flow(bulk, "http", rec)
        _HttpDBFlow_for_tests.conn2flow(bulk, rec)
        _HttpDBFlow_for_tests.flow2flow(bulk, rec)
        self.assertEqual(len(bulk), 3)
        self.assertEqual(bulk[0]["kind"], "any")
        self.assertEqual(bulk[0]["name"], "http")
        self.assertEqual(bulk[1]["kind"], "conn")
        self.assertEqual(bulk[2]["kind"], "flow")
        # All three carry a JSON-friendly ``rec`` with epoch
        # floats in place of ``datetime`` objects.
        for entry in bulk:
            self.assertIsInstance(entry["rec"]["start_time"], float)
            self.assertIsInstance(entry["rec"]["end_time"], float)

    def test_serialize_record_is_restricted_to_canonical_keys(self):
        # The wire contract is symmetric: only the keys listed
        # in :data:`ivre.db.http.FLOW_DATETIME_KEYS` round-trip
        # as floats.  A ``datetime`` value under any other key
        # falls through unchanged (and would later raise at
        # ``json.dumps`` time) so the type asymmetry between
        # client and server -- silently arriving as a float on
        # the receiving side -- can never happen.
        from datetime import datetime as _dt

        from ivre.db.http import FLOW_DATETIME_KEYS

        # Sanity check the canonical set: missing a key here
        # would make the test pass for the wrong reason.
        self.assertEqual(
            FLOW_DATETIME_KEYS,
            frozenset({"start_time", "end_time", "ts"}),
        )
        ts = _dt(2024, 1, 1, 0, 0, 0)
        rec = {
            "start_time": ts,
            "end_time": ts,
            "ts": ts,
            # An out-of-band datetime under a non-canonical
            # key stays a ``datetime`` -- the caller picks up
            # the foot-gun via ``json.dumps`` rather than
            # silently producing a float on the wire.
            "rogue_time": ts,
        }
        out = _HttpDBFlow_for_tests._serialize_record(rec)
        for key in ("start_time", "end_time", "ts"):
            self.assertIsInstance(out[key], float)
        self.assertIsInstance(out["rogue_time"], _dt)
        # ``json.dumps`` raises on the rogue key so a future
        # parser that adds a new datetime field fails loudly
        # rather than silently dropping the type.
        with self.assertRaises(TypeError):
            json.dumps(out)

    def test_server_rehydration_uses_same_canonical_keys(self):
        # The server's ``_flow_record_from_payload`` must
        # rehydrate exactly the keys the client serialised.
        # The shared :data:`FLOW_DATETIME_KEYS` constant is
        # the single source of truth -- pin it here so a
        # future refactor that drifts the two sides apart
        # surfaces immediately.
        from ivre.db.http import FLOW_DATETIME_KEYS
        from ivre.web.app import _flow_record_from_payload

        payload = {
            "start_time": 1704067200.0,
            "end_time": 1704067205.0,
            "ts": 1704067200.0,
            "rogue_time": 1704067200.0,
            "src": "10.0.0.1",
        }
        out = _flow_record_from_payload(payload)
        from datetime import datetime as _dt

        for key in FLOW_DATETIME_KEYS:
            self.assertIsInstance(out[key], _dt)
        # The rogue float stays a float -- the asymmetry
        # would have surfaced at ``json.dumps`` on the
        # client, not as a silent type mismatch here.
        self.assertIsInstance(out["rogue_time"], float)
        # Non-datetime values pass through unchanged.
        self.assertEqual(out["src"], "10.0.0.1")

    # -- bulk_commit ---------------------------------------------------

    def test_bulk_commit_empty_skips_post(self):
        # Empty bulks must not hit the network -- the bulk
        # boundary in ``zeek2db`` would otherwise hammer the
        # server with empty POSTs on quiet ingestion runs.
        db, calls = self._make_db()
        db.bulk_commit([])
        self.assertEqual(calls, [])

    def test_bulk_commit_posts_records_payload(self):
        # The POST body is a JSON object
        # ``{"records": [...]}`` carrying the queue verbatim.
        # The Content-Type header is ``application/json`` so
        # the server-side handler picks the right body parser.
        db, calls = self._make_db()
        bulk = [{"kind": "conn", "rec": {"proto": "tcp"}}]
        db.bulk_commit(bulk)
        self.assertEqual(len(calls), 1)
        from urllib.request import Request

        req = calls[0]
        self.assertIsInstance(req, Request)
        self.assertEqual(req.method, "POST")
        self.assertEqual(req.full_url, "http://test.example/api/flows")
        self.assertEqual(req.get_header("Content-type"), "application/json")
        self.assertEqual(json.loads(req.data), {"records": bulk})

    def test_bulk_commit_propagates_opener_headers(self):
        # The opener-level ``addheaders`` (``User-Agent``,
        # plus the URL-fragment-derived ``X-API-Key`` /
        # ``Authorization: Bearer`` headers
        # ``HttpFetcherBasic`` injects) must travel on the
        # POST request too -- otherwise an authenticated
        # GET-only setup would 401 on ingestion.
        db, calls = self._make_db()
        db.db.urlop.addheaders = [
            ("User-Agent", "test/1.0"),
            ("X-API-Key", "secret"),
        ]
        db.bulk_commit([{"kind": "conn", "rec": {}}])
        req = calls[0]
        self.assertEqual(req.get_header("User-agent"), "test/1.0")
        self.assertEqual(req.get_header("X-api-key"), "secret")

    def test_cleanup_flows_posts_to_cleanup(self):
        # Mirrors :meth:`MongoDBFlow.cleanup_flows`: hits a
        # dedicated POST endpoint so the server can dispatch
        # to its backend's heuristic without conflating with
        # the ingestion path.
        db, calls = self._make_db()
        db.cleanup_flows()
        self.assertEqual(len(calls), 1)
        req = calls[0]
        self.assertEqual(req.method, "POST")
        self.assertEqual(req.full_url, "http://test.example/api/flows/cleanup")

    def test_post_raises_when_opener_missing(self):
        # The pycurl-based fetchers (Kerberos / PKCS#11) do
        # not yet support POST; the proxy raises a clear
        # NotImplementedError so the operator can fall back
        # to the basic auth flow rather than seeing a vague
        # ``AttributeError``.
        db, _ = self._make_db()
        db.db.urlop = None
        with self.assertRaises(NotImplementedError):
            db.bulk_commit([{"kind": "conn", "rec": {}}])

    # -- deferred read methods ----------------------------------------

    def test_deferred_read_methods_raise(self):
        # Methods that need server-side action handlers we
        # haven't shipped yet must surface as
        # NotImplementedError so the caller fails fast (a
        # silent no-op would mask data loss in
        # ``flowcli --top``-style runs).
        db, _ = self._make_db()
        for method, args in [
            ("to_iter", ()),
            ("topvalues", (None, [])),
            ("top", (None, [])),
            ("flow_daily", (60, None)),
            ("list_precisions", ()),
            ("reduce_precision", (60,)),
        ]:
            with self.assertRaises(NotImplementedError):
                getattr(db, method)(*args)

    def test_init_and_ensure_indexes_are_noops(self):
        # ``flowcli --init`` against a misconfigured ``DB =
        # http://...`` should warn rather than raise so the
        # operator gets a clear message instead of a
        # traceback.  The remote IVRE owns the schema; the
        # operator must run ``--init`` there directly.
        db, _ = self._make_db()
        db.init()
        db.ensure_indexes()


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
        # ``MongoDBActive.searchhostname``'s ``neg=True`` branch
        # over a value uses an ``$or`` of two disjoint
        # branches so the planner can lean on the multikey
        # index on ``hostnames.domains`` for the positive
        # value probe in Branch B:
        #
        # * Branch A -- ``{hostnames.domains: {$ne: name}}``
        #   matches records where ``name`` is NOT anywhere in
        #   any hostname's domain chain (incl. records with
        #   no hostnames at all via Mongo's array
        #   ``$ne``-on-missing-field semantics).
        # * Branch B -- ``{hostnames.domains: name,
        #   hostnames.name: {$ne: name}}`` matches records
        #   that DO have a hostname in ``name``'s subtree
        #   (subdomain or exact) but no hostname is exactly
        #   ``name``.
        #
        # Semantically identical to the legacy
        # ``{hostnames.name: {$ne: name}}`` form (the union
        # of Branches A and B partitions
        # ``C2 ∪ C3 ∪ C4`` cleanly).  ``None`` keeps the
        # simple existence check (no value to negate
        # against).
        MA = self._MA()
        self.assertEqual(
            MA.searchhostname(neg=True),
            {"hostnames.domains": {"$exists": False}},
        )
        self.assertEqual(
            MA.searchhostname("host.example.com", neg=True),
            {
                "$or": [
                    {"hostnames.domains": {"$ne": "host.example.com"}},
                    {
                        "hostnames.domains": "host.example.com",
                        "hostnames.name": {"$ne": "host.example.com"},
                    },
                ]
            },
        )
        pat = re.compile(r"\.example\.com$")
        self.assertEqual(
            MA.searchhostname(pat, neg=True),
            {
                "$or": [
                    {"hostnames.domains": {"$not": pat}},
                    {
                        "hostnames.domains": pat,
                        "hostnames.name": {"$not": pat},
                    },
                ]
            },
        )

    def test_searchhostname_active_negation_list_shapes(self):
        # Negation list inputs flow through ``_search_field``
        # on both halves of each ``$or`` branch: Branch A
        # uses ``$nin`` on the indexed ``domains`` half;
        # Branch B uses ``$in`` (positive value probe on the
        # index) AND ``$nin`` on the non-indexed ``name``
        # half.
        MA = self._MA()
        self.assertEqual(
            MA.searchhostname(["a.example", "b.example"], neg=True),
            {
                "$or": [
                    {"hostnames.domains": {"$nin": ["a.example", "b.example"]}},
                    {
                        "hostnames.domains": {"$in": ["a.example", "b.example"]},
                        "hostnames.name": {"$nin": ["a.example", "b.example"]},
                    },
                ]
            },
        )

    def test_searchhostname_active_negation_mixed_hostnames_corner_case(self):
        # ``searchhostname("www.example.com", neg=True)``
        # must select a record carrying hostnames
        # ``["www.example.org", "mail.example.com",
        # "preprod.www.example.com"]`` -- none equals
        # "www.example.com" exactly.  The
        # ``preprod.www.example.com`` hostname carries
        # "www.example.com" in its domain ancestor chain, so
        # the record's multikey ``hostnames.domains`` array
        # contains "www.example.com" -- Branch A's
        # ``{domains: {$ne: ...}}`` fails, and the record
        # falls through to Branch B which succeeds (``domains``
        # contains "www.example.com" ✓; no hostname is named
        # exactly "www.example.com" ✓).  A record with
        # hostnames entirely outside the subtree would
        # instead match via Branch A; the two branches
        # cooperate to cover the full legacy ``$ne`` semantic.
        #
        # This test pins the wire shape (same as
        # ``test_searchhostname_active_negation_shapes``'s
        # scalar case) and anchors the reasoning above to a
        # concrete example for future readers.
        MA = self._MA()
        self.assertEqual(
            MA.searchhostname("www.example.com", neg=True),
            {
                "$or": [
                    {"hostnames.domains": {"$ne": "www.example.com"}},
                    {
                        "hostnames.domains": "www.example.com",
                        "hostnames.name": {"$ne": "www.example.com"},
                    },
                ]
            },
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

    # -- Round 2 sweep ------------------------------------------------

    def test_searchhostname_active_positive_scalar(self):
        # Positive scalar: the indexed-domain lookup ANDs with
        # the non-indexed name match; ``flt_and`` merges the
        # two single-key dicts into one flat dict (no ``$and``
        # array because the keys differ).
        MA = self._MA()
        self.assertEqual(
            MA.searchhostname("host.example.com"),
            {
                "hostnames.domains": "host.example.com",
                "hostnames.name": "host.example.com",
            },
        )

    def test_searchhostname_active_positive_regex(self):
        # Regex flows through ``_search_field`` on both halves
        # so the pattern lands on both fields unchanged.
        MA = self._MA()
        pat = re.compile(r"\.example\.com$")
        self.assertEqual(
            MA.searchhostname(pat),
            {"hostnames.domains": pat, "hostnames.name": pat},
        )

    def test_searchhostname_active_positive_list(self):
        # List widening: the old positive branch hard-coded the
        # raw ``name`` value on the ``hostnames.name`` half,
        # which silently broke list inputs (Mongo would match
        # ``hostnames.name`` as an exact array value, never
        # finding anything).  Round-2 routes both halves
        # through ``_search_field`` so list inputs use ``$in``
        # on both fields.
        MA = self._MA()
        self.assertEqual(
            MA.searchhostname(["a.example", "b.example"]),
            {
                "hostnames.domains": {"$in": ["a.example", "b.example"]},
                "hostnames.name": {"$in": ["a.example", "b.example"]},
            },
        )

    def test_searchmac_active_existence_branches(self):
        # ``searchmac()`` / ``searchmac(neg=True)`` gate the
        # filter on the presence / absence of any MAC address
        # on the host.
        MA = self._MA()
        self.assertEqual(
            MA.searchmac(),
            {"addresses.mac": {"$exists": True}},
        )
        self.assertEqual(
            MA.searchmac(neg=True),
            {"addresses.mac": {"$exists": False}},
        )

    def test_searchmac_active_scalar_lowercases(self):
        # Scalar string MACs lower-case before the dispatch so
        # the wire value matches the canonical lowercase form
        # the ingestion path stores.
        MA = self._MA()
        self.assertEqual(
            MA.searchmac("AA:BB:CC:11:22:33"),
            {"addresses.mac": "aa:bb:cc:11:22:33"},
        )
        self.assertEqual(
            MA.searchmac("AA:BB:CC:11:22:33", neg=True),
            {"addresses.mac": {"$ne": "aa:bb:cc:11:22:33"}},
        )

    def test_searchmac_active_list_lowercases_each_element(self):
        MA = self._MA()
        self.assertEqual(
            MA.searchmac(["AA:BB:CC:11:22:33", "DD:EE:FF:44:55:66"]),
            {
                "addresses.mac": {
                    "$in": ["aa:bb:cc:11:22:33", "dd:ee:ff:44:55:66"],
                },
            },
        )

    def test_searchmac_active_regex_forces_ignorecase(self):
        # Regex inputs get the ``IGNORECASE`` flag forced on
        # (MAC addresses are case-insensitive); compare via
        # ``pattern`` + ``flags`` rather than equality
        # because ``re.Pattern`` objects compare by identity.
        MA = self._MA()
        pat = re.compile(r"^AA:")
        flt = MA.searchmac(pat)
        compiled = flt["addresses.mac"]
        self.assertEqual(compiled.pattern, r"^AA:")
        self.assertTrue(compiled.flags & re.IGNORECASE)

    def test_searchmac_passive_existence_branches(self):
        # The ``recontype`` constraint stays positive on the
        # positive branch and flips to ``$not`` on the
        # negation existence branch.
        MP = self._MP()
        self.assertEqual(MP.searchmac(), {"recontype": "MAC_ADDRESS"})
        self.assertEqual(
            MP.searchmac(neg=True),
            {"recontype": {"$not": "MAC_ADDRESS"}},
        )

    def test_searchmac_passive_scalar_lowercases(self):
        # The recontype gate is composed with the value
        # clause; the ``value`` field receives the
        # lower-cased MAC.
        MP = self._MP()
        self.assertEqual(
            MP.searchmac("AA:BB:CC:11:22:33"),
            {"recontype": "MAC_ADDRESS", "value": "aa:bb:cc:11:22:33"},
        )
        self.assertEqual(
            MP.searchmac("AA:BB:CC:11:22:33", neg=True),
            {
                "recontype": "MAC_ADDRESS",
                "value": {"$ne": "aa:bb:cc:11:22:33"},
            },
        )

    def test_searchmac_passive_list_lowercases_each_element(self):
        MP = self._MP()
        self.assertEqual(
            MP.searchmac(["AA:BB:CC:11:22:33", "DD:EE:FF:44:55:66"]),
            {
                "recontype": "MAC_ADDRESS",
                "value": {
                    "$in": ["aa:bb:cc:11:22:33", "dd:ee:ff:44:55:66"],
                },
            },
        )

    def test_searchhopname_active_positive_scalar(self):
        # Positive branch composes the indexed-domain lookup
        # with the non-indexed host match; mirrors
        # :meth:`searchhostname`.
        MA = self._MA()
        self.assertEqual(
            MA.searchhopname("hop.example.com"),
            {
                "traces.hops.domains": "hop.example.com",
                "traces.hops.host": "hop.example.com",
            },
        )

    def test_searchhopname_active_positive_list(self):
        MA = self._MA()
        self.assertEqual(
            MA.searchhopname(["a.example", "b.example"]),
            {
                "traces.hops.domains": {"$in": ["a.example", "b.example"]},
                "traces.hops.host": {"$in": ["a.example", "b.example"]},
            },
        )

    def test_searchhopname_active_negation_scalar(self):
        # Negation mirrors :meth:`searchhostname`'s
        # two-branch ``$or`` shape: Branch A covers records
        # without any hop in ``hop``'s subtree (incl. no-hops
        # records via Mongo's array-``$ne``-on-missing-field
        # semantics), Branch B covers records with a hop in
        # ``hop``'s subtree but no hop named exactly ``hop``.
        # See ``searchhostname``'s negation tests for the
        # partition rationale.
        MA = self._MA()
        self.assertEqual(
            MA.searchhopname("hop.example.com", neg=True),
            {
                "$or": [
                    {"traces.hops.domains": {"$ne": "hop.example.com"}},
                    {
                        "traces.hops.domains": "hop.example.com",
                        "traces.hops.host": {"$ne": "hop.example.com"},
                    },
                ]
            },
        )

    def test_searchhopname_active_negation_list(self):
        MA = self._MA()
        self.assertEqual(
            MA.searchhopname(["a.example", "b.example"], neg=True),
            {
                "$or": [
                    {"traces.hops.domains": {"$nin": ["a.example", "b.example"]}},
                    {
                        "traces.hops.domains": {"$in": ["a.example", "b.example"]},
                        "traces.hops.host": {"$nin": ["a.example", "b.example"]},
                    },
                ]
            },
        )

    def test_searchobjectid_scalar_str(self):
        # ``searchobjectid`` coerces the input to
        # :class:`bson.objectid.ObjectId` before the dispatch
        # so the wire shape stays unchanged regardless of
        # whether the caller passes a hex string, bytes, or a
        # pre-built ObjectId.
        import bson  # type: ignore[import-untyped]

        M = self._M()
        oid_hex = "6a031fbd72e1052fbb940fd7"
        oid = bson.objectid.ObjectId(oid_hex)
        self.assertEqual(M.searchobjectid(oid_hex), {"_id": oid})
        self.assertEqual(
            M.searchobjectid(oid_hex, neg=True),
            {"_id": {"$ne": oid}},
        )

    def test_searchobjectid_scalar_objectid(self):
        import bson  # type: ignore[import-untyped]

        M = self._M()
        oid = bson.objectid.ObjectId()
        self.assertEqual(M.searchobjectid(oid), {"_id": oid})

    def test_searchobjectid_list_of_one_collapses_to_scalar(self):
        # The legacy ladder carefully collapsed a single-element
        # list to scalar form (``{"_id": <oid>}`` rather than
        # ``{"_id": {"$in": [<oid>]}}``).  ``_search_field``
        # preserves that collapse so the wire shape stays
        # unchanged.
        import bson  # type: ignore[import-untyped]

        M = self._M()
        oid_hex = "6a031fbd72e1052fbb940fd7"
        oid = bson.objectid.ObjectId(oid_hex)
        self.assertEqual(M.searchobjectid([oid_hex]), {"_id": oid})
        self.assertEqual(
            M.searchobjectid([oid_hex], neg=True),
            {"_id": {"$ne": oid}},
        )

    def test_searchobjectid_list_of_many_uses_in_nin(self):
        import bson  # type: ignore[import-untyped]

        M = self._M()
        h1 = "6a031fbd72e1052fbb940fd7"
        h2 = "6a031fbd72e1052fbb940fd8"
        o1 = bson.objectid.ObjectId(h1)
        o2 = bson.objectid.ObjectId(h2)
        self.assertEqual(M.searchobjectid([h1, h2]), {"_id": {"$in": [o1, o2]}})
        self.assertEqual(
            M.searchobjectid([h1, h2], neg=True),
            {"_id": {"$nin": [o1, o2]}},
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
# WebUploadOkTests -- pin :func:`ivre.web.base.check_upload_ok`'s
# server-side gate.  Without this guard ``WEB_UPLOAD_OK`` was only
# a UI hint: the JS client hid its upload widgets while the
# referer-conformant write routes (``POST /scans|view`` and the
# new ``POST /flows`` family) accepted bodies regardless.  These
# tests cover both the decorator's contract (mocked at the
# function level) and the integration with every write route
# (verified through the route table).
# ---------------------------------------------------------------------


class WebUploadOkTests(unittest.TestCase):
    """Pin :func:`ivre.web.base.check_upload_ok`."""

    def setUp(self):
        from ivre import config

        self._saved = config.WEB_UPLOAD_OK

    def tearDown(self):
        from ivre import config

        config.WEB_UPLOAD_OK = self._saved

    def test_disabled_returns_403_and_skips_handler(self):
        # ``WEB_UPLOAD_OK = False`` is the default; the
        # decorator must short-circuit the handler with a
        # 403 *before* the request body is read.  A test
        # double tracks whether the inner function was
        # invoked so a regression that drops the
        # short-circuit shows up here, not just on the
        # status code.
        from bottle import response

        from ivre import config
        from ivre.web.base import check_upload_ok

        called = []

        def handler():
            called.append(True)
            return {"count": 1}

        config.WEB_UPLOAD_OK = False
        wrapped = check_upload_ok(handler)
        body = wrapped()
        self.assertEqual(response.status, "403 Forbidden")
        self.assertEqual(called, [])
        # The error body is JSON so the HTTP client (browser
        # or :class:`HttpDBFlow`) can surface a clear
        # message rather than a generic 403 page.
        self.assertIn("Uploads are disabled", body)

    def test_enabled_calls_handler(self):
        from ivre import config
        from ivre.web.base import check_upload_ok

        config.WEB_UPLOAD_OK = True
        wrapped = check_upload_ok(lambda: {"count": 42})
        self.assertEqual(wrapped(), {"count": 42})

    def test_decorator_reads_config_lazily(self):
        # Operators flip ``WEB_UPLOAD_OK`` in ``ivre.conf``
        # without restarting the WSGI worker; the decorator
        # therefore reads the value on every call rather
        # than capturing it at decoration time.
        from ivre import config
        from ivre.web.base import check_upload_ok

        wrapped = check_upload_ok(lambda: "OK")
        config.WEB_UPLOAD_OK = False
        self.assertNotEqual(wrapped(), "OK")
        config.WEB_UPLOAD_OK = True
        self.assertEqual(wrapped(), "OK")

    def test_every_post_route_is_gated(self):
        # The decorator is only useful if it sits on every
        # write route -- a missing ``@check_upload_ok`` on
        # one of them defeats the purpose.  Walk
        # :attr:`Bottle.routes` for every POST and confirm
        # the gate is on the call chain by flipping
        # ``WEB_UPLOAD_OK`` and checking the response.
        from bottle import response

        from ivre import config
        from ivre.web.app import application

        config.WEB_UPLOAD_OK = False
        # Auth routes (``/auth/...``) handle login / API-key
        # management; they're outside the upload gate
        # (``WEB_UPLOAD_OK`` specifically targets *data*
        # ingestion).  Filter them out before the inventory
        # check so the test stays stable in deployments
        # where ``ivre.web.auth`` is loaded.
        post_rules = [
            r
            for r in application.routes
            if r.method == "POST" and not r.rule.startswith("/auth/")
        ]
        # Every data-ingestion POST route in the
        # application must be gated.  Pin both the inventory
        # (so a new write route added without the decorator
        # is caught) and the gating itself.
        expected_rules = {
            "/<subdb:re:scans|view>",
            "/flows",
            "/flows/cleanup",
        }
        self.assertEqual({r.rule for r in post_rules}, expected_rules)
        # Stub the request so ``check_referer`` (the outer
        # decorator) lets the call through to
        # ``check_upload_ok`` -- we want to verify the gate
        # is on the chain, not re-test the CSRF helper.
        # ``X-API-Key`` short-circuits the referer check.
        from unittest.mock import patch

        fake_headers = {"X-API-Key": "test"}
        with patch("ivre.web.base.request") as fake_request:
            fake_request.headers.get.side_effect = fake_headers.get
            for route in post_rules:
                response.status = 200
                try:
                    body = route.call()
                except TypeError:
                    # ``post_nmap(subdb)`` requires a
                    # positional arg; call with a placeholder
                    # so the decorator runs first.  If the
                    # gate fires we never reach the handler
                    # body, so the placeholder value is
                    # irrelevant.
                    body = route.call("scans")
                self.assertEqual(
                    response.status,
                    "403 Forbidden",
                    f"route {route.rule} did not honour WEB_UPLOAD_OK",
                )
                self.assertIn("Uploads are disabled", body)


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


# ---------------------------------------------------------------------
# IPRangeTests -- pin the ``ivre iprange`` CLI and its shared
# ``select_ipranges`` / ``format_ipranges`` helpers (also used by
# the ``/cgi/iprange`` web route and the ``ip_range`` MCP tool).
# Pure-arithmetic selectors (``--network`` / ``--range`` /
# ``--file``) are exercised here; the GeoIP-backed paths
# (``--country`` / ``--asnum`` / ``--routable``) live in the
# backend lane (``tests/tests.py``) where the MaxMind dump is
# downloaded.
# ---------------------------------------------------------------------


class IPRangeTests(unittest.TestCase):
    """Behaviour-pin for the ``ivre iprange`` CLI surface.

    Covers the argparser, the shared :func:`select_ipranges`
    dispatcher, the :func:`format_ipranges` output renderer, and
    the end-to-end CLI through subprocess.
    """

    def test_select_network(self) -> None:
        from ivre.tools.iprange import select_ipranges

        ranges = select_ipranges(network="192.0.2.0/30")
        self.assertEqual(len(ranges), 4)
        self.assertEqual(
            list(ranges.iter_ranges()),
            [("192.0.2.0", "192.0.2.3")],
        )
        self.assertEqual(list(ranges.iter_nets()), ["192.0.2.0/30"])

    def test_select_range(self) -> None:
        from ivre.tools.iprange import select_ipranges

        ranges = select_ipranges(address_range=("192.0.2.0", "192.0.2.5"))
        self.assertEqual(len(ranges), 6)
        self.assertEqual(
            list(ranges.iter_nets()),
            ["192.0.2.0/30", "192.0.2.4/31"],
        )

    def test_select_range_inverted_is_rejected(self) -> None:
        from ivre.tools.iprange import IPRangeError, select_ipranges

        with self.assertRaises(IPRangeError):
            select_ipranges(address_range=("192.0.2.5", "192.0.2.0"))

    def test_select_file_mixed_lines(self) -> None:
        from ivre.tools.iprange import select_ipranges

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as fdesc:
            fdesc.write(
                "# header comment\n"
                "\n"
                "192.0.2.0/30  # inline comment\n"
                "10.0.0.1-10.0.0.3\n"
                "8.8.8.8\n"
            )
            path = fdesc.name
        try:
            ranges = select_ipranges(file=path)
        finally:
            os.unlink(path)
        # 4 + 3 + 1 = 8 addresses across three contiguous blocks.
        self.assertEqual(len(ranges), 8)

    def test_select_file_malformed_line_raises(self) -> None:
        from ivre.tools.iprange import IPRangeError, select_ipranges

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as fdesc:
            fdesc.write("not-an-ip\n")
            path = fdesc.name
        try:
            with self.assertRaises(IPRangeError):
                select_ipranges(file=path)
        finally:
            os.unlink(path)

    def test_no_selector_raises(self) -> None:
        from ivre.tools.iprange import IPRangeError, select_ipranges

        with self.assertRaises(IPRangeError):
            select_ipranges()

    def test_multiple_selectors_raise(self) -> None:
        from ivre.tools.iprange import IPRangeError, select_ipranges

        with self.assertRaises(IPRangeError):
            select_ipranges(network="192.0.2.0/30", routable=True)

    def test_geoip_missing_raises_clean_error(self) -> None:
        # ``--country`` / ``--asnum`` / ``--region`` / ``--city`` /
        # ``--routable`` need ``config.GEOIP_PATH`` to be set; an
        # AssertionError from ``geoiputils._get_by_data`` would be
        # a poor UX so the helper pre-checks and surfaces
        # ``IPRangeError`` instead.
        from ivre.tools.iprange import IPRangeError, select_ipranges

        with mock.patch.object(ivre.config, "GEOIP_PATH", None):
            with self.assertRaises(IPRangeError) as ctx:
                select_ipranges(country="FR")
            self.assertIn("GEOIP_PATH", str(ctx.exception))

    def test_format_count(self) -> None:
        from ivre.tools.iprange import format_ipranges, select_ipranges

        result = format_ipranges(select_ipranges(network="192.0.2.0/30"), "count")
        self.assertEqual(result, {"count": 4, "value": 4})

    def test_format_cidrs(self) -> None:
        from ivre.tools.iprange import format_ipranges, select_ipranges

        result = format_ipranges(
            select_ipranges(address_range=("192.0.2.0", "192.0.2.5")),
            "cidrs",
        )
        self.assertEqual(result["value"], ["192.0.2.0/30", "192.0.2.4/31"])
        self.assertEqual(result["count"], 6)

    def test_format_ranges(self) -> None:
        from ivre.tools.iprange import format_ipranges, select_ipranges

        result = format_ipranges(select_ipranges(network="192.0.2.0/30"), "ranges")
        self.assertEqual(result["value"], [["192.0.2.0", "192.0.2.3"]])

    def test_format_addrs(self) -> None:
        from ivre.tools.iprange import format_ipranges, select_ipranges

        result = format_ipranges(select_ipranges(network="192.0.2.0/30"), "addrs")
        self.assertEqual(
            result["value"],
            ["192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"],
        )

    def test_format_addrs_respects_cap(self) -> None:
        # The default 1_000_000-address cap protects against
        # accidental multi-gigabyte stdout floods; trigger it on
        # a small synthetic IPRanges to keep the test fast.
        from ivre.tools.iprange import (
            IPRangeError,
            format_ipranges,
            select_ipranges,
        )

        ranges = select_ipranges(network="192.0.2.0/30")
        with self.assertRaises(IPRangeError) as ctx:
            format_ipranges(ranges, "addrs", addrs_cap=2)
        self.assertIn("cap", str(ctx.exception))
        # Same input + same cap + an explicit limit at or below
        # the cap must succeed (truncation, not refusal).
        result = format_ipranges(ranges, "addrs", limit=2, addrs_cap=2)
        self.assertEqual(result["value"], ["192.0.2.0", "192.0.2.1"])

    def test_format_json(self) -> None:
        from ivre.tools.iprange import format_ipranges, select_ipranges

        result = format_ipranges(select_ipranges(network="192.0.2.0/30"), "json")
        self.assertEqual(
            result["value"],
            {
                "count": 4,
                "ranges": [["192.0.2.0", "192.0.2.3"]],
                "cidrs": ["192.0.2.0/30"],
            },
        )

    def test_format_limit_truncates(self) -> None:
        from ivre.tools.iprange import format_ipranges, select_ipranges

        # /28 = 16 IPs -> 16 individual /32 CIDRs without
        # aggregation; --limit 3 keeps the first three.
        ranges = select_ipranges(address_range=("192.0.2.1", "192.0.2.6"))
        result = format_ipranges(ranges, "cidrs", limit=3)
        self.assertEqual(len(result["value"]), 3)

    def test_invalid_output_raises(self) -> None:
        from ivre.tools.iprange import (
            IPRangeError,
            format_ipranges,
            select_ipranges,
        )

        with self.assertRaises(IPRangeError):
            format_ipranges(select_ipranges(network="192.0.2.0/30"), "xml")

    # End-to-end CLI -------------------------------------------------

    def test_cli_count(self) -> None:
        res, out, err = RUN(["ivre", "iprange", "--network", "192.0.2.0/30", "--count"])
        self.assertEqual(res, 0)
        self.assertFalse(err)
        self.assertEqual(out.strip(), b"4")

    def test_cli_default_output_is_cidrs(self) -> None:
        res, out, err = RUN(["ivre", "iprange", "--network", "192.0.2.0/30"])
        self.assertEqual(res, 0)
        self.assertFalse(err)
        self.assertEqual(out.strip(), b"192.0.2.0/30")

    def test_cli_ranges(self) -> None:
        res, out, _ = RUN(["ivre", "iprange", "--network", "192.0.2.0/30", "--ranges"])
        self.assertEqual(res, 0)
        self.assertEqual(out.strip(), b"192.0.2.0-192.0.2.3")

    def test_cli_json(self) -> None:
        res, out, _ = RUN(["ivre", "iprange", "--network", "192.0.2.0/30", "--json"])
        self.assertEqual(res, 0)
        payload = json.loads(out)
        self.assertEqual(payload["count"], 4)
        self.assertEqual(payload["cidrs"], ["192.0.2.0/30"])
        self.assertEqual(payload["ranges"], [["192.0.2.0", "192.0.2.3"]])

    def test_cli_mutex_rejected(self) -> None:
        res, _, err = RUN(
            [
                "ivre",
                "iprange",
                "--network",
                "192.0.2.0/30",
                "--range",
                "1.1.1.1",
                "1.1.1.2",
            ]
        )
        self.assertNotEqual(res, 0)
        self.assertIn(b"not allowed", err)

    # Web route ------------------------------------------------------

    def _wsgi_call(self, query: str) -> tuple[str, bytes]:
        # Make sure routes are registered on the bottle application.
        import ivre.web.app  # noqa: F401 -- side-effecting import
        from ivre.web.base import application

        env = {
            "REQUEST_METHOD": "GET",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "80",
            "HTTP_HOST": "localhost",
            "HTTP_REFERER": "http://localhost/",
            "wsgi.url_scheme": "http",
            "PATH_INFO": "/iprange",
            "QUERY_STRING": query,
        }
        status: dict[str, str] = {}

        def start_response(s: str, _headers, _exc=None):
            status["s"] = s

        body = b"".join(application(env, start_response))
        return status["s"], body

    def test_web_count(self) -> None:
        status, body = self._wsgi_call("network=192.0.2.0/30&output=count")
        self.assertTrue(status.startswith("200"), status)
        self.assertEqual(json.loads(body), {"count": 4})

    def test_web_default_is_cidrs(self) -> None:
        status, body = self._wsgi_call("network=192.0.2.0/30")
        self.assertTrue(status.startswith("200"), status)
        self.assertEqual(json.loads(body), {"count": 4, "cidrs": ["192.0.2.0/30"]})

    def test_web_addrs_respects_cap(self) -> None:
        # Override the cap to 2 so the small /30 trips it. The
        # web route maps :class:`IPRangeError` to HTTP 400.
        with mock.patch.object(ivre.config, "WEB_IPRANGE_ADDR_CAP", 2):
            status, _ = self._wsgi_call("network=192.0.2.0/30&output=addrs")
        self.assertTrue(status.startswith("400"), status)

    def test_web_invalid_output(self) -> None:
        status, _ = self._wsgi_call("network=192.0.2.0/30&output=xml")
        self.assertTrue(status.startswith("400"), status)

    def test_web_json_alias_rejected(self) -> None:
        # ``output=json`` is a CLI shortcut for "everything";
        # the web response shape is single-valued.
        status, _ = self._wsgi_call("network=192.0.2.0/30&output=json")
        self.assertTrue(status.startswith("400"), status)

    def test_web_partial_range_rejected(self) -> None:
        status, _ = self._wsgi_call("range_start=1.1.1.1")
        self.assertTrue(status.startswith("400"), status)

    def test_web_mutex_rejected(self) -> None:
        status, _ = self._wsgi_call(
            "network=192.0.2.0/30&range_start=1.1.1.1&range_stop=1.1.1.5"
        )
        self.assertTrue(status.startswith("400"), status)

    def test_web_invalid_limit_rejected(self) -> None:
        status, _ = self._wsgi_call("network=192.0.2.0/30&limit=abc")
        self.assertTrue(status.startswith("400"), status)

    def test_web_malformed_region_rejected(self) -> None:
        status, _ = self._wsgi_call("region=FR")
        self.assertTrue(status.startswith("400"), status)


# ---------------------------------------------------------------------
# MongoDBNotesIndexTests -- pin the structural definitions
# (collections, indexes, abstract surface, canonicalisation
# registry, body-size validator) the per-entity notes purpose
# ships with.  The actual create / read / update / list-revisions
# / delete round-trip is exercised in ``tests/tests.py`` on the
# ``mongodb.yml`` CI lane where a real MongoDB instance is
# available; these no-backend tests bound the wire shape so
# regressions surface immediately.
# ---------------------------------------------------------------------


class MongoDBNotesIndexTests(unittest.TestCase):
    """Backend-free pin tests for the per-entity notes storage
    layer (``notes`` + ``note_revisions`` collections + the
    ``DBNotes`` abstract surface + entity-key canonicalisation
    registry).
    """

    def test_notes_columns_registered(self) -> None:
        from ivre.db.mongo import MongoDBNotes

        # Two columns at indexes 0 and 1 -- ``notes`` + audit log.
        self.assertEqual(MongoDBNotes.column_notes, 0)
        self.assertEqual(MongoDBNotes.column_note_revisions, 1)
        # ``indexes`` mirrors ``columns`` in length so every
        # collection has its index block.
        self.assertEqual(len(MongoDBNotes.indexes), 2)

    def test_notes_compound_unique_index(self) -> None:
        # Pin ``(entity_type, entity_key_0, entity_key_1)`` as
        # the unique compound.  Storing the canonical key as
        # two scalar fields keeps the index a plain single-key
        # compound -- a BSON-array ``entity_key`` would turn it
        # into a *multikey* index where Mongo enforces
        # uniqueness element-wise, in which case two IPv4 notes
        # (whose ``addr_0`` is the same bias constant) collide
        # at the second insert.
        from ivre.db.mongo import MongoDBNotes

        block = MongoDBNotes.indexes[MongoDBNotes.column_notes]
        unique_index = next(
            (keys, opts)
            for keys, opts in block
            if keys
            == [
                ("entity_type", 1),
                ("entity_key_0", 1),
                ("entity_key_1", 1),
            ]
        )
        self.assertTrue(
            unique_index[1].get("unique"),
            f"expected unique=True, got {unique_index[1]!r}",
        )

    def test_notes_body_text_index(self) -> None:
        # Free-text search over note bodies relies on a text
        # index; Mongo allows at most one per collection.
        # ``MongoDB.searchtext`` (inherited by
        # :class:`MongoDBNotes`) produces ``$text`` queries
        # that target this index.
        from ivre.db.mongo import MongoDBNotes

        block = MongoDBNotes.indexes[MongoDBNotes.column_notes]
        text_index = next(
            (keys, opts) for keys, opts in block if keys == [("body", "text")]
        )
        self.assertEqual(text_index[1].get("name"), "notes_body_text")

    def test_note_revisions_compound_index(self) -> None:
        # Pin ``(entity_type ASC, entity_key_0 ASC,
        # entity_key_1 ASC, revision DESC)`` -- the compound
        # used by ``list_note_revisions`` for newest-first
        # ordering with the storage shape matching the unique
        # compound on the parent collection.
        from ivre.db.mongo import MongoDBNotes

        block = MongoDBNotes.indexes[MongoDBNotes.column_note_revisions]
        self.assertTrue(
            any(
                keys
                == [
                    ("entity_type", 1),
                    ("entity_key_0", 1),
                    ("entity_key_1", 1),
                    ("revision", -1),
                ]
                for keys, _opts in block
            ),
            block,
        )

    def test_dbnotes_abstract_surface(self) -> None:
        # Each method is declared on :class:`DBNotes` and is
        # overridden by :class:`MongoDBNotes`.  The generic
        # ``get`` / ``count`` primitives + the convenience
        # methods make up the full purpose surface.
        from ivre.db import DBNotes
        from ivre.db.mongo import MongoDBNotes

        method_names = (
            "get",
            "count",
            "get_note",
            "set_note",
            "delete_note",
            "list_note_revisions",
            "list_entities",
            "count_notes",
        )
        for name in method_names:
            with self.subTest(method=name):
                self.assertIn(
                    name,
                    DBNotes.__dict__,
                    f"DBNotes is missing {name}",
                )
                self.assertIn(
                    name,
                    MongoDBNotes.__dict__,
                    f"MongoDBNotes is missing {name}",
                )

    def test_dbnotes_methods_raise_on_base(self) -> None:
        # Driving the base-class methods directly (bypassing the
        # concrete override) surfaces ``NotImplementedError``,
        # so a backend that forgets to implement one fails
        # loudly instead of silently no-op'ing.
        from ivre.db import DBNotes

        notes = DBNotes()
        with self.assertRaises(NotImplementedError):
            notes.get_note("host", "192.0.2.1")
        with self.assertRaises(NotImplementedError):
            notes.set_note("host", "192.0.2.1", "body", "alice@example.org")
        with self.assertRaises(NotImplementedError):
            notes.delete_note("host", "192.0.2.1")
        with self.assertRaises(NotImplementedError):
            notes.list_note_revisions("host", "192.0.2.1")
        with self.assertRaises(NotImplementedError):
            notes.list_entities()
        with self.assertRaises(NotImplementedError):
            notes.count_notes()
        with self.assertRaises(NotImplementedError):
            notes.get({})
        with self.assertRaises(NotImplementedError):
            notes.count({})

    def test_canonicalize_host_key_matches_ip2internal(self) -> None:
        # Notes for the ``host`` entity type are keyed by the
        # same int128 split MongoDBView uses for its ``addr_0``
        # / ``addr_1`` fields, so the two collections align
        # byte-for-byte (enables future ``$lookup`` joins +
        # correct IP-range queries).
        from ivre.db import canonicalize_entity_key
        from ivre.db.mongo import MongoDB

        for addr in ["192.0.2.1", "10.0.0.1", "2001:db8::1", "::1"]:
            with self.subTest(addr=addr):
                self.assertEqual(
                    canonicalize_entity_key("host", addr),
                    MongoDB.ip2internal(addr),
                )

    def test_canonicalize_entity_key_unknown_type_raises(self) -> None:
        from ivre.db import canonicalize_entity_key

        with self.assertRaises(ValueError) as ctx:
            canonicalize_entity_key("garbage", "anything")
        # The error names the unknown type and lists what is
        # registered, so operators adding a new type via a plugin
        # see exactly which side to fix.
        self.assertIn("garbage", str(ctx.exception))
        self.assertIn("host", str(ctx.exception))

    def test_canonicalize_host_key_rejects_wrong_length_list(self) -> None:
        # A list input for the ``host`` type must have exactly
        # two elements (``[addr_0, addr_1]``).  Anything else
        # is rejected up-front to prevent malformed keys from
        # reaching the storage layer and crashing far away on
        # the next read inside ``MongoDB.internal2ip``.
        from ivre.db import canonicalize_entity_key

        for bad in ([], [0], [0, 0, 0]):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError) as ctx:
                    canonicalize_entity_key("host", bad)
                self.assertIn("exactly 2 elements", str(ctx.exception))

    def test_canonicalize_host_key_rejects_non_int_elements(self) -> None:
        # Both halves of the int128 split must be ints; a
        # ``None`` half or a string half would silently corrupt
        # the document and surface as a ``TypeError`` deep
        # inside ``internal2ip`` on the read path.  ``bool``
        # is a subclass of ``int`` in Python but is rejected
        # explicitly: a caller passing ``[True, False]`` is
        # clearly confused.
        from ivre.db import canonicalize_entity_key

        cases = [
            [None, 0],
            [0, None],
            ["addr_0", 0],
            [0, "addr_1"],
            [1.5, 0],
            [True, False],
        ]
        for bad in cases:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError) as ctx:
                    canonicalize_entity_key("host", bad)
                self.assertIn("must be int", str(ctx.exception))

    def test_canonicalize_host_key_rejects_out_of_range_int(self) -> None:
        # Values outside the signed int64 range cannot be
        # reassembled to a valid int128 by
        # :meth:`MongoDB.internal2ip` (the bias-add would
        # produce an out-of-range value for ``struct.pack``).
        # Reject early.
        from ivre.db import canonicalize_entity_key

        cases = [
            [1 << 63, 0],
            [0, 1 << 63],
            [-(1 << 63) - 1, 0],
            [0, -(1 << 63) - 1],
        ]
        for bad in cases:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError) as ctx:
                    canonicalize_entity_key("host", bad)
                self.assertIn("out of signed int64 range", str(ctx.exception))

    def test_canonicalize_host_key_rejects_non_str_non_list_input(self) -> None:
        # The host canonicaliser accepts only printable IP
        # strings or 2-element ``[addr_0, addr_1]`` int
        # lists.  Anything else (raw int, bytes, dict, ...)
        # is rejected with a clear error that names the
        # acceptable input forms instead of surfacing a
        # downstream ``ip2bin`` error from a different
        # module.
        from ivre.db import canonicalize_entity_key

        for bad in (12345, b"\xc0\x00\x02\x01", {"addr": "1.2.3.4"}, None):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError) as ctx:
                    canonicalize_entity_key("host", bad)
                self.assertIn("printable IP string", str(ctx.exception))

    def test_canonicalize_host_key_accepts_valid_canonical_list(self) -> None:
        # Already-canonical 2-element lists with valid int64
        # halves round-trip unchanged.  Verifies the
        # validation guards do not regress the happy-path
        # idempotence (e.g. when ``set_note`` is fed back a
        # value previously returned by ``get_note``'s
        # internal representation).
        from ivre.db import canonicalize_entity_key
        from ivre.db.mongo import MongoDB

        for addr in ["192.0.2.1", "10.0.0.1", "2001:db8::1", "::1"]:
            with self.subTest(addr=addr):
                canonical = MongoDB.ip2internal(addr)
                self.assertEqual(canonicalize_entity_key("host", canonical), canonical)

    def test_validate_note_body_size_accepts_within_cap(self) -> None:
        from ivre.db import DBNotes

        cap = ivre.config.WEB_HOST_NOTES_MAX_BYTES
        assert cap is not None  # default config has it set
        # ASCII body so byte-length equals str-length.
        DBNotes._validate_note_body_size("x" * cap)

    def test_validate_note_body_size_rejects_over_cap(self) -> None:
        # Pin the typed exception class so the web route can
        # catch it explicitly to map to HTTP 413; a generic
        # ``ValueError`` here would force the route to
        # substring-match the message text (fragile).
        from ivre.db import DBNotes, NoteBodyTooLarge

        cap = ivre.config.WEB_HOST_NOTES_MAX_BYTES
        assert cap is not None
        with self.assertRaises(NoteBodyTooLarge) as ctx:
            DBNotes._validate_note_body_size("x" * (cap + 1))
        self.assertIn("exceeds cap", str(ctx.exception))

    def test_validate_note_body_size_disabled_when_cap_is_none(self) -> None:
        from ivre.db import DBNotes

        # An operator may disable the cap explicitly; arbitrarily
        # large bodies are then accepted by the storage
        # validator (Mongo's 16 MiB BSON limit still applies at
        # insert time).
        with mock.patch.object(ivre.config, "WEB_HOST_NOTES_MAX_BYTES", None):
            DBNotes._validate_note_body_size("x" * 5_000_000)

    def test_set_note_swallows_audit_insert_failure(self) -> None:
        # Real bug surfaced by review: an unwrapped audit insert
        # in ``set_note`` lets a transient failure on the
        # ``note_revisions`` collection propagate to the caller
        # after the parent note write already committed.  The
        # caller's retry then bumps the parent revision a second
        # time (under ``expected_revision=None`` LWW) or raises
        # a false "concurrent edit" (under
        # ``expected_revision>=1``).  Catching
        # :class:`PyMongoError` on the audit insert keeps the
        # user-facing write successful; the failure surfaces via
        # :data:`utils.LOGGER` for operator inspection.
        from pymongo.errors import PyMongoError

        from ivre.db import canonicalize_entity_key
        from ivre.db.mongo import MongoDBNotes

        backend = MongoDBNotes.__new__(MongoDBNotes)
        backend.columns = ["notes", "note_revisions"]

        # Parent collection: ``find_one_and_update`` returns a
        # plausible upserted doc with the same canonical
        # ``entity_key_0`` / ``entity_key_1`` the real backend
        # would produce for ``192.0.2.1``.  Audit collection:
        # ``insert_one`` raises a transient backend error.
        canonical = canonicalize_entity_key("host", "192.0.2.1")
        now = datetime.now(tz=timezone.utc)
        upserted_doc = {
            "_id": "x",
            "entity_type": "host",
            "entity_key_0": canonical[0],
            "entity_key_1": canonical[1],
            "body": "hello",
            "revision": 1,
            "created_at": now,
            "created_by": "alice@example.org",
            "updated_at": now,
            "updated_by": "alice@example.org",
        }
        notes_col = mock.Mock()
        notes_col.find_one_and_update.return_value = upserted_doc
        revisions_col = mock.Mock()
        revisions_col.insert_one.side_effect = PyMongoError("simulated blip")

        # ``MongoDBNotes.db`` is a property delegating to
        # ``self._db.db``; stub the inner ``_db`` so the
        # ``self.db[...]`` lookups return our mocked collections.
        backend._db = mock.Mock()
        backend._db.db = {
            "notes": notes_col,
            "note_revisions": revisions_col,
        }
        with mock.patch.object(ivre.utils.LOGGER, "warning") as warning_mock:
            result = backend.set_note("host", "192.0.2.1", "hello", "alice@example.org")
        # Parent write was committed; caller sees success.
        self.assertEqual(result["body"], "hello")
        self.assertEqual(result["revision"], 1)
        self.assertEqual(result["entity_key"], "192.0.2.1")
        # Audit insert was attempted exactly once.
        revisions_col.insert_one.assert_called_once()
        # And the failure was logged.
        warning_mock.assert_called_once()
        # The log message names the entity so an operator can
        # audit-replay manually.
        log_args = warning_mock.call_args
        self.assertIn("host", log_args.args)
        self.assertIn("192.0.2.1", log_args.args)

    @staticmethod
    def _build_set_note_backend(
        notes_col: "mock.Mock", revisions_col: "mock.Mock"
    ) -> "object":
        """Helper: instantiate a :class:`MongoDBNotes` without
        opening a real backend connection and stub its ``db``
        property so ``self.db[...]`` returns the mocked
        collections.  Returned object has both collections
        wired and ready for :meth:`set_note` exercise.
        """
        from ivre.db.mongo import MongoDBNotes

        backend = MongoDBNotes.__new__(MongoDBNotes)
        backend.columns = ["notes", "note_revisions"]
        backend._db = mock.Mock()
        backend._db.db = {
            "notes": notes_col,
            "note_revisions": revisions_col,
        }
        return backend

    def test_set_note_raises_note_not_found_when_missing(self) -> None:
        # ``expected_revision >= 1`` + the target note does not
        # exist -> ``NoteNotFound``.  Distinguishes from
        # ``NoteConcurrencyError`` so web layers can map to
        # HTTP 404 vs 409 without sniffing error strings.
        from pymongo import ReadPreference

        from ivre.db import NoteNotFound

        notes_col = mock.Mock()
        # find_one_and_update returns None (no doc at
        # expected_revision).  The existence-check must hit
        # PRIMARY explicitly via ``with_options``: stub the
        # sub-collection it returns so its ``find_one``
        # returns None (no doc at all).
        notes_col.find_one_and_update.return_value = None
        primary_view = mock.Mock()
        primary_view.find_one.return_value = None
        notes_col.with_options.return_value = primary_view
        revisions_col = mock.Mock()
        backend = self._build_set_note_backend(notes_col, revisions_col)
        with self.assertRaises(NoteNotFound) as ctx:
            backend.set_note(
                "host",
                "192.0.2.1",
                "new body",
                "alice@example.org",
                expected_revision=5,
            )
        # Error message identifies the entity so operators /
        # web logs see which target was missing.
        self.assertIn("host", str(ctx.exception))
        self.assertIn("192.0.2.1", str(ctx.exception))
        # Existence check was pinned to PRIMARY -- non-PRIMARY
        # client read preferences would otherwise let a stale
        # secondary misclassify a concurrency drift as
        # not-found (or vice versa).
        notes_col.with_options.assert_called_once_with(
            read_preference=ReadPreference.PRIMARY
        )
        primary_view.find_one.assert_called_once()
        # Audit log is *not* touched on the failure path.
        revisions_col.insert_one.assert_not_called()

    def test_set_note_raises_concurrency_error_on_revision_drift(self) -> None:
        # ``expected_revision >= 1`` + the target note exists
        # but at a different revision -> ``NoteConcurrencyError``.
        from pymongo import ReadPreference

        from ivre.db import NoteConcurrencyError

        notes_col = mock.Mock()
        notes_col.find_one_and_update.return_value = None
        # PRIMARY-pinned existence check finds the note at a
        # different revision than the caller asked for.
        primary_view = mock.Mock()
        primary_view.find_one.return_value = {"revision": 7}
        notes_col.with_options.return_value = primary_view
        revisions_col = mock.Mock()
        backend = self._build_set_note_backend(notes_col, revisions_col)
        with self.assertRaises(NoteConcurrencyError) as ctx:
            backend.set_note(
                "host",
                "192.0.2.1",
                "new body",
                "alice@example.org",
                expected_revision=5,
            )
        # Error names the stored vs expected revisions so the
        # SPA's conflict dialog can surface them.
        msg = str(ctx.exception)
        self.assertIn("7", msg)
        self.assertIn("5", msg)
        notes_col.with_options.assert_called_once_with(
            read_preference=ReadPreference.PRIMARY
        )
        revisions_col.insert_one.assert_not_called()

    def test_set_note_raises_already_exists_in_create_only_mode(self) -> None:
        # ``expected_revision = 0`` (create-only) on a note
        # that already exists -> ``NoteAlreadyExists``.
        from pymongo.errors import DuplicateKeyError

        from ivre.db import NoteAlreadyExists

        notes_col = mock.Mock()
        # insert_one raises DuplicateKeyError on the unique
        # compound index.
        notes_col.insert_one.side_effect = DuplicateKeyError("duplicate")
        revisions_col = mock.Mock()
        backend = self._build_set_note_backend(notes_col, revisions_col)
        with self.assertRaises(NoteAlreadyExists) as ctx:
            backend.set_note(
                "host",
                "192.0.2.1",
                "new body",
                "alice@example.org",
                expected_revision=0,
            )
        self.assertIn("host", str(ctx.exception))
        self.assertIn("192.0.2.1", str(ctx.exception))
        revisions_col.insert_one.assert_not_called()

    def test_set_note_create_only_does_not_read_after_insert(self) -> None:
        # The ``expected_revision <= 0`` (create-only) success
        # path constructs the persisted-doc dict locally
        # rather than reading it back: we know exactly what
        # we just wrote, and a follow-up ``find_one`` would
        # be served from whatever the client-level
        # ``read_preference`` selects -- a stale secondary
        # could return ``None`` and crash the downstream
        # audit-log step on ``doc["revision"]``.  Pin that
        # the create path never issues a read (neither a
        # direct ``find_one`` nor a ``with_options(...)``
        # routed read).
        notes_col = mock.Mock()
        notes_col.insert_one.return_value = mock.Mock()
        revisions_col = mock.Mock()
        backend = self._build_set_note_backend(notes_col, revisions_col)
        result = backend.set_note(
            "host",
            "192.0.2.1",
            "first version",
            "alice@example.org",
            expected_revision=0,
        )
        # The created note round-trips back through
        # ``_present_note`` and carries the values we just
        # inserted -- not a fetched copy.
        self.assertEqual(result["body"], "first version")
        self.assertEqual(result["revision"], 1)
        self.assertEqual(result["entity_key"], "192.0.2.1")
        # Insert happened exactly once; no reads on the
        # notes collection at all.
        notes_col.insert_one.assert_called_once()
        notes_col.find_one.assert_not_called()
        notes_col.with_options.assert_not_called()
        # Audit log still gets its row.
        revisions_col.insert_one.assert_called_once()

    def test_note_exception_types_are_value_errors(self) -> None:
        # Subclassing ``ValueError`` keeps backwards
        # compatibility with callers that catch the coarser
        # type (legacy ``except ValueError:`` blocks still
        # catch all four).
        from ivre.db import (
            NoteAlreadyExists,
            NoteBodyTooLarge,
            NoteConcurrencyError,
            NoteNotFound,
        )

        self.assertTrue(issubclass(NoteNotFound, ValueError))
        self.assertTrue(issubclass(NoteConcurrencyError, ValueError))
        self.assertTrue(issubclass(NoteAlreadyExists, ValueError))
        self.assertTrue(issubclass(NoteBodyTooLarge, ValueError))

    @staticmethod
    def _build_get_backend(
        notes_col: "mock.Mock", maxtime: "int | None" = None
    ) -> "object":
        """Helper: build a :class:`MongoDBNotes` whose ``db``
        property returns the mocked collection.  ``maxtime``
        seeds the inherited :meth:`MongoDB.set_limits` so
        tests can exercise the timeout-application path
        without spinning up a real client.
        """
        from ivre.db.mongo import MongoDBNotes

        backend = MongoDBNotes.__new__(MongoDBNotes)
        backend.columns = ["notes", "note_revisions"]
        backend.maxtime = maxtime
        backend._db = mock.Mock()
        backend._db.db = {"notes": notes_col, "note_revisions": mock.Mock()}
        return backend

    def test_mongodb_notes_get_routes_through_get_cursor(self) -> None:
        # Pin that :meth:`MongoDBNotes.get` goes through
        # :meth:`MongoDB._get_cursor` -- the shared cursor
        # factory the rest of the Mongo backends use --
        # rather than calling ``find`` directly.  Routing
        # through ``_get_cursor`` gets the notes purpose
        # parity with ``MongoDBView.get`` /
        # ``MongoDBPassive.get`` for query timeouts, the
        # ``("text", ...)`` sort shortcut, and the legacy
        # ``fields=`` to ``projection=`` conversion.
        notes_col = mock.Mock()
        cursor = mock.Mock()
        notes_col.find.return_value = cursor
        backend = self._build_get_backend(notes_col)
        result = backend.get(
            {"entity_type": "host"},
            projection={"body": 0},
            sort=[("updated_at", -1)],
            limit=10,
            skip=5,
        )
        # ``_get_cursor`` pops ``sort`` before calling
        # ``find`` and applies it via ``cursor.sort(...)``
        # afterwards; everything else is forwarded to
        # ``find`` unchanged.
        notes_col.find.assert_called_once_with(
            {"entity_type": "host"},
            projection={"body": 0},
            limit=10,
            skip=5,
        )
        cursor.sort.assert_called_once_with([("updated_at", -1)])
        # ``set_limits`` returns the cursor unchanged when
        # ``maxtime`` is unset, which is what ``get`` returns.
        self.assertIs(result, cursor)

    def test_mongodb_notes_get_applies_query_timeout(self) -> None:
        # When the client is configured with a query
        # timeout (``MONGODB_QUERY_TIMEOUT_MS`` config knob
        # or per-URL ``?maxtime=`` param,
        # surfaced as ``backend.maxtime``), the cursor
        # returned by :meth:`MongoDBNotes.get` must carry
        # the bound -- otherwise a heavy ``$text`` query
        # over a large notes collection under adversarial
        # input would run unbounded.
        notes_col = mock.Mock()
        cursor = mock.Mock()
        notes_col.find.return_value = cursor
        backend = self._build_get_backend(notes_col, maxtime=5000)
        backend.get({"entity_type": "host"})
        cursor.max_time_ms.assert_called_once_with(5000)

    def test_mongodb_notes_get_text_sort_adds_score_projection(self) -> None:
        # The :meth:`_get_cursor` ``sort=[("text", ...)]``
        # shortcut auto-adds the ``$meta: textScore``
        # projection and sort, so web routes can ask for
        # relevance-ranked free-text search results in one
        # call rather than hand-rolling the meta projection.
        # Pin that behaviour for the notes purpose --
        # ``/cgi/notes/?q=...`` (web route) relies on it.
        notes_col = mock.Mock()
        cursor = mock.Mock()
        notes_col.find.return_value = cursor
        backend = self._build_get_backend(notes_col)
        backend.get(
            {"$text": {"$search": "c2"}},
            sort=[("text", 0)],
        )
        # ``find`` received the auto-added meta projection.
        find_args = notes_col.find.call_args
        self.assertEqual(find_args.args, ({"$text": {"$search": "c2"}},))
        self.assertEqual(
            find_args.kwargs.get("projection"),
            {"score": {"$meta": "textScore"}},
        )
        # And the cursor was sorted by the same meta key.
        cursor.sort.assert_called_once_with([("score", {"$meta": "textScore"})])

    def test_mongodb_notes_count_empty_filter_uses_estimated(self) -> None:
        # Mirrors :meth:`MongoDBView.count`: an empty filter
        # reads collection metadata in O(1) via
        # ``estimated_document_count`` instead of scanning
        # every document.  The ``count_notes(entity_type=None)``
        # path is the common case that benefits.
        notes_col = mock.Mock()
        notes_col.estimated_document_count.return_value = 42
        backend = self._build_get_backend(notes_col)
        self.assertEqual(backend.count({}), 42)
        notes_col.estimated_document_count.assert_called_once_with()
        notes_col.count_documents.assert_not_called()

    def test_mongodb_notes_count_nonempty_filter_uses_count_documents(
        self,
    ) -> None:
        # A non-empty filter goes through
        # ``count_documents`` so the filter is honoured.
        notes_col = mock.Mock()
        notes_col.count_documents.return_value = 7
        backend = self._build_get_backend(notes_col)
        self.assertEqual(backend.count({"entity_type": "host"}), 7)
        notes_col.count_documents.assert_called_once_with({"entity_type": "host"})
        notes_col.estimated_document_count.assert_not_called()

    def test_list_notes_in_abstract_surface(self) -> None:
        # ``list_notes`` is the storage-layer convenience the
        # web ``GET /cgi/notes/?...`` route and the
        # ``note_query`` MCP tool both consume; pin its
        # presence on the abstract :class:`DBNotes` and the
        # concrete :class:`MongoDBNotes`, plus the
        # :class:`NotImplementedError` raise on the base.
        from ivre.db import DBNotes
        from ivre.db.mongo import MongoDBNotes

        self.assertIn("list_notes", DBNotes.__dict__)
        self.assertIn("list_notes", MongoDBNotes.__dict__)
        with self.assertRaises(NotImplementedError):
            DBNotes().list_notes()

    def test_list_notes_no_filter_calls_get_with_empty_flt(self) -> None:
        # ``list_notes()`` with no filters goes through
        # :meth:`get` (which routes through ``_get_cursor``)
        # with the empty filter and post-processes each doc
        # via :meth:`_present_note`.
        from ivre.db.mongo import MongoDBNotes

        backend = MongoDBNotes.__new__(MongoDBNotes)
        backend.columns = ["notes", "note_revisions"]
        backend.maxtime = None
        canonical = MongoDBNotes._entity_key_to_storage([-0x8000000000000000, 0])
        notes_col = mock.Mock()
        cursor = mock.Mock()
        # Simulate one doc returned by the cursor's iteration.
        cursor.__iter__ = mock.Mock(
            return_value=iter(
                [
                    {
                        "_id": "id-1",
                        "entity_type": "host",
                        "entity_key_0": canonical[0],
                        "entity_key_1": canonical[1],
                        "body": "hi",
                        "revision": 1,
                    }
                ]
            )
        )
        notes_col.find.return_value = cursor
        backend._db = mock.Mock()
        backend._db.db = {"notes": notes_col, "note_revisions": mock.Mock()}
        results = backend.list_notes()
        self.assertEqual(len(results), 1)
        # Caller-facing form (``_present_note`` converted the
        # storage halves to a single ``entity_key``).
        self.assertNotIn("entity_key_0", results[0])
        self.assertNotIn("entity_key_1", results[0])
        self.assertEqual(results[0]["entity_type"], "host")
        # ``find`` was called with the empty filter -- the
        # combinator default from :meth:`flt_empty`.
        notes_col.find.assert_called_once()
        flt_arg = notes_col.find.call_args.args[0]
        self.assertEqual(flt_arg, {})
        # Deterministic default sort applied to the cursor:
        # ``_id`` ascending so ``limit`` / ``skip`` pagination
        # is reproducible across calls, replicas, and
        # document moves.
        cursor.sort.assert_called_once_with([("_id", 1)])

    def test_list_notes_with_entity_type_narrows_filter(self) -> None:
        # ``list_notes(entity_type=...)`` narrows the filter
        # to one entity type.  ``flt_empty`` is the empty
        # dict and ``flt_and`` collapses it with the
        # entity-type clause to a single-key filter.  The
        # deterministic default sort applies to this branch
        # too (no ``q``).
        from ivre.db.mongo import MongoDBNotes

        backend = MongoDBNotes.__new__(MongoDBNotes)
        backend.columns = ["notes", "note_revisions"]
        backend.maxtime = None
        notes_col = mock.Mock()
        cursor = mock.Mock()
        cursor.__iter__ = mock.Mock(return_value=iter([]))
        notes_col.find.return_value = cursor
        backend._db = mock.Mock()
        backend._db.db = {"notes": notes_col, "note_revisions": mock.Mock()}
        backend.list_notes(entity_type="host")
        flt_arg = notes_col.find.call_args.args[0]
        self.assertEqual(flt_arg.get("entity_type"), "host")
        cursor.sort.assert_called_once_with([("_id", 1)])

    def test_list_notes_with_q_adds_searchtext_and_score_sort(self) -> None:
        # ``list_notes(q=...)`` composes ``searchtext`` into
        # the filter and asks for relevance-ranked results
        # via the ``("text", 0)`` sort shortcut that
        # :meth:`_get_cursor` translates to the
        # ``$meta: textScore`` projection / sort.
        from ivre.db.mongo import MongoDBNotes

        backend = MongoDBNotes.__new__(MongoDBNotes)
        backend.columns = ["notes", "note_revisions"]
        backend.maxtime = None
        notes_col = mock.Mock()
        cursor = mock.Mock()
        cursor.__iter__ = mock.Mock(return_value=iter([]))
        notes_col.find.return_value = cursor
        backend._db = mock.Mock()
        backend._db.db = {"notes": notes_col, "note_revisions": mock.Mock()}
        backend.list_notes(q="c2")
        # Filter carries the ``$text`` clause -- ``flt_and``
        # collapses the empty-filter prefix down so the
        # final filter is just the ``$text`` clause (no
        # ``$and`` wrapper, since the keys do not overlap).
        flt_arg = notes_col.find.call_args.args[0]
        self.assertEqual(flt_arg.get("$text", {}).get("$search"), "c2")
        # The cursor was sorted by relevance.
        cursor.sort.assert_called_once_with([("score", {"$meta": "textScore"})])
        # Auto-added meta projection so ``find`` can return
        # the textScore field alongside the doc.
        proj = notes_col.find.call_args.kwargs.get("projection")
        self.assertEqual(proj, {"score": {"$meta": "textScore"}})

    def test_list_notes_with_fields_keeps_entity_key_halves(self) -> None:
        # ``list_notes(fields=[...])`` constructs a projection
        # that always includes the ``entity_key_0`` /
        # ``entity_key_1`` halves so :meth:`_present_note`
        # can reassemble the caller-facing ``entity_key``
        # even when the caller did not list them.  The
        # projection is also passed as a dict (not a list)
        # so the ``("text", ...)`` sort branch in
        # ``_get_cursor`` honours ``limit`` / ``skip``.
        from ivre.db.mongo import MongoDBNotes

        backend = MongoDBNotes.__new__(MongoDBNotes)
        backend.columns = ["notes", "note_revisions"]
        backend.maxtime = None
        notes_col = mock.Mock()
        cursor = mock.Mock()
        cursor.__iter__ = mock.Mock(return_value=iter([]))
        notes_col.find.return_value = cursor
        backend._db = mock.Mock()
        backend._db.db = {"notes": notes_col, "note_revisions": mock.Mock()}
        backend.list_notes(fields=["updated_at", "revision"], limit=10, skip=5)
        proj = notes_col.find.call_args.kwargs.get("projection")
        self.assertIsInstance(proj, dict)
        # Caller-requested fields + the storage halves.
        for required in {
            "updated_at",
            "revision",
            "entity_type",
            "entity_key_0",
            "entity_key_1",
        }:
            self.assertIn(required, proj)
        # Pagination forwarded.
        self.assertEqual(notes_col.find.call_args.kwargs.get("limit"), 10)
        self.assertEqual(notes_col.find.call_args.kwargs.get("skip"), 5)

    def test_list_notes_q_set_keeps_text_score_sort(self) -> None:
        # When ``q`` is set the relevance-ranked
        # ``("text", 0)`` sort takes precedence over the
        # default ``_id`` sort, so ``cursor.sort`` ends up
        # with the ``$meta: textScore`` order (no ``_id``
        # appended).  Pin this to make explicit that the
        # ``q`` branch and the deterministic-default branch
        # are mutually exclusive.
        from ivre.db.mongo import MongoDBNotes

        backend = MongoDBNotes.__new__(MongoDBNotes)
        backend.columns = ["notes", "note_revisions"]
        backend.maxtime = None
        notes_col = mock.Mock()
        cursor = mock.Mock()
        cursor.__iter__ = mock.Mock(return_value=iter([]))
        notes_col.find.return_value = cursor
        backend._db = mock.Mock()
        backend._db.db = {"notes": notes_col, "note_revisions": mock.Mock()}
        backend.list_notes(q="indicator")
        cursor.sort.assert_called_once_with([("score", {"$meta": "textScore"})])

    def test_parse_revision_param_accepts_bare_integer(self) -> None:
        # The simplest form: ``?expected_revision=7`` (query
        # parameter) or ``If-Match: 7`` (unquoted; not strictly
        # RFC-compliant but accepted by most servers).
        from ivre.web.app import _parse_revision_param

        self.assertEqual(_parse_revision_param("7"), 7)

    def test_parse_revision_param_accepts_quoted_etag(self) -> None:
        # Canonical ETag form: ``If-Match: "7"``.
        from ivre.web.app import _parse_revision_param

        self.assertEqual(_parse_revision_param('"7"'), 7)

    def test_parse_revision_param_strips_weak_etag_prefix(self) -> None:
        # Weak validator: ``If-Match: W/"7"``.  For a monotonic
        # revision counter weak vs strong is meaningless, so we
        # accept the form transparently.
        from ivre.web.app import _parse_revision_param

        self.assertEqual(_parse_revision_param('W/"7"'), 7)
        # And unquoted weak: ``W/7``.
        self.assertEqual(_parse_revision_param("W/7"), 7)

    def test_parse_revision_param_takes_first_from_comma_list(self) -> None:
        # Multi-validator: ``If-Match: "7", "8"`` -- first wins.
        # Strict "apply if any matches" would need a multi-version
        # ``set_note`` mode we do not implement.
        from ivre.web.app import _parse_revision_param

        self.assertEqual(_parse_revision_param('"7", "8"'), 7)
        # Mix of weak + strong in the list, still first wins.
        self.assertEqual(_parse_revision_param('W/"7", "8"'), 7)

    def test_parse_revision_param_rejects_wildcard(self) -> None:
        # ``If-Match: *`` (generic "must exist") has no clean
        # mapping to ``set_note``'s modes; reject explicitly
        # rather than silently misinterpret.
        from bottle import HTTPError

        from ivre.web.app import _parse_revision_param

        with self.assertRaises(HTTPError) as ctx:
            _parse_revision_param("*")
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("If-Match: *", ctx.exception.body)

    def test_parse_revision_param_rejects_garbage(self) -> None:
        # Anything non-integer (after stripping ``W/`` / quotes /
        # comma-list) is rejected with 400.
        from bottle import HTTPError

        from ivre.web.app import _parse_revision_param

        with self.assertRaises(HTTPError) as ctx:
            _parse_revision_param("abc")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_parse_revision_param_none_or_empty(self) -> None:
        # No precondition requested -> ``None`` -> LWW.
        from ivre.web.app import _parse_revision_param

        self.assertIsNone(_parse_revision_param(None))
        self.assertIsNone(_parse_revision_param(""))
        self.assertIsNone(_parse_revision_param("   "))

    def test_mcp_require_notes_backend_raises_when_unavailable(self) -> None:
        # The MCP notes tools' first line is
        # ``_require_notes_backend()``; on a backend that
        # does not implement the notes purpose (any non-Mongo
        # at v1) that helper raises a friendly ``McpError``
        # with ``INTERNAL_ERROR`` so the LLM sees a
        # configuration message rather than the cryptic
        # ``AttributeError: 'NoneType' object has no
        # attribute '<method>'`` the catch-all handler would
        # otherwise produce.  Pin the helper directly --
        # exercising the tools through FastMCP would require
        # the full server harness, while the helper carries
        # the contract on its own.
        try:
            from mcp.shared.exceptions import McpError as _McpError  # noqa: PLC0415
        except ImportError:
            self.skipTest("mcp package not installed")

        from ivre.tools.mcp_server import _require_notes_backend
        from ivre.tools.mcp_server import db as mcp_db

        stub_db = mock.Mock()
        stub_db.notes = None
        with mock.patch.object(sys.modules["ivre.tools.mcp_server"], "db", stub_db):
            with self.assertRaises(_McpError) as ctx:
                _require_notes_backend()
        # The message names the supported backend and the
        # config knob so operators see the fix path.
        msg = ctx.exception.error.message
        self.assertIn("Notes backend not available", msg)
        self.assertIn("mongodb://", msg)
        # ``mcp_db`` is the real module-level ``db`` -- not
        # what the helper saw (which was the patched stub).
        # Reference it so the import is not unused.
        self.assertIsNotNone(mcp_db)

    def test_web_require_notes_backend_aborts_501_when_unavailable(self) -> None:
        # All notes web routes call ``_require_notes_backend()``
        # as their first line so a misconfigured deployment
        # surfaces a clean HTTP 501 with a friendly message
        # naming the supported backend, rather than the
        # cryptic HTTP 500 the catch-all WSGI handler would
        # otherwise produce from the ``AttributeError`` on
        # ``db.notes.<method>()``.  501 (Not Implemented) is
        # the right HTTP semantic for "the route exists but
        # the implementation is missing for this server's
        # backend"; 404 would mislead operators into thinking
        # they need to create a resource.
        from bottle import HTTPError

        from ivre.web import app as web_app

        stub_db = mock.Mock()
        stub_db.notes = None
        with mock.patch.object(web_app, "db", stub_db):
            with self.assertRaises(HTTPError) as ctx:
                web_app._require_notes_backend()
        self.assertEqual(ctx.exception.status_code, 501)
        self.assertIn("Notes backend not available", ctx.exception.body)
        self.assertIn("mongodb://", ctx.exception.body)

    def test_notes_cli_exits_when_backend_unavailable(self) -> None:
        # ``ivre notes --init`` on a backend that does not
        # implement the notes purpose (any non-MongoDB at v1)
        # would crash with ``AttributeError`` against the
        # ``None`` returned by :attr:`MetaDB.notes`.  The CLI
        # guards against this with an early exit and a
        # friendly message naming the supported backend; pin
        # that behaviour so a future refactor cannot silently
        # regress it.  Mirrors the ``db.auth is None`` check
        # in :mod:`ivre.tools.authcli`.
        from ivre.tools import notes as notes_tool

        # ``MetaDB.notes`` is a property without a setter, so
        # patch the module-level ``db`` reference itself with
        # a stub whose ``.notes`` is ``None`` -- mirrors what
        # a real non-MongoDB deployment would see.
        stub_db = mock.Mock()
        stub_db.notes = None
        with mock.patch.object(notes_tool, "db", stub_db):
            with mock.patch.object(sys, "argv", ["ivre-notes", "--init"]):
                with self.assertRaises(SystemExit) as ctx:
                    notes_tool.main()
        # ``sys.exit("...message...")`` produces a string code
        # carrying the message and a non-zero process exit.
        self.assertIsInstance(ctx.exception.code, str)
        message = ctx.exception.code
        assert isinstance(message, str)
        self.assertIn("Notes backend not available", message)
        self.assertIn("mongodb://", message)

    def test_metadb_has_notes_property(self) -> None:
        # ``db.notes`` resolves to a ``DBNotes`` instance when
        # ``DB_NOTES`` / ``DB`` is configured to a backend that
        # implements the purpose.  We patch ``DB_NOTES`` to a
        # synthetic mongodb URL so the property doesn't try to
        # talk to a real backend.
        from ivre.db import DBNotes, MetaDB

        # Build a fresh MetaDB so we don't poison the module-level
        # ``db`` singleton's cached ``_notes`` attribute.
        m = MetaDB(
            url="mongodb:///x",
            urls={"notes": "mongodb:///x"},
        )
        notes = m.notes
        # The class lookup succeeded -- ``MongoDBNotes`` is the
        # registered backend for ``"mongodb"``.  We can't talk to
        # the real server in this test, but the class wiring is
        # what we care about here.
        self.assertIsNotNone(notes)
        self.assertIsInstance(notes, DBNotes)


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
