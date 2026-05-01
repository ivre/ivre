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

"""Residual setup.py for data_files (dynamic os.listdir() calls
require Python, which pyproject.toml cannot express).
"""

import os

from setuptools import setup


def collect_files(directory, extensions):
    """Collect files from directory matching given extensions."""
    return [
        os.path.join(directory, f)
        for f in sorted(os.listdir(directory))
        if any(f.endswith(ext) for ext in extensions)
    ]


setup(
    data_files=[
        ("share/ivre/zeek", ["zeek/passiverecon2db-ignore.example"]),
        ("share/ivre/zeek/ivre", ["zeek/ivre/__load__.zeek"]),
        ("share/ivre/zeek/ivre/arp", ["zeek/ivre/arp/__load__.zeek"]),
        (
            "share/ivre/zeek/ivre/passiverecon",
            [
                "zeek/ivre/passiverecon/__load__.zeek",
                "zeek/ivre/passiverecon/bare.zeek",
                "zeek/ivre/passiverecon/hassh.zeek",
                "zeek/ivre/passiverecon/ja3.zeek",
                "zeek/ivre/passiverecon/ntlm.zeek",
            ],
        ),
        ("share/ivre/honeyd", ["data/.empty"]),
        ("share/ivre/geoip", ["data/.empty"]),
        (
            "share/ivre/data",
            [
                "data/ike-vendor-ids",
                "data/manuf",
                "data/censys_scanners.txt",
                "data/rapid7_scanners.txt",
                "data/ssigouvfr_scanners.txt",
                "data/ukncsc_scanners.txt",
                "data/cdn_nuclei.json",
                "data/govcloud.json",
                "data/govcloud_aws.json",
                "data/govcloud_azure.json",
            ],
        ),
        ("share/ivre/data/honeyd", ["data/honeyd/sshd"]),
        ("share/ivre/rir_data", ["data/.empty"]),
        ("share/ivre/docker", ["docker/Vagrantfile"]),
        ("share/ivre/docker/base", ["docker/base/Dockerfile"]),
        ("share/ivre/docker/client", ["docker/client/Dockerfile"]),
        (
            "share/ivre/docker/web",
            ["docker/web/Dockerfile", "docker/web/nginx-default-site"],
        ),
        (
            "share/ivre/docker/web-doku",
            [
                "docker/web-doku/Dockerfile",
                "docker/web-doku/doku-conf-acl.auth.php",
                "docker/web-doku/doku-conf-local.php",
                "docker/web-doku/doku-conf-plugins.local.php",
                "docker/web-doku/doku-conf-users.auth.php",
            ],
        ),
        (
            "share/ivre/docker/web-mcp",
            ["docker/web-mcp/Dockerfile"],
        ),
        (
            "share/ivre/docker/web-uwsgi",
            ["docker/web-uwsgi/Dockerfile"],
        ),
        (
            "share/ivre/web/static",
            collect_files("web/static", [".gif", ".html", ".json", ".png"]),
        ),
        (
            "share/ivre/web/static/templates",
            collect_files("web/static/templates", [".html"]),
        ),
        # Doc (Web)
        (
            "share/ivre/web/static/doc",
            collect_files("web/static/doc", [".html", ".js"]),
        ),
        (
            "share/ivre/web/static/doc/dev",
            collect_files("web/static/doc/dev", [".html"]),
        ),
        (
            "share/ivre/web/static/doc/install",
            collect_files("web/static/doc/install", [".html"]),
        ),
        (
            "share/ivre/web/static/doc/overview",
            collect_files("web/static/doc/overview", [".html"]),
        ),
        (
            "share/ivre/web/static/doc/usage",
            collect_files("web/static/doc/usage", [".html"]),
        ),
        (
            "share/ivre/web/static/doc/_images",
            collect_files("web/static/doc/_images", [".png", ".png.map", ".svg"]),
        ),
        (
            "share/ivre/web/static/doc/_static",
            collect_files("web/static/doc/_static", [".css", ".js", ".png"]),
        ),
        (
            "share/ivre/web/static/doc/_static/css",
            collect_files("web/static/doc/_static/css", [".css"]),
        ),
        (
            "share/ivre/web/static/doc/_static/js",
            collect_files("web/static/doc/_static/js", [".js"]),
        ),
        (
            "share/ivre/web/static/doc/_sources",
            collect_files("web/static/doc/_sources", [".rst.txt"]),
        ),
        (
            "share/ivre/web/static/doc/_sources/dev",
            collect_files("web/static/doc/_sources/dev", [".rst.txt"]),
        ),
        (
            "share/ivre/web/static/doc/_sources/install",
            collect_files("web/static/doc/_sources/install", [".rst.txt"]),
        ),
        (
            "share/ivre/web/static/doc/_sources/overview",
            collect_files("web/static/doc/_sources/overview", [".rst.txt"]),
        ),
        (
            "share/ivre/web/static/doc/_sources/usage",
            collect_files("web/static/doc/_sources/usage", [".rst.txt"]),
        ),
        # IVRE
        (
            "share/ivre/web/static/ivre",
            collect_files("web/static/ivre", [".css", ".js"]),
        ),
        ("share/ivre/web/static/ivre/flow", ["web/static/ivre/flow/controllers.js"]),
        # Bootstrap
        (
            "share/ivre/web/static/bs/css",
            ["web/static/bs/css/bootstrap.css", "web/static/bs/css/bootstrap.css.map"],
        ),
        ("share/ivre/web/static/bs/js", ["web/static/bs/js/bootstrap.js"]),
        (
            "share/ivre/web/static/bs/fonts",
            [
                "web/static/bs/fonts/glyphicons-halflings-regular.woff",
                "web/static/bs/fonts/glyphicons-halflings-regular.woff2",
            ],
        ),
        # jQuery
        ("share/ivre/web/static/jq", ["web/static/jq/jquery.js"]),
        # d3.js
        (
            "share/ivre/web/static/d3/js",
            ["web/static/d3/js/d3.v3.min.js", "web/static/d3/js/topojson.v1.min.js"],
        ),
        # AngularJS
        ("share/ivre/web/static/an/js", ["web/static/an/js/angular.js"]),
        # Linkurious/sigma.js
        (
            "share/ivre/web/static/lk",
            [
                "web/static/lk/plugins.min.js",
                "web/static/lk/plugins.min.js.map",
                "web/static/lk/sigma.min.js",
                "web/static/lk/sigma.min.js.map",
            ],
        ),
        # flag-icon-css
        ("share/ivre/web/static/fi/css", ["web/static/fi/css/flag-icon.css"]),
        (
            "share/ivre/web/static/fi/flags/4x3",
            [
                os.path.join("web/static/fi/flags/4x3/", x)
                for x in sorted(os.listdir("web/static/fi/flags/4x3/"))
            ],
        ),
        # WSGI application
        ("share/ivre/web/wsgi", ["web/wsgi/app.wsgi"]),
        # Dokuwiki
        ("share/ivre/dokuwiki/media", ["web/dokuwiki/media/logo.png"]),
        # Patches
        (
            "share/ivre/patches/dokuwiki",
            [
                "patches/dokuwiki/backlinks.patch",
                "patches/dokuwiki/backlinks-20200729.patch",
                "patches/dokuwiki/backlinks-20230404a.patch",
            ],
        ),
        (
            "share/ivre/patches/nmap",
            [
                "patches/nmap/pr-2142.patch",
                "patches/nmap/pr-2229.patch",
                "patches/nmap/rtsp-url-brute.patch",
            ],
        ),
        (
            "share/ivre/patches/nmap/scripts",
            collect_files("patches/nmap/scripts", [".nse"]),
        ),
        ("share/ivre/patches/p0f", ["patches/p0f/p0f.fp.patch"]),
        (
            "share/doc/ivre/rst",
            collect_files("doc", [".rst"]),
        ),
        (
            "share/doc/ivre/rst/dev",
            collect_files("doc/dev", [".rst"]),
        ),
        (
            "share/doc/ivre/rst/install",
            collect_files("doc/install", [".rst"]),
        ),
        (
            "share/doc/ivre/rst/overview",
            collect_files("doc/overview", [".rst"]),
        ),
        (
            "share/doc/ivre/rst/usage",
            collect_files("doc/usage", [".rst"]),
        ),
        (
            "share/doc/ivre/rst/screenshots",
            collect_files("doc/screenshots", [".cast", ".png", ".svg"]),
        ),
        ("share/bash-completion/completions", ["bash_completion/ivre"]),
    ],
)
