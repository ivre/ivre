#! /usr/bin/env python

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

"""Standard setup.py file. Run

$ python setup.py build
# python setup.py install
"""


from distutils.core import setup
from distutils.command.install_data import install_data
from distutils.command.install_lib import install_lib
from distutils.dist import DistributionMetadata
import os
from tempfile import TemporaryFile


VERSION = __import__("ivre").VERSION


class smart_install_data(install_data):
    """Replacement for distutils.command.install_data to handle
    configuration files location.

    """

    def run(self):
        # install files to /etc when target was /usr(/local)/etc
        if self.install_dir.endswith("/usr") or self.install_dir.endswith("/usr/local"):
            self.data_files = [
                ("/%s" % path if path.startswith("etc/") else path, files)
                for path, files in self.data_files
                if path  # skip README.md or any file with an empty path
            ]
        else:
            self.data_files = [
                (path, files)
                for path, files in self.data_files
                if path  # skip README.md or any file with an empty path
            ]
        return super().run()


class smart_install_lib(install_lib):
    """Replacement for distutils.command.install_lib to handle
    version file.

    """

    def run(self):
        super().run()
        fullfname = os.path.join(self.install_dir, "ivre", "__init__.py")
        tmpfname = "%s.tmp" % fullfname
        stat = os.stat(fullfname)
        os.rename(fullfname, tmpfname)
        with open(fullfname, "w") as newf:
            with open(tmpfname) as oldf:
                for line in oldf:
                    if line.startswith("import "):
                        newf.write("VERSION = %r\n" % VERSION)
                        break
                    newf.write(line)
        os.chown(fullfname, stat.st_uid, stat.st_gid)
        os.chmod(fullfname, stat.st_mode)
        os.unlink(tmpfname)


with open(
    os.path.join(os.path.abspath(os.path.dirname("__file__")), "README.md")
) as fdesc:
    long_description = fdesc.read()
long_description_content_type = "text/markdown"


# Monkey patching (distutils does not handle Description-Content-Type
# from long_description_content_type parameter in setup()).
_write_pkg_file_orig = DistributionMetadata.write_pkg_file


def _write_pkg_file(self, file):
    with TemporaryFile(mode="w+") as tmpfd:
        _write_pkg_file_orig(self, tmpfd)
        tmpfd.seek(0)
        for line in tmpfd:
            if line.startswith("Metadata-Version: "):
                file.write("Metadata-Version: 2.1\n")
            elif line.startswith("Description: "):
                file.write(
                    "Description-Content-Type: %s; charset=UTF-8\n"
                    % long_description_content_type
                )
                file.write(line)
            else:
                file.write(line)


DistributionMetadata.write_pkg_file = _write_pkg_file


setup(
    name="ivre",
    version=VERSION,
    author="Pierre LALET",
    author_email="pierre@droids-corp.org",
    url="https://ivre.rocks/",
    download_url="https://github.com/ivre/ivre/tarball/master",
    license="GPLv3+",
    description="Network recon framework",
    long_description=long_description,
    long_description_content_type=long_description_content_type,
    keywords=[
        "network",
        "network recon",
        "network cartography",
        "nmap",
        "masscan",
        "zmap",
        "zgrab",
        "zdns",
        "bro",
        "zeek",
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Software Distribution",
    ],
    python_requires=">=3.6, <4",
    install_requires=[
        "cryptography",
        "pymongo>=2.7.2",
        "pyOpenSSL>=16.1.0",
        "bottle",
    ],
    extras_require={
        "TinyDB (experimental)": ["tinydb"],
        "PostgreSQL (experimental)": ["sqlalchemy", "psycopg2"],
        "Elasticsearch (experimental)": ["elasticsearch", "elasticsearch-dsl"],
        "GSSAPI authentication for MongoDB": ["python-krbV"],
        "GSSAPI authentication for HTTP": ["pycurl"],
        "Screenshots": ["PIL"],
        "MediaWiki integration": ["MySQL-python"],
        "3D traceroute graphs": ["dbus-python"],
        "Plots": ["matplotlib"],
        "JA3 fingerprints from reverse-ssl services": ["scapy"],
    },
    packages=[
        "ivre",
        "ivre/active",
        "ivre/analyzer",
        "ivre/data",
        "ivre/data/microsoft",
        "ivre/db",
        "ivre/db/sql",
        "ivre/parser",
        "ivre/tools",
        "ivre/types",
        "ivre/web",
    ],
    scripts=["bin/ivre"],
    data_files=[
        ("", ["README.md"]),  # needed for the package description
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
        ("share/ivre/data", ["data/ike-vendor-ids"]),
        ("share/ivre/data/honeyd", ["data/honeyd/sshd"]),
        ("share/ivre/docker", ["docker/Vagrantfile"]),
        ("share/ivre/docker/agent", ["docker/agent/Dockerfile"]),
        ("share/ivre/docker/base", ["docker/base/Dockerfile"]),
        ("share/ivre/docker/client", ["docker/client/Dockerfile"]),
        ("share/ivre/docker/db", ["docker/db/Dockerfile"]),
        (
            "share/ivre/docker/web",
            [
                "docker/web/Dockerfile",
                "docker/web/doku-conf-acl.auth.php",
                "docker/web/doku-conf-local.php",
                "docker/web/doku-conf-plugins.local.php",
                "docker/web/doku-conf-users.auth.php",
                "docker/web/nginx-default-site",
            ],
        ),
        (
            "share/ivre/docker/web-apache",
            ["docker/web-apache/Dockerfile", "docker/web-apache/doku-conf-local.php"],
        ),
        (
            "share/ivre/web/static",
            [
                "web/static/index.html",
                "web/static/compare.html",
                "web/static/flow.html",
                "web/static/report.html",
                "web/static/upload.html",
                "web/static/favicon-loading.gif",
                "web/static/favicon.png",
                "web/static/loading.gif",
                "web/static/logo.png",
                "web/static/anssi.png",
                "web/static/anssi-white.png",
                "web/static/cea.png",
                "web/static/cea-white.png",
                "web/static/world-110m.json",
            ],
        ),
        (
            "share/ivre/web/static/templates",
            [
                "web/static/templates/filters.html",
                "web/static/templates/graph-right-click.html",
                "web/static/templates/menu.html",
                "web/static/templates/messages.html",
                "web/static/templates/progressbar.html",
                "web/static/templates/query-builder.html",
                "web/static/templates/view-cpes-only.html",
                "web/static/templates/view-hosts.html",
                "web/static/templates/view-screenshots-only.html",
                "web/static/templates/view-scripts-only.html",
                "web/static/templates/view-ports-only.html",
                "web/static/templates/view-services-only.html",
                "web/static/templates/view-vulnerabilities-only.html",
                "web/static/templates/subview-cpes.html",
                "web/static/templates/subview-graph-elt-details.html",
                "web/static/templates/subview-host-summary.html",
                "web/static/templates/subview-port-summary.html",
                "web/static/templates/subview-ports-summary.html",
                "web/static/templates/subview-service-summary.html",
                "web/static/templates/topvalues.html",
            ],
        ),
        # Doc (Web)
        (
            "share/ivre/web/static/doc",
            [
                os.path.join("web/static/doc", x)
                for x in os.listdir("web/static/doc")
                if x.endswith(".html") or x.endswith(".js")
            ],
        ),
        (
            "share/ivre/web/static/doc/dev",
            [
                os.path.join("web/static/doc/dev", x)
                for x in os.listdir("web/static/doc/dev")
                if x.endswith(".html")
            ],
        ),
        (
            "share/ivre/web/static/doc/install",
            [
                os.path.join("web/static/doc/install", x)
                for x in os.listdir("web/static/doc/install")
                if x.endswith(".html")
            ],
        ),
        (
            "share/ivre/web/static/doc/overview",
            [
                os.path.join("web/static/doc/overview", x)
                for x in os.listdir("web/static/doc/overview")
                if x.endswith(".html")
            ],
        ),
        (
            "share/ivre/web/static/doc/usage",
            [
                os.path.join("web/static/doc/usage", x)
                for x in os.listdir("web/static/doc/usage")
                if x.endswith(".html")
            ],
        ),
        (
            "share/ivre/web/static/doc/_images",
            [
                os.path.join("web/static/doc/_images", x)
                for x in os.listdir("web/static/doc/_images")
                if x.endswith(".png") or x.endswith(".png.map") or x.endswith(".svg")
            ],
        ),
        (
            "share/ivre/web/static/doc/_static",
            [
                os.path.join("web/static/doc/_static", x)
                for x in os.listdir("web/static/doc/_static")
                if x.endswith(".css") or x.endswith(".js") or x.endswith(".png")
            ],
        ),
        (
            "share/ivre/web/static/doc/_static/css",
            [
                os.path.join("web/static/doc/_static/css", x)
                for x in os.listdir("web/static/doc/_static/css")
                if x.endswith(".css")
            ],
        ),
        (
            "share/ivre/web/static/doc/_static/js",
            [
                os.path.join("web/static/doc/_static/js", x)
                for x in os.listdir("web/static/doc/_static/js")
                if x.endswith(".js")
            ],
        ),
        (
            "share/ivre/web/static/doc/_sources",
            [
                os.path.join("web/static/doc/_sources", x)
                for x in os.listdir("web/static/doc/_sources")
                if x.endswith(".rst.txt")
            ],
        ),
        (
            "share/ivre/web/static/doc/_sources/dev",
            [
                os.path.join("web/static/doc/_sources/dev", x)
                for x in os.listdir("web/static/doc/_sources/dev")
                if x.endswith(".rst.txt")
            ],
        ),
        (
            "share/ivre/web/static/doc/_sources/install",
            [
                os.path.join("web/static/doc/_sources/install", x)
                for x in os.listdir("web/static/doc/_sources/install")
                if x.endswith(".rst.txt")
            ],
        ),
        (
            "share/ivre/web/static/doc/_sources/overview",
            [
                os.path.join("web/static/doc/_sources/overview", x)
                for x in os.listdir("web/static/doc/_sources/overview")
                if x.endswith(".rst.txt")
            ],
        ),
        (
            "share/ivre/web/static/doc/_sources/usage",
            [
                os.path.join("web/static/doc/_sources/usage", x)
                for x in os.listdir("web/static/doc/_sources/usage")
                if x.endswith(".rst.txt")
            ],
        ),
        # IVRE
        (
            "share/ivre/web/static/ivre",
            [
                "web/static/ivre/flow.css",
                "web/static/ivre/ivre.css",
                "web/static/ivre/compare.js",
                "web/static/ivre/controllers.js",
                "web/static/ivre/filters.js",
                "web/static/ivre/form-helpers.js",
                "web/static/ivre/graph.js",
                "web/static/ivre/ivre.js",
                "web/static/ivre/params.js",
                "web/static/ivre/tooltip.js",
                "web/static/ivre/utils.js",
                "web/static/ivre/content.js",
            ],
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
                for x in os.listdir("web/static/fi/flags/4x3/")
            ],
        ),
        # WSGI application
        ("share/ivre/web/wsgi", ["web/wsgi/app.wsgi"]),
        # Dokuwiki
        ("share/ivre/dokuwiki", ["web/dokuwiki/backlinks.patch"]),
        ("share/ivre/dokuwiki/media", ["web/dokuwiki/media/logo.png"]),
        (
            "share/ivre/nmap_scripts",
            [
                "nmap_scripts/http-screenshot.nse",
                "nmap_scripts/mainframe-banner.nse",
                "nmap_scripts/mainframe-screenshot.nse",
                "nmap_scripts/rtsp-screenshot.nse",
                "nmap_scripts/vnc-screenshot.nse",
                "nmap_scripts/x11-screenshot.nse",
            ],
        ),
        (
            "share/ivre/nmap_scripts/patches",
            ["nmap_scripts/patches/rtsp-url-brute.patch"],
        ),
        (
            "share/doc/ivre/rst",
            [os.path.join("doc/", x) for x in os.listdir("doc/") if x.endswith(".rst")],
        ),
        (
            "share/doc/ivre/rst/dev",
            [
                os.path.join("doc/dev", x)
                for x in os.listdir("doc/dev")
                if x.endswith(".rst")
            ],
        ),
        (
            "share/doc/ivre/rst/install",
            [
                os.path.join("doc/install", x)
                for x in os.listdir("doc/install")
                if x.endswith(".rst")
            ],
        ),
        (
            "share/doc/ivre/rst/overview",
            [
                os.path.join("doc/overview", x)
                for x in os.listdir("doc/overview")
                if x.endswith(".rst")
            ],
        ),
        (
            "share/doc/ivre/rst/usage",
            [
                os.path.join("doc/usage", x)
                for x in os.listdir("doc/usage")
                if x.endswith(".rst")
            ],
        ),
        (
            "share/doc/ivre/rst/screenshots",
            [
                "doc/screenshots/passive-cli.cast",
                "doc/screenshots/passive-cli.svg",
                "doc/screenshots/passive-view-cli.cast",
                "doc/screenshots/passive-view-cli.svg",
                "doc/screenshots/webui-details-heatmapzoom.png",
                "doc/screenshots/webui-flow-details-flow.png",
                "doc/screenshots/webui-flow-details-host.png",
                "doc/screenshots/webui-flow-dns-halo.png",
                "doc/screenshots/webui-flow-flow-map.png",
                "doc/screenshots/webui-home-heatmap.png",
                "doc/screenshots/webui-screenshots-solar-world.png",
                "doc/screenshots/webui-tooltip-topenipvendors.png",
                "doc/screenshots/webui-topproducts-80.png",
            ],
        ),
        ("etc/bash_completion.d", ["bash_completion/ivre"]),
    ],
    package_data={
        "ivre": ["VERSION"],
    },
    cmdclass={"install_data": smart_install_data, "install_lib": smart_install_lib},
)
