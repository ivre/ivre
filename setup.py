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

"""
This module is part of IVRE.
Copyright 2011 - 2017 Pierre LALET <pierre.lalet@cea.fr>

Standard setup.py file. Run

$ python setup.py build
# python setup.py install
"""

from distutils.core import setup
from distutils.command.install_data import install_data
from distutils.command.install_lib import install_lib
import os
import sys

VERSION = __import__('ivre').VERSION

class smart_install_data(install_data):
    """Replacement for distutils.command.install_data to handle
    configuration files location and CGI files shebang lines.

    """
    def run(self):
        # install files to /etc when target was /usr(/local)/etc
        if self.install_dir.endswith('/usr') or \
           self.install_dir.endswith('/usr/local'):
            self.data_files = [
                ("/%s" % path if path.startswith('etc/') else path, files)
                for path, files in self.data_files
            ]
        result = install_data.run(self)
        # handle CGI files like files in [PREFIX]/bin, replace first
        # line based on sys.executable
        for path, files in self.data_files:
            for fname in files:
                if fname.startswith('web/cgi-bin/') and fname.endswith('.py'):
                    fullfname = os.path.join(self.install_dir, path,
                                             os.path.basename(fname))
                    tmpfname = "%s.tmp" % fullfname
                    stat = os.stat(fullfname)
                    os.rename(fullfname, tmpfname)
                    with open(fullfname, 'w') as newf:
                        with open(tmpfname) as oldf:
                            oldf.readline()
                            newf.write("#!%s\n" % sys.executable)
                            for line in oldf:
                                newf.write(line)
                    os.chown(fullfname, stat.st_uid, stat.st_gid)
                    os.chmod(fullfname, stat.st_mode)
                    os.unlink(tmpfname)
        return result

class smart_install_lib(install_lib):
    """Replacement for distutils.command.install_lib to handle
    version file.

    """
    def run(self):
        result = install_lib.run(self)
        fullfname = os.path.join(self.install_dir, 'ivre', '__init__.py')
        tmpfname = "%s.tmp" % fullfname
        stat = os.stat(fullfname)
        os.rename(fullfname, tmpfname)
        with open(fullfname, 'w') as newf:
            with open(tmpfname) as oldf:
                for line in oldf:
                    if line.startswith('import '):
                        newf.write('VERSION = %r\n' % VERSION)
                        break
                    newf.write(line)
        os.chown(fullfname, stat.st_uid, stat.st_gid)
        os.chmod(fullfname, stat.st_mode)
        os.unlink(tmpfname)
        return result

setup(
    name='ivre',
    version=VERSION,
    author='Pierre LALET',
    author_email='pierre@droids-corp.org',
    url='https://ivre.rocks/',
    download_url='https://github.com/cea-sec/ivre/tarball/master',
    license='GPLv3+',
    description='Network recon framework',
    long_description="""
IVRE is a set of tools aimed at gathering and exploiting network
information.

It consists of a Python library, a Web UI, CLI tools and several
specialized scripts.
""",
    keywords=["network", "network recon", "network cartography",
              "nmap", "bro", "p0f"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: "
        "GNU General Public License v3 or later (GPLv3+)",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Software Distribution",
    ],
    install_requires=[
        'pycrypto',
        'pymongo>=2.7.2',
    ],
    extras_require={
        'Flow':  ["py2neo>=3"],
        'PostgreSQL': ["sqlalchemy", "psycopg2"],
    },
    packages=['ivre', 'ivre/tools', 'ivre/db', 'ivre/parser', 'ivre/analyzer'],
    scripts=['bin/ivre'],
    data_files=[
        ('share/ivre/passiverecon',
         ['passiverecon/passiverecon.bro',
          'passiverecon/passiverecon2db-ignore.example']),
        ('share/ivre/bro/flow',
         ['bro/flow/__load__.bro',
          'bro/flow/dhcp_names.bro',
          'bro/flow/rpc.bro',
          'bro/flow/settings.bro']),
        ('share/ivre/honeyd', []),
        ('share/ivre/geoip', []),
        ('share/ivre/data', ['data/ike-vendor-ids']),
        ('share/ivre/data/honeyd', ['data/honeyd/sshd']),
        ('share/ivre/docker', ['docker/Vagrantfile']),
        ('share/ivre/docker/agent', ['docker/agent/Dockerfile']),
        ('share/ivre/docker/base', ['docker/base/Dockerfile',
                                    'docker/base/ivre.conf']),
        ('share/ivre/docker/client', ['docker/client/Dockerfile']),
        ('share/ivre/docker/db', ['docker/db/Dockerfile']),
        ('share/ivre/docker/web', ['docker/web/Dockerfile',
                                   'docker/web/doku-conf-acl.auth.php',
                                   'docker/web/doku-conf-local.php',
                                   'docker/web/doku-conf-plugins.local.php',
                                   'docker/web/doku-conf-users.auth.php',
                                   'docker/web/nginx-default-site']),
        ('share/ivre/docker/web-apache',
         ['docker/web-apache/Dockerfile',
          'docker/web-apache/doku-conf-local.php']),
        ('share/ivre/web/static',
         ['web/static/index.html',
          'web/static/compare.html',
          'web/static/flow.html',
          'web/static/report.html',
          'web/static/upload.html',
          'web/static/favicon-loading.gif',
          'web/static/favicon.png',
          'web/static/loading.gif',
          'web/static/logo.png',
          'web/static/cea.png',
          'web/static/cea-white.png',
          'web/static/world-110m.json']),
        ('share/ivre/web/static/templates',
         ['web/static/templates/filters.html',
          'web/static/templates/graph-right-click.html',
          'web/static/templates/menu.html',
          'web/static/templates/messages.html',
          'web/static/templates/progressbar.html',
          'web/static/templates/query-builder.html',
          'web/static/templates/view-cpes-only.html',
          'web/static/templates/view-hosts.html',
          'web/static/templates/view-screenshots-only.html',
          'web/static/templates/view-scripts-only.html',
          'web/static/templates/subview-cpes.html',
          'web/static/templates/subview-graph-elt-details.html',
          'web/static/templates/subview-host-summary.html',
          'web/static/templates/subview-port-summary.html',
          'web/static/templates/subview-ports-summary.html',
          'web/static/templates/subview-service-summary.html',
          'web/static/templates/topvalues.html']),
        # IVRE
        ('share/ivre/web/static/ivre',
         ['web/static/ivre/flow.css',
          'web/static/ivre/ivre.css',
          'web/static/ivre/compare.js',
          'web/static/ivre/controllers.js',
          'web/static/ivre/filters.js',
          'web/static/ivre/form-helpers.js',
          'web/static/ivre/graph.js',
          'web/static/ivre/ivre.js',
          'web/static/ivre/params.js',
          'web/static/ivre/tooltip.js',
          'web/static/ivre/utils.js',
          'web/static/ivre/content.js']),
        ('share/ivre/web/static/ivre/flow',
         ['web/static/ivre/flow/controllers.js']),
        # Bootstrap
        ('share/ivre/web/static/bs/css',
         ['web/static/bs/css/bootstrap.css',
          'web/static/bs/css/bootstrap.css.map']),
        ('share/ivre/web/static/bs/js',
         ['web/static/bs/js/bootstrap.js']),
        ('share/ivre/web/static/bs/fonts',
         ['web/static/bs/fonts/glyphicons-halflings-regular.woff',
          'web/static/bs/fonts/glyphicons-halflings-regular.woff2']),
        # jQuery
        ('share/ivre/web/static/jq',
         ['web/static/jq/jquery.js']),
        # d3.js
        ('share/ivre/web/static/d3/js',
         ['web/static/d3/js/d3.v3.min.js',
          'web/static/d3/js/topojson.v1.min.js']),
        # AngularJS
        ('share/ivre/web/static/an/js',
         ['web/static/an/js/angular.js']),
        # Linkurious/sigma.js
        ('share/ivre/web/static/lk',
         ['web/static/lk/plugins.min.js',
          'web/static/lk/plugins.min.js.map',
          'web/static/lk/sigma.min.js',
          'web/static/lk/sigma.min.js.map']),
        # flag-icon-css
        ('share/ivre/web/static/fi/css',
         ['web/static/fi/css/flag-icon.css']),
        ('share/ivre/web/static/fi/flags/4x3',
         [os.path.join('web/static/fi/flags/4x3/', x)
          for x in os.listdir('web/static/fi/flags/4x3/')]),
        # Dokuwiki
        ('share/ivre/dokuwiki',
         ['web/dokuwiki/backlinks.patch']),
        ('share/ivre/dokuwiki/doc',
         ['web/dokuwiki/doc/agent.txt',
          'web/dokuwiki/doc/docker.txt',
          'web/dokuwiki/doc/faq.txt',
          'web/dokuwiki/doc/fast-install-and-first-run.txt',
          'web/dokuwiki/doc/flow.txt',
          'web/dokuwiki/doc/install.txt',
          'web/dokuwiki/doc/license-external.txt',
          'web/dokuwiki/doc/license.txt',
          'web/dokuwiki/doc/readme.txt',
          'web/dokuwiki/doc/screenshots.txt',
          'web/dokuwiki/doc/tests.txt',
          'web/dokuwiki/doc/webui.txt']),
        ('share/ivre/dokuwiki/media',
         ['web/dokuwiki/media/logo.png']),
        ('share/ivre/dokuwiki/media/doc/screenshots',
         [os.path.join('doc/screenshots', x)
          for x in os.listdir('doc/screenshots')]),
        ('share/ivre/web/cgi-bin',
         ['web/cgi-bin/flowjson.py',
          'web/cgi-bin/jsconfig.py',
          'web/cgi-bin/scanjson.py',
          'web/cgi-bin/scanupload.py']),
        ('share/ivre/nmap_scripts',
         ['nmap_scripts/http-screenshot.nse',
          'nmap_scripts/mainframe-banner.nse',
          'nmap_scripts/mainframe-screenshot.nse',
          'nmap_scripts/rtsp-screenshot.nse',
          'nmap_scripts/vnc-screenshot.nse',
          'nmap_scripts/x11-screenshot.nse']),
        ('share/ivre/nmap_scripts/patches',
         ['nmap_scripts/patches/rtsp-url-brute.patch']),
        ('share/doc/ivre',
         ['doc/AGENT.md',
          'doc/DOCKER.md',
          'doc/FAQ.md',
          'doc/FAST-INSTALL-AND-FIRST-RUN.md',
          'doc/FLOW.md',
          'doc/INSTALL.md',
          'doc/LICENSE-EXTERNAL.md',
          'doc/LICENSE.md',
          'doc/README.md',
          'doc/SCREENSHOTS.md',
          'doc/TESTS.md',
          'doc/WEBUI.md']),
        ('share/doc/ivre/screenshots',
         ['doc/screenshots/webui-details-heatmapzoom.png',
          'doc/screenshots/webui-flow-details-flow.png',
          'doc/screenshots/webui-flow-details-host.png',
          'doc/screenshots/webui-flow-dns-halo.png',
          'doc/screenshots/webui-flow-flow-map.png',
          'doc/screenshots/webui-home-heatmap.png',
          'doc/screenshots/webui-screenshots-solar-world.png',
          'doc/screenshots/webui-tooltip-topenipvendors.png',
          'doc/screenshots/webui-topproducts-80.png']),
        ('etc/bash_completion.d', ['bash_completion/ivre']),
    ],
    package_data={
        'ivre': ['VERSION'],
    },
    cmdclass={'install_data': smart_install_data,
              'install_lib': smart_install_lib},
)
