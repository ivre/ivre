#! /usr/bin/env python

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
This module is part of IVRE.
Copyright 2011 - 2015 Pierre LALET <pierre.lalet@cea.fr>

Standard setup.py file. Run

$ python setup.py build
# python setup.py install
"""

from distutils.core import setup
import os

setup(
    name='ivre',
    version='0.9.2',
    author='Pierre LALET',
    author_email='pierre@droids-corp.org',
    url='https://ivre.rocks/',
    download_url = 'https://github.com/cea-sec/ivre/tarball/master',
    license='GPLv3+',
    description="Network recon framework",
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
    packages=['ivre', 'ivre/db'],
    scripts=['bin/getmoduli', 'bin/ipdata', 'bin/ipinfo', 'bin/ipinfohost',
             'bin/httpd-ivre', 'bin/nmap2db', 'bin/p0f2db', 'bin/analyzercli',
             'bin/passiverecon2db', 'bin/passivereconworker',
             'bin/runscans', 'bin/runscans-agent', 'bin/runscans-agentdb',
             'bin/plotdb', 'bin/scancli', 'bin/scanstatus'],
    data_files=[
        ('share/ivre/passiverecon',
         ['passiverecon/passiverecon.bro',
          'passiverecon/passiverecon2db-ignore.example']),
        ('share/ivre/honeyd', ['honeyd/sshd']),
        ('share/ivre/geoip', []),
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
          'web/static/report.html',
          'web/static/upload.html',
          'web/static/config-sample.js',
          'web/static/favicon-loading.gif',
          'web/static/favicon.png',
          'web/static/loading.gif',
          'web/static/logo.png',
          'web/static/droids.png',
          'web/static/world-110m.json']),
        ('share/ivre/web/static/templates',
         ['web/static/templates/filters.html',
          'web/static/templates/menu.html',
          'web/static/templates/messages.html',
          'web/static/templates/progressbar.html',
          'web/static/templates/view-cpes-only.html',
          'web/static/templates/view-hosts.html',
          'web/static/templates/view-screenshots-only.html',
          'web/static/templates/view-scripts-only.html',
          'web/static/templates/subview-cpes.html',
          'web/static/templates/subview-host-summary.html',
          'web/static/templates/subview-port-summary.html',
          'web/static/templates/subview-ports-summary.html',
          'web/static/templates/subview-service-summary.html',
          'web/static/templates/topvalues.html']),
        # IVRE
        ('share/ivre/web/static/ivre',
         ['web/static/ivre/ivre.css',
          'web/static/ivre/controllers.js',
          'web/static/ivre/graph.js',
          'web/static/ivre/ivre.js',
          'web/static/ivre/params.js',
          'web/static/ivre/tooltip.js',
          'web/static/ivre/utils.js',
          'web/static/ivre/content.js']),
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
          'web/dokuwiki/doc/fast-install-and-first-run.txt',
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
         ['web/cgi-bin/scanjson.py',
          'web/cgi-bin/scanupload.py']),
        ('share/doc/ivre',
         ['doc/AGENT.md',
          'doc/DOCKER.md',
          'doc/FAST-INSTALL-AND-FIRST-RUN.md',
          'doc/INSTALL.md',
          'doc/LICENSE-EXTERNAL.md',
          'doc/LICENSE.md',
          'doc/README.md',
          'doc/SCREENSHOTS.md',
          'doc/TESTS.md',
          'doc/WEBUI.md']),
    ],
)
