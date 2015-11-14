#! /usr/bin/env python
#
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

"""Command line interface tool to access the analyzer API"""

import sys

from ivre import webutils
from ivre.db import db
from ivre.cliutils import colorize_log, StackCli
from ivre.analyzer import Context


class AnalyzerCli(StackCli):
    """
    Command line utility wrapper to access analyzer API
    """
    def __init__(self):
        StackCli.__init__(self)
        self._dfilter = {}

    def preloop(self):
        context = Context()
        colorize_log('info', 'Initialization')
        self._build_filter(raw_input('Filter > '))
        colorize_log('info', 'Reading database..')
        context.dfilter = self._dfilter
        context.init_hosts()
        self.push(context)

    def postloop(self):
        colorize_log('info', 'Leaving..')

    @staticmethod
    def _flt_param(param):
        """
        Return a tuple (neg, param), where `neg` is True if the param was
        negative (i.e. starts with '!') and `param` is the argument stripped
        from the potential heading '!'
        """
        return (True, param[1:]) if param.startswith('!') else (False, param)

    def _build_filter(self, cmd):
        """Build a db.nmap.flt from the string `cmd`"""
        query = webutils.query_from_params({'q': cmd})
        (self._dfilter['filter'], _, _, _,
         self._dfilter['skip'],
         self._dfilter['limit']) = webutils.flt_from_query(
             query, base_flt=db.nmap.flt_empty)

    def do_count(self, _):
        """Print host count to stdout"""
        colorize_log('info', "Number of hosts:\n\t%s" % '\n\t'.join(
            '%s:\t%s' % (key, value)
            for key, value in self.get_context().count().iteritems()
        ))

    def do_plot2d(self, _):
        """Plot hosts in 2 dimensions"""
        self.get_context().plot(plot3d=False)

    def do_plot3d(self, _):
        """Plot hosts in 3 dimensions"""
        self.get_context().plot(plot3d=True)

    def do_search_anomalies(self, line):
        """Search [N|N%] anomalies"""
        percent = False
        if line.endswith('%'):
            percent = True
            line = line[:-1]
        try:
            if percent:
                outliers = float(line)
            else:
                outliers = int(line)
        except ValueError:
            self.help_search_anomalies()
            return
        self.get_context().search_anomalies(outliers, percent)

    def do_cluster_hosts_kmeans(self, line):
        """Cluster hosts in N groups"""
        try:
            n_clusters = int(line)
        except ValueError:
            self.help_cluster_hosts_kmeans()
            return
        self.get_context().clusterize_kmeans(n_clusters=n_clusters)

    def do_cluster_hosts_dbscan(self, line):
        """Cluster hosts with DBSCAN algorithm"""
        METRICS = ['cityblock', 'euclidiean', 'l1', 'l2']
        kwargs = {}
        try:
            line = line.split()
            if len(line) > 0:
                kwargs['min_samples'] = int(line[0])
            if len(line) > 1:
                # Maximum distance between elements.
                kwargs['eps'] = float(line[1])
            if len(line) > 2 and line[2] in METRICS:
                kwargs['metric'] = line[2]
        except ValueError:
            self.help_cluster_hosts_dbscan()
            return
        self.get_context().clusterize_dbscan(**kwargs)

    def do_display_hosts(self, _):
        """Print hosts' ObjectId(s) to stdout"""
        print ','.join(map(str, self.get_context().host_ids))

    def do_remove_anomalies(self, _):
        """Remove anomalies from hosts"""
        try:
            self.push(self.get_context().remove_anomalies())
        except (RuntimeError, AttributeError):
            colorize_log('warning', 'Search anomalies first.')

    def do_select_anomalies(self, _):
        """Select anomalies from hosts"""
        try:
            self.push(self.get_context().select_anomalies())
        except (RuntimeError, AttributeError):
            colorize_log('warning', 'Search anomalies first.')

    def do_select_clusters(self, line):
        """Select provided clusters"""
        try:
            cluster_labels = [int(idx) for idx in line.split()]
            if not cluster_labels:
                raise ValueError()
        except ValueError:
            self.help_select_clusters()
            return
        try:
            self.push(self.get_context().select_clusters(cluster_labels))
        except (RuntimeError, AttributeError):
            colorize_log('warning', 'Cluster hosts first.')

    def do_remove_clusters(self, line):
        """Remove provided clusters"""
        try:
            cluster_labels = [int(idx) for idx in line.split()]
            if not cluster_labels:
                raise ValueError()
        except ValueError:
            self.help_select_clusters()
            return
        try:
            self.push(self.get_context().remove_clusters(cluster_labels))
        except (RuntimeError, AttributeError):
            colorize_log('warning', 'Cluster hosts first.')

    def do_select_centers(self, _):
        """Select cluster centers"""
        try:
            self.push(self.get_context().select_cluster_centers())
        except (RuntimeError, AttributeError):
            colorize_log('warning', 'Cluster hosts first.')

    @staticmethod
    def help_count():
        """Help for do_count command"""
        colorize_log('usage', 'count\n\tPrint host count to sdout')

    @staticmethod
    def help_plot2d():
        """Print help for do_plot2d command"""
        colorize_log('usage', 'plot2d\n\tPlot hosts in two dimensions')

    @staticmethod
    def help_plot3d():
        """Print help for do_plot3d command"""
        colorize_log('usage', 'plot3d\n\tPlot hosts in three dimensions')

    @staticmethod
    def help_remove_anomalies():
        """Print help for do_remove_anomalies command"""
        colorize_log('usage', """remove_anomalies
\tRemove anomalies from context""")

    @staticmethod
    def help_select_anomalies():
        """Print help for do_select_anomalies command"""
        colorize_log('usage', """select_anomalies
\tRemove NON-anomalies from context""")

    @staticmethod
    def help_select_centers():
        """Print help for do_select_centers command"""
        colorize_log('usage', 'select_centers\n\tSelect cluster centers')

    @staticmethod
    def help_display_hosts():
        """Print help for do_display_hosts command"""
        colorize_log('usage', """display_hosts
\tReturn current context host(s) ObjectID(s)""")

    @staticmethod
    def help_search_anomalies():
        """Print help for search_anomalies command"""
        colorize_log('usage', """search_anomalies [N|N%]
\tSearch N (or N%) most abnormal hosts""")

    @staticmethod
    def help_cluster_hosts_kmeans():
        """Print help for cluster_hosts_kmeans command"""
        colorize_log('usage', """cluster_hosts_kmeans [nb_clusters]
\tCluster hosts in [nb_clusters] groups using KMeans algorithm""")

    @staticmethod
    def help_cluster_hosts_dbscan():
        """Print help for cluster_hosts_dbscan command"""
        colorize_log('usage', """cluster_hosts_dbscan [min_samples] [max_dist] [metric]
\tmin_samples : minimum number of hosts to form a cluster
\tmax_dist : maximum distance between two hosts to form a cluster
\tmetric : can be "cityblock", "euclidean", "l1", "l2" or "manhattan" """)

    @staticmethod
    def help_select_clusters():
        """Print help for select_clusters command"""
        colorize_log('usage', """select_clusters c1 [c2 [c3..]]
\tSelect clusters c1, c2, c3.. for further analysis
\tEnter -1 for noise if DBSCAN clusterring""")

    @staticmethod
    def help_remove_clusters():
        """Print help for remove_clusters command"""
        colorize_log('usage', """remove_clusters c1 [c2 [c3..]]
\tRemove clusters c1, c2, c3.. from current context
\tEnter -1 for noise if DBSCAN clusterring""")


def main():
    # no argparse / optparse here, so...
    if "-h" in sys.argv or "--help" in sys.argv:
        sys.stdout.write("usage: %s\n\n" % (sys.argv[0]))
        sys.stdout.write(__doc__)
        sys.stdout.write("\n\n")
    else:
        AnalyzerCli().cmdloop()
