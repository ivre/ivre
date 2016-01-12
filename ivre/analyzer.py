#! /usr/bin/env python
# -*- coding: utf-8 -*-

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

"""This sub-module is an API for clustering and anomaly-detection
inside IVRE.

"""

from collections import OrderedDict

from ivre.db import db

import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D  # Mandatory for 3d-plot
from sklearn import svm
from sklearn.decomposition import RandomizedPCA
from sklearn.cluster import KMeans, DBSCAN


class Anomalies(object):
    """
    Class containing all information about anomalies
    """
    def __init__(self, anomalies_idx, name):
        """
        `anomalies_idx` is a list containing indexes
        of anomalies among Context.matrix
        """
        self._anomalies_idx = anomalies_idx
        self._name = name

    def __str__(self):
        return self._name

    def __len__(self):
        """
        Return anomalies count
        """
        return len(self._anomalies_idx)

    def select(self, list_id, matrix):
        """
        Return a new list_id and numpy matrix whose indexes are anomalies'
        """
        new_list_id = [list_id[idx] for idx in self._anomalies_idx]
        new_matrix = matrix[self._anomalies_idx]
        return new_list_id, new_matrix

    def remove(self, list_id, matrix):
        """
        Return a new list_id and numpy matrix whose indexes are NOT anomalies'
        """
        non_anomalies_idx = [idx for idx in xrange(len(list_id))
                             if idx not in self._anomalies_idx]
        new_list_id = [list_id[idx] for idx in non_anomalies_idx]
        new_matrix = matrix[non_anomalies_idx]
        return new_list_id, new_matrix

    def plot(self, plot, hosts, plot3d=False):
        """
        Plot host and anomalies
        hosts must be a numpy matrix with 2 or 3 columns
        depending on plot3d is False or True
        """
        dim = 3 if plot3d else 2
        non_anomalies_idx = [idx for idx in xrange(hosts.shape[0])
                             if idx not in self._anomalies_idx]
        non_anomalies = hosts[non_anomalies_idx]
        anomalies = hosts[self._anomalies_idx]
        # Plot non-anomalies.
        args = (non_anomalies[:, i] for i in xrange(dim))
        plot.plot(*args, marker='o', markerfacecolor='b', markeredgecolor='k',
                  markersize=8, linestyle='None')
        # Plot anomalies.
        args = (anomalies[:, i] for i in xrange(dim))
        plot.plot(*args, marker='o', markerfacecolor='k', markeredgecolor='k',
                  markersize=6, linestyle='None')


class Clusters(object):
    """
    Cluster object containing all information
    to seperate hosts in several clusters
    This is the abstract main class, one should instanciate one of its subclass
    either KmeansClusters or DbscanClusters
    """
    def __init__(self, n_clusters, cluster_labels, name):
        """
        `self._cluster_labels` is a list of cluster labels giving
        each host affiliation
        """
        self._n_clusters = n_clusters
        self._cluster_labels = cluster_labels
        self._unique_labels = set(cluster_labels)
        self._name = name

    def __str__(self):
        return self._name

    def count(self):
        """
        Return an OrderedDict whose keys are the cluster labels
        and values the host count in that cluster
        """
        count = OrderedDict()
        for lab in self._unique_labels:
            if lab == -1:   # Noise
                count['noise'] = sum((self._cluster_labels == lab))
            else:
                count['cluster%d' % lab] = sum((self._cluster_labels == lab))
        return count

    def select(self, cluster_labels, list_id, matrix):
        """
        Return a new list_id and numpy matrix
        which only contains hosts from the clusters
        labeled in `cluster_labels` list
        """
        cluster_mask = np.zeros(len(list_id), dtype=bool)
        for lab in cluster_labels:
            cluster_mask = np.logical_or((self._cluster_labels == lab),
                                         cluster_mask)
        indexes_to_keep = [i for i, keep in enumerate(cluster_mask) if keep]
        new_list_id = [list_id[idx] for idx in indexes_to_keep]
        new_matrix = matrix[indexes_to_keep]
        return new_list_id, new_matrix

    def remove(self, cluster_labels, list_id, matrix):
        """
        Return a new list_id and a numpy matrix
        which only contains hosts NOT from the clusters
        labeled in `cluster_labels` list
        """
        not_cluster_labels = [lab for lab in self._unique_labels
                              if lab not in cluster_labels]
        return self.select(not_cluster_labels, list_id, matrix)

    def select_centers(self, list_id, matrix):
        """
        Return a new list_id and numpy matrix
        which only contains cluster 'centers'
        Depending on the Clusters instance, centers might be one host
        per cluster or every core-cluster hosts
        """
        raise NotImplementedError('Abstract class')

    def plot(self, plot, hosts, plot3d):
        """
        Plot clusters and cluster numbers in color
        in 2 or 3 dimensions
        """
        raise NotImplementedError('Abstract class')


class KmeansClusters(Clusters):
    """
    Concrete class instanciated when calling cluster_hosts_kmeans
    """
    def __init__(self, n_clusters, cluster_labels,
                 theorical_centers, center_hosts_idx):
        Clusters.__init__(self, n_clusters, cluster_labels, 'kmeans')
        self._theorical_centers = theorical_centers
        self._center_hosts_idx = center_hosts_idx

    def select_centers(self, list_id, matrix):
        """
        Return a new list_id and numpy matrix
        which contains cluster center closest hosts
        """
        new_list_id = [list_id[idx] for idx in self._center_hosts_idx]
        new_matrix = matrix[self._center_hosts_idx]
        return new_list_id, new_matrix

    def plot(self, plot, hosts, plot3d=False):
        """
        Plot hosts by clusters and their closest cluster-center host.
        hosts must be a numpy matrix with 2 or 3 columns
        depending on plot3d is False or True
        """
        dim = 3 if plot3d else 2
        colors = plt.cm.Spectral(np.linspace(0, 1, len(self._unique_labels)))
        for lab, col in zip(self._unique_labels, colors):
            # Plot cluster.
            class_member_mask = (self._cluster_labels == lab)
            hosts_lab = hosts[class_member_mask]
            args = (hosts_lab[:, i] for i in xrange(dim))
            plot.plot(*args, marker='o', markerfacecolor=col,
                      markeredgecolor='k', markersize=8, linestyle='None')
            # Plot cluster center.
            for idx in self._center_hosts_idx:
                if class_member_mask[idx]:
                    lab = '$%s$' % lab
                    args = ([hosts[idx, i]] for i in xrange(dim))
                    plot.plot(*args, marker=lab, markerfacecolor=col,
                              markersize=22, markeredgecolor='k',
                              markeredgewidth=1, linestyle='None')


class DbscanClusters(Clusters):
    """
    Concrete class instanciated when calling cluster_hosts_dbscan
    """
    def __init__(self, n_clusters, cluster_labels, core_samples_mask):
        Clusters.__init__(self, n_clusters, cluster_labels, 'dbscan')
        self._core_samples_mask = core_samples_mask
        self._unique_labels = set(cluster_labels)

    def select_centers(self, list_id, matrix):
        """
        Return a new list_id and numpy matrix
        which contains every core-cluster hosts
        """
        indexes_to_keep = [idx for idx, keep
                           in enumerate(self._core_samples_mask) if keep]
        new_list_id = [list_id[idx] for idx in indexes_to_keep]
        new_matrix = matrix[indexes_to_keep]
        return new_list_id, new_matrix

    @staticmethod
    def _calculate_barycenter(matrix):
        """
        Return the barycenter of a numpy matrix
        """
        nb_hosts, dim = matrix.shape
        return [sum(matrix[:, col])/float(nb_hosts)
                for col in xrange(dim)]

    def plot(self, plot, hosts, plot3d=False):
        """
        Plot hosts and their clusters
        hosts must be a numpy matrix with 2 or 3 columns
        depending on plot3d is False or True
        """
        dim = 3 if plot3d else 2
        colors = plt.cm.Spectral(np.linspace(0, 1, len(self._unique_labels)))
        for lab, col in zip(self._unique_labels, colors):
            if lab == -1:
                # Black used for noise.
                col = 'k'
            class_member_mask = (self._cluster_labels == lab)
            # Plot core-samples.
            core_hosts = hosts[class_member_mask & self._core_samples_mask]
            args = (core_hosts[:, i] for i in xrange(dim))
            plot.plot(*args, marker='o', markerfacecolor=col,
                      markeredgecolor='k', markersize=10, linestyle='None')
            # Plot barycenters.
            if lab != -1:   # Cluster is not noise.
                barycenter = self._calculate_barycenter(core_hosts)
                lab = '$%d$' % lab
                args = ([barycenter[i]] for i in xrange(dim))
                plot.plot(*args, marker=lab, markeredgewidth=1, markersize=22,
                          markeredgecolor='k', markerfacecolor=col,
                          linestyle='None')
            # Plot non-core-samples.
            non_core_hosts = hosts[class_member_mask &
                                   ~self._core_samples_mask]
            args = (non_core_hosts[:, i] for i in xrange(dim))
            plot.plot(*args, marker='o', markerfacecolor=col,
                      markeredgecolor='k', markersize=6, linestyle='None')


class Context(object):
    """
    Main object which should be instanciated to perform analysis
    """
    def __init__(self, list_id=None, matrix=None, matrix_col_mean=None,
                 name='.'):
        self._dfilter = {'filter': db.nmap.flt_empty,
                         'skip': 0}
        self._list_id = list_id
        self._matrix = matrix
        self._matrix_col_mean = matrix_col_mean
        self._name = name
        self._clusters = None
        self._anomalies = None

    def __str__(self):
        return self._name

    @property
    def dfilter(self):
        """
        dfilter is a dict with two mandatory keys:
        'filter': a db.nmap filter
        'skip': number of results to skip
        one optional key:
        'limit': maximum number of results to get
        """
        return self._dfilter

    @dfilter.setter
    def dfilter(self, dfilter):
        """self._dfilter setter"""
        self._dfilter = dfilter

    @property
    def host_ids(self):
        """self._list_id getter"""
        return self._list_id

    def count(self):
        """
        Return a dict containing host repartition
        """
        count = OrderedDict()
        count['total'] = len(self._list_id)
        if self._clusters is not None:
            count.update(self._clusters.count())
        if self._anomalies is not None:
            count['anomalies'] = len(self._anomalies)
        return count

    def init_hosts(self):
        """
        Query the database and build
        self._list_id : a list containing ObjectId() of each host
        self._matrix : a numpy-matrix containing one host per line,
        each column representing a port number.
        The value is the occurence frequency of the service/product
        probed for the host.
        self._matrix_col_mean : list of 'protocol/port' representing
        self._matrix's columns
        """
        # List all port services/products by frequency.
        cursor = db.nmap.get(self._dfilter['filter'],
                             fields=['ports.port',
                                     'ports.protocol',
                                     'ports.service_name',
                                     'ports.state_state',
                                     'ports.service_product'])
        limit = self._dfilter.get('limit')
        if limit is not None:
            hosts_count = min(cursor.count() - self._dfilter['skip'], limit)
        else:
            hosts_count = cursor.count() - self._dfilter['skip']
        cursor.sort([("starttime",
                      1)]).skip(self._dfilter['skip']).limit(hosts_count)
        categorizer = self._build_categorizer(hosts_count)
        self._matrix_col_mean = categorizer.keys()
        ports_count = len(self._matrix_col_mean)
        # Set and fill the matrix of hosts.
        self._matrix = np.zeros((hosts_count, ports_count))
        self._list_id = []
        for num, host in enumerate(cursor):
            self._list_id.append(host["_id"])
            host_ports = dict(
                ('%s/%s' % (port['protocol'], port['port']),
                 '%s/%s' % (port.get('service_name', 'UNKNOWN'),
                            port.get('service_product', 'UNKNOWN')))
                for port in host.get('ports', [])
                if port.get('state_state') == 'open'
            )
            # frequence
            self._matrix[num] = [categorizer[p_nb][host_ports.get(p_nb)]
                                 if host_ports.get(p_nb) in categorizer[p_nb]
                                 else categorizer[p_nb]['UNAVAILABLE']
                                 for p_nb in self._matrix_col_mean]

    @staticmethod
    def _handle_none(field):
        """
        Used to create pipeline handling None values in field
        """
        return {'$cond': {
            "if": {"$eq": [{"$ifNull": [field, None]}, None]},
            "then": "UNKNOWN",
            "else": field,
        }}

    def _build_categorizer(self, host_count):
        """
        Create a dict() which keys are port numbers (ex:u'tcp/22')
        and values are dict() listing service/product:frequency
        among the dataset provided by mongodb
        """
        pipeline = [{'$match': self._dfilter['filter']}] \
                   if self._dfilter['filter'] else []
        pipeline += [
            {'$sort': {'starttime': 1}},
            {'$skip': self._dfilter['skip']},
            {'$limit': host_count},
            {'$project': {'_id': 0, 'ports.port': 1, 'ports.protocol': 1,
                          'ports.service_name': 1, 'ports.state_state': 1,
                          'ports.service_product': 1}},
            {'$match': {'ports.state_state': "open"}},
            {'$unwind': '$ports'},
            {'$project': {
                'port': {"$concat": [
                    # tcp/502
                    "$ports.protocol",
                    "/",
                    {"$toLower": "$ports.port"},
                ]},
                'srvprod': {"$concat": [
                    Context._handle_none('$ports.service_name'),
                    "/",
                    Context._handle_none('$ports.service_product'),
                ]},
            }},
            {'$group': {'_id': {"port": "$port", "srvprod": "$srvprod"},
                        "count": {"$sum": 1}}},
            {'$group': {"_id": "$_id.port",
                        "srvprods": {"$push": {"name": "$_id.srvprod",
                                               "count": "$count"}},
                        "count": {"$sum": "$count"}}},
            {'$sort': {"count": -1}},
        ]
        result = {}
        for rec in db.nmap.db[db.nmap.colname_hosts].aggregate(pipeline,
                                                               cursor={}):
            result[rec['_id']] = dict((srvprod['name'],
                                       float(srvprod['count']) / host_count)
                                      for srvprod in rec['srvprods'])
            result[rec['_id']][u'UNAVAILABLE'] = 1 - \
                float(rec['count']) / host_count
        return result

    def _explain_components(self, variance, pca_indexes,
                            n_comp=10, dimension=2):
        """
        Plot n_comp most relevant components for the first dimensions
        """
        assert dimension <= 3
        # Prevent from index error in case PCA went on fewer dimension
        n_comp = min(n_comp, len(pca_indexes[0]), len(pca_indexes[1]))
        fig = plt.figure()
        axis = ['X', 'Y', 'Z']
        for dim in xrange(dimension):
            plot = fig.add_subplot(dimension, 1, dim + 1)
            values = [pca_indexes[dim][i][1] for i in xrange(n_comp)]
            ind = np.arange(n_comp)
            width = 0.35
            plot.bar(ind, values, width, color='cyan')
            marks = [self._matrix_col_mean[pca_indexes[dim][i][0]]
                     for i in xrange(n_comp)]
            plot.set_xticks(ind + width / 2.0)
            plot.set_xticklabels(marks)
            plot.set_xlim(-width, len(ind) + width / 2.0)
            margin = 0.1 * max(abs(i) for i in values)
            plot.set_ylim(min(values) - margin, max(values) + margin)
            plot.legend(['Variance : %f' % variance[dim]])
            plot.set_title('%s axis decomposition' % axis[dim])

    @staticmethod
    def _pca(hosts, dim=2):
        """
        Principal component analysis
        Reduce the numpy-matrix hosts to a dim-dimensional vector space
        """
        pca = RandomizedPCA(n_components=dim)
        pca.fit(hosts)
        # Return most discriminating values by axis.
        pca_indexes = []
        for ind in xrange(dim):
            vect = pca.components_[ind]
            pca_indexes.append([(idx, vect[idx])
                                for idx in (-abs(vect)).argsort()])
        return (pca, pca_indexes)

    @staticmethod
    def _search_matrix_extremum(hosts):
        """
        Return two lists containing minimum and maximum values
        by dimensions for the numpy matrix hosts
        """
        min_size = []
        max_size = []
        dim = hosts.shape[1]
        for idx in xrange(dim):
            min_size.append(round(hosts[:, idx].min() - 1))
            max_size.append(round(hosts[:, idx].max() + 1))
        return (min_size, max_size)

    def plot(self, plot3d=False):
        """
        Plot hosts, clusters and anomalies if previously calculated
        in 2 or 3 dimensions, depending on `plot3d`
        Context must contain at least 2 hosts
        """
        if len(self._list_id) < 2:
            raise ValueError('Cannot plot less than 2 hosts')

        dim = 3 if plot3d else 2
        fig = plt.figure()
        plot = fig.add_subplot(111, projection='3d') if plot3d \
               else fig.add_subplot(111)

        # Plot hosts.
        pca, pca_indexes = self._pca(self._matrix, dim=dim)
        hosts_reduced = pca.transform(self._matrix)
        if self._clusters is None and self._anomalies is None:
            args = (hosts_reduced[:, i] for i in xrange(dim))
            plot.plot(*args, marker='o', markerfacecolor='b',
                      markeredgecolor='k', markersize=6, linestyle='None')
        if self._clusters is not None:
            self._clusters.plot(plot, hosts_reduced, plot3d)
        if self._anomalies is not None:
            self._anomalies.plot(plot, hosts_reduced, plot3d)

        # Format plot.
        min_s, max_s = self._search_matrix_extremum(hosts_reduced)
        func_label = [plot.set_xlabel, plot.set_ylabel]
        func_limit = [plot.set_xlim, plot.set_ylim]
        axis = ['X axis', 'Y axis']
        if plot3d:
            func_label.append(plot.set_zlabel)
            func_limit.append(plot.set_zlim)
            axis.append('Z axis')
        plot.set_title('Hosts')
        for idx in xrange(dim):
            func_limit[idx]((min_s[idx], max_s[idx]))
            func_label[idx](axis[idx])

        # Print 10 most relevant components by printed dimensions.
        variance = pca.explained_variance_ratio_
        self._explain_components(variance, pca_indexes,
                                 n_comp=10, dimension=dim)
        plt.show()

    def clusterize_kmeans(self, *args, **kwargs):
        """
        Cluster hosts using KMeans algorithm
        n_clusters : the number of clusters to form
        Update self._clusters attribute
        """
        # Launch KMeans algorithm with all available CPUs (n_jobs=-1).
        kwargs.setdefault('n_jobs', -1)
        classifier = KMeans(*args, **kwargs)
        classifier.fit(self._matrix)
        theorical_centers = classifier.cluster_centers_
        center_hosts_idx = []
        dist = classifier.transform(self._matrix)
        for i_center in xrange(len(theorical_centers)):
            center_hosts_idx.append(np.argsort(dist[:, i_center])[0])
        cluster_labels = classifier.predict(self._matrix)
        self._clusters = KmeansClusters(kwargs['n_clusters'], cluster_labels,
                                        theorical_centers, center_hosts_idx)

    def clusterize_dbscan(self, *args, **kwargs):
        """
        Cluster hosts using DBSCAN algorithm
        Optional parameters for the algorithm :
        min_samples : minimum number of hosts to form a cluster.
        max_dist : maximum distance between two hosts to form a cluster.
        metric : metric used to compute distances,
        can be ‘cityblock’, ‘euclidean’, ‘l1’, ‘l2’ or ‘manhattan’
        Update self._clusters attribute
        """
        classifier = DBSCAN(*args, **kwargs).fit(self._matrix)
        core_samples_mask = np.zeros_like(classifier.labels_, dtype=bool)
        core_samples_mask[classifier.core_sample_indices_] = True
        cluster_labels = classifier.labels_
        # Number of clusters in labels, ignoring noise if present.
        n_clusters = len(set(cluster_labels)) - (1 if -1 in cluster_labels
                                                 else 0)
        self._clusters = DbscanClusters(n_clusters, cluster_labels,
                                        core_samples_mask)

    def search_anomalies(self, outliers, percent_mode=False):
        """
        Search anomalies in self._matrix
        percent_mode: if True, search `outliers`% anomalies
        instead of `outliers` anomalies
        Update self._anomalies attribute
        """
        # 0.01 is faster and works well most of the time
        # but 0.5 works with small host number.
        nu_percent = outliers * 0.01 if percent_mode else 0.5

        clf = svm.OneClassSVM(nu=nu_percent, kernel='rbf', gamma=0.1)
        clf.fit(self._matrix)

        # is_anomaly : distance from the separating 'hyperplane'
        is_anomaly = clf.decision_function(self._matrix).ravel()
        if not percent_mode:
            threshold = sorted(is_anomaly)[outliers] \
                if outliers < is_anomaly.shape[0] \
                else sorted(is_anomaly)[-1]
        else:
            threshold = 0
        is_anomaly = is_anomaly < threshold
        anomalies_idx = [i for i, ano in enumerate(is_anomaly) if ano]
        name = "%s%s%s" % (outliers,
                           '%' if percent_mode else '',
                           "-anom")
        self._anomalies = Anomalies(anomalies_idx, name)

    def _apply_anomalies(self, cmd_name, function):
        """
        Return a new `Context` which only contains hosts returned by `function`
        `cmd_name` is a string representing the function
        """
        if self._anomalies is None:
            raise RuntimeError('self._anomalies must be initialised first')
        new_list_id, new_matrix = function(self._list_id,
                                           self._matrix)
        cmd_name = '%s-%s' % (cmd_name, self._anomalies)
        return Context(new_list_id, new_matrix, list(self._matrix_col_mean),
                       cmd_name)

    def remove_anomalies(self):
        """
        Return a new `Context` containing hosts without anomalies
        """
        return self._apply_anomalies('rm', self._anomalies.remove)

    def select_anomalies(self):
        """
        Return a new `Context` containing anomalies
        """
        return self._apply_anomalies('sel', self._anomalies.select)

    def _apply_clusters(self, cluster_labels, cmd_name, function):
        """
        Return a new `Context` which only contains hosts returned by `function`
        `cluster_labels` is a list of integer containing labels
        to remove or select, depending on `function`
        `cmd_name` is a string representing the function
        """
        if self._clusters is None:
            raise RuntimeError('self._clusters must be initialised first')
        new_list_id, new_matrix = function(cluster_labels,
                                           self._list_id,
                                           self._matrix)
        cmd_name = '%s-clust-%s_%s' % (cmd_name, self._clusters,
                                       '-'.join(map(str,
                                                    sorted(cluster_labels))))
        return Context(new_list_id, new_matrix, list(self._matrix_col_mean),
                       cmd_name)

    def select_clusters(self, cluster_labels):
        """
        Return a new `Context` which only contains hosts from the clusters
        labeled in `cluster_labels` list
        """
        return self._apply_clusters(cluster_labels, 'sel',
                                    self._clusters.select)

    def remove_clusters(self, cluster_labels):
        """
        Return a new `Context` which only contains hosts NOT from the clusters
        labeled in `cluster_labels` list
        """
        return self._apply_clusters(cluster_labels, 'rm',
                                    self._clusters.remove)

    def select_cluster_centers(self):
        """
        Return a new `Context` which only contains cluster centers
        Depending on self._clusters type, centers might be one host
        per cluster or every core-cluster hosts
        """
        if self._clusters is None:
            raise RuntimeError('self._clusters must be initialised first')
        new_list_id, new_matrix = self._clusters.select_centers(self._list_id,
                                                                self._matrix)
        cmd_name = 'sel-centers-%s' % self._clusters
        return Context(new_list_id, new_matrix, list(self._matrix_col_mean),
                       cmd_name)
