#! /usr/bin/env python
# -*- coding: utf-8 -*-

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

"""
This module is part of IVRE.
Copyright 2011 - 2014 Pierre LALET <pierre.lalet@cea.fr>

This sub-module builds graphs of traceroute results.

"""
from ivre import utils

# to build graphs with rtgraph3d
try:
    import dbus
    import dbus.mainloop.glib
    HAVE_DBUS = True
except ImportError:
    HAVE_DBUS = False


def buildgraph(cursor, include_last_hop=False, include_target=False,
               only_connected=True):
    """Builds a graph (a dict object, {node: [dest nodes]}) by getting
    host documents from the database `cursor`, including (or not) the
    last hop and the target (for each host).

    If `only_connected` is True (which is the default) edges are only
    considered between two consecutive hops. If it is False, edges
    will be added between hops 1 and 3, for example, if hop 2 is not
    present.

    """
    graph = {}
    entry_nodes = set()
    for host in cursor:
        if 'traces' not in host:
            continue
        for trace in host['traces']:
            hops = trace['hops']
            hops.sort(key=lambda hop: hop['ttl'])
            if not hops:
                continue
            entry_nodes.add(hops[0]['ipaddr'])
            if not include_last_hop and not include_target:
                if hops[-1]['ipaddr'] == host['addr']:
                    hops.pop()
                if not include_last_hop:
                    hops.pop()
            for i, hop in enumerate(hops[1:]):
                if (not only_connected) or (hop['ttl'] - hops[i]['ttl'] == 1):
                    graph.setdefault(hops[i]['ipaddr'],
                                     set()).update([hop['ipaddr']])
    return graph, entry_nodes


def writedotgraph(graph, out, cluster=None):
    """From a graph produced by buildgraph(), produces an output in
    the (Graphiz) Dot format.

    `cluster`, if provided, should be a function receiving an IP
    address (as an integer) and returning either a cluster the address
    belongs to or None if the address do not belong to a cluster. The
    `cluster` returned may be either a string or a tuple of two
    strings (label, name).

    """
    out.write('digraph traceroute {\n')
    nodes = set()
    edges = set()
    if cluster is None:
        def _add_node(node):
            if node not in nodes:
                nodes.add(node)
                out.write('\t%d [label="%s"];\n' % (node, utils.int2ip(node)))
    else:
        clusters = {}
        def _add_node(node):
            if node not in nodes:
                nodes.add(node)
                clusters.setdefault(cluster(node), set()).update([node])
    for node, node_edges in graph.iteritems():
        _add_node(node)
        for destnode in node_edges:
            _add_node(destnode)
            if (node, destnode) not in edges:
                out.write("\t%d -> %d;\n" % (node, destnode))
                edges.add((node, destnode))
    if cluster is not None:
        if None in clusters:
            for node in clusters.pop(None):
                out.write('\t%d [label="%s"];\n' % (node, utils.int2ip(node)))
        for clu, nodes in clusters.iteritems():
            if isinstance(clu, basestring):
                clu = (clu, clu)
            out.write('\tsubgraph cluster_%s {\n' % clu[0])
            out.write('\t\tlabel = "%s";\n' % clu[1])
            for node in nodes:
                out.write('\t\t%d [label="%s"];\n' % (node, utils.int2ip(node)))
            out.write('\t}\n')
    out.write('}\n')

if HAVE_DBUS:
    def display3dgraph(graph, reset_world=True):
        """Send the graph (produced by buildgraph()) to a running
        rtgraph3d instance.

        """
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
        bus = dbus.SessionBus()
        control = bus.get_object("org.secdev.rtgraph3d", "/control")
        graph3d = dbus.Interface(control, "org.secdev.rtgraph3d.command")
        if reset_world:
            graph3d.reset_world()
        for node, node_edges in graph.iteritems():
            for destnode in node_edges:
                if destnode == node:
                    continue
                try:
                    graph3d.new_edge(utils.int2ip(node), {},
                                     utils.int2ip(destnode), {})
                except Exception as exc:
                    print "WARNING: %r" % exc
        return graph3d
