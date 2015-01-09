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


def buildgraph(cursor, include_last_hop=False, include_target=False):
    """Builds a graph (a dict object, {node: [dest nodes]}) from by
    getting host documents from the database cursor (first argument),
    including (or not) the last hop and the target (for each host).

    """
    graph = {}
    entry_nodes = set()
    for host in cursor:
        if 'traces' not in host:
            continue
        for trace in host['traces']:
            hops = trace['hops']
            hops.sort(key=lambda hop: hop['ttl'])
            if hops == []:
                continue
            entry_nodes.add(hops[0]['ipaddr'])
            if not include_last_hop and not include_target:
                hops = hops[:-1]
            for i, hop in enumerate(hops[1:]):
                edges = graph.get(hops[i]['ipaddr'], set())
                edges.add(hop['ipaddr'])
                graph[hops[i]['ipaddr']] = edges
            if include_target:
                edges = graph.get(hops[-1]['ipaddr'], set())
                edges.add(host['addr'])
                graph[hops[-1]['ipaddr']] = edges
    return graph, entry_nodes


def writedotgraph(graph, out):
    """From a graph produced by buildgraph(), produces an output in
    the (Graphiz) Dot format.

    """
    out.write('digraph traceroute {\n')
    nodes = set()
    edges = set()
    for node, node_edges in graph.iteritems():
        if node not in nodes:
            out.write('\t%d [label="%s"];\n' % (node, utils.int2ip(node)))
            nodes.add(node)
        for destnode in node_edges:
            if destnode not in nodes:
                out.write('\t%d [label="%s"];\n' % (destnode,
                                                    utils.int2ip(destnode)))
                nodes.add(destnode)
            if (node, destnode) not in edges:
                out.write("\t%d -> %d;\n" % (node, destnode))
                edges.add((node, destnode))
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
                    print("WARNING: %r" % exc)
        return graph3d
