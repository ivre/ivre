#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2016 Pierre LALET <pierre.lalet@cea.fr>
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

import json
import logging
import random
import sys
import time

try:
    imp = "ivre"
    from ivre import utils, webutils, config
    from ivre.db import db
    from ivre.utils import str2pyval
    imp = "py2neo"
    from py2neo import Graph, Node, Relationship
    from py2neo.types import remote
except Exception as exc:
    sys.stdout.write('Content-Type: application/javascript\r\n\r\n')
    sys.stdout.write(
        'alert("ERROR: Could not import %s. Check the server\'s logs!");' % imp
    )
    sys.stderr.write(
        "IVRE: ERROR: cannot import %s [%s (%r)].\n" % (imp, exc.message, exc)
    )
    sys.exit(0)

logging.basicConfig(level=logging.ERROR)
log = logging.getLogger("flowjson")
log.setLevel(logging.DEBUG)

webutils.check_referer()

def cleanup_record(elt):
    for k, v in elt.iteritems():
        if len(v) == 1 and all(x == None for x in v[0]):
            elt[k] = None

    db.flow.from_dbdict(super_get_props(elt["elt"]))
    new_meta = {}
    for rec in elt["meta"]:
        if rec["info"] is None and rec["link"] is None:
            continue
        info = rec["info"] or {}
        info_props = super_get_props(info)
        link = rec["link"] or {}
        link_tag = link.get("type", link.get("labels", [""])[0]).lower()
        link_props = super_get_props(link)
        key = "%s%s" % ("_".join(label
                                 for label in super_get_labels(info, info_props)
                                 if label != "Intel"),
                        "_%s" % link_tag if link_tag else "")
        new_data = dict(("%s_%s" % (link_tag, k), v)
                        for k, v in link_props.iteritems())
        new_data.update(info_props)
        new_meta.setdefault(key, []).append(new_data)
    if new_meta:
        elt["meta"] = new_meta
        for reclist in new_meta.itervalues():
            for rec in reclist:
                db.flow.from_dbdict(rec)
    else:
        del(elt["meta"])

def get_host_details(node_id):
    q = """
    MATCH (n)
    WHERE ID(n) = {nid}
    OPTIONAL MATCH (n)-[sr]->(infos:Intel)
    WITH n, collect(distinct {info: infos, link: sr}) as infos
    OPTIONAL MATCH (n)<-[:TO]-(in:Flow)<-[:SEND]-()
    WITH n, infos,
         COLLECT(DISTINCT [in.proto, COALESCE(in.dport, in.type)]) as in_flows
    OPTIONAL MATCH (n)-[:SEND]->(out:Flow)-[:TO]->()
    WITH n, infos, in_flows,
         COLLECT(DISTINCT [out.proto, COALESCE(out.dport, out.type)]) as out_flows
    OPTIONAL MATCH (n)-[:SEND]->(:Flow)-[:TO]->(dst:Host)
    WITH n, infos, in_flows, out_flows,
         COLLECT(DISTINCT dst.addr) as servers
    OPTIONAL MATCH (n)<-[:TO]-(:Flow)<-[:SEND]-(src:Host)
    WITH n, infos, in_flows, out_flows, servers,
         COLLECT(DISTINCT src.addr) as clients
    RETURN {elt: n, meta: infos,
            in_flows: in_flows, out_flows: out_flows,
            servers: servers, clients: clients}
    """
    node = dict(db.flow.db.run(q, nid=node_id).evaluate())
    cleanup_record(node)
    return node

def get_flow_details(node_id):
    q = """
    MATCH (n)
    WHERE ID(n) = {nid}
    OPTIONAL MATCH (n)-[sr]->(infos:Intel)
    WITH n, collect(distinct {info: infos, link: sr}) as infos
    RETURN {elt: n, meta: infos}
    """
    node = dict(db.flow.db.run(q, nid=node_id).evaluate())
    cleanup_record(node)
    return node


def query2cypher(queries, mode="default", count=False, limit=None, skip=0):
    limit = config.WEB_GRAPH_LIMIT if limit is None else limit
    query = db.flow.query(
        skip=skip, limit=limit,
    )
    for flt_type in ["node", "edge"]:
        for flt in queries.get("%ss" % flt_type, []):
            query.add_clause_from_filter(flt, mode=flt_type)

    if mode == "default":
        query.add_clause("""
        WITH {elt: src, meta: [] } as src,
             {elt: link, meta: [] } as link,
             {elt: dst, meta: [] } as dst
        """)
        query.ret = "RETURN src, link, dst"
        executor = super_cursor2json

    elif mode == "talk_map":
        query.add_clause('WITH src, dst, COUNT(link) AS t, '
                         'COLLECT(DISTINCT LABELS(link)) AS labels, '
                         'HEAD(COLLECT(ID(link))) AS ref')
        query.ret = ("""
            RETURN {elt: src, meta: []},
                   {meta: [],
                    elt: {
                        data: { count: t, labels: labels },
                        metadata: {labels: ["TALK"], id: ref}
                    }} as F,
                   {elt: dst, meta: []}
        """)
        executor = super_cursor2json

    elif mode == "flow_map":
        query.add_clause('WITH src, dst, '
                         'COLLECT(DISTINCT [link.proto, link.dport]) AS flows, '
                         'HEAD(COLLECT(ID(link))) AS ref')
        query.add_clause('WITH src, dst, flows, ref, SIZE(flows) AS t')
        query.ret = ("""
            RETURN {elt: src, meta: []},
                   {meta: [],
                    elt: {
                        data: { count: t, flows: flows },
                        metadata: {labels: ["MERGED_FLOWS"], id: ref}
                    }} as F,
                   {elt: dst, meta: []}
        """)
        executor = super_cursor2json

    if count:
        query.ret = """
            RETURN count(distinct src) as clients,
                   count(distinct link) as flows,
                   count(distinct dst) as servers
        """
        executor = count_data
    else:
        query.ret +=  " SKIP {skip} LIMIT {limit}"

    log.info("Executing query:\n%s\nWith params: %s" % (query.query, query.params))
    return query.query, query.params, executor


def flow2name(ref, labels, properties):
    proto = properties.get("proto", "Flow")
    attr = properties.get("dport", properties.get("type", None))
    return "%s%s" % (proto, "/%s" % attr if attr is not None else "")


LABEL2NAME = {
    "Host": ["addr"],
    "Flow": [flow2name],
}


def elt2name(ref, labels, properties):
    name = None
    for label in labels:
        for attr in LABEL2NAME.get(label, []):
            if isinstance(attr, str) or isinstance(attr, unicode):
                if attr in properties:
                    name = properties[attr]
                    break
            else:
                # It's a function
                name = attr(ref, labels, properties)
                break
        if name is not None:
            break
    if name is None:
        name = ", ".join(labels)
    return name

def node2json(ref, labels, properties):
    name = elt2name(ref, labels, properties)
    return {
        "id": ref,
        "label": name,
        "labels": labels,
        "data": properties,
        "x": random.random(),
        "y": random.random(),
    }

def edge2json(ref, from_ref, to_ref, labels, properties):
    name = elt2name(ref, labels, properties)
    return {
        "id": ref,
        "label": name,
        "labels": labels,
        "data": properties,
        "source": from_ref,
        "target": to_ref,
    }

def cursor2json(cursor):
    # Same pseudo-random sequence for each exec: allows stable layout on the UI
    random.seed(0)
    g = {"nodes": [], "edges": []}
    done = set()

    for res in cursor:
        for node in res.nodes():
            ref = remote(node).ref
            if ref not in done:
                labels = list(node.labels())
                g["nodes"].append(node2json(ref, labels, dict(node)))
            done.add(ref)

        for edge in res.relationships():
            ref = remote(edge).ref
            if ref not in done:
                from_ref = remote(edge.start_node()).ref
                to_ref = remote(edge.end_node()).ref
                g["edges"].append(edge2json(ref, from_ref, to_ref,
                                            [edge.type()], dict(edge)))
            done.add(ref)

    return g

def _get_ref(elt, cls, props):
    return remote(elt).ref if isinstance(elt, cls) else props.pop("_ref")

def _get_labels(elt, cls, props):
    if issubclass(cls, Node):
        return list(elt.labels()) if isinstance(elt, cls)\
                                  else props.pop("_labels")
    elif issubclass(cls, Relationship):
        return [elt.type()] if isinstance(elt, cls) else props.pop("_labels")
    else:
        raise ValueError("Unsupported cls %s" % cls.__name__)

def _get_props(elt, cls):
    if isinstance(elt, cls):
        return dict(elt)
    elif isinstance(elt, dict):
        return elt
    else:
        raise ValueError("Unsupported elt type")

def super_get_props(elt, meta=None):
    if isinstance(elt, Node) or isinstance(elt, Relationship):
        props = elt.properties
    else:
        props = elt.get("data", {})
    if meta:
        props["meta"] = meta
    return props

def super_get_ref(elt, props):
    if isinstance(elt, Node):
        return int(remote(elt).ref.split('/', 1)[-1])
    else:
        return elt["metadata"]["id"]

def super_get_labels(elt, props):
    if isinstance(elt, Node):
        return list(elt.labels())
    elif isinstance(elt, Relationship):
        return [elt.type()]
    else:
        meta = elt["metadata"]
        return meta["labels"] if "labels" in meta else [meta["type"]]

def super_cursor2json(cursor):
    """Same as cursor2json but relies on the fact that the cursor will return
    triplets (node, edge, node) and that elements of that triplets may be
    raw Neo4j maps rather that proper node or edge elements."""
    random.seed(0)
    g = {"nodes": [], "edges": []}
    done = set()

    for src, edge, dst in cursor:
        map(cleanup_record, (src, edge, dst))
        src_props = super_get_props(src["elt"], src.get("meta"))
        src_ref = super_get_ref(src["elt"], src_props)
        if src_ref not in done:
            src_labels = super_get_labels(src["elt"], src_props)
            g["nodes"].append(node2json(src_ref, src_labels, src_props))
            done.add(src_ref)

        dst_props = super_get_props(dst["elt"], dst.get("meta"))
        dst_ref = super_get_ref(dst["elt"], dst_props)
        if dst_ref not in done:
            dst_labels = super_get_labels(dst["elt"], dst_props)
            g["nodes"].append(node2json(dst_ref, dst_labels, dst_props))
            done.add(dst_ref)

        edge_props = super_get_props(edge["elt"], edge.get("meta"))
        edge_ref = super_get_ref(edge["elt"], edge_props)
        if edge_ref not in done:
            edge_labels = super_get_labels(edge["elt"], edge_props)
            g["edges"].append(edge2json(edge_ref, src_ref, dst_ref,
                                        edge_labels, edge_props))
            done.add(edge_ref)
        #log.info("\n%s\n%s\n%s", src_props, edge_props, dst_props)
    return g

def count_data(cursor):
    res = cursor.next
    # Compat py2neo < 3
    try:
        res = res()
    except TypeError:
        pass
    return {"clients": res['clients'],
            "flows": res['flows'],
            "servers": res['servers']}


def main():
    # write headers
    sys.stdout.write(webutils.JS_HEADERS)
    params = webutils.parse_query_string()

    # TODO
    #flt, archive, sortby, unused, skip, limit = webutils.flt_from_query(query)
    #if limit is None:
    #    limit = config.WEB_LIMIT
    #if config.WEB_MAXRESULTS is not None:
    #    limit = min(limit, config.WEB_MAXRESULTS)
    callback = params.get("callback")

    action = params.get("action", "")
    if callback is None:
        sys.stdout.write('Content-Disposition: attachment; '
                         'filename="IVRE-results.json"\r\n')
    sys.stdout.write("\r\n")

    if callback is not None:
        sys.stdout.write(webutils.js_del_alert("param-unused"))
        sys.stdout.write("%s(\n" % callback)


    log.info("%s", params)
    query = json.loads(params.get('q', {}) or "{}")
    limit = query.get("limit", config.WEB_GRAPH_LIMIT)
    skip = query.get("skip", config.WEB_GRAPH_LIMIT)
    mode = query.get("mode", "default")
    count = query.get("count", False)
    log.info("Query: %s", query)

    if action == "details":
        # TODO: error
        if "Host" in query["labels"]:
            res = get_host_details(query["id"])
        else:
            res = get_flow_details(query["id"])
    else:
        # TODO: return object
        q, qparams, executor = query2cypher(query, mode=mode, count=count,
                                            limit=limit, skip=skip)

        t1 = time.time()
        cypher_res = db.flow.db.run(q, **qparams)
        log.info("result in %s\n" % (time.time() - t1))
        res = executor(cypher_res)

    sys.stdout.write("%s" % json.dumps(res, default=utils.serialize))

    if callback is not None:
        sys.stdout.write(");\n")

if __name__ == '__main__':
    main()
