#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2018 Pierre LALET <pierre.lalet@cea.fr>
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

"""This sub-module contains functions to interact with PostgreSQL
databases.

"""


import datetime
import time


from builtins import int
from sqlalchemy import desc, func, text, column, delete, exists, insert, \
    join, select, update, and_, Column, Table, ARRAY, LargeBinary, String, \
    tuple_
from sqlalchemy.dialects import postgresql


from ivre import config, utils, xmlnmap
from ivre.db.sql import PassiveCSVFile, ScanCSVFile, SQLDB, SQLDBActive, \
    SQLDBFlow, SQLDBNmap, SQLDBPassive, SQLDBView


class PostgresDB(SQLDB):

    def __init__(self, url):
        SQLDB.__init__(self, url)

    @staticmethod
    def ip2internal(addr):
        return utils.force_int2ip(addr)

    @staticmethod
    def internal2ip(addr):
        return addr

    def copy_from(self, *args, **kargs):
        cursor = self.db.raw_connection().cursor()
        conn = self.db.connect()
        trans = conn.begin()
        cursor.copy_from(*args, **kargs)
        trans.commit()
        conn.close()

    def create_tmp_table(self, table, extracols=None):
        cols = [c.copy() for c in table.__table__.columns]
        for c in cols:
            c.index = False
            c.nullable = True
            c.foreign_keys = None
            if c.primary_key:
                c.primary_key = False
                c.index = True
        if extracols is not None:
            cols.extend(extracols)
        t = Table("tmp_%s" % table.__tablename__,
                  table.__table__.metadata, *cols,
                  prefixes=['TEMPORARY'])
        t.create(bind=self.db, checkfirst=True)
        return t

    def start_bulk_insert(self, size=None, retries=0):
        return BulkInsert(self.db, size=size, retries=retries)


class BulkInsert(object):
    """A PostgreSQL transaction, with automatic commits"""

    def __init__(self, db, size=None, retries=0):
        """`size` is the number of inserts per commit and `retries` is the
        number of times to retry a failed transaction (when inserting
        concurrently for example). 0 is forever, 1 does not retry, 2 retries
        once, etc.
        """
        self.db = db
        self.start_time = time.time()
        self.commited_counts = {}
        self.size = config.POSTGRES_BATCH_SIZE if size is None else size
        self.retries = retries
        self.conn = db.connect()
        self.trans = self.conn.begin()
        self.queries = {}

    def append(self, query):
        query._set_bind(self.db)
        s_query = str(query)
        params = query.parameters
        query.parameters = None
        self.queries.setdefault(s_query,
                                (query, []))[1].append(params)
        if len(self.queries[s_query][1]) >= self.size:
            self.commit(query=s_query)

    def commit(self, query=None, renew=True):
        if query is None:
            last = len(self.queries) - 1
            for i, query in enumerate(list(self.queries)):
                self.commit(query=query, renew=True if i < last else renew)
            return
        q_query, params = self.queries.pop(query)
        self.conn.execute(q_query, *params)
        self.trans.commit()
        newtime = time.time()
        l_params = len(params)
        try:
            self.commited_counts[query] += l_params
        except KeyError:
            self.commited_counts[query] = l_params
        rate = l_params / (newtime - self.start_time)
        utils.LOGGER.debug("DB:%s", query)
        utils.LOGGER.debug("DB:%d inserts, %f/sec (total %d)",
                           l_params, rate, self.commited_counts[query])
        if renew:
            self.start_time = newtime
            self.trans = self.conn.begin()

    def close(self):
        self.commit(renew=False)
        self.conn.close()


class PostgresDBFlow(PostgresDB, SQLDBFlow):

    def __init__(self, url):
        PostgresDB.__init__(self, url)
        SQLDBFlow.__init__(self, url)


class PostgresDBActive(PostgresDB, SQLDBActive):

    def __init__(self, url):
        PostgresDB.__init__(self, url)
        SQLDBActive.__init__(self, url)

    def __migrate_schema_10_11(self):
        """Converts a record from version 10 to version 11.

The PostgreSQL backend is only conerned by a limited subset of
changes.

        """
        req = (select([self.tables.scan.id,
                       self.tables.script.port,
                       self.tables.script.output,
                       self.tables.script.data])
               .select_from(join(join(self.tables.scan, self.tables.port),
                                 self.tables.script))
               .where(and_(
                   self.tables.scan.schema_version == 10,
                   self.tables.script.name == "ssl-cert",
               )))
        for rec in self.db.execute(req):
            if 'ssl-cert' in rec.data:
                if 'pem' in rec.data['ssl-cert']:
                    data = ''.join(
                        rec.data['ssl-cert']['pem'].splitlines()[1:-1]
                    ).encode()
                    try:
                        newout, newinfo = xmlnmap.create_ssl_cert(data)
                    except Exception:
                        utils.LOGGER.warning('Cannot parse certificate %r',
                                             data,
                                             exc_info=True)
                    else:
                        self.db.execute(
                            update(self.tables.script)
                            .where(and_(self.tables.script.port == rec.port,
                                        self.tables.script.name == "ssl-cert"))
                            .values(data={"ssl-cert": newinfo},
                                    output='\n'.join(newout))
                        )
                        continue
                    try:
                        pubkeytype = {
                            'rsaEncryption': 'rsa',
                            'id-ecPublicKey': 'ec',
                            'id-dsa': 'dsa',
                            'dhpublicnumber': 'dh',
                        }[rec.data['ssl-cert'].pop('pubkeyalgo')]
                    except KeyError:
                        pass
                    else:
                        self.db.execute(
                            update(self.tables.script)
                            .where(and_(self.tables.script.port == rec.port,
                                        self.tables.script.name == "ssl-cert"))
                            .values(data={"ssl-cert":
                                          dict(rec.data['ssl-cert'],
                                               type=pubkeytype)})
                        )
        self.db.execute(
            update(self.tables.scan)
            .where(self.tables.scan.schema_version == 10)
            .values(schema_version=11)
        )
        return 0

    def start_store_hosts(self):
        """Backend-specific subclasses may use this method to create some bulk
insert structures.

        """
        self.bulk = self.start_bulk_insert()

    def stop_store_hosts(self):
        """Backend-specific subclasses may use this method to commit bulk
insert structures.

        """
        self.bulk.close()
        self.bulk = None

    def _get_ips_ports(self, flt, limit=None, skip=None):
        req = flt.query(select([self.tables.scan.id]))
        if skip is not None:
            req = req.offset(skip)
        if limit is not None:
            req = req.limit(limit)
        base = req.cte("base")
        return (
            {
                "addr": rec[2], "starttime": rec[1],
                "ports": [
                    {"proto": proto, "port": int(port), "state_state": state}
                    for proto, port, state in (
                        elt.split(',') for elt in
                        ''.join(rec[0])[3:-3].split(')","(')
                    )
                ]
            }
            for rec in
            self.db.execute(
                select([
                    func.array_agg(postgresql.aggregate_order_by(
                        tuple_(self.tables.port.protocol,
                               self.tables.port.port,
                               self.tables.port.state).label('a'),
                        tuple_(self.tables.port.protocol,
                               self.tables.port.port).label('a')
                    )).label('ports'),
                    self.tables.scan.time_start, self.tables.scan.addr,
                ])
                .select_from(join(self.tables.port, self.tables.scan))
                .group_by(self.tables.scan.addr, self.tables.scan.time_start)
                .where(and_(self.tables.port.port >= 0,
                            self.tables.scan.id.in_(base)))
            )
        )

    def get_ips_ports(self, flt, limit=None, skip=None):
        result = list(self._get_ips_ports(flt, limit=limit, skip=skip))
        return result, sum(len(host.get('ports', [])) for host in result)

    def topvalues(self, field, flt=None, topnbr=10, sort=None,
                  limit=None, skip=None, least=False):
        """
        This method makes use of the aggregation framework to produce
        top values for a given field or pseudo-field. Pseudo-fields are:
          - category / label / asnum / country / net[:mask]
          - port
          - port:open / :closed / :filtered / :<servicename>
          - portlist:open / :closed / :filtered
          - countports:open / :closed / :filtered
          - service / service:<portnbr>
          - product / product:<portnbr>
          - cpe / cpe.<part> / cpe:<cpe_spec> / cpe.<part>:<cpe_spec>
          - devicetype / devicetype:<portnbr>
          - script:<scriptid> / script:<port>:<scriptid>
            / script:host:<scriptid>
          - cert.* / smb.* / sshkey.*
          - httphdr / httphdr.{name,value} / httphdr:<name>
          - modbus.* / s7.* / enip.*
          - mongo.dbs.*
          - vulns.*
          - screenwords
          - file.* / file.*:scriptid
          - hop
        """
        if flt is None:
            flt = self.flt_empty
        base = flt.query(
            select([self.tables.scan.id]).select_from(flt.select_from)
        ).cte("base")
        order = "count" if least else desc("count")
        outputproc = None
        if field == "port":
            field = self._topstructure(self.tables.port,
                                       [self.tables.port.protocol,
                                        self.tables.port.port],
                                       self.tables.port.state == "open")
        elif field == "ttl":
            field = self._topstructure(
                self.tables.port, [self.tables.port.state_reason_ttl],
                self.tables.port.state_reason_ttl != None,
                # noqa: E711 (BinaryExpression)
            )
        elif field == "ttlinit":
            field = self._topstructure(
                self.tables.port,
                [func.least(255, func.power(2, func.ceil(
                    func.log(2, self.tables.port.state_reason_ttl)
                )))],
                self.tables.port.state_reason_ttl != None,
                # noqa: E711 (BinaryExpression)
            )
            outputproc = int
        elif field.startswith('port:'):
            info = field[5:]
            field = self._topstructure(
                self.tables.port,
                [self.tables.port.protocol, self.tables.port.port],
                (self.tables.port.state == info)
                if info in ['open', 'filtered', 'closed', 'open|filtered'] else
                (self.tables.port.service_name == info),
            )
        elif field.startswith('countports:'):
            info = field[11:]
            return (
                {"count": result[0], "_id": result[1]}
                for result in self.db.execute(
                    select([func.count().label("count"),
                            column('cnt')])
                    .select_from(
                        select([func.count().label('cnt')])
                        .select_from(self.tables.port)
                        .where(and_(
                            self.tables.port.state == info,
                            # self.tables.port.scan.in_(base),
                            exists(
                                select([1])\
                                .select_from(base)\
                                .where(
                                    self.tables.port.scan == base.c.id
                                )
                            ),
                        ))\
                        .group_by(self.tables.port.scan)\
                        .alias('cnt')
                    ).group_by('cnt').order_by(order).limit(topnbr)
                )
            )
        elif field.startswith('portlist:'):
            ### Deux options pour filtrer:
            ###   -1- self.tables.port.scan.in_(base),
            ###   -2- exists(select([1])\
            ###       .select_from(base)\
            ###       .where(
            ###         self.tables.port.scan == base.c.id
            ###       )),
            ###
            ### D'après quelques tests, l'option -1- est plus beaucoup
            ### rapide quand (base) est pas ou peu sélectif, l'option
            ### -2- un peu plus rapide quand (base) est très sélectif
            ###
            ### TODO: vérifier si c'est pareil pour:
            ###  - countports:open
            ###  - tous les autres
            info = field[9:]
            return (
                {"count": result[0], "_id": [
                    (proto, int(port)) for proto, port in (
                        elt.split(',') for elt in
                        result[1][3:-3].split(')","(')
                    )
                ]}
                for result in self.db.execute(
                    select([func.count().label("count"),
                            column('ports')])
                    .select_from(
                        select([
                            func.array_agg(postgresql.aggregate_order_by(
                                tuple_(self.tables.port.protocol,
                                       self.tables.port.port).label('a'),
                                tuple_(self.tables.port.protocol,
                                       self.tables.port.port).label('a')
                            )).label('ports'),
                        ])
                        .where(and_(
                            self.tables.port.state == info,
                            self.tables.port.scan.in_(base),
                            # exists(select([1])\
                            #        .select_from(base)\
                            #        .where(
                            #            self.tables.port.scan == base.c.id
                            #        )),
                        ))
                        .group_by(self.tables.port.scan)
                        .alias('ports')
                    )
                    .group_by('ports').order_by(order).limit(topnbr)
                )
            )
        elif field == "service":
            field = self._topstructure(self.tables.port,
                                       [self.tables.port.service_name],
                                       self.tables.port.state == "open")
        elif field.startswith("service:"):
            info = field[8:]
            if '/' in info:
                info = info.split('/', 1)
                field = self._topstructure(
                    self.tables.port, [self.tables.port.service_name],
                    and_(self.tables.port.protocol == info[0],
                         self.tables.port.port == int(info[1])),
                )
            else:
                field = self._topstructure(self.tables.port,
                                           [self.tables.port.service_name],
                                           self.tables.port.port == int(info))
        elif field == "product":
            field = self._topstructure(
                self.tables.port,
                [self.tables.port.service_name,
                 self.tables.port.service_product],
                self.tables.port.state == "open",
            )
        elif field.startswith("product:"):
            info = field[8:]
            if info.isdigit():
                info = int(info)
                flt = self.flt_and(flt, self.searchport(info))
                field = self._topstructure(
                    self.tables.port,
                    [self.tables.port.service_name,
                     self.tables.port.service_product],
                    and_(self.tables.port.state == "open",
                         self.tables.port.port == info),
                )
            elif info.startswith('tcp/') or info.startswith('udp/'):
                info = (info[:3], int(info[4:]))
                flt = self.flt_and(flt, self.searchport(info[1],
                                                        protocol=info[0]))
                field = self._topstructure(
                    self.tables.port,
                    [self.tables.port.service_name,
                     self.tables.port.service_product],
                    and_(self.tables.port.state == "open",
                         self.tables.port.port == info[1],
                         self.tables.port.protocol == info[0]),
                )
            else:
                flt = self.flt_and(flt, self.searchservice(info))
                field = self._topstructure(
                    self.tables.port,
                    [self.tables.port.service_name,
                     self.tables.port.service_product],
                    and_(self.tables.port.state == "open",
                         self.tables.port.service_name == info),
                )
        elif field == "devicetype":
            field = self._topstructure(self.tables.port,
                                       [self.tables.port.service_devicetype],
                                       self.tables.port.state == "open")
        elif field.startswith("devicetype:"):
            info = field[11:]
            if info.isdigit():
                info = int(info)
                flt = self.flt_and(flt, self.searchport(info))
                field = self._topstructure(
                    self.tables.port,
                    [self.tables.port.service_devicetype],
                    and_(self.tables.port.state == "open",
                         self.tables.port.port == info)
                )
            elif info.startswith('tcp/') or info.startswith('udp/'):
                info = (info[:3], int(info[4:]))
                flt = self.flt_and(flt, self.searchport(info[1],
                                                        protocol=info[0]))
                field = self._topstructure(
                    self.tables.port,
                    [self.tables.port.service_devicetype],
                    and_(self.tables.port.state == "open",
                         self.tables.port.port == info[1],
                         self.tables.port.protocol == info[0])
                )
            else:
                flt = self.flt_and(flt, self.searchservice(info))
                field = self._topstructure(
                    self.tables.port,
                    [self.tables.port.service_devicetype],
                    and_(self.tables.port.state == "open",
                         self.tables.port.service_name == info)
                )
        elif field == "version":
            field = self._topstructure(
                self.tables.port,
                [self.tables.port.service_name,
                 self.tables.port.service_product,
                 self.tables.port.service_version],
                self.tables.port.state == "open",
            )
        elif field.startswith("version:"):
            info = field[8:]
            if info.isdigit():
                info = int(info)
                flt = self.flt_and(flt, self.searchport(info))
                field = self._topstructure(
                    self.tables.port,
                    [self.tables.port.service_name,
                     self.tables.port.service_product,
                     self.tables.port.service_version],
                    and_(self.tables.port.state == "open",
                         self.tables.port.port == info),
                )
            elif info.startswith('tcp/') or info.startswith('udp/'):
                info = (info[:3], int(info[4:]))
                flt = self.flt_and(flt, self.searchport(info[1],
                                                        protocol=info[0]))
                field = self._topstructure(
                    self.tables.port,
                    [self.tables.port.service_name,
                     self.tables.port.service_product,
                     self.tables.port.service_version],
                    and_(self.tables.port.state == "open",
                         self.tables.port.port == info[1],
                         self.tables.port.protocol == info[0]),
                )
            elif ':' in info:
                info = info.split(':', 1)
                flt = self.flt_and(flt, self.searchproduct(info[1],
                                                           service=info[0]))
                field = self._topstructure(
                    self.tables.port,
                    [self.tables.port.service_name,
                     self.tables.port.service_product,
                     self.tables.port.service_version],
                    and_(self.tables.port.state == "open",
                         self.tables.port.service_name == info[0],
                         self.tables.port.service_product == info[1]),
                )
            else:
                flt = self.flt_and(flt, self.searchservice(info))
                field = self._topstructure(
                    self.tables.port,
                    [self.tables.port.service_name,
                     self.tables.port.service_product,
                     self.tables.port.service_version],
                    and_(self.tables.port.state == "open",
                         self.tables.port.service_name == info),
                )
        elif field == "asnum":
            field = self._topstructure(self.tables.scan,
                                       [self.tables.scan.info["as_num"]])
        elif field == "as":
            field = self._topstructure(self.tables.scan,
                                       [self.tables.scan.info["as_num"],
                                        self.tables.scan.info["as_name"]])
        elif field == "country":
            field = self._topstructure(self.tables.scan,
                                       [self.tables.scan.info["country_code"],
                                        self.tables.scan.info["country_name"]])
        elif field == "city":
            field = self._topstructure(self.tables.scan,
                                       [self.tables.scan.info["country_code"],
                                        self.tables.scan.info["city"]])
        elif field == "net" or field.startswith("net:"):
            info = field[4:]
            info = int(info) if info else 24
            field = self._topstructure(
                self.tables.scan,
                [func.set_masklen(text("scan.addr::cidr"), info)],
            )
        elif field == "script" or field.startswith("script:"):
            info = field[7:]
            if info:
                field = self._topstructure(self.tables.script,
                                           [self.tables.script.output],
                                           self.tables.script.name == info)
            else:
                field = self._topstructure(self.tables.script,
                                           [self.tables.script.name])
        elif field in ["category", "categories"]:
            field = self._topstructure(self.tables.category,
                                       [self.tables.category.name])
        elif field.startswith('cert.'):
            subfield = field[5:]
            field = self._topstructure(
                self.tables.script,
                [self.tables.script.data['ssl-cert'][subfield]],
                and_(self.tables.script.name == 'ssl-cert',
                     self.tables.script.data['ssl-cert'].has_key(subfield))
            )  # noqa: W601 (BinaryExpression)
        elif field == "source":
            field = self._topstructure(self.tables.scan,
                                       [self.tables.scan.source])
        elif field == "domains":
            field = self._topstructure(
                self.tables.hostname,
                [func.unnest(self.tables.hostname.domains)]
            )
        elif field.startswith("domains:"):
            level = int(field[8:]) - 1
            base1 = (select([func.unnest(self.tables.hostname.domains)
                             .label("domains")])
                     .where(exists(select([1])
                                   .select_from(base)
                                   .where(self.tables.hostname.scan ==
                                          base.c.id)))
                     .cte("base1"))
            return (
                {"count": result[1], "_id": result[0]}
                for result in self.db.execute(
                    select([base1.c.domains, func.count().label("count")])
                    .where(base1.c.domains.op('~')(
                        '^([^\\.]+\\.){%d}[^\\.]+$' % level
                    ))
                    .group_by(base1.c.domains)
                    .order_by(order)
                    .limit(topnbr)
                )
            )
        elif field == "hop":
            field = self._topstructure(self.tables.hop,
                                       [self.tables.hop.ipaddr])
        elif field.startswith('hop') and field[3] in ':>':
            ttl = int(field[4:])
            field = self._topstructure(
                self.tables.hop, [self.tables.hop.ipaddr],
                (self.tables.hop.ttl > ttl) if field[3] == '>' else
                (self.tables.hop.ttl == ttl),
            )
        elif field == 'file' or (field.startswith('file') and
                                 field[4] in '.:'):
            if field.startswith('file:'):
                scripts = field[5:]
                if '.' in scripts:
                    scripts, field = scripts.split('.', 1)
                else:
                    field = 'filename'
                scripts = scripts.split(',')
                flt = (self.tables.script.name == scripts[0]
                       if len(scripts) == 1 else
                       self.tables.script.name.in_(scripts))
            else:
                field = field[5:] or 'filename'
                flt = True
            field = self._topstructure(
                self.tables.script,
                [func.jsonb_array_elements(
                    func.jsonb_array_elements(
                        self.tables.script.data['ls']['volumes']
                    ).op('->')('files')
                ).op('->>')(field).label(field)],
                and_(
                    flt,
                    self.tables.script.data.op('@>')(
                        '{"ls": {"volumes": [{"files": []}]}}'
                    ),
                ),
            )
        elif field.startswith('modbus.'):
            subfield = field[7:]
            field = self._topstructure(
                self.tables.script,
                [self.tables.script.data['modbus-discover'][subfield]],
                and_(self.tables.script.name == 'modbus-discover',
                     self.tables.script.data['modbus-discover']
                     .has_key(subfield)),
                # noqa: W601 (BinaryExpression)
            )
        elif field.startswith('s7.'):
            subfield = field[3:]
            field = self._topstructure(
                self.tables.script,
                [self.tables.script.data['s7-info'][subfield]],
                and_(self.tables.script.name == 's7-info',
                     self.tables.script.data['s7-info'].has_key(subfield)),
                # noqa: W601 (BinaryExpression)
            )
        elif field == 'httphdr':
            flt = self.flt_and(flt, self.searchscript(name="http-headers"))
            field = self._topstructure(
                self.tables.script,
                [column("hdr").op('->>')('name').label("name"),
                 column("hdr").op('->>')('value').label("value")],
                self.tables.script.name == 'http-headers',
                [column("name"), column("value")],
                func.jsonb_array_elements(
                    self.tables.script.data['http-headers']
                ).alias('hdr'),
            )
        elif field.startswith('httphdr.'):
            flt = self.flt_and(flt, self.searchscript(name="http-headers"))
            field = self._topstructure(
                self.tables.script,
                [column("hdr").op('->>')(field[8:]).label("topvalue")],
                self.tables.script.name == 'http-headers',
                [column("topvalue")],
                func.jsonb_array_elements(
                    self.tables.script.data['http-headers']
                ).alias('hdr'),
            )
        elif field.startswith('httphdr:'):
            flt = self.flt_and(flt, self.searchhttphdr(name=field[8:].lower()))
            field = self._topstructure(
                self.tables.script,
                [column("hdr").op('->>')("value").label("value")],
                and_(self.tables.script.name == 'http-headers',
                     column("hdr").op('->>')("name") == field[8:].lower()),
                [column("value")],
                func.jsonb_array_elements(
                    self.tables.script.data['http-headers']
                ).alias('hdr'),
            )
        else:
            raise NotImplementedError()
        s_from = {
            self.tables.script: join(self.tables.script, self.tables.port),
            self.tables.port: self.tables.port,
            self.tables.category: join(self.tables.association_scan_category,
                                       self.tables.category),
            self.tables.hostname: self.tables.hostname,
            self.tables.hop: join(self.tables.trace, self.tables.hop),
        }
        where_clause = {
            self.tables.script: self.tables.port.scan == base.c.id,
            self.tables.port: self.tables.port.scan == base.c.id,
            self.tables.category:
            self.tables.association_scan_category.scan == base.c.id,
            self.tables.hostname: self.tables.hostname.scan == base.c.id,
            self.tables.hop: self.tables.trace.scan == base.c.id
        }
        if field.base == self.tables.scan:
            req = flt.query(
                select([func.count().label("count")] + field.fields)
                .select_from(self.tables.scan)
                .group_by(*field.fields)
            )
        else:
            req = (select([func.count().label("count")] + field.fields)
                   .select_from(s_from[field.base]))
            if field.extraselectfrom is not None:
                req = req.select_from(field.extraselectfrom)
            req = (req
                   .group_by(*(field.fields if field.group_by is None
                               else field.group_by))
                   .where(exists(select([1]).select_from(base)
                                 .where(where_clause[field.base]))))
        if field.where is not None:
            req = req.where(field.where)
        if outputproc is None:
            return ({"count": result[0],
                     "_id": result[1:] if len(result) > 2 else result[1]}
                    for result in
                    self.db.execute(req.order_by(order).limit(topnbr)))
        else:
            return ({"count": result[0],
                     "_id": outputproc(result[1:] if len(result) > 2
                                       else result[1])}
                    for result in
                    self.db.execute(req.order_by(order).limit(topnbr)))


class PostgresDBNmap(PostgresDBActive, SQLDBNmap):

    def __init__(self, url):
        PostgresDBActive.__init__(self, url)
        SQLDBNmap.__init__(self, url)

    def store_scan_doc(self, scan):
        scan = scan.copy()
        if 'start' in scan:
            scan['start'] = datetime.datetime.utcfromtimestamp(
                int(scan['start'])
            )
        if 'scaninfos' in scan:
            scan["scaninfo"] = scan.pop('scaninfos')
        scan["sha256"] = utils.decode_hex(scan.pop('_id'))
        insrt = insert(self.tables.scanfile).values(
            **dict(
                (key, scan[key])
                for key in ['sha256', 'args', 'scaninfo', 'scanner', 'start',
                            'version', 'xmloutputversion']
                if key in scan
            )
        )
        if config.DEBUG:
            scanfileid = self.db.execute(
                insrt.returning(self.tables.scanfile.sha256)
            ).fetchone()[0]
            utils.LOGGER.debug("SCAN STORED: %r", utils.encode_hex(scanfileid))
        else:
            self.db.execute(insrt)

    def _store_host(self, host):
        addr = self.ip2internal(host['addr'])
        info = host.get('infos')
        source = host.get('source', '')
        host_tstart = utils.all2datetime(host['starttime'])
        host_tstop = utils.all2datetime(host['endtime'])
        scanid = self.db.execute(
            postgresql.insert(self.tables.scan).values(
                addr=addr,
                source=source,
                info=info,
                time_start=host_tstart,
                time_stop=host_tstop,
                # FIXME: masscan results may lack 'state' and 'state_reason'
                state=host.get('state'),
                state_reason=host.get('state_reason'),
                state_reason_ttl=host.get('state_reason_ttl'),
            )
            .on_conflict_do_nothing()
            .returning(self.tables.scan.id)
        ).fetchone()[0]
        for category in host.get("categories", []):
            insrt = postgresql.insert(self.tables.category)
            catid = self.db.execute(
                insrt.values(name=category)
                .on_conflict_do_update(
                    index_elements=['name'],
                    set_={'name': insrt.excluded.name}
                )
                .returning(self.tables.category.id)
            ).fetchone()[0]
            self.db.execute(postgresql.insert(
                self.tables.association_scan_category
            ).values(scan=scanid, category=catid)
             .on_conflict_do_nothing())
        for port in host.get('ports', []):
            scripts = port.pop('scripts', [])
            # FIXME: handle screenshots
            for fld in ['screendata', 'screenshot', 'screenwords',
                        'service_method']:
                try:
                    del port[fld]
                except KeyError:
                    pass
            if 'service_servicefp' in port:
                port['service_fp'] = port.pop('service_servicefp')
            if 'state_state' in port:
                port['state'] = port.pop('state_state')
            if 'state_reason_ip' in port:
                port['state_reason_ip'] = self.ip2internal(
                    port['state_reason_ip']
                )
            portid = self.db.execute(
                insert(self.tables.port)
                .values(scan=scanid, **port)
                .returning(self.tables.port.id)
            ).fetchone()[0]
            for script in scripts:
                name, output = script.pop('id'), script.pop('output')
                self.bulk.append(insert(self.tables.script).values(
                    port=portid,
                    name=name,
                    output=output,
                    data=script
                ))
        for trace in host.get('traces', []):
            traceid = self.db.execute(insert(self.tables.trace).values(
                scan=scanid,
                port=trace.get('port'),
                protocol=trace['protocol']
            ).returning(self.tables.trace.id)).fetchone()[0]
            for hop in trace.get('hops'):
                hop['ipaddr'] = self.ip2internal(hop['ipaddr'])
                self.bulk.append(insert(self.tables.hop).values(
                    trace=traceid,
                    ipaddr=self.ip2internal(hop['ipaddr']),
                    ttl=hop["ttl"],
                    rtt=None if hop["rtt"] == '--' else hop["rtt"],
                    host=hop.get("host"),
                    domains=hop.get("domains"),
                ))
        for hostname in host.get('hostnames', []):
            self.bulk.append(insert(self.tables.hostname).values(
                scan=scanid,
                domains=hostname.get('domains'),
                name=hostname.get('name'),
                type=hostname.get('type'),
            ))
        utils.LOGGER.debug("HOST STORED: %r", scanid)
        return scanid

    def store_host(self, host):
        scanid = self._store_host(host)
        insrt = postgresql.insert(self.tables.association_scan_scanfile)
        self.db.execute(insrt
                        .values(scan=scanid,
                                scan_file=utils.decode_hex(host['scanid']))
                        .on_conflict_do_nothing())

    def store_hosts(self, hosts):
        tmp = self.create_tmp_table(self.tables.scan, extracols=[
            Column("scanfileid", ARRAY(LargeBinary(32))),
            Column("categories", ARRAY(String(32))),
            Column("source", String(32)),
            # Column("cpe", postgresql.JSONB),
            # Column("extraports", postgresql.JSONB),
            Column("hostnames", postgresql.JSONB),
            # openports
            # Column("os", postgresql.JSONB),
            Column("ports", postgresql.JSONB),
            # Column("traceroutes", postgresql.JSONB),
        ])
        with ScanCSVFile(hosts, self.ip2internal, tmp) as fdesc:
            self.copy_from(fdesc, tmp.name)


class PostgresDBView(PostgresDBActive, SQLDBView):

    def __init__(self, url):
        PostgresDBActive.__init__(self, url)
        SQLDBView.__init__(self, url)

    def _store_host(self, host):
        addr = self.ip2internal(host['addr'])
        info = host.get('infos')
        source = host.get('source', [])
        host_tstart = utils.all2datetime(host['starttime'])
        host_tstop = utils.all2datetime(host['endtime'])
        insrt = postgresql.insert(self.tables.scan)
        scanid, scan_tstop = self.db.execute(
            insrt.values(
                addr=addr,
                source=source,
                info=info,
                time_start=host_tstart,
                time_stop=host_tstop,
                **dict(
                    (key, host.get(key)) for key in
                    ['state', 'state_reason', 'state_reason_ttl']
                    if key in host
                )
            )
            .on_conflict_do_update(
                index_elements=['addr'],
                set_={
                    'source': self.tables.scan.source + insrt.excluded.source,
                    'time_start': func.least(
                        self.tables.scan.time_start,
                        insrt.excluded.time_start,
                    ),
                    'time_stop': func.greatest(
                        self.tables.scan.time_stop,
                        insrt.excluded.time_stop,
                    ),
                },
            )
            .returning(self.tables.scan.id, self.tables.scan.time_stop)
        ).fetchone()
        newest = scan_tstop <= host_tstop
        for category in host.get("categories", []):
            insrt = postgresql.insert(self.tables.category)
            catid = self.db.execute(
                insrt.values(name=category)
                .on_conflict_do_update(
                    index_elements=['name'],
                    set_={'name': insrt.excluded.name}
                )
                .returning(self.tables.category.id)
            ).fetchone()[0]
            self.db.execute(postgresql.insert(
                self.tables.association_scan_category
            ).values(scan=scanid, category=catid)
             .on_conflict_do_nothing())
        for port in host.get('ports', []):
            scripts = port.pop('scripts', [])
            # FIXME: handle screenshots
            for fld in ['screendata', 'screenshot', 'screenwords',
                        'service_method']:
                try:
                    del port[fld]
                except KeyError:
                    pass
            if 'service_servicefp' in port:
                port['service_fp'] = port.pop('service_servicefp')
            if 'state_state' in port:
                port['state'] = port.pop('state_state')
            if 'state_reason_ip' in port:
                port['state_reason_ip'] = self.ip2internal(
                    port['state_reason_ip']
                )
            insrt = postgresql.insert(self.tables.port)
            portid = self.db.execute(
                insrt.values(scan=scanid, **port)
                .on_conflict_do_update(
                    index_elements=['scan', 'port',
                                    'protocol'],
                    set_=dict(
                        scan=scanid,
                        **(port if newest else {})
                    )
                )
                .returning(self.tables.port.id)
            ).fetchone()[0]
            for script in scripts:
                name, output = script.pop('id'), script.pop('output')
                if newest:
                    insrt = postgresql.insert(self.tables.script)
                    self.bulk.append(insrt
                                     .values(
                                         port=portid,
                                         name=name,
                                         output=output,
                                         data=script
                                     )
                                     .on_conflict_do_update(
                                         index_elements=['port', 'name'],
                                         set_={
                                             "output":
                                             insrt.excluded.output,
                                             "data": insrt.excluded.data,
                                         },
                                     ))
                else:
                    insrt = postgresql.insert(self.tables.script)
                    self.bulk.append(insrt
                                     .values(
                                         port=portid,
                                         name=name,
                                         output=output,
                                         data=script
                                     )
                                     .on_conflict_do_nothing())
        for trace in host.get('traces', []):
            traceid = self.db.execute(
                postgresql.insert(self.tables.trace).values(
                    scan=scanid,
                    port=trace.get('port'),
                    protocol=trace['protocol']
                ).on_conflict_do_nothing()
                 .returning(self.tables.trace.id)
            ).fetchone()[0]
            for hop in trace.get('hops'):
                hop['ipaddr'] = self.ip2internal(hop['ipaddr'])
                self.bulk.append(postgresql.insert(self.tables.hop).values(
                    trace=traceid,
                    ipaddr=self.ip2internal(hop['ipaddr']),
                    ttl=hop["ttl"],
                    rtt=None if hop["rtt"] == '--' else hop["rtt"],
                    host=hop.get("host"),
                    domains=hop.get("domains"),
                ))
        for hostname in host.get('hostnames', []):
            self.bulk.append(postgresql.insert(self.tables.hostname).values(
                scan=scanid,
                domains=hostname.get('domains'),
                name=hostname.get('name'),
                type=hostname.get('type'),
            ).on_conflict_do_nothing())
        utils.LOGGER.debug("VIEW STORED: %r", scanid)
        return scanid

    def store_host(self, host):
        self._store_host(host)


class PostgresDBPassive(PostgresDB, SQLDBPassive):

    def __init__(self, url):
        PostgresDB.__init__(self, url)
        SQLDBPassive.__init__(self, url)

    def _insert_or_update(self, timestamp, vals, lastseen=None):
        stmt = postgresql.insert(self.tables.passive).values(vals)
        index = ['addr', 'sensor', 'recontype', 'port',
                 'source', 'value', 'targetval', 'info']
        upsert = {
            'firstseen': func.least(
                self.tables.passive.firstseen,
                timestamp,
            ),
            'lastseen': func.greatest(
                self.tables.passive.lastseen,
                lastseen or timestamp,
            ),
            'count': self.tables.passive.count + stmt.excluded.count,
        }
        self.db.execute(
            stmt.on_conflict_do_update(index_elements=index, set_=upsert,)
        )

    def insert_or_update_bulk(self, specs, getinfos=None,
                              separated_timestamps=True):
        """Like `.insert_or_update()`, but `specs` parameter has to be an
        iterable of `(timestamp, spec)` (if `separated_timestamps` is
        True) or `spec` (if it is False) values. This will perform
        PostgreSQL COPY FROM inserts with the major drawback that the
        `getinfos` parameter will be called (if it is not `None`) for
        each spec, even when the spec already exists in the database
        and the call was hence unnecessary.

        It's up to you to decide whether having bulk insert is worth
        it or if you want to go with the regular `.insert_or_update()`
        method.

        """
        more_to_read = True
        tmp = self.create_tmp_table(self.tables.passive)
        if config.DEBUG_DB:
            total_upserted = 0
            total_start_time = time.time()
        while more_to_read:
            if config.DEBUG_DB:
                start_time = time.time()
            with PassiveCSVFile(specs, self.ip2internal, tmp,
                                getinfos=getinfos,
                                separated_timestamps=separated_timestamps,
                                limit=config.POSTGRES_BATCH_SIZE) as fdesc:
                self.copy_from(fdesc, tmp.name)
                more_to_read = fdesc.more_to_read
                if config.DEBUG_DB:
                    count_upserted = fdesc.count
            insrt = postgresql.insert(self.tables.passive)
            self.db.execute(
                insrt.from_select(
                    [column(col) for col in [
                        'addr',
                        # sum / min / max
                        'count', 'firstseen', 'lastseen',
                        # grouped
                        'sensor', 'port', 'recontype', 'source', 'targetval',
                        'value', 'fullvalue', 'info', 'moreinfo'
                    ]],
                    select([tmp.columns['addr'],
                            func.sum_(tmp.columns['count']),
                            func.min_(tmp.columns['firstseen']),
                            func.max_(tmp.columns['lastseen'])] + [
                                tmp.columns[col] for col in [
                                    'sensor', 'port', 'recontype', 'source',
                                    'targetval', 'value', 'fullvalue', 'info',
                                    'moreinfo']])\
                    .group_by(*(tmp.columns[col] for col in [
                        'addr', 'sensor', 'port', 'recontype', 'source',
                        'targetval', 'value', 'fullvalue', 'info', 'moreinfo'
                    ]))
                )\
                .on_conflict_do_update(
                    index_elements=['addr', 'sensor', 'recontype', 'port',
                                    'source', 'value', 'targetval', 'info'],
                    set_={
                        'firstseen': func.least(
                            self.tables.passive.firstseen,
                            insrt.excluded.firstseen,
                        ),
                        'lastseen': func.greatest(
                            self.tables.passive.lastseen,
                            insrt.excluded.lastseen,
                        ),
                        'count':
                        self.tables.passive.count + insrt.excluded.count,
                    },
                )
            )
            self.db.execute(delete(tmp))
            if config.DEBUG_DB:
                stop_time = time.time()
                time_spent = stop_time - start_time
                total_upserted += count_upserted
                total_time_spent = stop_time - total_start_time
                utils.LOGGER.debug(
                    "DB:PERFORMANCE STATS %s upserts, %f s, %s/s\n"
                    "\ttotal: %s upserts, %f s, %s/s",
                    utils.num2readable(count_upserted), time_spent,
                    utils.num2readable(count_upserted / time_spent),
                    utils.num2readable(total_upserted), total_time_spent,
                    utils.num2readable(total_upserted / total_time_spent),
                )
