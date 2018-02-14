# Introduction #

IVRE flow is a beta feature meant to analyze network flows between hosts.
It can be seen as:

  * a recon tool for the case of an unknown network (hence its
    apparition in IVRE/DRUNK)
  * a cartography tool to get a better understanding of a supposedly known
    network (but there is no such thing as a "known network")
  * a monitoring tool to spot unwanted flows in your network

# Installation #

Start by following the standard ivre installation.

In addition, install `neo4j` and set a user/password (for example through the
default admin interface on `http://localhost:7474`). Default user/password is
`neo4j`/`neo4j`. Set the relevent URL in you `ivre.conf`:

```python
DB_FLOW = "neo4j://<user>:<password>@localhost:7474/"
```

Run `ivre flowcli --init` to initialize the database (**WARNING:** this will
**REMOVE** everything in the db).

And that should be it. The Web UI is available at `<ivre-web-root>/flow.html`.

As the Web UI is super-beta, no error will show up in it, check the logs of the
webserver for debugging.

# Usage #

## Data insertion ##

There are two tools for data insertion, the first is bro-based:

```bash
    $ bro -r capture_file.pcap
    $ ivre bro2db ./*.log
    $ ivre flowcli
```

The second can take either argus logs or netflow logs:

```bash
    $ argus -m -r capture_file.pcap -w flows.argus
    $ ivre flow2db flows.argus
```

Or:

```bash
    $ ivre flow2db flows.nfdump
```

Or:
```bash
    $ ivre flow2db -t iptables iptables-from-syslog.log

```
Any of these tools can be called with '--init' to reinitialize the DB.

## Data exploration ##

The main exploration tool are the CLI (`ivre flowcli`) and the Web UI
(`<ivre-web-root>/flow.html`).

### CLI ###

You can access the CLI through `ivre flowcli`. Features include:

  - Searching for flows and nodes with filters (see the Flow Filters section of
    this document)
  - Producing top values for given criterias
  - Plotting flows amounts over hours of days, on average.

See `ivre flowcli -h` for usage details.

### Web UI ###

#### Overview ####

The central view is a graph representing the network:

  - nodes represent hosts; white ones represent hosts that have incoming network
    flows, grey ones those who do not have any
  - edges represent network flows; same [proto, dport] couple will have the same
    color

Flows are aggregated by destination port (or code, for icmp), two different
connection from the same source to the same destination on the same destination
port (so called `dport`) but with different source ports will be aggregated on
the same edge.

On the bottom of the graph, there is a timeline, representing the amount of
different flows during some time ranges. This timeline can be played by going to
the **Display** pane.

On the left, there is a control pane with 3 tabs:

  - **Explore:** Allows to explore and reduce the dataset to display with
    node-based or edge-based queries. See the next section for more details. It
    also allows to navigate through the data (limit/skip) and change the query
    mode. At the top of this pane, there is a count of the flows, servers and
    clients matching the current query. Note that servers can also be counted
    as clients if they have outgoing flows.
  - **Display:** Allows to change the way data is displayed (size of nodes
    and edges, timeline precision).
  - **Details:** Details on the currently selected item.

#### Interaction ####

Hover nodes and edges to display their basic properties in the **Details** tab.
Click on an edge or a node to query the database for more information, including
any associated metadata (for example DNS queries happening on a network flow).

There are two ways of filtering the data:

  - Right click on a node or edge and `Filter by`/`Filter out` by attribute
  - Write filters yourself

See the Flow Filter section of this document for more information on the filter
syntax.

The **Display** pane allows to change the size of nodes and edges based on some
criterias:

  - On nodes, available keywords are `$in` and `$out`, to make the size
    proportional to the number of incoming or outgoing flows of a node.
  - On edges, a poperty can be specified (for example `scbytes`, the number of
    bytes from the server to the client).

Do not forget to increase the `Size scale` to make the result more visible.

The **Display** pane also allows to change the amount of time slots to represent
on the timeline (capped by the actual time precision set in `ivre.conf`). The
timeline can also be played on the graph by clicking the 'Play timeline' button.

### Raw Database queries ###

Ivre flow module is currently built on top of neo4j. The query language of this
database is quite intuitive and the user is encouraged to execute his own
custom queries. The model is as follows:

```
   (:Host)-[:SEND]->(:Flow)-[:TO]->(:Host)
      |                |
      \                /
       `-->(:Intel)<--'
```

As an example, the following query returns the most common (proto, dport):

```
MATCH (f:Flow)
RETURN [f.proto, f.dport], count(*) AS cnt
ORDER BY cnt DESC
```

### Flow Filters ###

To write filters, the syntax is as follows:

    [!][ANY|ALL|ONE|LEN ][src.|dst.][meta.]<attribute> [<operator> <value>]
    [OR <other filter>]

The `[src.|dst.]` part is only available for node filters.

The special keywords `ANY`, `ALL`, `ONE` and `LEN` are for working with array
attributes:

  - ALL: matches if all the elements of the array fullfil the predicate
  - ANY: the same if any of the elements match
  - ONE: the same if exactly one of the elements match
  - LEN: the predicate will use the len of the array

Some examples:

  - Node filter `dst.addr = 192.168.1.1` will match all the flows whose
    destination is a host with address `192.168.1.1`.
  - Node filter `addr =~ 192\.168\.1\..*`  will match all the flows that come
    from or go to a host whose address matches the `192\.168\.1\..*` regex
    (sorry, CIDR masks are on their way to be implemented).
  - Edge filter `dport > 10000` will match all the flows with a `dport`
    (destination port) above 10000. `!dport <= 10000` will match the same
    flows plus the ones that do not have any destination port.
  - Edge filter `meta.query =~ .*google.*` will match all the flows that have
    an associated metadata wich have a `query` attribute that match the
    `.*google.*` regex.
  - Edge filter `ANY sports < 1024` will match flows with at least one source
    port < 1024.
  - Edge filter `LEN sports = 1` will match flows with only one known source
    port.
  - Filter `ANY meta.answers =~ .*example.com` will match any metadata that
    contain an array attribute `answers` where at least one entry matches
    `'.*example.com'`.

Available operators are:

  - `=` or `:` (equality)
  - `!=`
  - `<`, `<=`, `>`, `>=`
  - `=~`


---

This file is part of IVRE. Copyright 2011 - 2017
[Pierre LALET](mailto:pierre.lalet@cea.fr)
