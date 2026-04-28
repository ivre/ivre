# This file is part of IVRE.
# Copyright 2011 - 2026 Pierre LALET <pierre@droids-corp.org>
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

ACTIVE_SCHEMA = {
    "fields": [
        # Top-level
        {
            "path": "schema_version",
            "type": "integer",
            "description": "Document schema version",
        },
        {"path": "addr", "type": "IP address", "description": "Host address"},
        {"path": "state", "type": "string", "description": "Host state (up, down)"},
        {
            "path": "state_reason",
            "type": "string",
            "description": "Reason for host state",
        },
        {
            "path": "state_reason_ttl",
            "type": "integer",
            "description": "TTL from state probe",
        },
        {"path": "starttime", "type": "datetime", "description": "Scan start time"},
        {"path": "endtime", "type": "datetime", "description": "Scan end time"},
        {"path": "source", "type": "string", "description": "Data source"},
        {
            "path": "categories",
            "type": "array[string]",
            "description": "Host categories",
        },
        # hostnames[]
        {"path": "hostnames[].name", "type": "string", "description": "Hostname"},
        {
            "path": "hostnames[].type",
            "type": "string",
            "description": (
                "Source/type of the hostname (open set). Common values: "
                "'user' (user-supplied: CLI, DNS analyzer, dns-zone-transfer "
                "script); "
                "'PTR' (reverse DNS lookup); "
                "'A', 'AAAA', 'CNAME', 'NS', 'MX' (passive DNS answers "
                "merged into the view, named after the DNS record type); "
                "'smb' (DNS_Computer_Name from SMB OS discovery); "
                "'ntlm' (DNS_Computer_Name from NTLM challenges, HTTP "
                "Negotiate or SMB); "
                "'service' (extracted by service detection, e.g. "
                "Elasticsearch cluster banner); "
                "'cert-subject-cn' (Subject CN of a TLS certificate); "
                "'cert-san-dns' (TLS cert SAN of type DNS:); "
                "'cert-san-uri' (host part of a TLS cert SAN of type URI:); "
                "'cert-san-dirname-cn' (CN inside a TLS cert SAN of type "
                "DirName:); "
                "'cert-san-othername-upn' (TLS cert SAN othername:UPN:); "
                "'cert-san-othername-<subtype>' (TLS cert SAN "
                "othername:<subtype>:..., subtype lower-cased)."
            ),
        },
        {
            "path": "hostnames[].domains[]",
            "type": "string",
            "description": "Parent domains",
        },
        # ports[]
        {"path": "ports[].port", "type": "integer", "description": "Port number"},
        {"path": "ports[].protocol", "type": "string", "description": "tcp or udp"},
        {
            "path": "ports[].state_state",
            "type": "string",
            "description": "Port state (open, closed, ...)",
        },
        {
            "path": "ports[].state_reason",
            "type": "string",
            "description": "Reason for port state",
        },
        {
            "path": "ports[].service_name",
            "type": "string",
            "description": "Service name",
        },
        {
            "path": "ports[].service_product",
            "type": "string",
            "description": "Product name",
        },
        {
            "path": "ports[].service_version",
            "type": "string",
            "description": "Product version",
        },
        {
            "path": "ports[].service_ostype",
            "type": "string",
            "description": "OS type from service detection",
        },
        {
            "path": "ports[].service_devicetype",
            "type": "string",
            "description": "Device type from service detection",
        },
        {
            "path": "ports[].service_extrainfo",
            "type": "string",
            "description": "Extra service info",
        },
        {
            "path": "ports[].service_hostname",
            "type": "string",
            "description": "Hostname from service detection",
        },
        {
            "path": "ports[].service_method",
            "type": "string",
            "description": "Detection method",
        },
        {
            "path": "ports[].service_conf",
            "type": "integer",
            "description": "Detection confidence (0-10)",
        },
        {
            "path": "ports[].screenshot",
            "type": "string",
            "description": "Screenshot identifier",
        },
        {
            "path": "ports[].screendata",
            "type": "binary",
            "description": "Screenshot data",
        },
        {
            "path": "ports[].screenwords[]",
            "type": "string",
            "description": "OCR words from screenshot",
        },
        # ports[].scripts[]
        {
            "path": "ports[].scripts[].id",
            "type": "string",
            "description": "NSE script ID",
        },
        {
            "path": "ports[].scripts[].output",
            "type": "string",
            "description": "Script text output",
        },
        # openports
        {
            "path": "openports.count",
            "type": "integer",
            "description": "Total open ports",
        },
        {
            "path": "openports.tcp.count",
            "type": "integer",
            "description": "Open TCP ports",
        },
        {
            "path": "openports.tcp.ports[]",
            "type": "integer",
            "description": "TCP port numbers",
        },
        {
            "path": "openports.udp.count",
            "type": "integer",
            "description": "Open UDP ports",
        },
        {
            "path": "openports.udp.ports[]",
            "type": "integer",
            "description": "UDP port numbers",
        },
        # os
        {"path": "os.osmatch[].name", "type": "string", "description": "OS match name"},
        {
            "path": "os.osmatch[].accuracy",
            "type": "integer",
            "description": "Match accuracy",
        },
        {"path": "os.osclass[].vendor", "type": "string", "description": "OS vendor"},
        {"path": "os.osclass[].osfamily", "type": "string", "description": "OS family"},
        {
            "path": "os.osclass[].osgen",
            "type": "string",
            "description": "OS generation",
        },
        {
            "path": "os.osclass[].accuracy",
            "type": "integer",
            "description": "Class accuracy",
        },
        {
            "path": "os.fingerprint",
            "type": "string",
            "description": "Raw OS fingerprint",
        },
        # cpes[]
        {"path": "cpes[].type", "type": "string", "description": "CPE type (a, o, h)"},
        {"path": "cpes[].vendor", "type": "string", "description": "Vendor name"},
        {"path": "cpes[].product", "type": "string", "description": "Product name"},
        {"path": "cpes[].version", "type": "string", "description": "Version"},
        {
            "path": "cpes[].origins[]",
            "type": "string",
            "description": "Origin references",
        },
        # traces[]
        {
            "path": "traces[].protocol",
            "type": "string",
            "description": "Trace protocol",
        },
        {"path": "traces[].port", "type": "integer", "description": "Trace port"},
        {"path": "traces[].hops[].ttl", "type": "integer", "description": "Hop TTL"},
        {
            "path": "traces[].hops[].rtt",
            "type": "float",
            "description": "Round-trip time",
        },
        {
            "path": "traces[].hops[].host",
            "type": "string",
            "description": "Hop hostname",
        },
        {
            "path": "traces[].hops[].ipaddr",
            "type": "IP address",
            "description": "Hop IP address",
        },
        {
            "path": "traces[].hops[].domains[]",
            "type": "string",
            "description": "Hop domains",
        },
        # tags[]
        {"path": "tags[].value", "type": "string", "description": "Tag value"},
        {"path": "tags[].type", "type": "string", "description": "Tag type"},
        {"path": "tags[].info[]", "type": "string", "description": "Tag info entries"},
        # infos (geo/ASN)
        {"path": "infos.country_code", "type": "string", "description": "Country code"},
        {"path": "infos.country_name", "type": "string", "description": "Country name"},
        {"path": "infos.city", "type": "string", "description": "City name"},
        {
            "path": "infos.as_num",
            "type": "integer",
            "description": "Autonomous System number",
        },
        {"path": "infos.as_name", "type": "string", "description": "AS name"},
        # addresses
        {"path": "addresses.mac[]", "type": "string", "description": "MAC addresses"},
    ],
    "pseudo_fields": [
        # Network
        {"pattern": "addr", "description": "Host address"},
        {"pattern": "net", "description": "Network blocks"},
        {
            "pattern": "net:<mask>",
            "description": "Network blocks with given prefix length",
        },
        # Geography
        {"pattern": "country", "description": "Country code aggregation"},
        {"pattern": "city", "description": "City aggregation"},
        {"pattern": "asnum", "description": "AS number aggregation"},
        {"pattern": "as", "description": "AS number and name aggregation"},
        # Ports
        {"pattern": "port", "description": "Port numbers"},
        {"pattern": "port:<state>", "description": "Port numbers filtered by state"},
        {
            "pattern": "port:<service>",
            "description": "Port numbers filtered by service",
        },
        # Port lists
        {"pattern": "portlist:<state>", "description": "Port lists by state"},
        {"pattern": "countports:<state>", "description": "Port counts by state"},
        # Services
        {"pattern": "service", "description": "Service names"},
        {
            "pattern": "service:<port>",
            "description": "Service names on a specific port",
        },
        # Products
        {"pattern": "product", "description": "Service and product names"},
        {"pattern": "product:<port>", "description": "Products on a specific port"},
        {
            "pattern": "product:<service>",
            "description": "Products for a specific service",
        },
        # Versions
        {"pattern": "version", "description": "Service, product and version"},
        {"pattern": "version:<port>", "description": "Versions on a specific port"},
        {"pattern": "version:<service>", "description": "Versions for a service"},
        {
            "pattern": "version:<service>:<product>",
            "description": "Versions for a service and product",
        },
        # Device types
        {"pattern": "devicetype", "description": "Device types"},
        {"pattern": "devicetype:<port>", "description": "Device types on a port"},
        # Categories
        {"pattern": "category", "description": "Host categories"},
        {
            "pattern": "category:<regexp>",
            "description": "Categories matching a pattern",
        },
        # CPE
        {"pattern": "cpe", "description": "CPE entries"},
        {"pattern": "cpe.<part>", "description": "CPE entries by part (a, o, h)"},
        {"pattern": "cpe:<spec>", "description": "CPE entries matching a spec"},
        {
            "pattern": "cpe.<part>:<spec>",
            "description": "CPE entries by part matching a spec",
        },
        # Certificates
        {"pattern": "cert.<field>", "description": "SSL certificate fields"},
        {"pattern": "cacert.<field>", "description": "CA certificate fields"},
        # SSH keys
        {"pattern": "sshkey.bits", "description": "SSH key sizes"},
        {"pattern": "sshkey.keytype", "description": "SSH key types"},
        {"pattern": "sshkey.<field>", "description": "SSH key fields"},
        # JA3/JA4
        {
            "pattern": "ja3-client[:<filter>][.<type>]",
            "description": "JA3 client fingerprints",
        },
        {
            "pattern": "ja3-server[:<filter>][:<client>][.<type>]",
            "description": "JA3 server fingerprints",
        },
        {
            "pattern": "ja4-client[:<filter>][.<type>]",
            "description": "JA4 client fingerprints",
        },
        {"pattern": "jarm", "description": "JARM fingerprints"},
        {"pattern": "jarm:<port>", "description": "JARM fingerprints on a port"},
        # HASSH
        {"pattern": "hassh[.<type>]", "description": "SSH fingerprints"},
        {"pattern": "hassh-client[.<type>]", "description": "SSH client fingerprints"},
        {"pattern": "hassh-server[.<type>]", "description": "SSH server fingerprints"},
        # HTTP
        {"pattern": "httphdr", "description": "HTTP header names"},
        {"pattern": "httphdr.<field>", "description": "HTTP header fields"},
        {"pattern": "httphdr:<name>", "description": "HTTP header values by name"},
        {"pattern": "httpapp", "description": "HTTP applications"},
        {"pattern": "httpapp:<name>", "description": "HTTP application versions"},
        {"pattern": "useragent", "description": "User-Agent values"},
        {
            "pattern": "useragent:<pattern>",
            "description": "User-Agent values matching a pattern",
        },
        # Scripts
        {"pattern": "script", "description": "NSE script IDs"},
        {
            "pattern": "script:<id>",
            "description": "Script output for a specific script",
        },
        {"pattern": "script:<port>:<id>", "description": "Script output on a port"},
        {"pattern": "script:host:<id>", "description": "Host script output"},
        # SMB/NTLM
        {"pattern": "smb.<field>", "description": "SMB discovery fields"},
        {"pattern": "ntlm", "description": "NTLM discovery"},
        {"pattern": "ntlm.<field>", "description": "NTLM discovery fields"},
        # IKE
        {"pattern": "ike.vendor_ids", "description": "IKE vendor IDs"},
        {"pattern": "ike.transforms", "description": "IKE transforms"},
        {"pattern": "ike.notification", "description": "IKE notifications"},
        {"pattern": "ike.<field>", "description": "IKE protocol fields"},
        # ICS
        {"pattern": "modbus.<field>", "description": "Modbus protocol fields"},
        {"pattern": "s7.<field>", "description": "Siemens S7 protocol fields"},
        {"pattern": "enip.<field>", "description": "EtherNet/IP protocol fields"},
        # MongoDB
        {"pattern": "mongo.dbs.<field>", "description": "MongoDB database fields"},
        # Vulns
        {"pattern": "vulns.id", "description": "Vulnerability IDs"},
        {"pattern": "vulns.<field>", "description": "Vulnerability fields"},
        # Files
        {"pattern": "file", "description": "File listings"},
        {"pattern": "file.<field>", "description": "File fields"},
        {"pattern": "file:<script>", "description": "Files from a specific script"},
        {
            "pattern": "file:<script>.<field>",
            "description": "File fields from a script",
        },
        # Screenshots
        {"pattern": "screenwords", "description": "Screenshot text"},
        # Traceroute
        {"pattern": "hop", "description": "Traceroute hops"},
        {"pattern": "hop:<ttl>", "description": "Hops at a specific TTL"},
        {"pattern": "hop:><ttl>", "description": "Hops beyond a TTL"},
        # Scanner
        {"pattern": "scanner.name", "description": "Scanner names"},
        {"pattern": "scanner.port:tcp", "description": "TCP ports scanned"},
        {"pattern": "scanner.port:udp", "description": "UDP ports scanned"},
        # Domains
        {"pattern": "domains", "description": "Domain hierarchy"},
        {"pattern": "domains:<level>", "description": "Domains at a specific level"},
        {"pattern": "domains:<domain>", "description": "Subdomains of a domain"},
        {"pattern": "domains:<domain>:<level>", "description": "Subdomains at a level"},
        # Tags
        {"pattern": "tag", "description": "Host tags"},
        {"pattern": "tag.<field>", "description": "Tag fields"},
        {"pattern": "tag:<value>", "description": "Tags with a specific value"},
    ],
}

PASSIVE_SCHEMA = {
    "fields": [
        {
            "path": "schema_version",
            "type": "integer",
            "description": "Document schema version",
        },
        {
            "path": "addr",
            "type": "IP address",
            "description": "Host address (absent when targetval is set)",
        },
        {"path": "recontype", "type": "string", "description": "Reconnaissance type"},
        {"path": "source", "type": "string", "description": "Data source"},
        {"path": "value", "type": "string", "description": "Observed value"},
        {
            "path": "targetval",
            "type": "string",
            "description": "Target value (absent when addr is set)",
        },
        {"path": "sensor", "type": "string", "description": "Sensor name"},
        {"path": "port", "type": "integer", "description": "Port number"},
        {
            "path": "firstseen",
            "type": "datetime",
            "description": "First observation time",
        },
        {
            "path": "lastseen",
            "type": "datetime",
            "description": "Last observation time",
        },
        {"path": "count", "type": "integer", "description": "Observation count"},
        # infos - DNS
        {"path": "infos.domain[]", "type": "string", "description": "Source domain(s)"},
        {
            "path": "infos.domaintarget[]",
            "type": "string",
            "description": "Target domain(s)",
        },
        # infos - SSL certificates
        {
            "path": "infos.subject",
            "type": "string",
            "description": "Certificate subject",
        },
        {"path": "infos.issuer", "type": "string", "description": "Certificate issuer"},
        {
            "path": "infos.md5",
            "type": "string",
            "description": "Certificate/key MD5 fingerprint",
        },
        {
            "path": "infos.sha1",
            "type": "string",
            "description": "Certificate/key SHA1 fingerprint",
        },
        {
            "path": "infos.sha256",
            "type": "string",
            "description": "Certificate/key SHA256 fingerprint",
        },
        {
            "path": "infos.not_before",
            "type": "datetime",
            "description": "Certificate validity start",
        },
        {
            "path": "infos.not_after",
            "type": "datetime",
            "description": "Certificate validity end",
        },
        {
            "path": "infos.san[]",
            "type": "string",
            "description": "Subject Alternative Names",
        },
        {
            "path": "infos.pubkey.type",
            "type": "string",
            "description": "Public key type",
        },
        {
            "path": "infos.pubkey.bits",
            "type": "integer",
            "description": "Public key size",
        },
        # infos - SSH keys
        {"path": "infos.algo", "type": "string", "description": "Key algorithm"},
        {"path": "infos.bits", "type": "integer", "description": "Key size"},
        # infos - Banners/services
        {"path": "infos.service_name", "type": "string", "description": "Service name"},
        {
            "path": "infos.service_product",
            "type": "string",
            "description": "Product name",
        },
        {
            "path": "infos.service_version",
            "type": "string",
            "description": "Product version",
        },
        {
            "path": "infos.service_extrainfo",
            "type": "string",
            "description": "Extra service info",
        },
        # infos - JA3/JA4/HASSH
        {"path": "infos.raw", "type": "string", "description": "Raw fingerprint"},
    ],
    "pseudo_fields": [
        # Network
        {"pattern": "addr", "description": "Host address"},
        {"pattern": "net", "description": "Network blocks"},
        {
            "pattern": "net:<mask>",
            "description": "Network blocks with given prefix length",
        },
        # Domains
        {"pattern": "domains", "description": "DNS domain hierarchy"},
        {"pattern": "domains:<level>", "description": "Domains at a specific level"},
        {"pattern": "domains:<domain>", "description": "Subdomains of a domain"},
        {"pattern": "domains:<domain>:<level>", "description": "Subdomains at a level"},
        # SSH keys
        {"pattern": "sshkey.bits", "description": "SSH key sizes"},
        {"pattern": "sshkey.keytype", "description": "SSH key types"},
        {"pattern": "sshkey.<field>", "description": "SSH key fields"},
        # HASSH
        {"pattern": "hassh[.<type>]", "description": "SSH fingerprints"},
        {"pattern": "hassh-client[.<type>]", "description": "SSH client fingerprints"},
        {"pattern": "hassh-server[.<type>]", "description": "SSH server fingerprints"},
        # HTTP
        {"pattern": "useragent", "description": "User-Agent values"},
        {
            "pattern": "useragent:<pattern>",
            "description": "User-Agent values matching a pattern",
        },
    ],
}

SCHEMAS = {
    "nmap": ACTIVE_SCHEMA,
    "passive": PASSIVE_SCHEMA,
    "view": ACTIVE_SCHEMA,
}
