#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2020 Pierre LALET <pierre@droids-corp.org>
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

"""This submodule contains functions to manipulate documents from the
active (nmap & view) purposes.

"""


from datetime import datetime
from itertools import chain
from textwrap import wrap


from future.utils import viewitems, viewvalues


from ivre.active.cpe import add_cpe_values
from ivre.config import VIEW_SYNACK_HONEYPOT_COUNT
from ivre.utils import nmap_decode_data, nmap_encode_data


ALIASES_TABLE_ELEMS = {
    # Use the same structured output for both ssl-cert and ssl-cacert
    "ssl-cacert": "ssl-cert",
    # ls unified output (ls NSE module + ftp-anon)
    #   grep -lF 'ls.new_vol' * | sed 's#^#    "#;s#.nse$#": "ls",#'
    "afp-ls": "ls",
    "http-ls": "ls",
    "nfs-ls": "ls",
    "smb-ls": "ls",
    #   + ftp-anon
    "ftp-anon": "ls",
    # vulns unified output (vulns NSE module)
    #   grep -l -F vulns.Report * | sed 's#^#    "#;s#.nse$#": "vulns",#'
    "afp-path-vuln": "vulns",
    "clamav-exec": "vulns",
    "distcc-cve2004-2687": "vulns",
    "ftp-libopie": "vulns",
    "ftp-vsftpd-backdoor": "vulns",
    "ftp-vuln-cve2010-4221": "vulns",
    "http-avaya-ipoffice-users": "vulns",
    "http-cross-domain-policy": "vulns",
    "http-dlink-backdoor": "vulns",
    "http-frontpage-login": "vulns",
    "http-huawei-hg5xx-vuln": "vulns",
    "http-iis-short-name-brute": "vulns",
    "http-method-tamper": "vulns",
    "http-phpmyadmin-dir-traversal": "vulns",
    "http-phpself-xss": "vulns",
    "http-sap-netweaver-leak": "vulns",
    "http-shellshock": "vulns",
    "http-slowloris-check": "vulns",
    "http-tplink-dir-traversal": "vulns",
    "http-vuln-cve2006-3392": "vulns",
    "http-vuln-cve2009-3960": "vulns",
    "http-vuln-cve2010-2861": "vulns",
    "http-vuln-cve2011-3192": "vulns",
    "http-vuln-cve2011-3368": "vulns",
    "http-vuln-cve2012-1823": "vulns",
    "http-vuln-cve2013-0156": "vulns",
    "http-vuln-cve2013-6786": "vulns",
    "http-vuln-cve2013-7091": "vulns",
    "http-vuln-cve2014-2126": "vulns",
    "http-vuln-cve2014-2127": "vulns",
    "http-vuln-cve2014-2128": "vulns",
    "http-vuln-cve2014-2129": "vulns",
    "http-vuln-cve2014-3704": "vulns",
    "http-vuln-cve2014-8877": "vulns",
    "http-vuln-cve2015-1427": "vulns",
    "http-vuln-cve2015-1635": "vulns",
    "http-vuln-cve2017-1001000": "vulns",
    "http-vuln-cve2017-5638": "vulns",
    "http-vuln-cve2017-5689": "vulns",
    "http-vuln-cve2017-8917": "vulns",
    "http-vuln-misfortune-cookie": "vulns",
    "http-vuln-wnr1000-creds": "vulns",
    "ipmi-cipher-zero": "vulns",
    "mysql-vuln-cve2012-2122": "vulns",
    "qconn-exec": "vulns",
    "rdp-vuln-ms12-020": "vulns",
    "realvnc-auth-bypass": "vulns",
    "rmi-vuln-classloader": "vulns",
    "rsa-vuln-roca": "vulns",
    "samba-vuln-cve-2012-1182": "vulns",
    "smb2-vuln-uptime": "vulns",
    "smb-double-pulsar-backdoor": "vulns",
    "smb-vuln-conficker": "vulns",
    "smb-vuln-cve2009-3103": "vulns",
    "smb-vuln-cve-2017-7494": "vulns",
    "smb-vuln-ms06-025": "vulns",
    "smb-vuln-ms07-029": "vulns",
    "smb-vuln-ms08-067": "vulns",
    "smb-vuln-ms10-054": "vulns",
    "smb-vuln-ms10-061": "vulns",
    "smb-vuln-ms17-010": "vulns",
    "smb-vuln-regsvc-dos": "vulns",
    "smb-vuln-webexec": "vulns",
    "smtp-vuln-cve2011-1720": "vulns",
    "smtp-vuln-cve2011-1764": "vulns",
    "ssl-ccs-injection": "vulns",
    "ssl-dh-params": "vulns",
    "ssl-heartbleed": "vulns",
    "ssl-poodle": "vulns",
    "sslv2-drown": "vulns",
    "supermicro-ipmi-conf": "vulns",
    "tls-ticketbleed": "vulns",
    # ntlm unified output (*-ntlm-info modules)
    #   ls *ntlm* | sed 's#^#    "#;s#.nse$#": "ntlm-info",#'
    "http-ntlm-info": "ntlm-info",
    "imap-ntlm-info": "ntlm-info",
    "ms-sql-ntlm-info": "ntlm-info",
    "nntp-ntlm-info": "ntlm-info",
    "pop3-ntlm-info": "ntlm-info",
    "rdp-ntlm-info": "ntlm-info",
    "smtp-ntlm-info": "ntlm-info",
    "telnet-ntlm-info": "ntlm-info",
}


def create_ssl_output(info):
    out = []
    for key, name in [('subject_text', 'Subject'),
                      ('issuer_text', 'Issuer')]:
        try:
            out.append('%s: %s' % (name, info[key]))
        except KeyError:
            pass
    try:
        pubkey = info['pubkey']
    except KeyError:
        pass
    else:
        try:
            out.append('Public Key type: %s' % pubkey['type'])
        except KeyError:
            pass
        try:
            out.append('Public Key bits: %d' % pubkey['bits'])
        except KeyError:
            pass
    for key, name in [('not_before', 'Not valid before: '),
                      ('not_after', 'Not valid after:  ')]:
        try:
            out.append('%s%s' % (name, info[key]))
        except KeyError:
            pass
    for san in info.get('san', []):
        out.append('Subject Alternative Name: %s' % san)
    for key, name in [('md5', 'MD5:'), ('sha1', 'SHA-1:'),
                      ('sha256', 'SHA-256:')]:
        # NB: SHA-256 is not (yet) reported by Nmap, but it might help.
        try:
            out.append('%-7s%s' % (name, ' '.join(wrap(info[key], 4))))
        except KeyError:
            pass
    try:
        out.append(info['pem'])
    except KeyError:
        pass
    return out


def is_real_service_port(port):
    """Decides whether a port has a "real" service (=> True) or if it is
**possibly** a SYN-ACK "honeypot" (=> False).

The idea is that a port is "real" if it has a reason that is not
"syn-ack" (or similar), or if it has a service_name, or if it has a
least one script.

Host scripts (port == -1) are also considered True.

    """
    if port.get('port') == -1:
        return True
    if port.get('reason') and not (
            # might be "syn-ack" but might as
            # well be "syn-ack-cwr" or
            # "syn-psh-ack"
            port['reason'].startswith('syn-') or
            port['reason'] == 'passive'
    ):
        return True
    if port.get('service_name'):
        return True
    if port.get('scripts'):
        return True
    return False


def set_openports_attribute(host):
    """This function sets the "openports" value in the `host` record,
based on the elements of the "ports" list. This is used in MongoDB to
speed up queries based on open ports.

    """
    openports = host['openports'] = {'count': 0}
    for port in host.get('ports', []):
        if port.get('state_state') != 'open':
            continue
        cur = openports.setdefault(port['protocol'], {'count': 0, 'ports': []})
        if port['port'] not in cur['ports']:
            openports['count'] += 1
            cur['count'] += 1
            cur['ports'].append(port['port'])


def cleanup_synack_honeypot_host(host, update_openports=True):
    """This function will clean the `host` record if it has too many (at
least `VIEW_SYNACK_HONEYPOT_COUNT`) open ports that may be "syn-ack"
honeypots (which means, ports for which is_real_service_port() returns
False).

    """
    if VIEW_SYNACK_HONEYPOT_COUNT is None:
        return
    n_ports = len(host.get("ports", []))
    if n_ports < VIEW_SYNACK_HONEYPOT_COUNT:
        return
    # check if we have too many open ports that could be "syn-ack
    # honeypots"...
    newports = [port for port in host['ports'] if is_real_service_port(port)]
    if n_ports - len(newports) > VIEW_SYNACK_HONEYPOT_COUNT:
        # ... if so, keep only the ports that cannot be "syn-ack
        # honeypots"
        host['ports'] = newports
        host["synack_honeypot"] = True
        if update_openports:
            set_openports_attribute(host)


def merge_ja3_scripts(curscript, script, script_id):

    def is_server(script_id):
        return script_id == 'ssl-ja3-server'

    def ja3_equals(a, b, script_id):
        return (a['raw'] == b['raw'] and
                (not is_server(script_id) or
                 a['client']['raw'] == b['client']['raw']))

    def ja3_output(ja3, script_id):
        output = ja3['md5']
        if is_server(script_id):
            output += ' - ' + ja3['client']['md5']
        return output

    return _merge_scripts(curscript, script, script_id, ja3_equals, ja3_output)


def merge_http_app_scripts(curscript, script, script_id):

    def http_app_equals(a, b, script_id):
        return (a['application'] == b['application'] and
                a['path'] == b['path'])

    def http_app_output(app, script_id):
        return '%s: path %s%s' % (
            app['application'],
            app['path'],
            (
                '' if app.get('version') is None else
                (', version %s' % app['version'])
            ),
        )

    return _merge_scripts(curscript, script, script_id, http_app_equals,
                          http_app_output)


def merge_ua_scripts(curscript, script, script_id):

    def ua_equals(a, b, script_id):
        return a == b

    def ua_output(ua, script_id):
        return ua

    return _merge_scripts(curscript, script, script_id, ua_equals, ua_output)


def merge_ssl_cert_scripts(curscript, script, script_id):

    def cert_equals(a, b, script_id):
        return a['sha256'] == b['sha256']

    def cert_output(cert, script_id):
        return '\n'.join(create_ssl_output(cert))

    return _merge_scripts(
        curscript, script, script_id, cert_equals, cert_output,
        outsep="\n------------------------------------------------------------"
        "----\n"
    )


def merge_axfr_scripts(curscript, script, script_id):
    # If one results has no structured output, keep the other
    # one. Prefer curscript over script.
    if script_id not in script:
        return curscript
    if script_id not in curscript:
        curscript['output'] = script['output']
        curscript[script_id] = script[script_id]
        return script
    res = []
    for data in chain(curscript[script_id], script[script_id]):
        if any(data['domain'] == r['domain'] for r in res):
            continue
        res.append(data)
    res = sorted(res, key=lambda r: tuple(reversed(r['domain'].split('.'))))
    line_fmt = "| %%-%ds  %%-%ds  %%s" % (
        max(len(r['name']) for data in res for r in data['records']),
        max(len(r['type']) for data in res for r in data['records']),
    )
    curscript['output'] = "\n".join(
        "\nDomain: %s\n%s\n\\\n" % (
            data['domain'],
            "\n".join(line_fmt % (r['name'], r['type'], r['data'])
                      for r in data['records'])
        )
        for data in res
    )
    curscript[script_id] = res
    return curscript


def _merge_scripts(curscript, script, script_id, script_equals, script_output,
                   outsep="\n"):
    """Helper function to merge two scripts and return the result, using
specific functions `script_equals` and `script_output`.

    """
    to_merge_list = []
    script_id_alias = ALIASES_TABLE_ELEMS.get(script_id, script_id)
    for to_add in script.setdefault(script_id_alias, []):
        to_merge = True
        for cur in curscript.get(script_id_alias, []):
            if script_equals(to_add, cur, script_id):
                to_merge = False
                break
        if to_merge:
            to_merge_list.append(to_add)
    curscript.setdefault(script_id_alias, []).extend(to_merge_list)
    # Compute output from curscript[script_id_alias]
    output = []
    for el in curscript[script_id_alias]:
        output.append(script_output(el, script_id))
    if output:
        curscript['output'] = outsep.join(output) + '\n'
    else:
        curscript['output'] = ''
    return curscript


def merge_scripts(curscript, script, script_id):
    """Merge curscript with script"""
    if script_id.startswith('ssl-ja3-'):
        return merge_ja3_scripts(curscript, script, script_id)
    if script_id == 'http-app':
        return merge_http_app_scripts(curscript, script, script_id)
    if script_id == 'http-user-agent':
        return merge_ua_scripts(curscript, script, script_id)
    if script_id == 'dns-zone-transfer':
        return merge_axfr_scripts(curscript, script, script_id)
    if script_id in {'ssl-cert', 'ssl-cacert'}:
        return merge_ssl_cert_scripts(curscript, script, script_id)
    return {}


def merge_host_docs(rec1, rec2):
    """Merge two host records and return the result. Unmergeable /
    hard-to-merge fields are lost (e.g., extraports).

    """
    if rec1.get("schema_version") != rec2.get("schema_version"):
        raise ValueError("Cannot merge host documents. "
                         "Schema versions differ (%r != %r)" % (
                             rec1.get("schema_version"),
                             rec2.get("schema_version")))
    rec = {}
    if "schema_version" in rec1:
        rec["schema_version"] = rec1["schema_version"]
    # When we have different values, we will use the one from the
    # most recent scan, rec2. If one result has no "endtime", we
    # consider it as older.
    if (
            (rec1.get("endtime") or datetime.fromtimestamp(0)) >
            (rec2.get("endtime") or datetime.fromtimestamp(0))
    ):
        rec1, rec2 = rec2, rec1
    for fname, function in [("starttime", min), ("endtime", max)]:
        try:
            rec[fname] = function(record[fname] for record in [rec1, rec2]
                                  if fname in record)
        except ValueError:
            pass
    sa_honeypot = rec1.get("synack_honeypot") or rec2.get("synack_honeypot")
    rec["state"] = "up" if rec1.get("state") == "up" else rec2.get("state")
    if rec["state"] is None:
        del rec["state"]
    rec["categories"] = list(
        set(rec1.get("categories", [])).union(
            rec2.get("categories", []))
    )
    for field in ["addr", "os"]:
        rec[field] = rec2[field] if rec2.get(field) else rec1.get(field)
        if not rec[field]:
            del rec[field]
    rec['source'] = list(set(rec1.get('source', []))
                         .union(set(rec2.get('source', []))))
    rec["traces"] = rec2.get("traces", [])
    for trace in rec1.get("traces", []):
        # Skip this result (from rec1) if a more recent traceroute
        # result exists using the same protocol and port in the
        # most recent scan (rec2).
        if any(other['protocol'] == trace['protocol'] and
               other.get('port') == trace.get('port')
               for other in rec['traces']):
            continue
        rec["traces"].append(trace)
    rec["cpes"] = rec2.get("cpes", [])
    for cpe in rec1.get("cpes", []):
        origins = set(cpe.pop("origins", []))
        cpe["origins"] = None
        try:
            other = next(
                ocpe for ocpe in rec["cpes"] if dict(ocpe, origins=None) == cpe
            )
        except StopIteration:
            rec["cpes"].append(dict(cpe, origins=origins))
        else:
            other["origins"] = set(other.get("origins", [])).union(origins)
    for cpe in rec["cpes"]:
        cpe["origins"] = list(cpe.get("origins", []))
    rec["infos"] = {}
    for record in [rec1, rec2]:
        rec["infos"].update(record.get("infos", {}))
    # We want to make sure of (type, name) unicity
    hostnames = dict(((h['type'], h['name']), h.get('domains'))
                     for h in (rec1.get("hostnames", []) +
                               rec2.get("hostnames", [])))
    rec["hostnames"] = [{"type": h[0], "name": h[1], "domains": d}
                        for h, d in viewitems(hostnames)]
    addresses = rec1.get('addresses', {})
    for atype, addrs in viewitems(rec2.get('addresses', {})):
        cur_addrs = addresses.setdefault(atype, [])
        for addr in addrs:
            if addr not in cur_addrs:
                cur_addrs.append(addr)
    if addresses:
        rec["addresses"] = addresses
    sa_honeypot_check = False
    if sa_honeypot:
        rec['synack_honeypot'] = True
        for record in [rec1, rec2]:
            if not record.get('synack_honeypot'):
                sa_honeypot_check = True
                record['ports'] = [
                    port for port in record.get('ports', [])
                    if is_real_service_port(port)
                ]
    ports = dict(((port.get("protocol"), port["port"]), port.copy())
                 for port in rec2.get("ports", []))
    for port in rec1.get("ports", []):
        if (port.get('protocol'), port['port']) in ports:
            curport = ports[(port.get('protocol'), port['port'])]
            if 'scripts' in curport:
                curport['scripts'] = curport['scripts'][:]
            else:
                curport['scripts'] = []
            present_scripts = set(
                script['id'] for script in curport['scripts']
            )
            for script in port.get("scripts", []):
                if script['id'] not in present_scripts:
                    curport['scripts'].append(script)
                elif (script['id'] in {
                        'ssl-ja3-server', 'ssl-ja3-client',
                        'http-app', 'http-user-agent',
                        'ssl-cacert', 'ssl-cert',
                        'dns-zone-transfer',
                }):
                    # Merge scripts
                    curscript = next(x for x in curport['scripts']
                                     if x['id'] == script['id'])
                    merge_scripts(curscript, script, script['id'])
            if not curport['scripts']:
                del curport['scripts']
            if 'service_name' in port:
                if 'service_name' not in curport:
                    for key in port:
                        if key.startswith("service_"):
                            curport[key] = port[key]
                elif port['service_name'] == curport['service_name']:
                    # if the "old" record has information missing
                    # from the "new" record and information from
                    # both records is consistent, let's keep the
                    # "old" data.
                    for key in port:
                        if (
                                key.startswith("service_") and
                                key not in curport
                        ):
                            curport[key] = port[key]
            if 'screenshot' in port and 'screenshot' not in curport:
                for key in ['screenshot', 'screendata', 'screenwords']:
                    if key in port:
                        curport[key] = port[key]
        else:
            ports[(port.get('protocol'), port['port'])] = port
    if sa_honeypot and sa_honeypot_check:
        rec["ports"] = sorted(
            (port for port in viewvalues(ports) if is_real_service_port(port)),
            key=lambda port: (
                port.get('protocol') or '~', port.get('port'),
            )
        )
    else:
        rec["ports"] = sorted(viewvalues(ports), key=lambda port: (
            port.get('protocol') or '~', port.get('port'),
        ))
    if not sa_honeypot:
        cleanup_synack_honeypot_host(rec, update_openports=False)
    set_openports_attribute(rec)
    for field in ["traces", "infos", "ports", "cpes"]:
        if not rec[field]:
            del rec[field]
    return rec


def handle_http_headers(host, port, headers, path='/', handle_server=True):
    """This function enriches scan results based on HTTP headers reported
by the Nmap script http-headers or any similar report, such as
Masscan or Zgrab(2).

    """
    # 1. add a script "http-server-header" if it does not exist
    if handle_server:
        srv_headers = [nmap_decode_data(h['value']) for h in headers
                       if h['name'] == 'server' and h['value']]
        if srv_headers and not any(s['id'] == 'http-server-header'
                                   for s in port.get('scripts', [])):
            port.setdefault('scripts', []).append({
                "id": "http-server-header",
                "output": '\n'.join(nmap_encode_data(hdr)
                                    for hdr in srv_headers),
                "http-server-header": [nmap_encode_data(hdr)
                                       for hdr in srv_headers],
            })
    # 2. add a script "http-app" for MS SharePoint, and merge it if
    # necessary
    try:
        header = next(
            nmap_decode_data(h['value']) for h in headers
            if h['name'] == 'microsoftsharepointteamservices' and h['value']
        )
    except StopIteration:
        pass
    else:
        version = nmap_encode_data(header.split(b':', 1)[0])
        add_cpe_values(host, 'ports.port:%s' % port.get('port', -1),
                       ["cpe:/a:microsoft:sharepoint_server:%s" % version])
        script = {
            'id': 'http-app',
            'output': 'SharePoint: path %s, version %s' % (path, version),
            'http-app': [{'path': path,
                          'application': 'SharePoint',
                          'version': version}],
        }
        try:
            cur_script = next(s for s in port.get('scripts', [])
                              if s['id'] == 'http-app')
        except StopIteration:
            port.setdefault('scripts', []).append(script)
        else:
            merge_http_app_scripts(cur_script, script, 'http-app')
