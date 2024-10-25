#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2024 Pierre LALET <pierre@droids-corp.org>
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

"""This submodule contains data needed for Nmap results manipulation.

"""


ALIASES_TABLE_ELEMS = {
    # Use the same structured output for both ssl-cert and ssl-cacert
    "ssl-cacert": "ssl-cert",
    # Use the same structured output for all the Nuclei scripts
    "dns-nuclei": "nuclei",
    "http-nuclei": "nuclei",
    "network-nuclei": "nuclei",
    "ssl-nuclei": "nuclei",
    "tcp-nuclei": "nuclei",
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
    "smb-double-pulsar-backdoor": "vulns",
    "smb-vuln-conficker": "vulns",
    "smb-vuln-cve-2017-7494": "vulns",
    "smb-vuln-cve2009-3103": "vulns",
    "smb-vuln-ms06-025": "vulns",
    "smb-vuln-ms07-029": "vulns",
    "smb-vuln-ms08-067": "vulns",
    "smb-vuln-ms10-054": "vulns",
    "smb-vuln-ms10-061": "vulns",
    "smb-vuln-ms17-010": "vulns",
    "smb-vuln-regsvc-dos": "vulns",
    "smb-vuln-webexec": "vulns",
    "smb2-vuln-uptime": "vulns",
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
