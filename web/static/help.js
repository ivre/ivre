/*
 * This file is part of IVRE.
 * Copyright 2011 - 2014 Pierre LALET <pierre.lalet@cea.fr>
 *
 * IVRE is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * IVRE is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with IVRE. If not, see <http://www.gnu.org/licenses/>.
 */

var HELP = {
    /* filters */
    "archives": {
	"title": "<b>(!)</b>archives",
	"content": "Look for archived results. <code>!archives</code> has no effect, since it is the default behavior.",
    },
    "host:": {
	"title": "<b>(!)[IP address]</b> or <b>(!)</b>host:<b>[IP address]</b>",
	"content": "Look for results for one specific IP address.",
    },
    "net:": {
	"title": "<b>(!)[IP address / netmask]</b> or <b>(!)</b>net:<b>[IP address / netmask]</b>",
	"content": "Look for results within a specific network (CIDR notation).",
    },
    "range:": {
	"title": "<b>(!)</b>range:<b>[IP address]-[IP address]</b>",
	"content": "Look for results within a specific IP range.",
    },
    "hostname:": {
	"title": "<b>(!)</b>hostname:<b>[FQDN]</b>",
	"content": "Look for results with a matching hostname ([FQDN] can be specified as a string or a regexp).",
    },
    "domain:": {
	"title": "<b>(!)</b>domain:<b>[FQDN]</b>",
	"content": "Look for results with a hostname within a matching domain name ([FQDN] can be specified as a string or a regexp).",
    },
    "category:": {
	"title": "<b>(!)</b>category:<b>[string or regexp]</b>",
	"content": "Look for results tagged with a matching category.",
    },
    "country:": {
	"title": "<b>(!)</b>country:<b>[two letters code]</b>",
	"content": "Look for hosts located in a specific country.",
    },
    "city:": {
	"title": "<b>(!)</b>city:<b>[string or regexp]</b>",
	"content": "Look for hosts located in a specific city. <b>Use with a <code>country:</code> filter</b>.",
    },
    "asnum:": {
	"title": "<b>(!)</b>asnum:<b>[number(,number(,...))]</b>",
	"content": "Look for hosts assigned to a specific AS given its number. Coma-separated multiple values can be used. See also <code>asname:</code>.",
    },
    "asname:": {
	"title": "<b>(!)</b>asname:<b>[string or regexp]</b>",
	"content": "Look for hosts assigned to a specific AS given its name. See also <code>asnum:</code>.",
    },
    "source:": {
	"title": "<b>(!)</b>source:<b>[name]</b>",
	"content": "Look for results obtained from a specific source.",
    },
    "timerange:": {
	"title": "<b>(!)</b>timerange:<b>[timestamp]-[timestamp]</b>",
	"content": "Look for results within a specific time range.",
    },
    "timeago:": {
	"title": "<b>(!)</b>timeago:<b>[time]</b>",
	"content": "Look for results more recent than the specified value. Time can be specified in seconds (the default), minutes (add <b>m</b>), hours (add <b>h</b>), days (add <b>d</b>), or years (add <b>y</b>).",
    },
    "service:": {
	"title": "service:<b>[service name](:[port number])</b>",
	"content": "Look for a particular service, optionally on the specified port. [service name] can be either a string or a regular expression.<br>See also <code>probedservice:</code>.",
    },
    "probedservice:": {
	"title": "probedservice:<b>[service name](:[port number])</b>",
	"content": "Look for a particular service, discovered with a service probe, optionally on the specified port. [service name] can be either a string or a regular expression.",
    },
    "product:": {
	"title": "product:<b>[service name]:[product name](:[port number])</b>",
	"content": "Look for a particular service and product, optionally on the specified port. [service name] and [product name] can be either strings or regular expressions.",
    },
    "version:": {
	"title": "version:<b>[service name]:[product name]:[version](:[port number])</b>",
	"content": "Look for a particular service, product and version, optionally on the specified port. [service name], [product name] and [version] can be either strings or regular expressions.",
    },
    "script:": {
	"title": "script:<b>[script id](:[script output])</b> or portscript:<b>[script id](:[script output])</b>",
	"content": "Look for a port script, given its id, and optionally for a specific output. Both [script id] and [script output] can be either strings or regular expressions.",
    },
    "hostscript:": {
	"title": "hostscript:<b>[script id](:[script output])</b>",
	"content": "Look for a host script, given its id, and optionally for a specific output. Both [script id] and [script output] can be either strings or regular expressions.",
    },
    /* results of scripts or version scans */
    "anonftp": {
	"title": "anonftp",
	"content": "Look for FTP servers allowing anonymous access.",
    },
    "anonldap": {
	"title": "anonldap",
	"content": "Look for LDAP servers with anonymous bind working.",
    },
    "authbypassvnc": {
	"title": "authbypassvnc",
	"content": "Look for VNC servers with authentication that can be bypassed.",
    },
    "authhttp": {
	"title": "authhttp",
	"content": "Look for HTTP servers requiring authentication with default credentials working (the Nmap script seems to get a lot of false positives).",
    },
    "banner:": {
	"title": "banner:<b>[string or regexp]</b>",
	"content": "Look for content in service banners (as discovered by Nmap script &quot;banner&quot;).",
    },
    "cookie:": {
	"title": "cookie:<b>[name]</b>",
	"content": "Look for HTTP servers setting a specific cookie.",
    },
    "file:": {
	"title": "file:<b>[pattern or regexp]</b>",
	"content": "Look for a pattern in the shared files (FTP, SMB, ...).",
    },
    "geovision": {
	"title": "geovision",
	"content": "Look for Geovision webcams (see also <code>devtype:webcam</code>).",
    },
    "httptitle:": {
	"title": "httptitle:<b>[string or regexp]</b>",
	"content": "Look for results with a specific title on the root page of an HTTP server.",
    },
    "nfs": {
	"title": "nfs",
	"content": "Look for NFS servers",
    },
    "nis": {
	"title": "<b>nis</b> or <b>yp</b>",
	"content": "Look for NIS (YP) servers",
    },
    "mssqlemptypwd": {
	"title": "mssqlemptypwd",
	"content": "Look for MS-SQL servers with an empty password for the <code>sa</code> account.",
    },
    "mysqlemptypwd": {
	"title": "mysqlemptypwd",
	"content": "Look for MySQL servers with an empty password for the <code>root</code> account.",
    },
    "owa": {
	"title": "owa",
	"content": "Look for OWA (Outlook Web App) servers.",
    },
    "phpmyadmin": {
	"title": "phpmyadmin",
	"content": "Look for PHPMyAdmin servers.",
    },
    "smb.dnsdomain:": {
	"title": "smb.dnsdomain:[FQDN]",
	"content": "Search results with SMB service in a specific DNS domain.",
    },
    "smb.domain:": {
	"title": "smb.domain:[NetBIOS]",
	"content": "Search results with SMB service in a specific NetBIOS domain.",
    },
    "smb.fqdn:": {
	"title": "smb.fqdn:[NetBIOS]",
	"content": "Search results with SMB service in a specific host name (FQDN).",
    },
    "smb.forest:": {
	"title": "smb.forest:[FQDN]",
	"content": "Search results with SMB service in a specific forest (DNS name).",
    },
    "smb.lanmanager:": {
	"title": "smb.lanmanager:[LAN Manager]",
	"content": "Search results with SMB service with a specific LAN Manager.",
    },
    "smb.os:": {
	"title": "smb.os:[OS]",
	"content": "Search results with SMB service with a specific OS.",
    },
    "smb.server:": {
	"title": "smb.server:[NetBIOS]",
	"content": "Search results with SMB service in a specific host name (NetBIOS).",
    },
    "smb.workgroup:": {
	"title": "smb.workgroup:[NetBIOS]",
	"content": "Search results with SMB service in a specific workgroup (NetBIOS).",
    },
    "smbshare": {
	"title": "smbshare<b>(:[access mode])</b>",
	"content": "Search results with SMB shares with anonymous access. Access can be 'r', 'w' or 'rw' (default is read or write).",
    },
    "sshkey:": {
	"title": "sshkey:<b>[fingerprint or base64]</b>",
	"content": "Look for a particular SSH key, given (part of) its fingerprint or base64 encoded key.",
    },
    "torcert": {
	"title": "torcert",
	"content": "Look for Tor certificates.",
    },
    "webfiles": {
	"title": "webfiles",
	"content": "Look for &quot;typical&quot; Web files. See also <code>file:</code>.",
    },
    "webmin": {
	"title": "webmin",
	"content": "Look for Webmin servers.",
    },
    "x11open": {
	"title": "x11open",
	"content": "Look for open X11 servers.",
    },
    "x11srv": {
	"title": "x11",
	"content": "Look for X11 servers. See also <code>x11open</code>.",
    },
    "xp445": {
	"title": "xp445",
	"content": "Look for Windows XP machines with TCP/445 port open.",
    },
    /* OS fingerprint */
    "os:": {
	"title": "os:<b>[string or regexp]</b>",
	"content": "Look for a specific OS, according to Nmap's fingerprint.",
    },
    /* device types */
    "devtype:": {
	"title": "<b>devtype:</b> or <b>devicetype:[string or regexp]</b>",
	"content": "Look for a specific device type. See also <code>netdev</code>, <code>phonedev</code> and <code>geovision</code>.",
    },
    "netdev": {
	"title": "netdev",
	"content": "Look for network devices (e.g., bridges, routers, firewalls, etc.).",
    },
    "phonedev": {
	"title": "phonedev",
	"content": "Look for phone devices (e.g., PBX, VoIP devices, phones, etc.).",
    },
    /* traceroute */
    "hop:": {
	"title": "<b>(!)</b>hop:<b>[IP address]</b>",
	"content": "Look for results with the specified IP address in the Traceroute result.",
    },
    "hopname:": {
	"title": "<b>(!)</b>hopname:<b>[FQDN]</b>",
	"content": "Look for results with a matching hostname in the Traceroute result ([FQDN] can be specified as a string or a regexp).",
    },
    "hopdomain:": {
	"title": "<b>(!)</b>hopdomain:<b>[FQDN]</b>",
	"content": "Look for results with a hostname within a matching domain name in the Traceroute result ([FQDN] can be specified as a string or a regexp).",
    },
    "tcp/": {
	"title": "<b>(!)[port number](,[port number](,...))</b> or <b>(!)</b>tcp/<b>[port number]</b>",
	"content": "Look for results with the specified TCP port(s) open.",
    },
    "udp/": {
	"title": "<b>(!)</b>udp/<b>[port number]</b>",
	"content": "Look for results with the specified UDP port open.",
    },
    "openport": {
	"title": "<b>(!)</b>openport",
	"content": "Look for hosts with at least one open port.",
    },
    "otheropenport:": {
	"title": "otheropenport:<b>[port number](,[port number](,...))</b>",
	"content": "Look for hosts with at least one open port other than those listed.",
    },
    "screenshot": {
	"title": "<b>(!)</b>screenshot<b>(:[port number])</b>",
	"content": "Search results with at least one screenshot.",
    },
    "notes": {
	"title": "notes",
	"content": "Search results with an associated note.",
    },
    /* sort */
    "skip:": {
	"title": "skip:<b>[count]</b>",
	"content": "Skip [count] results.",
    },
    "limit:": {
	"title": "limit:<b>[count]</b>",
	"content": "Only display [count] results.",
    },
    "sortby:": {
	"title": "<b>(!)</b>sortby:<b>[field name]</b>",
	"content": "Sort according to values for [field name]. Be careful with this setting as consequences on the performances can be terrible when using non-indexed fields.",
    },
    /* display */
    "display:host": {
	"title": "display:host",
	"content": "Set the default display mode.",
    },
    "display:script:": {
	"title": "display:script:<b>[script id]</b>",
	"content": "Display only a particular script output.",
    },
    "display:screenshot": {
	"title": "display:screenshot",
	"content": "Display only screenshots.",
    },
};

/* aliases */
HELP['portscript:'] = HELP['script:'];
HELP['yp'] = HELP['nis'];
HELP['devicetype:'] = HELP['devtype:'];
HELP['networkdevice'] = HELP['netdev'];

/* negation */
for(var key in HELP) {
    if(HELP[key].title.substr(0, 10) === '<b>(!)</b>') {
	HELP["!" + key] = HELP[key];
	HELP["-" + key] = HELP[key];
    }
}
