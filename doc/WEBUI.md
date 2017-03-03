# Introduction #

[IVRE](README.md) (Instrument de veille sur les réseaux extérieurs) or
DRUNK (Dynamic Recon of UNKnown networks) is a network recon
framework, including tools for passive recon (flow analytics relying
on [Bro](https://www.bro.org/), [Argus](http://qosient.com/argus/),
[Nfdump](http://nfdump.sourceforge.net/), fingerprint analytics based
on Bro and [p0f](http://lcamtuf.coredump.cx/p0f/) and active recon
(IVRE uses [Nmap](http://nmap.org/) to run scans, can use
[ZMap](https://zmap.io/) as a pre-scanner; IVRE can also import XML
output from Nmap and
[Masscan](https://github.com/robertdavidgraham/masscan)).

This web interface presents results of (Nmap) active scans that can be
filtered with keywords (and, for some of them, shortcuts are available
in the menus).

Keep in mind that the information available in this interface highly
depends on the options used to run Nmap.

# The interface #

## The top navigation bar ##

It contains several elements; from left to right:

  - A shortcut to the start page, that cleans every keyword.
  - A button to display this help page.
  - Some menus with shortcuts to add filtering, sort or display
    commands.
  - Some links to "share" (export) the current page.

## The left side bar ##

The first part allows to navigate within the results. Be careful with
the last button that goes to the last result page, as it can be very
slow when a lot of results are available.

The progress bar shows where the currently displayed results are
within the whole results set.

The second part allows to add, modify or remove filter, sort or
display commands.

The third part allows to explore the results by generating graphs
displayed in the rightmost part of the screen.

  - The first field displays a graph with the 15 most common values of
    a variable in the filtered results. This can be slow when the
    number of results to scan is important. Here is a list of
    (sometimes) interesting values to try here:
    - `category`, `source`
    - `country`, `city`, `as`
    - `domains`, `domains:[level]`
    - `hop`, `hop:[number]`
    - `port`, `port:[open/closed/filtered]`, `port:[service]`
      `portlist:[open/closed/filtered]`
    - `service`, `service:[port]`, `product`, `product:[port]`,
      `version`, `version:[port]`
    - `cpe`, `cpe.[type/vendor/product/version]`, `cpe:[cpe spec]`,
      `cpe.[type/vendor/product/version]:[cpe spec]` (examples:
      `cpe.product:a:microsoft` will show top product names in CPEs
      from vendor `microsoft`, `cpe.vendor:o:/^m/` will show top
      vendor names in CPEs that start with an `m`)
    - `devicetype`, `devicetype:[port]`
    - `script`
    - `script:[scriptname]`
    - `file` (or `file.filename`), `file.time`, `file.size`,
      `file.uid`, `file.gid`, `file.permission`
    - `smb.os`, `smb.lanmanager`, `smb.domain`, `smb.dnsdomain`,
      `smb.forest`, `smb.workgroup`
    - `cert.issuer`, `cert.subject`
    - `modbus.deviceid`, `enip.vendor`, `enip.product`, `enip.serial`,
      `enip.devtype`, `enip.prodcode`, `enip.rev`, `enip.ip`
  - The *Address space* button displays a graphical representation of
    the filtered addresses. The abscissa axis represents the two high
    bytes (or the three when the results belong to the same /16
    network), and the ordinate axis represents the two low bytes (or
    the low byte).
  - The *Map* button displays the locations of the results on a world
    map.
  - The *Timeline* and *Timeline 24h* buttons display time-lines where
    the abscissa axis represents the time and the ordinate axis
    represents the IP addresses.

## Scan results ##

Ten results (maximum) are displayed per page by default.

Each result has its own frame. In the default display mode, it
displays a summary for the host. Long-clicking a result frame toggles
between the summary display and the full display for the result.

The pencil icon in the upper-right corner opens the notepad page for
the current host (see below) in the rightmost part of the screen.

Each blue element in the results can be clicked to add a filter.

# Available commands #

## Command specification ##

The commands might require a parameter, provided after the colon sign
`:`. Some commands can be used negatively, by prefixing them with `!`
or `-`.

The commands can be entered in the input boxes in the second part of
the left side bar or added by clicking on a shortcut in the top bar
menus.

In the following list, a `[!]` before the command shows it can be used
negatively, and a `:` after the command indicates it requires a
parameter.

When a parameter is required the full value must be specified, or when
appropriate, a regular expression can be used, with the
`/[expression]/[flags]` syntax (e.g.:
`script:smb-enum-shares:/WRITE/`).

If your command includes spaces, you need to protect it by using
single or double quotes.

## Commands list ##

### Filters ###

  - `[!]archives` show results from the archives database (and
    `!archives` has no effect since it is the default behavior).
  - `[!]host:[IP address]` filter a specific IP address. Using the IP
    address directly (without `host:`) is equivalent.
  - `[!]net:[IP address/netmask]` filter a specific network (CIDR
    notation). Using the CIDR notation directly (without `net:`) is
    equivalent.
  - `[!]range:[IP address]-[IP address]` filter a specific IP address
    range
  - `[!]hostname:[FQDN]` look for results with a matching hostname.
  - `[!]domain:[FQDN]` look for results with a hostname within a
    matching domain name.
  - `[!]category:` filter a category.
  - `[!]country:[two letters code]` filter a country.
  - `[!]city:` filter a city (use with `country:`).
  - `[!]asnum:` filter by AS number (lists allowed).
  - `[!]asname:` filter by AS name (regular expressions allowed).
  - `[!]source:` filter a source (specify the source name).
  - `[!]timerange:[timestamp]-[timestamp]` filter results within a
    specific time range.
  - `[!]timeago:` filter recent enough results; the value can be
    specified in seconds or with the appropriate suffix in minutes
    (`m`), hours (`h`), days (`d`) or years (`y`).
  - `service:[expression]`, `service:[expression]:[port number]` look
    for an expression in the name of a service.
  - `product:[service]:[product]`,
    `product:[service]:[product]:[port number]` look for a product.
  - `version:[service]:[product]:[version]`,
    `product:[service]:[product]:[version]:[port number]` look for a
    specific version of a product.
  - `script:[scriptid]`, `script:[scriptid]:[output]` look for a
    specific script.
  - `anonftp` filter results with anonymous FTP allowed.
  - `anonldap` look for LDAP servers with anonymous bind working.
  - `authbypassvnc` look for VNC servers with authentication that can
    be bypassed.
  - `authhttp` look for HTTP servers with authentication and a default
    (e.g., `admin`/`admin`) login/password working. The Nmap script
    seems to get a lot a false positives.
  - `banner:` look for a specific banner of a service.
  - `cookie:` look for HTTP servers setting a specific cookie.
  - `file`, `file:[pattern]`, `file:[scriptid]:[pattern]`,
    `file:[scriptid],[scriptid],...:[pattern]` look for a pattern in
    the shared files (FTP, SMB, ...).
  - `geovision` look for GeoVision web-cams.
  - `httptitle:` look for a specific HTML title value of the homepage
    of a web site.
  - `nfs` look for NFS servers.
  - `nis`, `yp` look for NIS servers.
  - `mssqlemptypwd` look for MS-SQL servers with an empty password for
    the `sa` account.
  - `mysqlemptypwd` look for MySQL servers with an empty password for
    the `root` account.
  - `owa` look for OWA (Outlook Web App) servers.
  - `phpmyadmin` look for phpMyAdmin servers.
  - `smb.dnsdomain:[FQDN]` search results with SMB service in a
    specific DNS domain.
  - `smb.domain:[NetBIOS]` search results with SMB service in a
    specific NetBIOS domain.
  - `smb.fqdn:[NetBIOS]` search results with SMB service in a specific
    host name (FQDN).
  - `smb.forest:[FQDN]` search results with SMB service in a specific
    forest (DNS name).
  - `smb.lanmanager:[LAN Manager]` search results with SMB service with a specific LAN Manager.
  - `smb.os:[OS]` search results with SMB service with a specific OS.
  - `smb.server:[NetBIOS]` search results with SMB service in a
    specific host name (NetBIOS).
  - `smb.workgroup:[NetBIOS]` search results with SMB service in a
    specific workgroup (NetBIOS).
  - `smbshare`, `smbshare:[access mode]` search results with SMB
    shares with anonymous access. Access can be 'r', 'w' or 'rw'
    (default is read or write).
  - `sshkey:` look for a particular SSH key.
  - `torcert` look for Tor certificates.
  - `webfiles` look for "typical" web files in the shared folders.
  - `webmin` look for Webmin servers.
  - `x11open` look for open X11 servers.
  - `x11srv` look for X11 servers.
  - `xp445` look for Windows XP machines with TCP/445 port open.
  - `os:` look for a specific value in the OS discovery results.
  - `devtype:`, `devicetype:` look for a type of devices.
  - `netdev`, `networkdevice` look for network devices (firewalls,
    routers, ...).
  - `phonedev` look for telephony devices.
  - `cpe(:[type](:[vendor](:[product](:[version]))))` look for a given cpe. Each field can be a /regex/.
  - `[!]hop:[IP]`, `[!]hop:[IP]:[TTL]` look for a particular IP
    address in the traceroute results.
  - `[!]hopname:` look for a matching hostname in the traceroute
    results.
  - `[!]hopdomain:` look for a hostname within a matching domain name
    in the traceroute results.
  - `[!]tcp/[port number]`, `[!]udp/[port number]`, look for an open
    TCP or UDP port (using `[!][port number]` directly is equivalent
    to `[!]tcp/[port number]`).
  - `[!]openport` look for hosts with at least one open port.
  - `otheropenport:[port number]`,
    `otheropenport:[port number],[port number],...` look for hosts
    with at least one open port other than those specified.
  - `notes` search results with an associated note.

### Sort ###

  - `skip:[count]` skip `count` first results.
  - `limit:[count]` only display `count` results.
  - `[!]sortby:[field name]` sort according to a field value. Be
    careful with this setting as consequences on the performances can
    be terrible.

### Display ###

  - `display:host` set the default display mode.
  - `display:cpe` only display CPEs.
  - `display:script:`, `display:script:[script id]` or
    `display:script:[script id],[script id],...` only display (a
    particular) script outputs.
  - `display:screenshot` only display screenshots.


---

This file is part of IVRE. Copyright 2011 - 2015
[Pierre LALET](mailto:pierre.lalet@cea.fr)
