# FAQ #

If you cannot find the answer to your question, either here or in
[the documentation](README.md), feel free to
[open an issue](https://github.com/cea-sec/ivre/issues/new) and use
the label "question".

## Web interface ##

### Help / Dokuwiki shows "Forbidden" ###

**I cannot access the help pages or the notepad (the Dokuwiki content),
and get a "Forbidden" message.**

You need to configure your web server to allow access from other hosts
on the network to the Dokuwiki content. It is often restricted, by
default, to local users only. If you are using Apache, you can look
for an ACL like `Allow from localhost 127.0.0.1 ::1` and adapt it to
your network.

### How can I restrict access to IVRE's Web interface ###

**I want to prevent unauthorized access to IVRE's results.**

First, you have to configure your web server to authenticate remote
users. The most important, of course, is to protect access to CGI
files (the static files are publicly available and do not contain any
result).

In an AD or Kerberos environment for example, Apache can be configured
to provide SSO authentication.

Then, if you want to restrict access to the results based on the user
login or domain, you can add the following lines to `/etc/ivre.conf`:

    WEB_DEFAULT_INIT_QUERY = 'noaccess'
    WEB_INIT_QUERIES = {
        'admin@SUBNETWORK.NETWORK.AD': 'category:SubNetwork',
        '@ADMIN.NETWORK.AD': 'full',
    }

By default, users won't have access to any result. The user
`admin@SUBNETWORK.NETWORK.AD` will have access to the results in the
category `SubNetwork`. The users in the `ADMIN.NETWORK.AD` realm will
have access to all the results.

## Can IVRE be used to look for XXX? ##

IVRE is not a scanner or a network traffic analyzer. It relies on
tools like Nmap, Masscan, Bro and p0f, parses their results and stores
them in a database.

So when you are asking, for example, "can IVRE scan a network for
hosts with the [Heartbleed](https://en.wikipedia.org/wiki/Heartbleed)
vulnerability?", in reality you are asking two different questions:
  - "Can Nmap or Masscan detect when a scanned hosts is vulnerable to
    the Heartbleed vulnerability?"
  - "How can IVRE list the hosts that have been found vulnerable to
    Heartbleed by Nmap or Masscan?"

The first question is not related to IVRE (and should probably be
asked to Nmap or Masscan developers), but the second question is (and
may be asked as a "question" labeled issue).

For that particular Heartbleed example, both Nmap and Masscan can
(reliably) report hosts with the Heartbleed vulnerability, and IVRE
can be used to find such hosts.

## HowTo configure iptables to get logs used by flow2db tool

When you don't have acces to low level network data, an easy way to
discover a part of network traffic is to use netfilter logs collected
via syslog.

To be efficient, all the systems must have iptables activated and
configured to send logs.

For example

```
   -A INPUT   -j LOG --log-prefix "IPTABLES/INPUT: "
   -A OUTPUT  -j LOG --log-prefix "IPTABLES/OUTPUT: "
   -A FORWARD -j LOG --log-prefix "IPTABLES/FORWARD: "
```

To log all traffic, the rules can be set at the top of all rules.
Be careful with OUTPUT rule to avoid deathloop :

    syslog send log, netfilter log , syslog send log ...


On the syslog server or on each host, just run grep to collect the
data needed for the iptables flow2db parser:

```bash
   $ grep -l 'IPTABLES/' /var/log/syslog /var/log/kernel.log ... > syslog-iptables.log
```

Then import data to ivredb using flow2db tool:

```bash
   $ ivre flow2db -t iptables syslog-iptables.log
```


---

This file is part of IVRE. Copyright 2011 - 2018
[Pierre LALET](mailto:pierre.lalet@cea.fr)
