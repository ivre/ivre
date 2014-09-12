This file is part of IVRE.

Copyright 2011 - 2014 [Pierre LALET](mailto:pierre.lalet@cea.fr)

# Introduction #

IVRE agent is meant to be run in an environment not totally
controlled (e.g., during a pentest, on a machine you have just owned
and want to use to do some network recon without installing IVRE).

IVRE agent only requires nmap (of course), screen and rsync (plus
`/bin/sh` and basic shell utils, including `grep`).

# Installation #

On the "master", install IVRE following the instructions of the
[INSTALL](INSTALL.md) file. Install also `screen`.

On the "slave(s)", the `agent` script must be deployed, together with
`nmap`, `screen` and `rsync`.

# Run

## On the slave(s) ##

The computer running IVRE (the "master") needs to be able to access
via `rsync` the data directory of the agents (to add targets and to
retrieve results): this is not an issue if you are running the agent
and IVRE itself on the same machine. If you are running IVRE and the
agent on two different hosts (and, except for simple or testing
configurations, you should do that), you have to run `sshd` or
`rsyncd` on the agent host, or share the agent files (using NFS, SMB
or whatever the IVRE side can mount).

First, `mkdir` & `cd` to the directory you want to use as your agent
data directory.

Make sure the needed binaries are in the `PATH` environment variable
(including `nmap` and `screen`), adapt if needed the variables at the
beginning of the script (particularly `NMAPOPTS` and `THREADS`). Then
just run the `agent` script.

The script will start `screen`, and you can just detach by using (if
you have the default key bindings): `C-a d`.

When the scan is over, to stop the agent, reattach the screen session
by running `screen -r`, and type `C-c` as many times as needed to kill
all the instances of the script and get back to your shell.

Please refer to `screen` documentation if you need.

## On the master ##

You need to make sure the user running `runscans-agent` on the
"master" can access (without password) to the agents data directories.

When the agents are all ready, use `runscans-agent`. Scan options are
the same than with `runscans`, and you have to specify the agent(s)
data directory. For example, run:

    $ runscans-agent --routable --limit 1000 \
    >     agenthost1:/path/to/agent/dir      \
    >     agenthost2:/path/to/agent/dir      \

You can now import the results as if you had run the "regular"
`runscans` program to scan locally, see [README](README.md).
