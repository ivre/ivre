Agents
======

IVRE agent may be run in an environment not totally controlled (e.g.,
during a pentest, on a machine you have just owned and want to use to
do some network recon without installing IVRE), since it has a reduced
number of dependencies.

IVRE agent only requires ``nmap`` (of course), ``screen`` and
``rsync`` (plus ``/bin/sh`` and basic shell utils, including
``grep``).

Set-up
------

On the "master", install IVRE following the
:ref:`install/installation:Installation guidelines`. Install also
``screen``, ``tmux`` or ``nohup`` if you want to be able to "detach"
from the ``agent`` script (which is not a daemon).

On the "remotehost(s)", the ``agent`` script must be deployed, together with
``nmap``, and ``rsync``.

Run the remotehost(s)
----------------

The computer running IVRE (the "master") needs to be able to access via
``rsync`` the data directory of the agents (to add targets and to
retrieve results): this is not an issue if you are running the agent and
IVRE itself on the same machine. If you are running IVRE and the agent
on two different hosts (and, except for simple or testing
configurations, you should do that), you have to run ``sshd`` or
``rsyncd`` on the agent host, or share the agent files (using NFS, SMB
or whatever the IVRE side can mount).

First, ``mkdir`` & ``cd`` to the directory you want to use as your agent
data directory.

Make sure the needed binaries are in the ``PATH`` environment variable
(including ``nmap``). Generate the ``agent`` script, on a computer with
IVRE installed, by running
``ivre runscans --output Agent > agent; chmod +x agent`` , adapt if
needed the variables at the beginning of the script, particularly
``THREADS``.

By default, the ``default`` template is used. You can generate agents
using other scan templates using ``--nmap-template [template name]``.

Then just run the ``agent`` script.

When the scan is over, to stop the agent, type ``C-c`` or kill the
parent ``agent`` process.

Run the master
--------------

You need to make sure the user running ``ivre runscansagent`` or
``ivre runscansagentdb`` on the "master" can access (without password)
to the agents data directories.

When the agents are all ready, you have two options, using
``ivre runscansagent`` or ``ivre runscansagentdb``. In both cases, scan
options are the same than with ``ivre runscans``.

The first one (``ivre runscansagent``) is the "old-school" version: it
will not allow to dynamically add or remove agents, and will fetch the
results under ``./agentsdata/output`` directory, you have to import the
results by yourself.

On the other hand, the second one (``ivre runscansagentdb``) will use
the DB to manage the agents, but is still experimental.

**runscansagent**, the "old-school" one
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You have to specify the agent(s) data directory. For example, run:

::

   $ ivre runscansagent --routable --limit 1000 \
   >     agenthost1:/path/to/agent/dir      \
   >     agenthost2:/path/to/agent/dir      \

You can now import the results as if you had run the "regular" ``ivre
runscans`` program to scan locally. The results are stored under
``agentsdata/output/``

**runscansagentdb**, the "modern" (but probably broken) one
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Please note that it is important to run all the ``ivre runscansagentdb``
from the same host (the "master", which does not need to be the same
host than the database server), since it relies on local directories.

First, let's create a master and add the agent(s):

::

   $ ivre runscansagentdb --add-local-master
   $ ivre runscansagentdb --source MySource --add-agent \
   >     agenthost1:/path/to/agent/dir \
   >     agenthost2:/path/to/agent/dir

Let's check it's OK:

::

   $ ivre runscansagentdb --list-agents
   agent:
     - id: 543bfc8a312f915728f1709b
     - source name: MySource
     - remote host: agenthost1
     - remote path: /path/to/agent/dir/
     - local path: /var/lib/ivre/master/sbOist
     - rsync command: rsync
     - current scan: None
     - currently synced: True
     - max waiting targets: 60
     - waiting targets: 0
     - can receive: 60
   agent:
     - id: 543bfc8a312f915728f1709c
     - source name: MySource
     - remote host: agenthost2
     - remote path: /path/to/agent/dir/
     - local path: /var/lib/ivre/master/m2584z
     - rsync command: rsync
     - current scan: None
     - currently synced: True
     - max waiting targets: 60
     - waiting targets: 0
     - can receive: 60

Now we can add a scan, and assign the (available) agents to that scan:

::

   $ ivre runscansagentdb --assign-free-agents --routable --limit 1000

And see if it works:

::

   $ ivre runscansagentdb --list-scans
   scan:
     - id: 543bfcbf312f9158d6caeadf
     - categories:
       - ROUTABLE
     - targets added: 0
     - results fetched: 0
     - total targets to add: 1000
     - available targets: 2712693508
     - internal state: (2174385484, 551641673, 387527645, 0)
     - agents:
       - 543bfc8a312f915728f1709b
       - 543bfc8a312f915728f1709c

For now, nothing has been sent to the agents. To really start the
process, run:

::

   $ ivre runscansagentdb --daemon

After some time, the first results get imported in the database
(``READING [...]``, ``HOST STORED: [...]``, ``SCAN STORED: [...]``). You
can stop the daemon at any time by ``(p)kill``-ing it (using ``CTRL+c``
will do).

When all the targets have been sent to an agent, the agents get
disassociated from the scan so that another scan can use them. You can
check the scan evolution by issuing
``ivre runscansagentdb --list-scans``.
