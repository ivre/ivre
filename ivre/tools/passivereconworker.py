#! /usr/bin/env python

# This file is part of IVRE.
# Copyright 2011 - 2016 Pierre LALET <pierre.lalet@cea.fr>
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

"""Handle ivre passiverecon2db files."""

from ivre import config, utils

import re
import os
import sys
import shutil
import time
import subprocess
import gzip
import signal


SENSORS = {}  # shortname: fullname
FILEFORMAT = "^(?P<sensor>%s)\\.(?P<datetime>[0-9-]+)\\.log(?:\\.gz)?$"
SLEEPTIME = 2
CMDLINE = "%(progname)s -s %(sensor)s"
WANTDOWN = False


def shutdown(signum, _):
    """Sets the global variable `WANTDOWN` to `True` to stop
    everything after the current files have been processed.

    """
    global WANTDOWN
    print 'SHUTDOWN: got signal %d, will halt after current file.' % signum
    WANTDOWN = True


def getnextfiles(directory, sensor=None, count=1):
    """Returns a list of maximum `count` filenames to process, given
    the `directory` and the `sensor` (or, if it is `None`, from any
    sensor).

    """
    if sensor is None:
        fmt = re.compile(FILEFORMAT % "[^\\.]*")
    else:
        fmt = re.compile(FILEFORMAT % re.escape(sensor))
    files = [fmt.match(f) for f in os.listdir(directory)]
    files = [f for f in files if f is not None]
    files.sort(key=lambda x: map(int, x.groupdict()['datetime'].split('-')))
    return [f for f in files[:count]]


def create_process(progname, sensor):
    """Creates the insertion process for the given `sensor` using
    `progname`.

    """
    return subprocess.Popen(
        CMDLINE % {
            "progname": progname,
            "sensor": SENSORS.get(sensor, sensor)
        },
        shell=True, stdin=subprocess.PIPE
    )


def worker(progname, directory, sensor=None):
    """This function is the main loop, creating the processes when
    needed and feeding them with the data from the files.

    """
    utils.makedirs(os.path.join(directory, "current"))
    procs = {}
    while not WANTDOWN:
        # We get the next file to handle
        fname = getnextfiles(directory, sensor=sensor, count=1)
        # ... if we don't, we sleep for a while
        if not fname:
            if config.DEBUG:
                print "Sleeping for %d s" % SLEEPTIME,
                sys.stdout.flush()
            time.sleep(SLEEPTIME)
            if config.DEBUG:
                print "DONE"
            continue
        fname = fname[0]
        fname_sensor = fname.groupdict()['sensor']
        if fname_sensor in procs:
            proc = procs[fname_sensor]
        else:
            proc = create_process(progname, fname_sensor)
            procs[fname_sensor] = proc
        fname = fname.group()
        # Our "lock system": if we can move the file, it's ours
        try:
            shutil.move(os.path.join(directory, fname),
                        os.path.join(directory, "current"))
        except shutil.Error:
            continue
        if config.DEBUG:
            print "Handling %s" % fname,
            sys.stdout.flush()
        fname = os.path.join(directory, "current", fname)
        if fname.endswith('.gz'):
            fdesc = gzip.open(fname)
        else:
            fdesc = open(fname)
        handled_ok = True
        for line in fdesc:
            try:
                proc.stdin.write(line)
            except ValueError:
                proc = create_process(progname, fname_sensor)
                procs[fname_sensor] = proc
                # Second (and last) try
                try:
                    proc.stdin.write(line)
                except ValueError:
                    handled_ok = False
        fdesc.close()
        if handled_ok:
            os.unlink(fname)
        if config.DEBUG:
            if handled_ok:
                print "OK"
            else:
                print "KO!"
    # SHUTDOWN
    for sensor in procs:
        procs[sensor].stdin.close()
        procs[sensor].wait()


def main():
    """Parses the arguments and call worker()"""
    # Set the signal handler
    for s in [signal.SIGINT, signal.SIGTERM]:
        signal.signal(s, shutdown)
        signal.siginterrupt(s, False)
    try:
        import argparse
        parser = argparse.ArgumentParser(description=__doc__)
    except ImportError:
        # Python 2.6 compatibility
        import optparse
        parser = optparse.OptionParser(description=__doc__)
        parser.parse_args_orig = parser.parse_args
        parser.parse_args = lambda: parser.parse_args_orig()[0]
        parser.add_argument = parser.add_option
    parser.add_argument(
        '--sensor', metavar='SENSOR[:SENSOR]',
        help='sensor to check, optionally with a long name, defaults to all.',
    )
    parser.add_argument(
        '--directory', metavar='DIR',
        help='base directory (defaults to /ivre/passiverecon/).',
        default="/ivre/passiverecon/",
    )
    parser.add_argument(
        '--progname', metavar='PROG',
        help='Program to run (defaults to ivre passiverecon2db).',
        default="ivre passiverecon2db",
    )
    args = parser.parse_args()
    if args.sensor is not None:
        SENSORS.update(dict([args.sensor.split(':', 1)
                             if ':' in args.sensor
                             else [args.sensor, args.sensor]]))
        sensor = args.sensor.split(':', 1)[0]
    else:
        sensor = None
    worker(args.progname, args.directory, sensor=sensor)
