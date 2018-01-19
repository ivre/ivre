# -*- coding: utf-8 -*-

"""Put selected results in views."""

from __future__ import print_function
from datetime import datetime
import time
import os
import sys

from builtins import input
from past.builtins import basestring

from ivre import utils
from ivre.xmlnmap import SCHEMA_VERSION

from ivre.db import db
from ivre.tools import scancli

try:
    import argparse
    USING_ARGPARSE = True
except ImportError:
    import optparse
    USING_ARGPARSE = False

### Utilities ###

def stub_print(d, padd=''):
    if isinstance(d, list):
        for e in d:
            print(padd, end='')
            print("----------")
            stub_print(e, padd)
        print(padd, end='')
        print("----------")
    elif not isinstance(d, dict):
        if isinstance(d, basestring):
            lines = map(lambda x: x.strip(), d.splitlines())
            for l in lines:
                print(padd, end='')
                print(l)
        else:
            print(padd, end='')
            print(d)
    else:
        for k, v in d.items():
            print(padd, end='')
            print("*" + str(k))
            padd += "|  "
            stub_print(v, padd)
            padd = padd[:-3]

### Output functions ###

def output_std(flt):
    cursor = db.view.get(flt)
    for rec in cursor:
        print(rec)
        print()

def output_verbose(flt):
    cursor = db.view.get(flt)
    for rec in cursor:
        stub_print(rec)
        print()

def output_distinct(flt, field="addr"):
    cursor = db.view.distinct(field, flt=flt)
    for rec in cursor:
        print(db.view.convert_ip(rec) if field == "addr" else rec)

### Main function ###

def main():
    if USING_ARGPARSE:
        parser = argparse.ArgumentParser(
            description='Print out views.',
            parents=[db.view.argparser])
    else:
        parser = optparse.OptionParser(
            description='Print out views.')
        for args, kargs in db.db.nmap.argparser.args:
            parser.add_option(*args, **kargs)
        parser.parse_args_orig = parser.parse_args
        def my_parse_args():
            res = parser.parse_args_orig()
            res[0].ensure_value('ips', res[1])
            return res[0]
        parser.parse_args = my_parse_args
        parser.add_argument = parser.add_option

    flt = db.view.flt_empty

    parser.add_argument('--delete', action='store_true',
                        help='Remove results instead of displaying them.')
    parser.add_argument('--init', '--purgedb', action='store_true',
                        help='Purge or create and initialize view.')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Print out formated results.')
    parser.add_argument('--count', action='store_true',
                        help='Output number of results.')
    parser.add_argument('--short', action='store_true',
                        help='Print only addresses of filtered results.')
    parser.add_argument('--distinct', metavar='FIELD',
                        help='Output only unique FIELD part of the results.')

    args = parser.parse_args()

    flt = db.view.parse_args(args)

    # Initialization
    if args.init:
        if os.isatty(sys.stdin.fileno()):
            sys.stdout.write(
                'This will remove any view in your database. Process ? [y/N] '
            )
            ans = input()
            if ans.lower() not in ['y', 'yes']:
                exit(0)
        db.view.init()
        exit(0)

    # Filters

    # Outputs
    if args.delete:
        output = db.view.remove
    elif args.count:
        output = lambda x: print(db.view.count(x))
    elif args.short:
        output = output_distinct
    elif args.distinct is not None:
        output = lambda x: output_distinct(x, args.distinct)
    elif args.verbose:
        output = output_verbose
    else:
        output = output_std

    output(flt)
