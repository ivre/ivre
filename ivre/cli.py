#! /usr/bin/env python

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


"""IVRE command line"""

import argparse
import importlib
import logging
import os
import sys
import warnings
from errno import EPIPE

warnings.filterwarnings("ignore", category=DeprecationWarning)
# because some "dev" of the cryptography module decided that
# CryptographyDeprecationWarning should **not** inherit from
# DeprecationWarning
warnings.filterwarnings(
    "ignore", message="^Python [0-9\\.]+ .*support", module="cryptography|OpenSSL"
)


# pylint: disable=wrong-import-position,cyclic-import
from ivre import tools, utils  # noqa: E402
from ivre.tools.version import main as version  # noqa: E402

# pylint: enable=wrong-import-position,cyclic-import

try:
    # Only used at shell-completion generation time
    # (pkg/buildcompletion); optional [completion] extra.
    import shtab
except ImportError:
    shtab = None


HELP_COMMANDS = ["-h", "--help", "h", "help"]
VERSION_COMMANDS = ["-v", "--version"]


def _first_doc_line(text: str | None) -> str | None:
    """First non-empty line of a docstring / description, or None."""
    for line in (text or "").splitlines():
        if line.strip():
            return line.strip()
    return None


def get_parser() -> argparse.ArgumentParser:
    """Build a single argparse parser covering every built-in ``ivre``
    subcommand (one subparser per entry in :data:`ivre.tools.__all__`,
    with its aliases, plus the ``help`` pseudo-command).

    The runtime dispatcher (:func:`main`) does not use it -- each tool
    parses its own arguments -- but shell-completion generation
    (``pkg/buildcompletion``, based on ``shtab``) walks this parser to
    produce the completion script shipped in ``bash_completion/``.

    Building it imports every tool module and instantiates the
    configured DB backends (several tool parsers inherit filter
    options from ``db.<purpose>.argparser``), so the parser shape can
    reflect the local configuration and installed extras; no network
    connection is made.
    """
    parser = argparse.ArgumentParser(prog="ivre", description=__doc__)
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    rev_aliases: dict[str, list[str]] = {}
    for alias, target in tools.ALIASES.items():
        rev_aliases.setdefault(target, []).append(alias)
    for name in tools.__all__:
        module = importlib.import_module(f"ivre.tools.{name}")
        build = getattr(module, "build_parser", None)
        if build is None:
            # Tools without an argparse parser (e.g. getopt- or
            # stdin-based): complete the command name only.
            subparsers.add_parser(
                name,
                aliases=sorted(rev_aliases.get(name, [])),
                description=module.__doc__,
                help=_first_doc_line(module.__doc__),
            )
            continue
        tool_parser = build()
        if shtab is not None and name.endswith("2db"):
            # The ingestion tools take scan / log files as
            # positional arguments: complete them as paths.
            for action in tool_parser._get_positional_actions():
                if action.choices is None:
                    action.complete = shtab.FILE
        subparsers.add_parser(
            name,
            aliases=sorted(rev_aliases.get(name, [])),
            # The tool parser already carries its own --help action.
            parents=[tool_parser],
            add_help=False,
            description=tool_parser.description,
            help=_first_doc_line(module.__doc__)
            or _first_doc_line(tool_parser.description),
        )
    help_parser = subparsers.add_parser(
        "help",
        description="Display the help of another command.",
        help="Display the help of another command.",
    )
    help_parser.add_argument(
        "command",
        nargs="?",
        choices=sorted(list(tools.__all__) + list(tools.ALIASES)),
        help="Command to display the help of.",
    )
    return parser


def main():
    logging.basicConfig()
    try:
        _main()
    except KeyboardInterrupt:
        # Gracefully exit on Ctrl+C without a traceback; 130 = 128 + SIGINT
        sys.exit(130)
    except IOError as exc:
        if exc.errno != EPIPE:
            raise


def _main():
    executable = os.path.basename(sys.argv[0])
    if executable.startswith("ivre-"):
        # hack for blackarch package
        executable = executable[5:]
    if executable in tools.__all__ or executable in tools.ALIASES:
        utils.LOGGER.warning(
            "command %s deprecated. Use 'ivre %s' instead.",
            executable,
            tools.ALIASES.get(executable, executable),
        )
        command = tools.ALIASES.get(executable, executable)
    elif len(sys.argv) == 1:
        command = "help"
    else:
        command = tools.ALIASES.get(sys.argv[1], sys.argv[1])
        sys.argv = [f"{executable} {sys.argv[1]}"] + sys.argv[2:]
    if command.lower() in HELP_COMMANDS and len(sys.argv) > 1:
        command = sys.argv[1]
        sys.argv = [f"{executable} {sys.argv[1]}", "--help"] + sys.argv[2:]
    possible_commands = tools.guess_command(command)
    if len(possible_commands) == 1:
        tools.get_command(next(iter(possible_commands)))()
    elif command in tools.ALIASES:
        tools.get_command(tools.ALIASES[command])()
    elif command in VERSION_COMMANDS:
        version()
    else:
        if command.lower() in HELP_COMMANDS:
            output = sys.stdout
            retcode = 0
        else:
            output = sys.stderr
            output.write(
                f"{'Ambiguous' if possible_commands else 'Unknown'} command: {command}\n\n"
            )
            retcode = 1
        version()
        output.write(f"usage: {executable} [COMMAND]\n\n")
        output.write(f"{'matching' if possible_commands else 'available'} commands:\n")
        for availcmd in sorted(
            possible_commands if possible_commands else tools.guess_command("")
        ):
            output.write(f"  {availcmd}\n")
        output.write("\n")
        output.write(f"Try {executable} help [COMMAND]\n\n")
        sys.exit(retcode)
