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

"""Parsers for file formats / tool outputs"""


from __future__ import annotations  # needed for flake8

import subprocess
from collections.abc import Iterator
from types import TracebackType
from typing import Any, BinaryIO, Type, cast

from ivre.utils import FileOpener


class Parser:
    """Parent class for file parsers"""

    def __init__(self, fname: str | BinaryIO) -> None:
        self.fopener = FileOpener(fname)
        self.fdesc = self.fopener.fdesc

    def __iter__(self) -> Iterator[dict[str, Any]]:
        return self

    def __next__(self) -> dict[str, Any]:
        return self.parse_line(next(self.fdesc))

    def parse_line(self, line: bytes) -> dict[str, Any]:
        raise NotImplementedError

    def fileno(self) -> int:
        return self.fdesc.fileno()

    def close(self) -> None:
        self.fdesc.close()

    def __enter__(self) -> Parser:
        return self

    def __exit__(
        self,
        exc_type: Type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.fopener.__exit__(exc_type, exc_val, exc_tb)


class CmdParser(Parser):
    """Parent class for file parsers with commands"""

    def __init__(self, cmd: list[str], cmdkargs: dict[str, Any]) -> None:
        cmdkargs["stdout"] = subprocess.PIPE
        # pylint: disable=consider-using-with
        self.proc = subprocess.Popen(cmd, **cmdkargs)
        assert self.proc.stdout is not None
        self.fdesc = cast(BinaryIO, self.proc.stdout)

    def __exit__(
        self,
        exc_type: Type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        self.fdesc.close()
        if self.proc is not None:
            self.proc.wait()
