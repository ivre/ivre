#! /usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of IVRE.
# Copyright 2011 - 2018 Pierre LALET <pierre.lalet@cea.fr>
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

"""
This module is part of IVRE.
Copyright 2011 - 2018 Pierre LALET <pierre.lalet@cea.fr>

This sub-module contains math functions missing from Python's math
module that might be useful to any other sub-module or script.
"""


def genprimes():
    """Yields the sequence of prime numbers via the Sieve of Eratosthenes.

    http://code.activestate.com/recipes/117119/

    """
    D = {}  # map composite integers to primes witnessing their compositeness
    q = 2  # first integer to test for primality
    while 1:
        if q not in D:
            yield q  # not marked composite, must be prime
            D[q * q] = [q]  # first multiple of q not already marked
        else:
            for p in D[q]:  # move each witness to its next multiple
                D.setdefault(p + q, []).append(p)
            del D[q]  # no longer need D[q], free memory
        q += 1


def factors(n):
    """Yields the prime factors of the integer n."""
    for p in genprimes():
        while n != 1 and n % p == 0:
            yield p
            n //= p
        if n == 1:
            break
        if p * p > n:
            yield n
            break
