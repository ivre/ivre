This file is part of IVRE.

Copyright 2011 - 2014 [Pierre LALET](mailto:pierre.lalet@cea.fr)

# What is it? #

IVRE (Instrument de veille sur les réseaux extérieurs) or DRUNK
(Dynamic Recon of UNKnown networks) is a network recon framework,
including two modules for passive recon (one p0f-base and one
bro-based) and one module for active recon (mostly nmap-based, with a
bit of zmap).

The advertising slogans are:

  - (in French): IVRE, il scanne Internet.
  - (in English): Know the networks, get DRUNK!

The names IVRE and DRUNK have been chosen as a tribute to "Le
Taullier".

# Documentation #

See [doc/README](doc/README.md) (and `doc/*` files) for more
information.

On a server with the IVRE web server properly installed with a
Dokuwiki notepad, the `doc/*` files are available under the `doc:`
namespace (e.g., `doc:readme` for the [doc/README](doc/README.md)
file).

On a client with IVRE installed, you can use a `--help` option with
most IVRE CLI tools, and use `help(ivre.module)` with most IVRE Python
sub-modules.

# License #

IVRE is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

IVRE is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
[along with IVRE](doc/LICENSE.md). If not, see [the gnu.org web
site](http://www.gnu.org/licenses/).

# Support #

Try `--help` for the CLI tools, `help()` under Python and the "HELP"
button in the web interface.

Feel free to contact the author and offer him a beer if you need help!

If you don't like beer, a good scotch or any other good alcoholic
beverage will do (it is the author's unalienable right to decide
whether a beverage is good or not).

# Contributing #

Code contributions (pull-requests) are of course welcome!

The project needs scan results and capture files that can be provided
as examples. If you can contribute some samples, or if you want to
contribute some samples and would need some help to do so, or if you
can provide a server to run scans, please contact the author.
