/*
 * This file is part of IVRE.
 * Copyright 2011 - 2015 Pierre LALET <pierre.lalet@cea.fr>
 *
 * IVRE is free software: you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * IVRE is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
 * License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with IVRE. If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * IMPORTANT:
 *
 * The values set here only affect the interface. The important
 * settings change the (server-side) CGIs behavior (rather than the
 * client-side, user-controlled interface) and can be modified in
 * ivre.conf.
 */

var config = {
    /* default values, not needed */
    "notesbase": "/dokuwiki/#IP#",
    "cgibase": "/cgi-bin/scanjson.py",
    "dflt": {
	"limit": 10,
    },
    "warn_dots_count": 20000,
    "publicsrv": false,
    "uploadok": false,
};
