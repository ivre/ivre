#! /usr/bin/env phantomjs

/*
  This file is part of IVRE.
  Copyright 2011 - 2015 Pierre LALET <pierre.lalet@cea.fr>

  IVRE is free software: you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  IVRE is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
  License for more details.

  You should have received a copy of the GNU General Public License
  along with IVRE. If not, see <http://www.gnu.org/licenses/>.
 */

/*
  Simple Web screenshot script, ready for use with http-screenshot.nse
  Nmap script.

  Some values are hard-coded:
    - timeout: 10s
    - format: JPEG
    - image quality: 90%

  Requires phantomjs.

  Usage: screenshot.js URL FILENAME
 */

var system = require('system');
var webpage = require('webpage');

function capture(url, fname) {
    var page = webpage.create();
    page.open(url, function() {
	page.evaluate(function(){
	    document.body.bgColor = 'white';
        });
	page.render(fname, {format: 'jpeg', quality: '90'});
	phantom.exit();
    });
}

capture(system.args[1], system.args[2])
setTimeout(phantom.exit, 10000);
