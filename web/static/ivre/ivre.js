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

/****** Load Configuration *******/

function setdefaultconfig() {
    var defaultconfig = {
	"notesbase": "/dokuwiki/#IP#",
	"cgibase": "/cgi-bin/scanjson.py",
	"dflt": {
	    "limit": 10,
	},
	"warn_dots_count": 20000,
	"publicsrv": false,
	"uploadok": false,
    };

    for(var k in defaultconfig) {
	if (config[k] === undefined) {
	    config[k] = defaultconfig[k];
	}
    }
}

setdefaultconfig();

/****** Global Variables *******/

/* global variables */
var clicktimeout = null;
var wanted_scripts, wanted_hops;

/******* IVRE specific methods *******/

function hideall() {
    $("#notes-container").children().css("display", "none");
}

function addr_links(host) {
    var addr = host.addr.split('.');
    var result = [];
    var net;
    for(var i = 0; i < addr.length; i++) {
	//net = addr.slice(0, i + 1).join('.') + '.0'.repeat(3 - i);
	net = addr.slice(0, i + 1).join('.') + repeat('.0', 3 - i);
	if(i !== 3)
	    net += '/' + (8 * (i+1));
	result.push({
	    "addrpart": addr[i],
	    "net": net,
	});
    }
    return result;
}

function hostnames_links(host) {
    if(!('hostnames' in host))
	return [];
    var hostnames = host.hostnames;
    var results = [];
    for(var i in hostnames) {
	if('name' in hostnames[i]) {
	    var names = hostnames[i].name.split('.');
	    var fullname = names.shift();
	    var result = [{
		'param': 'hostname',
		'value': fullname + '.' + names.join('.'),
		'name': fullname,
	    }];
	    for(var j in names) {
		result.push({
		    'param': 'domain',
		    'value': names.slice(j).join('.'),
		    'name': names[j],
		});
	    }
	    results.push(result);
	}
    }
    return results;
}

function port_summary(host, width) {
    /*
      This function prepares the host with a summary for ports, and
      creates the hostscripts section.
     */
    var result = [], status;
    if(width === undefined)
	width = 4;
    if('extraports' in host) {
	for(status in host.extraports) {
	    var values = host.extraports[status];
	    result.push({"type": "extra", "status": status,
			 "count": values[0] + '',
			 "reasons": values[1]});
	}
    }
    if('ports' in host) {
	var ports = {};
	for(var i in host.ports) {
	    var port = host.ports[i];
	    if(port.port == "host") {
		host.scripts = port.scripts;
	    }
	    else {
		if(port.state_state in ports)
		    ports[port.state_state].push({
			'protocol': port.protocol,
			'port': port.port
		    });
		else
		    ports[port.state_state] = [{'protocol': port.protocol,
						'port': port.port}];
	    }
	}
	for(status in ports) {
	    result.push({"type": "ports", "status": status,
			 "count": ports[status].length,
			 "ports": ports[status]});
	}
    }
    return result;
}

function wait_filter(fct) {
    if(FILTER === undefined) {
	/* XXX Wait for FILTER to be ready. */
	setTimeout(fct, 100);
	return false;
    }
    return true
}

/******* Main function *********/

function load() {
    if(!(wait_filter(load)))
	return;
    window.onhashchange = load;
    if (!(load_params()))
	return;
    if(! FILTER.need_update()) {
	set_display_mode(getparam('display'));
	return;
    }
    var need_count = FILTER.need_count();

    clear_hosts();
    hidecharts();
    changefav("favicon-loading.gif");
    if(need_count)
	set_nbrres(undefined);

    var s = document.getElementById('resultsscript');
    if(s) document.body.removeChild(s);
    s = document.createElement('script');
    s.id = "resultsscript";
    s.src = config.cgibase + '?callback=add_host&q=' +
	encodeURIComponent(FILTER.query);
    s.onload = function() {
	var hostcount = count_displayed_hosts(),
	limit = getparam('limit'),
	skip = getparam('skip');
	if(limit === undefined)
	    limit = config.dflt.limit;
	else
	    limit = limit * 1;
	if(skip === undefined)
	    skip = 0;
	else {
	    skip = skip * 1;
	    if(skip < 0)
		setparam('skip', 0, true);
	}
	var maxres = skip + hostcount;
	set_display_mode(getparam('display'));
	if(maxres !== skip) {
	    set_display_bounds(skip + 1, maxres);
	}

	changefav("favicon.png");

	if(hostcount === 1) {
	    toggle_full_display(0);
	}

	document.getElementById("filter-last").focus();

	if(need_count) {
	    var s = document.getElementById('countscript');
	    if(s) document.body.removeChild(s);
	    s = document.createElement('script');
	    s.id = "countscript";
	    s.src = config.cgibase + '?callback=set_nbrres&action=count&q=' +
		encodeURIComponent(FILTER.query);
	    document.body.appendChild(s);
	}
	FILTER.end_new_query();
    };
    document.body.appendChild(s);
}

function init_report() {
    if(!(wait_filter(init_report)))
	return;
    load_params();
    window.onhashchange = init_report;
    if (!(load_params()))
	return;
}
