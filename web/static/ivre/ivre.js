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
var parameters = [];
var parametersprotected = [];
var parametersobj = {};
var parametersobjunalias = {};
var clicktimeout = null;
var wanted_scripts, wanted_hops;
// the initial prev_query has to be an object and to be different than
// any valid query
var prev_query = {"thiswillneverexist": []};
var query;

/******* IVRE specific methods *******/

function hideall() {
    var elts = Array.prototype.slice.call(
	document.getElementById('notes-container').children);
    for(var i in elts)
	elts[i].style.display = "none";
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

/******* Main function *********/

function load() {
    if (!(load_params()))
	return;
    var need_update = ! compare_params(parametersobjunalias,
				       prev_query,
				       false);
    if(! need_update)
	need_update = ! compare_params(prev_query,
				       parametersobjunalias,
				       false);
    if(! need_update) {
	set_display_mode(getparam('display'));
	return;
    }

    var need_count = ! compare_params(parametersobjunalias,
				      prev_query,
				      true);
    if(! need_count)
	need_count = ! compare_params(prev_query,
				      parametersobjunalias,
				      true);

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
	encodeURIComponent(query);
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
		encodeURIComponent(query);
	    document.body.appendChild(s);
	}
	prev_query = {};
	for(var key in parametersobjunalias) {
	    prev_query[key] = parametersobjunalias[key];
	}

    };
    document.body.appendChild(s);
}

window.onhashchange = load;
