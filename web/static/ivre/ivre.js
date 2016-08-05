/*
 * This file is part of IVRE.
 * Copyright 2011 - 2016 Pierre LALET <pierre.lalet@cea.fr>
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
        "dflt_limit": 10,
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
                "count": values["total"] + '',
                "reasons": values["reasons"]});
        }
    }
    if('ports' in host) {
        var ports = {};
        for(var i in host.ports) {
            var port = host.ports[i];
            if(port.port === -1) {
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
    return true;
}

function sync_hash_filter(filter) {
    /*
     * Syncs the filter's parameters/query and the page's hash.
     */

    window.onhashchange = function() {
        filter.query = get_hash();
        if(!(load_params(filter)))
            return;
        filter.on_query_update();
    };
    filter.add_callback("param_update", function(query) {
        var onhashchange = window.onhashchange;
        window.onhashchange = function() {
            window.onhashchange = onhashchange;
        };
        set_hash(query);
    });
}

/******* Main function *********/

function load() {

    /* Main Web UI */

    if(!(wait_filter(load)))
        return;

    sync_hash_filter(FILTER);

    FILTER.add_callback("pre_get_results", function() {
        clear_hosts();
        hidecharts();
        changefav("favicon-loading.gif");
    });
    FILTER.add_callback("get_results", function(data) {
        add_hosts(data);
    });
    FILTER.add_callback("end_update", function() {
        set_display_mode(getparam(FILTER, 'display'));
    });
    FILTER.add_callback("post_get_results", function() {
        var hostcount = count_displayed_hosts(),
        limit = getparam(FILTER, 'limit'),
        skip = getparam(FILTER, 'skip');
        if(limit === undefined)
            limit = config.dflt_limit;
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
        if(maxres !== skip) {
            set_display_bounds(skip + 1, maxres);
        }
        changefav("favicon.png");
        if(hostcount === 1) {
            toggle_full_display(0);
        }
    });
    document.getElementById("filter-last").focus();
    window.onhashchange();
}

function init_report() {
    /* Report Web UI

       Sync between parameters and query works through the hash. See
       load() function.

*/
    if(!(wait_filter(init_report)))
        return;
    sync_hash_filter(FILTER);
    window.onhashchange();
}
