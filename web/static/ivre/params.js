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

/************ Parameters handling ****************/

function params2hash() {
    var store = parametersobj;
    var res = "";
    for(var t in store)
	for(var k in store[t]) {
	    if(! store[t][k][0])
		res += '-';
	    res += protect(t);
	    if(store[t][k][1] !== undefined)
		res += ':' + protect(store[t][k][1]);
	    res += ' ';
	}
    set_hash(res.substr(0, res.length - 1));
}

function parse_params() {
    // this is more or less an equivalent to shlex.split() and builds
    // the global parameters array and the global query string from
    // document.location.hash
    var state = 0;
    query = get_hash();
    var curtoken = undefined;
    var curtokenprotected = undefined;
    parameters = [];
    parametersprotected = [];
    parametersobj = {};
    parametersobjunalias = {};
    for(var i in query) {
	switch(state) {
	case 0:
	    // state init / out of token
	    switch(query[i]) {
	    case " ":
		break;
	    case "\\":
		state = 3;
		curtokenprotected += query[i];
		break;
	    case '"':
		state = 2;
		curtokenprotected += query[i];
		break;
	    case "'":
		state = 5;
		curtokenprotected += query[i];
		break;
	    default:
		curtoken = query[i];
		curtokenprotected = query[i];
		state = 1;
	    }
	    break;
	case 1:
	    // in token, non protected
	    switch (query[i]) {
	    case " ":
		state = 0;
		if(curtoken !== undefined)
		    add_param_objects(curtoken, curtokenprotected);
		curtoken = undefined;
		curtokenprotected = undefined;
		break;
	    case "\\":
		state = 3;
		curtokenprotected += query[i];
		break;
	    case '"':
		state = 2;
		curtokenprotected += query[i];
		break;
	    case "'":
		state = 5;
		curtokenprotected += query[i];
		break;
	    default:
		curtoken += query[i];
		curtokenprotected += query[i];
	    }
	    break;
	case 2:
	    // in token, protected by double quotes
	    switch (query[i]) {
	    case "\\":
		state = 4;
		break;
	    case '"':
		state = 1;
		break;
	    default:
		curtoken += query[i];
	    }
	    curtokenprotected += query[i];
	    break;
	case 3:
	    // in token, protected by backslash
	    curtoken += query[i];
	    curtokenprotected += query[i];
	    state = 1;
	    break;
	case 4:
	    // in token, protected by double quotes and backslash
	    curtoken += query[i];
	    curtokenprotected += query[i];
	    state = 2;
	    break;
	case 5:
	    // in token, protected by simple quotes
	    switch (query[i]) {
	    case "\\":
		state = 6;
		curtokenprotected += query[i];
		break;
	    case "'":
		state=1;
		curtokenprotected += query[i];
		break;
	    default:
		curtoken += query[i];
		curtokenprotected += query[i];
	    }
	    break;
	case 6:
	    // in token, protected by simple quotes *and* backslash
	    curtoken += query[i];
	    curtokenprotected += query[i];
	    state = 5;
	    break;
	}
    }
    if(curtoken !== undefined)
	add_param_objects(curtoken, curtokenprotected);
    create_wanted_scripts();
}

function create_wanted_scripts() {
    function array2object(array) {
	// convert the array of [true, <script-id>[:<value>]] elements
	// to an object {<script-id>: <value>}
	return array
	    .filter(function(x) {return x[0];}) // keep only [true, x]
	    .map(function(x) {return x[1].split(':');}) // [true, x:y] => [x,y]
	    .reduce(function(o, v) {
		// [x, y] => {x: y}
		// inspired by http://stackoverflow.com/a/4215753/3223422
		var key = v.shift();
		var value;
		if(v.length > 0)
		    value = v.join(':');
		else
		    value = true;
		if(key in o) {
		    if(value !== true && !(value in o[key])) {
			o[key].push(value);
		    }
		}
		else {
		    if(value === true)
			o[key] = [];
		    else
			o[key] = [value];
		}
		return o;
	    }, {});
    }

    wanted_scripts = array2object(getparamvalues("script", true));
    wanted_hops = getparamvalues("hop")
	.filter(function(x) {return x[0];})
	.map(function(x) {return x[1];});
}

function add_param_object(p, f, v) {
    var s = p[f];
    if (s === undefined) s = [];
    s.push(v);
    p[f] = s;
}

function add_param_objects(p, pp) {
    if (p.length === 0) return;
    parameters.push(p);
    parametersprotected.push(pp);
    var b, i;
    if ('-!'.indexOf(p[0]) != -1) {
	b = false;
	p = p.substr(1);
	if (p.length === 0) return;
    }
    else
	b = true;
    var aliases_ls = ['ftp-anon', 'afp-ls', 'nfs-ls', 'smb-ls', 'http-ls'];

    // aliases
    if (p.substr(0, 7) === "banner:")
	add_param_object(parametersobjunalias, 'script',
			 [b, 'banner:' + p.substr(7)]);
    else if (p.substr(0, 7) === "sshkey:")
	add_param_object(parametersobjunalias, 'script',
			 [b, 'ssh-hostkey:' + p.substr(7)]);
    else if (p.substr(0, 5) === 'file:') {
	for (i = 0; i < aliases_ls.length; i++) {
	    add_param_object(
		parametersobjunalias, 'script',
		[b, aliases_ls[i] + ':' +
		 p.substr(5)]
	    );
	}
    }
    else if (p.substr(0, 7) === 'cookie:')
	add_param_object(parametersobjunalias, 'script',
			 [b, 'http-headers:/Set-Cookie: ' + p.substr(7) + '=/']);
    else if (p.substr(0, 8) === 'smbshare' && (p.length === 8 ||
					       p.substr(8, 1) === ':'))
	add_param_object(parametersobjunalias, 'script',
			 [b, 'smb-enum-shares:/READ|WRITE|STYPE_DISKTREE/']);
    else if (p.substr(0, 4) === 'smb.') {
	/*
	 * smb.* filters are very specific: they rely on the
	 * table/elem values of the smb-os-discovery host script,
	 * which may differ from the displayed output.
	 *
	 * For this reason, we do to rely on the value but rather on
	 * the field and highlight whole lines.
	 */
	var subfield = p.substr(4);
	var subfieldend = subfield.indexOf(':');
	if (subfieldend !== -1) {
	    subfield = subfield.substr(0, subfieldend);
	}
	switch(subfield) {
	case 'os':
	case 'lanmanager':
	    add_param_object(parametersobjunalias, 'script',
			     [b, 'smb-os-discovery:/^(OS|OS CPE): .*$/m']);
	    break;
	case 'server':
	    add_param_object(
		parametersobjunalias, 'script',
		[b, 'smb-os-discovery:/^NetBIOS computer name: .*$/m']
	    );
	    break;
	case 'workgroup':
	    add_param_object(parametersobjunalias, 'script',
			     [b, 'smb-os-discovery:/^Workgroup: .*$/m']);
	    break;
	case 'date':
	    add_param_object(parametersobjunalias, 'script',
			     [b, 'smb-os-discovery:/^System time: .*$/m']);
	    break;
	case 'domain_dns':
	    add_param_object(
		parametersobjunalias, 'script',
		[b, 'smb-os-discovery:/^Domain name: .*$/m']
	    );
	    break;
	case 'fqdn':
	    add_param_object(
		parametersobjunalias, 'script',
		[b, 'smb-os-discovery:/^FQDN: .*$/m']
	    );
	    break;
	default:
	    add_param_object(parametersobjunalias, 'script',
			     [b, 'smb-os-discovery']);
	}
    }
    else switch (p) {
    case 'nfs':
    case 'nfsexports':
	add_param_object(parametersobjunalias, 'script',
			 [b, 'rpcinfo:/nfs/']);
	break;
    case 'ypserv':
    case 'yp':
    case 'nis':
	add_param_object(parametersobjunalias, 'script',
			 [b, 'rpcinfo:/ypserv/']);
	break;
    case 'anonftp':
	add_param_object(parametersobjunalias, 'script',
			 [b, 'ftp-anon:/^Anonymous FTP login allowed/']);
	break;
    case 'authhttp':
	for (i = 0; i < 2; i++) {
	    add_param_object(parametersobjunalias, 'script',
			     [b, ['http-auth', 'http-default-accounts'][i] +
			      ':/HTTP server may accept|credentials found/']);
	}
	break;
    case 'authbypassvnc':
	add_param_object(parametersobjunalias, 'script',
			 [b, 'realvnc-auth-bypass']);
	break;
    case 'mssqlemptypwd':
	add_param_object(parametersobjunalias, 'script',
			 [b, 'ms-sql-empty-password:/Login Success/']);
	break;
    case 'mysqlemptypwd':
	add_param_object(parametersobjunalias, 'script',
			 [b, 'mysql-empty-password:/account has empty password/']);
	break;
    case 'x11srv':
	add_param_object(parametersobjunalias, 'service', [b, 'X11']);
	break;
    case 'x11open':
	add_param_object(parametersobjunalias, 'script',
			 [b, 'x11-access:X server access is granted']);
	break;
    case 'xp445':
	/* same as smb.os + tcp port 445*/
	add_param_object(parametersobjunalias, 'script',
			 [b, 'smb-os-discovery:/^(OS|OS CPE): .*$/m']);
	add_param_object(parametersobjunalias, 'tcp/445',
			 [b, undefined]);
	break;
    case 'webfiles':
	for (i = 0; i < aliases_ls.length; i++) {
	    add_param_object(
		parametersobjunalias, 'script',
		[b, aliases_ls[i] +
		 ':/vhost|www|web\.config|\.htaccess|' +
		 '\.([aj]sp|php|html?|js|css)/i']
	    );
	}
	break;
    case 'webmin':
	add_param_object(parametersobjunalias, 'service', [b, 'Webmin']);
	break;
    case 'owa':
	add_param_object(parametersobjunalias, 'script',
			 [b, 'http-headers', '/^ *(Location:.*(owa|exchweb)|X-OWA-Version)/i']);
	add_param_object(parametersobjunalias, 'script',
			 [b, 'http-auth-finder', '/\/(owa|exchweb)/i']);
	add_param_object(parametersobjunalias, 'script',
			 [b, 'http-title', '/Outlook Web A|(Requested resource was|Did not follow redirect to ).*\/(owa|exchweb)/i']);
	break;
    case 'phpmyadmin':
	add_param_object(parametersobjunalias, 'script',
			 [b, 'http-headers', '/^ *Set-Cookie: phpMyAdmin/i']);
	break;
    default:
	i = p.indexOf(':');
	if (i === -1)
	    add_param_object(parametersobjunalias, p,
			     [b, undefined]);
	else
	    add_param_object(parametersobjunalias, p.substr(0, i),
			     [b, p.substr(i+1)]);
    }
    i = p.indexOf(':');
    if (i === -1)
	add_param_object(parametersobj, p,
			 [b, undefined]);
    else
	add_param_object(parametersobj, p.substr(0, i),
			 [b, p.substr(i+1)]);
}

function getparamvalues(param, unalias) {
    var store;
    if (unalias === true)
	store = parametersobjunalias;
    else
	store = parametersobj;
    if (param in store)
	return store[param];
    return [];
}

function getparam(param) {
    // returns the first value for param
    var store = parametersobj, b;
    if (param.length > 0 && '-!'.indexOf(param[0]) != -1) {
	b = false;
	param = param.substr(1);
    }
    else
	b = true;
    if(param in store)
	for(var i in store[param])
	    if(store[param][i][0] === b)
		return store[param][i][1];
    return undefined;
}

function unsetparam(param) {
    var store = parametersobj;
    delete(store[param]);
    params2hash();
}

function setparam(param, value, unique, notnow) {
    var store = parametersobj, b;
    if (param.length > 0 && '-!'.indexOf(param[0]) != -1) {
	b = false;
	param = param.substr(1);
    }
    else
	b = true;
    if (param !== 'limit' && param !== 'skip') {
	delete(store.limit);
	delete(store.skip);
    }
    if(unique || ! (param in store)) {
	store[param] = [[b, value]];
    }
    else if(param in store) {
	var needed = true;
	for(var t in store[param])
	    if(store[param][t][0] === b && store[param][t][1] === value) {
		needed = false;
		break;
	    }
	if(needed)
	    store[param].push([b, value]);
    }
    if(! notnow) {
	params2hash();
    }
}

function compare_params(store, other, count) {
    for(var key in store) {
	if((count && (key == 'limit' || key == 'skip' || key == 'sortby')) ||
	   key == 'display') {
	    continue;
	}
	if(other[key] === undefined) {
	    return false;
	}
	next_index:
	for(var index in store[key]) {
	    for(var other_index in other[key]) {
		if(store[key][index][0] === other[key][other_index][0] &&
		   store[key][index][1] === other[key][other_index][1]) {
		    continue next_index;
		}
	    }
	    return false;
	}
    }
    return true;
}

function load_params(){
    parse_params();
    if (getparam('skip') == 0) {
	unsetparam('skip');
	return false;
    }
    if (getparam('limit') == config.dflt.limit) {
	unsetparam('limit');
	return false;
    }

    clear_filters();

    var ii = 0;
    for(var i in parametersprotected) {
	if (! (parametersprotected[i].substr(0,5) === "skip:" ||
	       parametersprotected[i].substr(0,6) === "limit:")) {
	    add_filter({
		"id": ii,
		"value": parametersprotected[i],
	    });
	    ii += 1;
	}
    }
    return true;
}
