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

function params2query(filter) {
    var store = filter.parametersobj,
    res = "";
    for(var t in store)
	for(var k in store[t]) {
	    if(! store[t][k][0])
		res += '-';
	    res += protect(t);
	    if(store[t][k][1] !== undefined)
		res += ':' + protect(store[t][k][1]);
	    res += ' ';
	}
    filter.query = res.substr(0, res.length - 1);
}

function parse_params(filter) {
    // this is more or less an equivalent to shlex.split() and builds
    // parameters array and the query string from
    // document.location.hash
    var state = 0;
    var curtoken, curtokenprotected, curchar;
    filter.parameters = [];
    filter.parametersprotected = [];
    filter.parametersobj = {};
    filter.parametersobjunalias = {};
    for(var i in filter.query) {
	curchar = filter.query[i];
	switch(state) {
	case 0:
	    // state init / out of token
	    switch(curchar) {
	    case " ":
		break;
	    case "\\":
		state = 3;
		curtokenprotected += curchar;
		break;
	    case '"':
		state = 2;
		curtokenprotected += curchar;
		break;
	    case "'":
		state = 5;
		curtokenprotected += curchar;
		break;
	    default:
		curtoken = curchar;
		curtokenprotected = curchar;
		state = 1;
	    }
	    break;
	case 1:
	    // in token, non protected
	    switch (curchar) {
	    case " ":
		state = 0;
		if(curtoken !== undefined)
		    add_param_objects(filter, curtoken, curtokenprotected);
		curtoken = undefined;
		curtokenprotected = undefined;
		break;
	    case "\\":
		state = 3;
		curtokenprotected += curchar;
		break;
	    case '"':
		state = 2;
		curtokenprotected += curchar;
		break;
	    case "'":
		state = 5;
		curtokenprotected += curchar;
		break;
	    default:
		curtoken += curchar;
		curtokenprotected += curchar;
	    }
	    break;
	case 2:
	    // in token, protected by double quotes
	    switch (curchar) {
	    case "\\":
		state = 4;
		break;
	    case '"':
		state = 1;
		break;
	    default:
		curtoken += curchar;
	    }
	    curtokenprotected += curchar;
	    break;
	case 3:
	    // in token, protected by backslash
	    curtoken += curchar;
	    curtokenprotected += curchar;
	    state = 1;
	    break;
	case 4:
	    // in token, protected by double quotes and backslash
	    curtoken += curchar;
	    curtokenprotected += curchar;
	    state = 2;
	    break;
	case 5:
	    // in token, protected by simple quotes
	    switch (curchar) {
	    case "\\":
		state = 6;
		curtokenprotected += curchar;
		break;
	    case "'":
		state=1;
		curtokenprotected += curchar;
		break;
	    default:
		curtoken += curchar;
		curtokenprotected += curchar;
	    }
	    break;
	case 6:
	    // in token, protected by simple quotes *and* backslash
	    curtoken += curchar;
	    curtokenprotected += curchar;
	    state = 5;
	    break;
	}
    }
    if(curtoken !== undefined)
	add_param_objects(filter, curtoken, curtokenprotected);
    if(filter.scope)
	filter.scope.parametersprotected = filter.parametersprotected;
    create_wanted_scripts(filter);
}

function create_wanted_scripts(filter) {
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

    wanted_scripts = array2object(getparamvalues(filter, "script", true));
    wanted_hops = getparamvalues(filter, "hop")
	.filter(function(x) {return x[0];})
	.map(function(x) {return x[1];});
}

function add_param_object(p, f, v) {
    var s = p[f];
    if (s === undefined) s = [];
    s.push(v);
    p[f] = s;
}

function add_param_objects(filter, p, pp) {
    if (p.length === 0) return;
    filter.parameters.push(p);
    filter.parametersprotected.push(pp);
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
	add_param_object(filter.parametersobjunalias, 'script',
			 [b, 'banner:' + p.substr(7)]);
    else if (p.substr(0, 7) === "sshkey:")
	add_param_object(filter.parametersobjunalias, 'script',
			 [b, 'ssh-hostkey:' + p.substr(7)]);
    else if (p.substr(0, 5) === 'file:') {
	for (i = 0; i < aliases_ls.length; i++) {
	    add_param_object(
		filter.parametersobjunalias, 'script',
		[b, aliases_ls[i] + ':' +
		 p.substr(5)]
	    );
	}
    }
    else if (p.substr(0, 7) === 'cookie:')
	add_param_object(filter.parametersobjunalias, 'script',
			 [b, 'http-headers:/Set-Cookie: ' + p.substr(7) + '=/']);
    else if (p.substr(0, 8) === 'smbshare' && (p.length === 8 ||
					       p.substr(8, 1) === ':'))
	add_param_object(filter.parametersobjunalias, 'script',
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
	    add_param_object(filter.parametersobjunalias, 'script',
			     [b, 'smb-os-discovery:/^(OS|OS CPE): .*$/m']);
	    break;
	case 'server':
	    add_param_object(
		filter.parametersobjunalias, 'script',
		[b, 'smb-os-discovery:/^NetBIOS computer name: .*$/m']
	    );
	    break;
	case 'workgroup':
	    add_param_object(filter.parametersobjunalias, 'script',
			     [b, 'smb-os-discovery:/^Workgroup: .*$/m']);
	    break;
	case 'date':
	    add_param_object(filter.parametersobjunalias, 'script',
			     [b, 'smb-os-discovery:/^System time: .*$/m']);
	    break;
	case 'domain_dns':
	    add_param_object(
		filter.parametersobjunalias, 'script',
		[b, 'smb-os-discovery:/^Domain name: .*$/m']
	    );
	    break;
	case 'fqdn':
	    add_param_object(
		filter.parametersobjunalias, 'script',
		[b, 'smb-os-discovery:/^FQDN: .*$/m']
	    );
	    break;
	default:
	    add_param_object(filter.parametersobjunalias, 'script',
			     [b, 'smb-os-discovery']);
	}
    }
    else if (p.substr(0, 4) === "tcp/" || p.substr(0, 4) === "udp/") {
	add_param_object(filter.parametersobjunalias, 'open', [b, p]);
    }
    else if (parseInt(p) == p) {
	add_param_object(filter.parametersobjunalias, 'open', [b, "tcp/" + p]);
    }
    else if (p.substr(0, 5) === "open:" || p.substr(0, 9) === "filtered:" ||
	     p.substr(0, 7) === "closed:") {
	var ports = p.split(":", 2)[1].split(","), status = p.split(":", 1);
	for(i in ports) {
	    var port = ports[i].split("/", 2);
	    if(port.length === 1)
		add_param_object(filter.parametersobjunalias, 'open',
				 [b, "tcp/" + port[0]]);
	    else
		add_param_object(filter.parametersobjunalias, 'open',
				 [b, port[0] + "/" + port[1]]);

	}
    }
    else switch (p) {
    case 'nfs':
    case 'nfsexports':
	add_param_object(filter.parametersobjunalias, 'script',
			 [b, 'rpcinfo:/nfs/']);
	break;
    case 'ypserv':
    case 'yp':
    case 'nis':
	add_param_object(filter.parametersobjunalias, 'script',
			 [b, 'rpcinfo:/ypserv/']);
	break;
    case 'anonftp':
	add_param_object(filter.parametersobjunalias, 'script',
			 [b, 'ftp-anon:/^Anonymous FTP login allowed/']);
	break;
    case 'authhttp':
	for (i = 0; i < 2; i++) {
	    add_param_object(filter.parametersobjunalias, 'script',
			     [b, ['http-auth', 'http-default-accounts'][i] +
			      ':/HTTP server may accept|credentials found/']);
	}
	break;
    case 'authbypassvnc':
	add_param_object(filter.parametersobjunalias, 'script',
			 [b, 'realvnc-auth-bypass']);
	break;
    case 'mssqlemptypwd':
	add_param_object(filter.parametersobjunalias, 'script',
			 [b, 'ms-sql-empty-password:/Login Success/']);
	break;
    case 'mysqlemptypwd':
	add_param_object(filter.parametersobjunalias, 'script',
			 [b, 'mysql-empty-password:/account has empty password/']);
	break;
    case 'x11srv':
	add_param_object(filter.parametersobjunalias, 'service', [b, 'X11']);
	break;
    case 'x11open':
	add_param_object(filter.parametersobjunalias, 'script',
			 [b, 'x11-access:X server access is granted']);
	break;
    case 'xp445':
	/* same as smb.os + tcp port 445*/
	add_param_object(filter.parametersobjunalias, 'script',
			 [b, 'smb-os-discovery:/^(OS|OS CPE): .*$/m']);
	add_param_object(filter.parametersobjunalias, 'tcp/445',
			 [b, undefined]);
	break;
    case 'webfiles':
	for (i = 0; i < aliases_ls.length; i++) {
	    add_param_object(
		filter.parametersobjunalias, 'script',
		[b, aliases_ls[i] +
		 ':/vhost|www|web\.config|\.htaccess|' +
		 '\.([aj]sp|php|html?|js|css)/i']
	    );
	}
	break;
    case 'webmin':
	add_param_object(filter.parametersobjunalias, 'service', [b, 'Webmin']);
	break;
    case 'owa':
	add_param_object(filter.parametersobjunalias, 'script',
			 [b, 'http-headers', '/^ *(Location:.*(owa|exchweb)|X-OWA-Version)/i']);
	add_param_object(filter.parametersobjunalias, 'script',
			 [b, 'http-auth-finder', '/\/(owa|exchweb)/i']);
	add_param_object(filter.parametersobjunalias, 'script',
			 [b, 'http-title', '/Outlook Web A|(Requested resource was|Did not follow redirect to ).*\/(owa|exchweb)/i']);
	break;
    case 'phpmyadmin':
	add_param_object(filter.parametersobjunalias, 'script',
			 [b, 'http-headers', '/^ *Set-Cookie: phpMyAdmin/i']);
	break;
    default:
	i = p.indexOf(':');
	if (i === -1)
	    add_param_object(filter.parametersobjunalias, p,
			     [b, undefined]);
	else
	    add_param_object(filter.parametersobjunalias, p.substr(0, i),
			     [b, p.substr(i+1)]);
    }
    i = p.indexOf(':');
    if (i === -1)
	add_param_object(filter.parametersobj, p,
			 [b, undefined]);
    else
	add_param_object(filter.parametersobj, p.substr(0, i),
			 [b, p.substr(i+1)]);
}

function getparamvalues(filter, param, unalias) {
    var store = (unalias ? filter.parametersobjunalias :
		 store = filter.parametersobj);
    if (param in store)
	return store[param];
    return [];
}

function getparam(filter, param) {
    // returns the first value for param
    var store = filter.parametersobj, b;
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

function unsetparam(filter, param) {
    var store = filter.parametersobj;
    delete(store[param]);
    filter.on_paramobj_update();
}

function setparam(filter, param, value, unique, notnow) {
    var store = filter.parametersobj, b;
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
    if(!notnow) {
	filter.on_paramobj_update();
    }
}

function load_params(filter){
    parse_params(filter);
    if (getparam(filter, 'skip') == 0) {
	unsetparam(filter, 'skip');
	return false;
    }
    if (getparam(filter, 'limit') == config.dflt_limit) {
	unsetparam(filter, 'limit');
	return false;
    }
    return true;
}
