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

/************ AngularJS related controllers ************/

// Our AngularJS App

var ivreWebUi = angular.module('ivreWebUi', []);

function get_scope(controller) {
    return angular.element(
	document.querySelector(
	    '[ng-controller=' + controller + ']'
	)).scope();
}

// Popover directive

ivreWebUi.directive('popover', function(){
    return {
        restrict: 'A',
        link: function(scope, element, attrs){
            $(element).hover(function(){
                // on mouseenter
                $(element).popover('show').on("mouseleave", function () {
                var _this = this;
                todo = function () {
                    if (!$(".popover:hover").length) {
                        $(_this).popover("hide");
                    } else {
                        setTimeout(todo, 100);
                    }
                };
                setTimeout(todo, 10);
            });
            }, function(){});
        }
    };
});

// The Web UI display controller

ivreWebUi
    .controller('IvreMainCtrl', function ($scope) {
	$scope.setparam = setparam;
	$scope.totalnbrres = undefined;
	// notes: here because the buttons are located in the menu and
	// the results
	$scope.notes_page = undefined;
	$scope.notes_display = "none";
	$scope.togglenotes = function (page) {
	    if($scope.notes_display === "none") {
		hideall();
		$scope.notes_display = "inline";
		$scope.notes_page = config.notesbase.replace(/#IP#/g, page);
	    }
	    else if($scope.notes_page.indexOf(
		config.notesbase.replace(/#IP#/g, page)) !== -1)
		$scope.notes_display = "none";
	    else
		$scope.notes_page = config.notesbase.replace(/#IP#/g, page);
	};
	// graphs:here beacause the buttons are located w/ the filters
	$scope.build_ip_plane = function() {
	    var totalnbrres = $scope.totalnbrres;
	    if(totalnbrres === undefined)
		return;
	    if(totalnbrres < config.warn_dots_count || confirm("You are about to ask your browser to display " + totalnbrres + " dots, which is a lot and might slow down, freeze or crash your browser. Do you want to continue?")) {
		hideall();
		var c1 = document.getElementById('chart1');
		c1.innerHTML = "";
		var s = document.getElementById('chart1script');
		if(s) c1.parentNode.removeChild(s);
		document.getElementById('charts').style.display = 'inline';
		s = document.createElement('script');
		s.id = 'chart1script';
		s.src = config.cgibase + '?callback=' + encodeURIComponent("(function(ips){build_chart_plane('chart1', ips);})")+ '&action=countopenports&ipsasnumbers=1&q=' + encodeURIComponent(query);
		c1.parentNode.appendChild(s);
	    }
	    else {
		hidecharts();
	    }
	};
	$scope.build_ip_map = build_ip_map;
	$scope.build_ip_timeline = function(modulo) {
	    var totalnbrres = $scope.totalnbrres;
	    if(totalnbrres === undefined)
		return;
	    if(totalnbrres < config.warn_dots_count || modulo !== undefined || confirm("You are about to ask your browser to display " + totalnbrres + " dots, which is a lot and might slow down, freeze or crash your browser. Do you want to continue?")) {
		hideall();
		var c1 = document.getElementById('chart1');
		c1.innerHTML = "";
		var s = document.getElementById('chart1script');
		if(s) c1.parentNode.removeChild(s);
		document.getElementById('charts').style.display = 'inline';
		s = document.createElement('script');
		s.id = 'chart1script';
		s.src = config.cgibase + '?callback=' + encodeURIComponent("(function(ips){build_chart_timeline('chart1', ips);})")+ '&action=timeline&ipsasnumbers=1&q=' + encodeURIComponent(query);
		if(modulo !== undefined)
		    s.src += '&modulo=' + modulo;
		c1.parentNode.appendChild(s);
	    }
	    else {
		hidecharts();
	    }
	};
	$scope.build_ip_ports = function() {
	    var totalnbrres = $scope.totalnbrres;
	    if(totalnbrres === undefined)
		return;
	    if(totalnbrres < config.warn_dots_count || confirm("You are about to ask your browser to display " + totalnbrres + " dots, which is a lot and might slow down, freeze or crash your browser. Do you want to continue?")) {
		hideall();
		var c1 = document.getElementById('chart1');
		c1.innerHTML = "";
		var s = document.getElementById('chart1script');
		if(s) c1.parentNode.removeChild(s);
		document.getElementById('charts').style.display = 'inline';
		s = document.createElement('script');
		s.id = 'chart1script';
		s.src = config.cgibase + '?callback=' + encodeURIComponent("(function(ips){build_chart_ports('chart1', ips);})")+ '&action=ipsports&ipsasnumbers=1&q=' + encodeURIComponent(query);
		c1.parentNode.appendChild(s);
	    }
	    else {
		hidecharts();
	    }
	};
    });

// The menu controller

ivreWebUi
    .controller('IvreMenuCtrl', function ($scope) {
	$scope.get_href = function() {return document.location.href;};
	$scope.get_title = function() {return document.title;};
	$scope.add_bookmark = function() {
	    // https://stackoverflow.com/questions/3024745
	    // https://stackoverflow.com/questions/19289739
	    if (window.sidebar) // Mozilla Firefox Bookmark
		return true;
	    else if(window.external) // IE Favorite
		window.external.AddFavorite(location.href, document.title);
	    else if(window.opera && window.print) // Opera Hotlist
		return true;
	    return false;
	};
	$scope.get_mail_href = function() {
	    return 'mailto:?subject=' +
		encodeURIComponent(document.title) +
		'&body=' +
		encodeURIComponent(document.location.href);
	};
	$scope.eval_action = function(string) {
	    // Eval action 'string' in the current context
	    eval(string);
	};
    })
    .directive('ivreMenu', function() {
	var linkFunction = function(scope, elements, attributes) {
	    scope.MENU = MENUS[attributes["ivreMenu"]];
	}
	return {
	    templateUrl: 'templates/menu.html',
	    link: linkFunction,
	};
    });

// The progress bar controller

ivreWebUi
    .controller('IvreProgressCtrl', function ($scope) {
	$scope.firstdisplayed = undefined;
	$scope.lastdisplayed = undefined;
	$scope.at_start = function() {
	    return $scope.firstdisplayed === 1;
	};
	$scope.at_end = function() {
	    return $scope.lastdisplayed === $scope.totalnbrres;
	};
	$scope.goto_start = function() {
	    if(!$scope.at_start())
		setparam('skip', '0', true);
	};
	$scope.goto_end = function() {
	    if(!$scope.at_end())
		setparam(
		    'skip',
		    $scope.totalnbrres - $scope.lastdisplayed +
			$scope.firstdisplayed - 1 + "",
		    true);
	};
	$scope.go_back = function(count) {
	    if(!$scope.at_start())
		setparam('skip', $scope.firstdisplayed - count - 1 + '', true);
	};
	$scope.go_forward = function(count) {
	    if(!$scope.at_end())
		setparam('skip', $scope.firstdisplayed + count - 1 + '', true);
	};
    })
    .directive('ivreProgressBar', function() {
	return {
	    templateUrl: 'templates/progressbar.html'
	};
    });


function set_nbrres(nbr) {
    var scope = get_scope('IvreMainCtrl');
    scope.$apply(function() {
	scope.totalnbrres = nbr;
    });
}

function set_display_bounds(first, last) {
    var scope = get_scope('IvreProgressCtrl');
    scope.$apply(function() {
	scope.firstdisplayed = first;
	scope.lastdisplayed = last;
    });
}

// The filter list controller

ivreWebUi
    .controller('IvreFilterListCtrl', function ($scope) {
	$scope.lastfiltervalue = "";
    })
    .directive('ivreFilters', function() {
	return {
	    templateUrl: 'templates/filters.html'
	};
    })
    .directive('ivreTopvalues', function() {
	return {
	    templateUrl: 'templates/topvalues.html'
	};
    });

function add_filter(filter) {
    var scope = get_scope('IvreFilterListCtrl');
    scope.$apply(function() {
	scope.filters.push(filter);
    });
}

function clear_filters() {
    var scope = get_scope('IvreFilterListCtrl');
    scope.$apply(function() {
	scope.filters = [];
	scope.lastfiltervalue = "";
    });
}


ivreWebUi
    .controller('IvreResultListCtrl', function ($scope) {
	$scope.results = [];
	$scope.display_mode = "host";
	$scope.display_mode_args = [];
	$scope.script_display_mode_needed_scripts_group = function(scripts) {
	    if(scripts === undefined || scripts.length === 0)
		return false;
	    if($scope.display_mode_args.length === 0)
		return true;
	    return scripts
		.some(function(x) {
		    return $scope.display_mode_args.indexOf(x.id) !== -1;
		});
	};
	$scope.script_display_mode_needed_script = function(scriptid) {
	    if($scope.display_mode_args.length === 0)
		return true;
	    return $scope.display_mode_args.indexOf(scriptid) !== -1;
	};
	$scope.set_timer_toggle_preview = function(event, host) {
	    event = event || window.event;
	    if((event.keyCode || event.which) === 1)
		clicktimeout = setTimeout(
		    function() {
			$scope.$apply(function() {
			    host.fulldisplay = !host.fulldisplay;
			});
		    },
		    200);
	    event.stopPropagation();
	};
	$scope.clear_timer_toggle_preview = function(event) {
	    if(clicktimeout !== null) {
		event = event || window.event;
		clearTimeout(clicktimeout);
		event.stopPropagation();
	    }
	};
	$scope.wanted_param = function(param, value) {
	    var wanted = getparamvalues(param)
		.filter(function(x) {return x[0];})
		.map(function(x) {return x[1];});
	    return wanted.indexOf(value) != -1;
	};
	$scope.wanted_trace = function(trace) {
	    var hops = trace.hops.map(function(hop) {return hop.ipaddr;});
	    for(var i in wanted_hops) {
		if(hops.indexOf(wanted_hops[i]) != -1)
		    return true;
	    }
	    return false;
	};
	$scope.wanted_hop = function(hop) {
	    return wanted_hops.indexOf(hop) != -1;
	};
	$scope.wanted_script = function(value) {
	    return value in wanted_scripts;
	};
	$scope.class_from_port_status = function(status) {
	    switch(status) {
	    case "open": return "label-success";
	    case "closed": return "label-danger";
	    case "filtered": return "label-warning";
	    }
	};
	$scope.short_port_status = function(status) {
	    if(status === "filtered")
		return "fltred";
	    return status;
	};
	$scope.url_from_port = function(port, addr) {
	    var result;
	    var schemes = {
		// service_name: [url_scheme, default_port,
		//		  url_scheme_ssl, default_port_ssl]
		'http': ['http', 80, 'https', 443],
		'ldap': ['ldap', 389, 'ldaps', 636],
		'ftp': ['ftp', 21, 'ftps', 990],
	    };
	    if ('service_name' in port && port.service_name in schemes) {
		if('service_tunnel' in port &&
		   port.service_tunnel === 'ssl') {
		    result = schemes[port.service_name][2] + '://' + addr;
		    if(port.port !== schemes[port.service_name][3])
			result += ':' + port.port;
		    result += '/';
		}
		else {
		    result = schemes[port.service_name][0] + '://' + addr;
		    if(port.port !== schemes[port.service_name][1])
			result += ':' + port.port;
		    result += '/';
		}
	    }
	    else {
		result = addr + ':' + port.port;
	    }
	    return result;
	};
    $scope.get_reshaped_cpes = function(host) {
        if(host.n_cpes)
            return host.n_cpes;
        var cpes = host.cpes,
        n_cpes = {},
        type2str = {
            'h': 'Hw',
            'o': 'OS',
            'a': 'App',
        },
        my_setdefault = function(d, key) {
            if(!("data" in d)) {
                d.data = {};
            }
            if(!(key in d.data)) {
                d.data[key] = {"name": key, "data": {}};
            }
            return d.data[key];
        };
        for(var i in cpes) {
            var cpe = cpes[i],
            type_d = my_setdefault(n_cpes, cpe.type),
            vend_d = my_setdefault(type_d, cpe.vendor),
            prod_d = my_setdefault(vend_d, cpe.product),
            comp_d = my_setdefault(prod_d, cpe.version);
            type_d.pretty_name = type2str[cpe.type] || "Unk";
	    vend_d.pretty_name = cpe.vendor == "" ? "---" : cpe.vendor;
	    prod_d.pretty_name = cpe.product == "" ? "---" : cpe.product;
	    comp_d.pretty_name = cpe.version == "" ? "---" : cpe.version;
            comp_d.origins || (comp_d.origins = []);
            comp_d.origins = comp_d.origins.concat(cpe.origins);
            comp_d.tooltitle = "cpe:/" +
                               [cpe.type, cpe.vendor, cpe.product, cpe.version]
                               .join(":").replace(/:+$/, "");
            comp_d.toolcontent = cpe.origins.join('<br/>');
        }
        host.n_cpes = n_cpes;
        return host.n_cpes;
    };
    $scope.set_cpe_param = function(type, vendor, product, version) {
        var query = [],
        parts = [type, vendor, product, version];
        for(var i in parts) {
            if(parts[i] && !!parts[i].name) {
                query.push(parts[i].name);
            } else {
                break;
            }
        }
        $scope.setparam("cpe", query.join(':'));
    }
    })
    .directive('displayHost', function() {
	return {
	    templateUrl: 'templates/view-hosts.html'
	};
    })
    .directive('displayScript', function() {
	return {
	    templateUrl: 'templates/view-scripts-only.html'
	};
    })
    .directive('displayScreenshot', function() {
	return {
	    templateUrl: 'templates/view-screenshots-only.html'
	};
    })
    .directive('displayCpe', function() {
	return {
	    templateUrl: 'templates/view-cpes-only.html'
	};
    })
    .directive('hostSummary', function() {
	return {
	    templateUrl: 'templates/subview-host-summary.html'
	};
    })
    .directive('portSummary', function() {
	return {
	    templateUrl: 'templates/subview-port-summary.html'
	};
    })
    .directive('portsSummary', function() {
	return {
	    templateUrl: 'templates/subview-ports-summary.html'
	};
    })
    .directive('serviceSummary', function() {
	return {
	    templateUrl: 'templates/subview-service-summary.html'
	};
    })
    .directive('cpes', function() {
	return {
	    templateUrl: 'templates/subview-cpes.html'
	};
    })
    .directive('scriptOutput', function() {
	return {"link": function(scope, element, attr) {
	    var wanted = wanted_scripts[scope.script.id];
	    var output = scope.script.output
		.split('\n')
		.map(function(x) {return x.trim();})
		.filter(function(x) {return x;})
		.join('\n')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;');
	    if(scope.wanted_script(scope.script.id)) {
		for(var i in wanted) {
		    var expr = str2regexp(wanted[i]);
		    output = output.replace(
			expr, '<span class="highlight-more">$&</span>'
		    );
		}
	    }
	    element.html(output);
	}};
    });

function prepare_host(host) {
    // This function adds the properties needed for the presentation
    // of an host object
    host.addr_links = addr_links(host);
    host.hostnames_links = hostnames_links(host);
    host.fulldisplay = false;
    host.port_summary = port_summary(host);
    host.starttime = 1000 * host.starttime;
    host.endtime = 1000 * host.endtime;
    return host;
}

function add_host(host) {
    var scope = get_scope('IvreResultListCtrl');
    scope.$apply(function() {
	scope.results.push(prepare_host(host));
    });
}

function clear_hosts() {
    var scope = get_scope('IvreResultListCtrl');
    scope.$apply(function() {
	scope.results = [];
    });
}

function toggle_full_display(hostindex) {
    var scope = get_scope('IvreResultListCtrl');
    scope.$apply(function() {
	scope.results[hostindex].fulldisplay = true;
    });
}

function count_displayed_hosts() {
    var scope = get_scope('IvreResultListCtrl');
    return scope.results.length;
}

function set_display_mode(mode) {
    var scope = get_scope('IvreResultListCtrl'), args = [];
    if(mode === undefined)
	mode = "host"; // default
    scope.$apply(function() { 
	if(mode.substr(0, 7) === "script:") {
	    args = mode.substr(7).split(',').reduce(function(accu, value) {
		switch(value) {
		case "":
		    return accu;
		case "ls":
		    return accu.concat([
			"afp-ls", "ftp-anon", "http-ls", "nfs-ls", "smb-ls",
		    ]);
		default:
		    return accu.concat([value]);
		}
	    }, []);
	    mode = "script";
	}
	scope.display_mode_args = args;
	scope.display_mode = mode;
    });
}

ivreWebUi
    .controller('IvreAnalysisCtrl', function ($scope) {
    });

ivreWebUi
    .controller('IvreMessagesCtrl', function ($scope) {
	$scope.messages = {};
	$scope.colors = {
	    "ok": "success",
	    "info": "info",
	    "warning": "warning",
	    "error": "danger",
	};
	$scope.signs = {
	    "ok": "glyphicon-ok-sign",
	    "info": "glyphicon-info-sign",
	    "warning": "glyphicon-exclamation-sign",
	    "error": "glyphicon-remove-sign",
	};
	$scope.remove_message = function(ident) {
	    delete $scope.messages[ident];
	    return false;
	};
    })
    .directive('ivreMessages', function() {
	return {
	    templateUrl: 'templates/messages.html'
	};
    });

function add_message(ident, level, content) {
    var message;
    if(content === undefined)
	message = {"level": "info", "content": level};
    else
	message = {"level": level, "content": content};
    var scope = get_scope('IvreMessagesCtrl');
    scope.$apply(function() {
	scope.messages[ident] = message;
    });
}

function del_message(ident) {
    var scope = get_scope('IvreMessagesCtrl');
    scope.$apply(function() {
	delete scope.messages[ident];
    });
}

ivreWebUi
    .controller('IvreReportCtrl', function ($scope) {

	/********** Common **********/

	$scope.query = get_hash();
	$scope.queryplural = parameters.length > 1;

	/********** Display **********/

	$scope.showfilter = true;
	$scope.toggleShowFilter = function() {
	    $scope.showfilter = $scope.showfilter === false ? true: false;
	};

	/********** Elements management **********/

	$scope.colors = [{bg: "#FFFFFF",
			  fg: "black"},
			 {bg: "#CF5044",
			  fg: "white"},
			 {bg: "#5B9BD5",
			  fg: "white"},
			 {bg: "#73B348",
			  fg: "white"},
			 {bg: "#F37F31",
			  fg: "white"},
			 {bg: "#4674CA",
			  fg: "white"},
			];
	$scope.types = ["Top-values", "Map + Top-values"];
	/* Element:
	   - type
	   - parameters
	   - text
	   - color
	*/
	$scope.elements = [
	    {"type": "Map + Top-values",
	     "parameters": "country",
	     "text": "Top countries",
	     "color": 0},
	    {"type": "Top-values",
	     "parameters": "port:open",
	     "text": "Top ports",
	     "color": 1},
	    {"type": "Top-values",
	     "parameters": "as",
	     "text": "Top AS",
	     "color": 2}
	];
	$scope.remove = function(index) {
	    $scope.elements.splice(index, 1);
	};

	$scope.elements_swap = function(id1, id2) {
	    array_swap($scope.elements, id1, id2);
	};

	/********** New element handling **********/

	$scope.cur_type = $scope.types[0];
	$scope.cur_title = "";
	$scope.cur_param = "";
	$scope.cur_color = 1;
	$scope.set_type = function(type) {
	    $scope.cur_type = type;
	    return false;
	};
	$scope.set_color = function(color) {
	    $scope.cur_color= color;
	    return false;
	};
	$scope.add_element = function() {
	    $scope.elements.push({type: $scope.cur_type,
				  parameters: $scope.cur_param,
				  text: $scope.cur_title,
				  color: $scope.cur_color});
	    $scope.cur_type = $scope.types[0];
	    $scope.cur_title = "";
	    $scope.cur_param = "";
	    $scope.cur_color = 1;
	};

	/********** Report building **********/

	$scope.build_ip_map = function(nb) {
	    var c1 = document.getElementById('chartmap' + nb);
	    var fullworld = undefined;
	    c1.innerHTML = "";
	    var s = document.getElementById('chartmap' + nb + 'script');
	    if(s) $(s).remove();
	    s = document.createElement('script');
	    s.id = 'chartmap' + nb + 'script';
	    component = "(function(ips){build_chart_map('chartmap" + nb +
		"', ips, " + fullworld + ");" +
		"to_remove = $.find('[download]'); for (var i in to_remove) { $(to_remove[i]).remove(); };" +
		"to_remove = $.find('[title=\"Zoom out\"]'); for (var i in to_remove) { $(to_remove[i]).remove(); };" +
		"})";
	    s.src = config.cgibase + '?callback=' +
		encodeURIComponent(component) +
		'&action=coordinates&ipsasnumbers=1&q=' + encodeURIComponent(query);
	    c1.parentNode.appendChild(s);
	};

	$scope.build_top_value = function(field, nb, size, colors) {
	    var c2 = document.getElementById('chart' + nb);
	    c2.innerHTML = "";
	    var s = document.getElementById('chart' + nb + 'script');
	    if(s) $(s).remove();
	    s = document.createElement('script');
	    s.id = 'chart' + nb + 'script';

	    s.src = config.cgibase + '?callback=' +
		encodeURIComponent(
		    "(function(data){build_chart('chart" + nb + "', '" +
			field + "', data, " + size + ", " + colors + ");" +
			"to_remove = $.find('[download]'); for (var i in to_remove) { $(to_remove[i]).remove(); }" +
			"})") +
		'&action=topvalues:' + encodeURIComponent(field) + ':10&q=' +
		encodeURIComponent(query);
	    c2.parentNode.appendChild(s);
	};
	$scope.build_all = function() {
	    $scope.query = get_hash();
	    $scope.queryplural = parameters.length > 1;

	    for (var elementid in $scope.elements) {
		element = $scope.elements[elementid];
		if (element.type === "Top-values") {
		    bcolor = undefined;
		    if ($scope.colors[element.color].fg === "white")
			bcolor = '["white"]';
		    $scope.build_top_value(element.parameters,
					   parseInt(elementid) + 1,
					   10, bcolor);
		} else if (element.type === "Map + Top-values") {
		    bcolor = undefined;
		    if ($scope.colors[element.color].fg === "white")
			bcolor = '["white"]';
		    $scope.build_top_value(element.parameters,
					   parseInt(elementid) + 1,
					   6, bcolor);
		    $scope.build_ip_map(parseInt(elementid) + 1);
		}

	    }
	};
    });

ivreWebUi
    .controller('IvreUploadCtrl', function ($scope) {
	$scope.publicsrv = config.publicsrv;
	$scope.uploadok = config.uploadok;
	$scope.files = undefined;
	$scope.error_files = false;
	$scope.error_source = false;
	$scope.error_agreed = false;
	$scope.checkfiles = function(elt) {
	    $scope.$apply(function() {
		$scope.files = elt.value;
	    });
	};
	$scope.ready = function() {
	    return ((!config.publicsrv || $scope.agreed) &&
		    $scope.source && $scope.source.length > 0 &&
		    $scope.files && $scope.files.length > 0);
	};
	$scope.check = function() {
	    $scope.error_files = !$scope.files || $scope.files.length === 0;
	    $scope.error_agreed = config.publicsrv && !$scope.agreed;
	    $scope.error_source = !$scope.source || $scope.source.length === 0;
	    return (!($scope.error_files || $scope.error_agreed ||
		     $scope.error_source))
	}
	$scope.upload = function() {
	    if($scope.check()) {
		$("#uploadReferer")
		    .attr("value", document.referrer);
		$("#upload")
		    .attr("action",
			  config.cgibase.replace(/json.py/, "upload.py"))
		    .submit();
	    }
	}
    });
