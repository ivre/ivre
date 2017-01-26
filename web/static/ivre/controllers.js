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

/************ AngularJS related controllers ************/

// Our AngularJS App

var ivreWebUi = angular.module('ivreWebUi', ["formHelpers"]);

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
	$scope.setparam = function(param, value, unique, notnow) {
	     return setparam($scope.shared.filter,
			     param, value, unique, notnow);
	};
	$scope.unsetparam = function(param) {
	     return unsetparam($scope.shared.filter, param);
	};
	// notes: here because the buttons are located in the menu and
	// the results
	$scope.notes_page = undefined;
	$scope.notes_display = "none";
	$scope.shared = {};
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
	    var totalnbrres = $scope.shared.filter.count;
	    if(totalnbrres === undefined)
		return;
	    if(totalnbrres < config.warn_dots_count || confirm("You are about to ask your browser to display " + totalnbrres + " dots, which is a lot and might slow down, freeze or crash your browser. Do you want to continue?")) {
	    new GraphPlane($("#chart"), $scope.shared.filter.query)
		.build();
	    }
	    else {
		hidecharts();
	    }
	};
	$scope.build_ip_map = function() {
	    new GraphMap($("#chart"), $scope.shared.filter.query)
		.build();
	};
	$scope.build_ip_timeline = function(modulo) {
	    var totalnbrres = $scope.shared.filter.count;
	    if(totalnbrres === undefined)
		return;
	    if(totalnbrres < config.warn_dots_count || modulo !== undefined || confirm("You are about to ask your browser to display " + totalnbrres + " dots, which is a lot and might slow down, freeze or crash your browser. Do you want to continue?")) {
		new GraphTimeline($("#chart"), $scope.shared.filter.query,
				  modulo)
		    .build();
	    }
	    else {
		hidecharts();
	    }
	};
	$scope.build_ip_ports = function() {
	    var totalnbrres = $scope.shared.filter.count;
	    if(totalnbrres === undefined)
		return;
	    if(totalnbrres < config.warn_dots_count || confirm("You are about to ask your browser to display " + totalnbrres + " dots, which is a lot and might slow down, freeze or crash your browser. Do you want to continue?")) {
		new GraphIpPort($("#chart"), $scope.shared.filter.query)
		    .build();
	    }
	    else {
		hidecharts();
	    }
	};
	$scope.build_top_chart = function() {
	    new GraphTopValues($("#chart"),
			       $scope.shared.filter.query,
			       $scope.shared.topvaluesfield)
		.build();
	};
	$scope.apply_on_filter_update = [$scope];
    });

// The menu controller

ivreWebUi
    .controller('IvreMenuCtrl', function ($scope) {
	$scope.version = config.version;
	$scope.get_href = function(page, drop_hash) {
	    if(page === undefined)
		return document.location.href;
	    if(drop_hash) {
		return getPagePath() + page;
	    }
	    return getPagePath() + page + document.location.hash;
	};
	$scope.get_json_export = function() {
	    var query;
	    if($scope.shared.filter !== undefined
	       && $scope.shared.filter.query !== "") {
		query = $scope.shared.filter.query + " limit:0";
	    }
	    else {
		query = "limit:0";
	    }
	    return 'cgi-bin/scanjson.py?q=' + encodeURIComponent(query) +
		'&ipsasnumbers=1&datesasstrings=1';
	};
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
	    scope.MENU = MENUS[attributes.ivreMenu];
	};
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
	    return $scope.shared.filter &&
		$scope.lastdisplayed === $scope.shared.filter.count;
	};
	$scope.goto_start = function() {
	    if(!$scope.at_start())
		$scope.setparam('skip', '0', true);
	};
	$scope.goto_end = function() {
	    if(!$scope.at_end())
		$scope.setparam(
		    'skip',
		    $scope.shared.filter.count - $scope.lastdisplayed +
			$scope.firstdisplayed - 1 + "",
		    true);
	};
	$scope.go_back = function(count) {
	    if(!$scope.at_start())
		$scope.setparam('skip', $scope.firstdisplayed - count - 1 + '', true);
	};
	$scope.go_forward = function(count) {
	    if(!$scope.at_end())
		$scope.setparam('skip', $scope.firstdisplayed + count - 1 + '', true);
	};
    })
    .directive('ivreProgressBar', function() {
	return {
	    templateUrl: 'templates/progressbar.html'
	};
    });


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
	    templateUrl: 'templates/filters.html',
	    link: function(scope, elem, attrs) {
		scope.title = attrs.title;
		switch(attrs.parent) {
		case undefined:
		    scope.filter = new Filter(attrs.name);
		    break;
		case "":
		    scope.filter = new SubFilter(attrs.name, FILTER);
		    break;
		default:
		    scope.filter = new SubFilter(attrs.name,
						 FILTERS[attrs.parent]);
		}
		scope.filter.scope = scope;
		scope.parametersprotected = scope.filter.parametersprotected;
		scope.idprefix = attrs.name ? attrs.name + "-" : "";
		scope.clear_and_submit = function(index) {
		    scope.parametersprotected[index] = "";
		    scope.submitform();
		};
		if(scope.submitform === undefined) {
		    scope.submitform = function() {
			ToolTip.remove_all();
			scope.filter.on_param_update();
		    };
		}
		if(!attrs.name && scope.shared !== undefined) {
		    scope.shared.filter = scope.filter;
		}
		if(scope.all_filters !== undefined) {
		    scope.all_filters.push(scope.filter);
		}
		if(scope.apply_on_filter_update !== undefined) {
		    $.merge(scope.filter.need_apply,
			    scope.apply_on_filter_update);
		}
		if(scope.on_filter_ready !== undefined) {
                    scope.on_filter_ready(scope.filter);
                }
	    }
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
	    var wanted = getparamvalues($scope.shared.filter, param)
		.filter(function(x) {return x[0];})
		.map(function(x) {return x[1];});
	    return wanted.indexOf(value) != -1;
	};
	$scope.wanted_port = function(status, protocol, port) {
	    var wanted = getparamvalues($scope.shared.filter, status, true)
		.filter(function(x) {return x[0];})
		.map(function(x) {return x[1];});
	    return wanted.indexOf(protocol + '/' + port) != -1;
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
	    case "filtered":
	    case "open|filtered":
		 return "label-warning";
	    }
	};
	$scope.short_port_status = function(status) {
	    return {
		"filtered": "flt",
		"open|filtered": "opn|flt"
	    }[status] || status;
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
		vend_d.pretty_name = cpe.vendor ? cpe.vendor : "---";
		prod_d.pretty_name = cpe.product ? cpe.product : "---";
		comp_d.pretty_name = cpe.version ? cpe.version : "---";
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
	};
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

function add_hosts(hosts) {
    // scope.$apply() has to be called at the end of
    // Filter.on_query_update()
    var scope = get_scope('IvreResultListCtrl');
    for(var i in hosts) {
	scope.results.push(prepare_host(hosts[i]));
    }
}

function clear_hosts() {
    // scope.$apply() has to be called at the end of
    // Filter.on_query_update()
    get_scope('IvreResultListCtrl').results = [];
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
    // scope.$apply() has to be called at the end of
    // Filter.on_query_update()
    var scope = get_scope('IvreResultListCtrl'), args = [];
    if(mode === undefined)
	mode = "host"; // default
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
    // scope.$apply() has to be called at the end of
    // Filter.on_query_update()
    var message;
    if(content === undefined)
	message = {"level": "info", "content": level};
    else
	message = {"level": level, "content": content};
    get_scope('IvreMessagesCtrl').messages[ident] = message;
}

function del_message(ident) {
    delete get_scope('IvreMessagesCtrl').messages[ident];
}

ivreWebUi
    .controller('IvreReportCtrl', function ($scope) {

	/********** Common **********/

	$scope.shared = {};

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
	    new GraphMap($("#chartmap" + nb), $scope.shared.filter.query)
		.no_buttons()
		.build();
	};

	$scope.build_top_value = function(field, nb, size, colors) {
	    new GraphTopValues($("#chart" + nb), $scope.shared.filter.query,
			      field, 10, size, colors)
		.no_buttons()
		.build();
	};
	$scope.build_all = function() {
	    for (var elementid in $scope.elements) {
		element = $scope.elements[elementid];
		if (element.type === "Top-values") {
		    bcolor = undefined;
		    if ($scope.colors[element.color].fg === "white")
			bcolor = ["white"];
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
		     $scope.error_source));
	};
	$scope.upload = function() {
	    if($scope.check()) {
		$("#uploadReferer")
		    .attr("value", document.referrer);
		$("#upload")
		    .attr("action",
			  'cgi-bin/scanupload.py')
		    .submit();
	    }
	};
    });

ivreWebUi
    .controller('IvreCompareCtrl', function ($scope) {
	$scope.all_filters = [];
	$scope.apply_on_filter_update = [$scope];
	$scope.names = {
	    undefined: "Common",
	    "set1": "Set 1",
	    "set2": "Set 2"
	};
	$scope.setparam = function(param, value, unique, notnow) {
	     return setparam(FILTER, param, value, unique, notnow);
	};
	$scope.unsetparam = function(param) {
	     return unsetparam(FILTER, param);
	};
	$scope.submitform = function() {
	    ToolTip.remove_all();
	    for(var i in $scope.all_filters) {
		$scope.all_filters[i].on_param_update();
	    }
	};
	$scope.is_ready = function() {
	    var filter;
	    for(var i in $scope.all_filters) {
		filter = $scope.all_filters[i];
		if(filter.name && filter.name.substr(0, 3) === "set" &&
		   filter.count === undefined) {
		    return false;
		}
	    }
	    return true;
	};
	$scope.build_ip_plane = function() {
	    var totalnbrres, filter, i = 1;
	    hidecharts();
	    for(var name in FILTERS) {
		if(name.substr(0, 3) === "set") {
		    filter = FILTERS[name];
		    totalnbrres = filter.count;
		    if(totalnbrres === undefined)
			return;
		    if(totalnbrres < config.warn_dots_count || confirm("You are about to ask your browser to display " + totalnbrres + " dots, which is a lot and might slow down, freeze or crash your browser. Do you want to continue?")) {
			new GraphPlane($("#chart" + i++), filter.query)
			    .build();
		    }
		}
	    }
	};
	$scope.build_ip_map = function() {
	    var i = 1;
	    hidecharts();
	    for(var name in FILTERS) {
		if(name.substr(0, 3) === "set")
		    new GraphMap($("#chart" + i++),
				 FILTERS[name].query)
		    .build();
	    }
	};
	$scope.build_ip_timeline = function(modulo) {
	    var totalnbrres, filter, i = 1;
	    hidecharts();
	    for(var name in FILTERS) {
		if(name.substr(0, 3) === "set") {
		    filter = FILTERS[name];
		    totalnbrres = filter.count;
		    if(totalnbrres === undefined)
			return;
		    if(totalnbrres < config.warn_dots_count || modulo !== undefined || confirm("You are about to ask your browser to display " + totalnbrres + " dots, which is a lot and might slow down, freeze or crash your browser. Do you want to continue?")) {
			new GraphTimeline($("#chart" + i++),
					  filter.query, modulo)
			    .build();
		    }
		}
	    }
	};
	$scope.build_ip_ports = function() {
	    var totalnbrres, filter, i = 1;
	    hidecharts();
	    for(var name in FILTERS) {
		if(name.substr(0, 3) === "set") {
		    filter = FILTERS[name];
		    totalnbrres = filter.count;
		    if(totalnbrres === undefined)
			return;
		    if(totalnbrres < config.warn_dots_count || confirm("You are about to ask your browser to display " + totalnbrres + " dots, which is a lot and might slow down, freeze or crash your browser. Do you want to continue?")) {
			new GraphIpPort($("#chart" + i++), filter.query)
		    .build();
		    }
		}
	    }
	};
	$scope.build_top_chart = function() {
	    var i = 1;
	    hidecharts();
	    for(var name in FILTERS) {
		if(name.substr(0, 3) === "set")
		    new GraphTopValues($("#chart" + i++),
				       FILTERS[name].query,
				       $scope.topvaluesfield, 10)
		    .build();
	    }
	};
});
