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

/************* Graphing utilities **************/

function hidecharts() {
    $(".chart").css("display", "none");
}

// from http://stackoverflow.com/a/12935903/3223422
function heatmapColour(value) {
    // 0 == 360 : red
    // 120 : green
    // 240 : blue
    // 300 : purple
    var h = 240 * (1 - value);
    return "hsl(" + h + ", 100%, 50%)";
}

var Graph = (function() {
    function Graph(chart, query) {
	this.container = chart;
	this.title = $('[name="charttitle"]', chart);
	this.chart = $('[name="chartcontent"]', chart);
	this.query = query;
	this.buttons = true;
	this.filename = "Graph";
    }

    $.extend(Graph.prototype, {
	build: function() {
	    var graphobject = this;
	    hideall();
	    this.chart.empty();
	    this.container.css("display", "inline");
	    $.ajax({
		url: this.get_url(),
		jsonp: "callback",
		dataType: "jsonp",
		success: function(data) {
		    graphobject.draw.call(graphobject, data);
		}
	    });
	},
	no_buttons: function() {
	    this.buttons = false;
	    return this;
	},
	add_download_button: function() {
	    if(! this.buttons)
		return;
	    var a = document.createElement('a');
	    a.onclick = function() {
		var blob = new Blob(
		    [this.parentNode.getElementsByTagName("svg")[0].outerHTML],
		    {type: "image/svg"});
		this.setAttribute('href', window.URL.createObjectURL(blob));
		return true;
	    };
	    a.download = "IVRE-" + this.filename + ".svg";
	    a.href = "#";
	    a.innerHTML = '<button><i class="glyphicon glyphicon-download-alt download"></i></button>';
	    a.setAttribute("title", "Download");
	    this.chart.append(a);
	}
    });

    return Graph;
})();

var GraphTopValues = (function(_super) {

    function GraphTopValues(chart, query, field, count, size, colors) {
        _super.call(this, chart, query);
	this.field = field;
	this.count = count || 15;
	this.size = size;
	this.colors = colors;
	this.filename = "TopValues";
    }

    $.extend(GraphTopValues.prototype, _super.prototype, {
	get_url: function() {
	    return 'cgi-bin/scanjson.py?action=topvalues:' +
		encodeURIComponent(this.field) + ':' + this.count + '&q=' +
		encodeURIComponent(this.query);
	},
	draw: function(dataset) {
	    var field = this.field,
	    chart = this.chart,
	    size = this.size || 5,
	    colors = this.colors || [ "steelblue", "lightblue" ],
	    w = 100 * size,
	    h = 30 * dataset.length,
	    //labelpad = 60,
	    labelpad = 10 + d3.max(dataset, function(t) {
		var v = d3.select(chart.selector)
		    .append('svg:svg')
		    .append('svg:text')
		    .text(t.value)[0][0]
		    .getComputedTextLength();
		d3.select(chart.selector)[0][0].innerHTML = '';
		return v;}),
	    data = dataset.map(function(t) {return t.value;}),
	    labels = dataset.map(function(t) {return t.label;}),
	    x = d3.scale.linear()
		.domain([0, d3.max(data)])
		.range([0, w - labelpad]),
	    y = d3.scale.ordinal()
		.domain(d3.range(data.length))
		.rangeBands([0, h], 0.2),
	    prepareoutput = function(x) {return x;},
	    preparefilter = undefined,
	    preparetitle = undefined,
	    neg;
	    if(field.substr(0,1) === "-") {
		field = field.substr(1);
		neg = true;
	    }
	    else
		neg = false;
	    if(field.substr(0, 9) === 'portlist:') {
		prepareoutput = function(x) {
		    return (
			x.length === 0) ? "None" :
			x.map(function(x) {return x.join('/')}
			     ).join(' / ');
		};
		if(field.substr(9) === 'open')
		    preparefilter = function(x) {
			if(x.length === 0)
			    return 'setparam(FILTER, "countports", "0", true);';
			else
			    return 'setparam(FILTER, "open", "' + x.map(function(x) {return x.join('/');}).join(',') + '", true, true); setparam(FILTER, "countports", "' + x.length + '", true);';
		    };
	    }
	    else if(['cert.issuer', 'cert.subject'].indexOf(field) !== -1)
		prepareoutput = function(x) {
		    var attributes = {
			'commonName': 'cn',
			'countryName': 'c',
			'organizationName': 'o',
			'organizationalUnitName': 'ou',
			'emailAddress': 'email',
			'localityName': 'locality',
			'stateOrProvinceName': 'state',
		    };
		    var result = [];
		    for(var k in x) {
			if(k in attributes)
			    result.push(attributes[k] + '=' + x[k]);
			else
			    result.push(k + '=' + x[k]);
		    }
		    return result.join('/');
		};
	    else if(field === 'asnum') {
		preparefilter = function(x) {
		    return 'setparam(FILTER, "asnum", "' + x + '", true);';
		};
	    }
	    else if(field.substr(0, 4) === 'smb.') {
		preparefilter = function(x) {
		    return 'setparam(FILTER, "' + field + '", "' +
			x.replace(/\\x/g, '\\\\\\\\x') + '", true);';
		};
	    }
	    else if(field === 'sshkey.bits') {
		prepareoutput = function(x) {
		    return x.join(' / ');
		};
		preparefilter = function(x) {
		    return 'setparam(FILTER, "sshkey.type", "' + x[0] + '", false, true); setparam(FILTER, "sshkey.bits", "' + x[1] + '");';
		};
	    }
	    else if(field.substr(0, 7) === 'sshkey.') {
		preparefilter = function(x) {
		    return 'setparam(FILTER, "' + field + '", "' + x + '");';
		};
	    }
	    else if(field === 'devicetype') {
		preparefilter = function(x) {
		    return 'setparam(FILTER, "devtype", "' + x + '", true);';
		};
	    }
	    else if(field === 'as') {
		prepareoutput = function(x) {
		    return x[1] || ("AS" + x[0]);
		};
		preparetitle = function(x) {
		    return x[0];
		};
		preparefilter = function(x) {
		    return 'setparam(FILTER, "asnum", "' + x[0] + '", true);';
		};
	    }
	    else if(field === 'country') {
		prepareoutput = function(x) {
		    return x[1];
		};
		preparetitle = function(x) {
		    return x[0];
		};
		preparefilter = function(x) {
		    return 'setparam(FILTER, "country", "' + x[0] + '", true);';
		};
	    }
	    else if(field === 'city') {
		prepareoutput = function(x) {
		    return x.join(' / ');
		};
		preparefilter = function(x) {
		    return 'setparam(FILTER, "country", "' + x[0] + '", true, true); setparam(FILTER, "city", "' + x[1] + '");';
		};
	    }
	    else if(field === 'vulns.id') {
		preparefilter = function(x) {
		    return 'setparam(FILTER, "vuln", "' + x + '");';
		};
	    }
	    else if(field.substr(0, 6) === 'vulns.') {
		prepareoutput = function(x) {
		    return x[1]
		};
		preparetitle = function(x) {
		    return x[0];
		};
		preparefilter = function(x) {
		    return 'setparam(FILTER, "vuln", "' + x[0] + '");';
		};
	    }
	    else if(field === 'category') {
		preparefilter = function(x) {
		    return 'setparam(FILTER, "category", "' + x + '");';
		};
	    }
	    else if(field === 'source') {
		preparefilter = function(x) {
		    return 'setparam(FILTER, "source", "' + x + '", true);';
		};
	    }
	    else if(field === 'script') {
		preparefilter = function(x) {
		    return 'setparam(FILTER, "script", "' + x + '");';
		};
	    }
	    else if(field === 'port') {
		prepareoutput = function(x) {
		    return x.join(' / ');
		};
	    }
	    else if(field.substr(0, 5) === 'port:') {
		var info = field.substr(5);
		prepareoutput = function(x) {
		    return x.join(' / ');
		};
		switch(info) {
		case "open":
		case "filtered":
		case "closed":
		    preparefilter = function(x) {
			return 'setparam(FILTER, "' + info + '", "' + x[0] + '/' + x[1] + '");';
		    };
		    break;
		default:
		    preparefilter = function(x) {
			return 'setparam(FILTER, "service", "' + info + ':' + x + '");';
		    };
		    break;
		}
	    }
	    else if(field === 'countports:open') {
		preparefilter = function(x) {
		    return 'setparam(FILTER, "countports", "' + x + '");';
		};
	    }
	    else if(field.substr(0, 7) === 'service') {
		prepareoutput = function(x) {
		    return x || '[unknown]';
		};
		if(field[7] === ':') {
		    preparefilter = function(x) {
			return 'setparam(FILTER, "service", "' + x + ':' + field.substr(8) + '");';
		    };
		}
		else {
		    preparefilter = function(x) {
			return 'setparam(FILTER, "service", "' + x + '");';
		    };
		}
	    }
	    else if(field.substr(0, 7) === 'product') {
		prepareoutput = function(x) {
		    return x[1] || (x[0] ? x[0] + ' / ' : '') + '[unknown]';
		};
		preparetitle = function(x) {
		    return x[0] || '[unknown]';
		};
		if(field[7] === ':' && field.substr(8) % 1 === 0) {
		    preparefilter = function(x) {
			return 'setparam(FILTER, "product", "' + x[0] + ':' + x[1] + field.substr(7) + '");';
		    };
		}
		else {
		    preparefilter = function(x) {
			return 'setparam(FILTER, "product", "' + x[0] + ':' + x[1] + '");';
		    };
		}
	    }
	    else if(field.substr(0, 7) === 'version') {
		prepareoutput = function(x) {
		    return x[2] ? x[1] + " " + x[2] : (
			x[1] ? x[1] + " [unknown]" : (
			    x[0] ? x[0] + ' / ' : '') + "[unknown]");
		};
		preparetitle = function(x) {
		    return x[0] || '[unknown]';
		};
		if(field[7] === ':' && field.substr(8) % 1 === 0) {
		    preparefilter = function(x) {
			return 'setparam(FILTER, "version", "' + x[0] + ':' + x[1] + ':' + x[2] + field.substr(7) + '");';
		    };
		}
		else {
		    preparefilter = function(x) {
			return 'setparam(FILTER, "version", "' + x[0] + ':' + x[1] + ':' + x[2] + '");';
		    };
		}
	    }
	    else if(field.substr(0, 3) === 'cpe') {
		prepareoutput = function(x) {
		    return x.join(":");
		};
		preparefilter = function(x) {
		    return 'setparam(FILTER, "cpe", "' + x.join(":") + '")';
		};
	    }
	    else if(field === 'screenwords') {
		preparefilter = function(x) {
		    return 'setparam(FILTER, "screenwords", "' + x + '")';
		};
	    }
	    else if(field.substr(0, 3) === 'hop') {
		if(field[3] === ':')
		    preparefilter = function(x) {
			return 'setparam(FILTER, "hop", "' + x + '", ' + field.substr(4) + ');';
		    };
		else
		    preparefilter = function(x) {
			return 'setparam(FILTER, "hop", "' + x + '");';
		    };
	    }
	    else if(field.substr(0, 7) === 'domains' && (field[7] === undefined ||
							 field[7] === ':')) {
		preparefilter = function(x) {
		    return 'setparam(FILTER, "domain", "' + x + '");';
		};
	    }
	    else if(field === 'ike.vendor_ids') {
		prepareoutput = function(x) {
		    return x[1];
		};
		preparetitle = function(x) {
		    return x[0];
		};
		preparefilter = function(x) {
		    return 'setparam(FILTER, "ike.vendor_id.value", "' + x[0] + '");';
		};
	    }
	    else if(field === 'ike.transforms') {
		prepareoutput = function(x) {
		    return x.join(" / ");
		};
	    }
	    else if(field === 'ike.notification') {
		preparefilter = function(x) {
		    return 'setparam(FILTER, "ike.notification", "' + x + '");';
		};
	    }

	    this.title.html(data.length + (neg ? " least" : " most") + " common " + field.replace(/</g, '&lt;').replace(/>/g, '&gt;') + " value" + (data.length >= 2 ? "s" : ""));

	    var vis = d3.select(chart.selector)
		.append("svg:svg")
		.attr("viewBox", [0, 0, w + 20, h + 20])
		.attr("preserveAspectRatio", "xMidYMid meet")
		.append("svg:g");

	    var bars = vis.selectAll("g.bar")
		.data(data)
		.enter().append("svg:g")
		.attr("class", "bar")
		.attr("transform", function(d, i) {
		    return "translate(" + labelpad + "," + y(i) + ")";
		});

	    colorBg = chart.getBg();
	    colorFg = getComputedStyle(chart[0]).color;

	    var bar = bars.append("svg:rect")
	    //.attr("fill", "steelblue")
		.attr("fill", function(d, i) {
		    return colors[i % colors.length];
		})
	    //.attr("width", x)
		.attr("width", 0)
		.attr("height", y.rangeBand())
		.attr("class", preparefilter === undefined ? "" : "clickable")
		.attr("onclick", function(d, i) {
		    return (preparefilter === undefined ?
			    undefined :
			    preparefilter(labels[i]));
		});

	    bar.append("svg:title")
		.text(function(d, i) {
		    if (preparetitle !== undefined)
			return preparetitle(labels[i]);
		});

	    bar.transition()
		.attr("width", x);

	    bars.append("svg:text")
		.attr("x", -6)
		.attr("y", y.rangeBand() / 2)
		.attr("dy", ".35em")
		.attr("text-anchor", "end")
		.text(function(d) {return d;})
		.attr("fill", colorFg);

	    bars.append("svg:text")
		.attr("x", function(d, i) {
		    return x(d, i) + (x(d, i) < (w - 10) / 2 ? 10 : -10);
		})
		.attr("fill", function(d, i) {
		    return x(d, i) < (w - 10) / 2 ? colorFg : colorBg;
		})
		.attr("font-weight", "bold")
		.attr("y", y.rangeBand() / 2)
		.attr("dy", ".35em")
		.attr("text-anchor", function(d, i) {
		    return x(d, i) < (w - 10) / 2 ? "start" : "end" ;
		})
		.text(function(d, i) {return prepareoutput(labels[i]);})
		.attr("class", preparefilter === undefined ? "" : "clickable")
		.attr("onclick", function(d, i) {
		    return (preparefilter === undefined ?
			    undefined :
			    preparefilter(labels[i]));
		})
		.append("svg:title")
		.text(function(d, i) {
		    if (preparetitle !== undefined)
			return preparetitle(labels[i]);
		});

	    // var rules = vis.selectAll("g.rule")
	    //     .data(x.ticks(10))
	    //     .enter().append("svg:g")
	    //     .attr("class", "rule")
	    //     .attr("transform", function(d) { return "translate(" + x(d) + ", 0)"; });

	    // rules.append("svg:line")
	    //     .attr("y1", h)
	    //     .attr("y2", h + 6)
	    //     .attr("x1", labelpad)
	    //     .attr("x2", labelpad)
	    //     .attr("stroke", "black");

	    // rules.append("svg:line")
	    //     .attr("y1", 0)
	    //     .attr("y2", h)
	    //     .attr("x1", labelpad)
	    //     .attr("x2", labelpad)
	    //     .attr("stroke", "white")
	    //     .attr("stroke-opacity", .3);

	    // rules.append("svg:text")
	    //     .attr("y", h + 10)
	    //     //.attr("x", labelpad-10)
	    //     .attr("dy", ".71em")
	    //     .attr("text-anchor", "middle")
	    //     .text(x.tickFormat(10));

	    this.add_download_button();
	}
    });

    return GraphTopValues;
})(Graph);

var GraphMap = (function(_super) {

    function GraphMap(chart, query, fullworld) {
        _super.call(this, chart, query);
	this.fullworld = fullworld;
	this.filename = "Map";
    }

    $.extend(GraphMap.prototype, _super.prototype, {
	get_url: function() {
	    return 'cgi-bin/scanjson.py?action=coordinates&ipsasnumbers=1&q=' +
		encodeURIComponent(this.query);
	},
	draw: function(locs) {
	    var chart = this.chart,
	    fullworld = this.fullworld,
	    w = 500,
	    h = 250;

	    this.title.html("Map");
	    var vis = d3.select(chart.selector).append("svg")
		.attr("viewBox", [0, 0, w, h])
		.attr("preserveAspectRatio", "xMidYMid meet");

	    d3.json("world-110m.json", function(error, world) {
		var projection =  d3.geo.mercator()
		    .scale(80)
		    .translate([w / 2, h / 2]);
		if(fullworld !== true) {
		    var bounds = [
			d3.extent(locs.geometries,
				  function(x) {return x.coordinates[0];}),
			d3.extent(locs.geometries,
				  function(x) {return x.coordinates[1];}),
		    ];
		    projection
			.center([d3.mean(bounds[0]), d3.mean(bounds[1])]);
		    var p1 = projection([bounds[0][0], bounds[1][0]]);
		    var p2 = projection([bounds[0][1], bounds[1][1]]);
		    projection
			.scale(70 * d3.min([w / Math.abs(p2[0] - p1[0]),
					    h / Math.abs(p2[1] - p1[1])]));
		}
		else {
		    projection.scale(w / 7);
		}

		var path = d3.geo.path()
		    .projection(projection);
		world = topojson.feature(world, world.objects.world110m);
		var locations = topojson.feature(locs, locs);
		var maxsize = 10, minsize = 1.2;
		var radiusscale = d3.scale.linear()
		    .domain(d3.extent(locations.features, function(i) {
			return i.properties.count;
		    }))
		    .range([minsize, maxsize]);

		var dotgradient = vis.append("svg:defs")
		    .append("svg:radialGradient")
		    .attr("id", "dotgradient");
		dotgradient.append("svg:stop")
		    .attr("offset", "0%")
		    .attr("stop-color", "red")
		    .attr("stop-opacity", 1);
		dotgradient.append("svg:stop")
		    .attr("offset", "30%")
		    .attr("stop-color", "red")
		    .attr("stop-opacity", 1/2);
		dotgradient.append("svg:stop")
		    .attr("offset", "100%")
		    .attr("stop-color", "red")
		    .attr("stop-opacity", 1/3);

		vis.selectAll("country")
		    .data(world.features)
		    .enter().append("path")
		    .attr("class", "clickable")
		    .attr("onclick", function(d) {
			return 'setparam(FILTER, "country", "' + d.id + '", true);';
		    })
		    .attr("d", path)
		    .attr("fill", "lightgrey")
		    .append("svg:title")
		    .text(function(d, i) {
			return d.properties.name + " (" + d.id + ")";
		    });
		vis.selectAll("dot")
		    .data(locations.features)
		    .enter().append("svg:circle")
		    .attr("class", "dot")
		    .attr("r", function(d) {
			return radiusscale(d.properties.count);
		    })
		    .attr("cx", function(d) {
			return projection(d.geometry.coordinates)[0];
		    })
		    .attr("cy", function(d) {
			return projection(d.geometry.coordinates)[1];
		    })
		    .attr("fill", "url(#dotgradient)");
		// The next lines enable "boundary dots" (debug)
		// vis.selectAll("dotbound")
		//     .data([[bounds[0][0], bounds[1][0]],
		// 	   [bounds[0][0], bounds[1][1]],
		// 	   [d3.mean(bounds[0]), d3.mean(bounds[1])],
		// 	   [bounds[0][1], bounds[1][0]],
		// 	   [bounds[0][1], bounds[1][1]]])
		//     .enter().append("svg:circle")
		//     .attr("class", "dot")
		//     .attr("r", 4)
		//     .attr("cx", function(d, i) {
		// 	return projection(d)[0];
		//     })
		//     .attr("cy", function(d, i) {
		// 	return projection(d)[1];
		//     })
		//     .attr("fill", "steelblue");
	    });

	    this.add_download_button();

	    if(this.buttons) {
		var b, graphobj = this;
		if(fullworld === true) {
		    b = document.createElement('button');
		    b.onclick = function() {
			new GraphMap(graphobj.container, graphobj.query)
			    .build();
		    };
		    b.innerHTML = '<i class="glyphicon glyphicon-zoom-in"></i>';
		    b.setAttribute("title", "Adjust zoom");
		}
		else {
		    b = document.createElement('button');
		    b.onclick = function() {
			new GraphMap(graphobj.container, graphobj.query, true)
			    .build();
		    };
		    b.innerHTML = '<i class="glyphicon glyphicon-zoom-out"></i>';
		    b.setAttribute("title", "Zoom out");
		}
		chart.append(b);
	    }
	}
    });

    return GraphMap;
})(Graph);

var GraphPlane = (function(_super) {

    function GraphPlane(chart, query) {
        _super.call(this, chart, query);
	this.filename = "AddressSpace";
    }

    $.extend(GraphPlane.prototype, _super.prototype, {
	get_url: function() {
	    return 'cgi-bin/scanjson.py?action=countopenports&ipsasnumbers=1&q=' +
		encodeURIComponent(this.query);
	},
	draw: function(ips) {
	    var chart = this.chart,
	    real_w = 500,
	    real_h = 450,
	    w = real_w - 100,
	    h = real_h - 50,
	    ipsint = ips.map(function(i) {
		return [~~(i[0] / 65536), i[0] % 65536, i[1]];
	    }),
	    xextent = d3.extent(ipsint, function(i) {return i[0];});
	    yextent = d3.extent(ipsint, function(i) {return i[1];}).reverse();
	    x = d3.scale.linear()
		.domain(xextent)
		.range([0, w]),
	    y = d3.scale.linear()
		.domain(yextent)
		.range([0, h]),
	    colscale = d3.scale.log()
		.domain(d3.extent(ips, function(i) {return i[1] + 1;}))
		.range([0, 1]),
	    same_slash_16 = false;
	    if(xextent[0] === xextent[1]) {
		ipsint = ips.map(function(i) {
		    return [~~(i[0] / 256), i[0] % 256, i[1]];
		});
		xextent = d3.extent(ipsint, function(i) {return i[0];});
		x.domain(xextent);
		yextent = d3.extent(ipsint, function(i) {return i[1];})
		    .reverse();
		y.domain(yextent);
		same_slash_16 = true;
	    }
	    this.title.html('IP addresses');

	    var vis = d3.select(chart.selector)
		.append("svg:svg")
		.attr("viewBox", [0, 0, real_w, real_h])
		.attr("preserveAspectRatio", "xMidYMid meet")
		.append("svg:g")
		.attr("transform", "translate(40, 10)");

	    var xaxis = [], yaxis = [], xstep, ystep;
	    if(same_slash_16) {
		xstep = (Math.max((xextent[1] - xextent[0]) / 7, 1));
		ystep = (Math.max((yextent[0] - yextent[1]) / 7, 1));
	    }
	    else {
		xstep = (Math.max((xextent[1] - xextent[0]) / 7 / 256, 1)) * 256;
		ystep = (Math.max((yextent[0] - yextent[1]) / 7, 1));
	    }
	    for(var i = xextent[0]; i <= (xextent[1]+1); i += xstep) {
		xaxis.push(i);
	    }
	    for(i=yextent[1]; i <= (yextent[0]+1); i += ystep) {
		yaxis.push(i);
	    }

	    var plane = vis.append("g");

	    plane.selectAll("g.dot")
		.data(ips)
		.enter().append("svg:circle")
		.attr("class", "dot")
		.attr("r", 1.5)
		.attr("cx", function(d, i) {return x(ipsint[i][0]);})
		.attr("cy", function(d, i) {return y(ipsint[i][1]);})
		.attr("fill-opacity", 1)
		.attr("fill", function(d, i) {
		    return heatmapColour(colscale(ipsint[i][2] + 1));
		});
	    //.attr("fill", "steelblue");

	    var rulesx = vis.selectAll("g.rulex")
		.data(xaxis)
		.enter().append("svg:g")
		.attr("class", "rule")
		.attr("transform", function(d) {
		    return "translate(" + x(d) + ", 0)";
		});

	    rulesx.append("svg:line")
		.attr("y1", h)
		.attr("y2", h + 10)
		.attr("x1", 0)
		.attr("x2", 0)
		.attr("stroke", "black");

	    rulesx.append("svg:text")
		.attr("y", h + 15)
		.attr("x", 0)
		.attr("dy", ".71em")
		.attr("text-anchor", "middle")
		.text(function(d) {
		    if(same_slash_16)
			return Math.floor(d/65536)+'.'+Math.floor((d/256)%256)+'.'+(Math.floor(d)%256);
		    else
			return Math.floor(d/256)+'.'+(Math.floor(d)%256);
		});

	    var rulesy = vis.selectAll("g.ruley")
		.data(yaxis)
		.enter().append("svg:g")
		.attr("class", "rule")
		.attr("transform", function(d) {
		    return "translate(0, " + y(d) + ")";
		});

	    rulesy.append("svg:line")
		.attr("y1", 0)
		.attr("y2", 0)
		.attr("x1", -10)
		.attr("x2", 0)
		.attr("stroke", "black");

	    rulesy.append("svg:text")
		.attr("y", 0)
		.attr("x", -25)
		.attr("dy", ".5ex")
		.attr("text-anchor", "middle")
		.text(function(d) {
		    if(same_slash_16)
			return Math.floor(d);
		    else
			return Math.floor(d/256);
		});

	    var brush = d3.svg.brush()
		.x(x)
		.on("brushend", brushended);

	    var gbrush = plane.append("g")
		.attr("class", "brush")
		.call(brush)
		.call(brush.event);

	    gbrush.selectAll("rect")
		.attr("height", h);

	    function brushended() {
		if(!d3.event.sourceEvent) return; // only transition after input
		var extent;
		if(same_slash_16) {
		    extent = brush.extent().map(function(val) {
			return Math.floor(val / 65536) + '.' +
			    Math.floor((val / 256) % 256) + '.' +
			    Math.floor(val % 256) + '.';
		    });
		    setparam(FILTER, "range", extent[0] + '0-' + extent[1] + '255');
		}
		else {
		    extent = brush.extent().map(function(val) {
			return Math.floor(val / 256) + '.' +
			    Math.floor(val % 256) + '.';
		    });
		    setparam(FILTER, "range",
			     extent[0] + '0.0-' + extent[1] + '255.255');
		}
		d3.select(this).transition()
		    .call(brush.extent(extent))
		    .call(brush.event);
	    }
	    this.add_download_button();
	}
    });

    return GraphPlane;
})(Graph);

var GraphIpPort = (function(_super) {

    function GraphIpPort(chart, query) {
        _super.call(this, chart, query);
	this.filename = "IPsPorts";
	this._colors = {"open": "green", "closed": "red", "filtered": "orange"};
	this.colors = function(val) {
	    return this._colors[val];
	};
    }

    $.extend(GraphIpPort.prototype, _super.prototype, {
	get_url: function() {
	    return 'cgi-bin/scanjson.py?action=ipsports&ipsasnumbers=1&q=' +
		encodeURIComponent(this.query);
	},
	draw: function(ips) {
	    var chart = this.chart, graphobject = this,
		real_w = 500,
		real_h = 450,
		w = real_w - 100,
		h = real_h - 60,
		xmin = d3.min(ips, function(i) {return i[0];}),
		xmax = d3.max(ips, function(i) {return i[0];}),
		ymin = d3.min(ips, function(i) {
		    return d3.min(i[1], function(j) {return j[0];});
		}),
		ymax = d3.max(ips, function(i) {
		    return d3.max(i[1], function(j) {return j[0];});
		}),
		x = d3.scale.linear()
		.domain(d3.extent(ips, function(i) {return i[0];}))
		.range([0, w]),
		y = d3.scale.log()
		.domain([ymin, ymax])
		.range([h, 0]),
		ips_ports = ips.map(function(x) {
		    return x[1].map(function(t) {
			return [x[0], t[0], t[1]];
		    });
		}).reduce(function(x, y) {
		    return x.concat(y);
		}, []);

	    this.title.html("Ports status");

	    var vis = d3.select(chart.selector)
		.append("svg:svg")
		.attr("viewBox", [0, 0, real_w, real_h])
		.attr("preserveAspectRatio", "xMidYMid meet")
		.append("svg:g")
		.attr("transform", "translate(70, 10)");

	    var plane = vis.append("g");

	    plane.selectAll("g.dot")
		.data(ips_ports)
		.enter().append("svg:circle")
		.attr("class", "dot")
		.attr("r", 1.5)
		.attr("cx", function(d) {return x(d[0]);})
		.attr("cy", function(d) {return y(d[1]);})
		.attr("fill-opacity", 1)
		.attr("fill", function(d) {return graphobject.colors(d[2]);});

	    var xaxis = [];
	    var xstep = Math.max((xmax - xmin) / 10 / 16777216, 1) * 16777216;
	    for(var i = xmin; i <= (xmax+1); i += xstep) {
		xaxis.push(i);
	    }

	    var rulesx = vis.selectAll("g.rulex")
		.data(xaxis)
		.enter().append("svg:g")
		.attr("class", "rule")
		.attr("transform", function(d) {
		    return "translate(" + x(d) + ", 0)";
		});

	    rulesx.append("svg:line")
		.attr("y1", h)
		.attr("y2", h + 10)
		.attr("x1", 0)
		.attr("x2", 0)
		.attr("stroke", "black");

	    rulesx.append("svg:text")
		.attr("y", h + 15)
		.attr("x", 0)
		.attr("dy", ".71em")
		.attr("text-anchor", "middle")
		.attr("dominant-baseline", "middle")
		.attr("transform", "rotate(-45, 5, " + (h + 25) + ")")
		.text(function(d) {
		    return Math.floor(d / 16777216) + '.' +
			(Math.floor(d / 65536) % 256);
		});

	    var yaxis = [];
	    var ystep = Math.max(h / 10);
	    for(i = 0; i <= h; i += ystep) {
		yaxis.push(i);
	    }

	    var rulesy = vis.selectAll("g.ruley")
		.data(yaxis)
		.enter().append("svg:g")
		.attr("class", "rule")
		.attr("transform", function(d) {
		    return "translate(0, " + d + ")";
		});

	    rulesy.append("svg:line")
		.attr("y1", 0)
		.attr("y2", 0)
		.attr("x1", -10)
		.attr("x2", 0)
		.attr("stroke", "black");

	    rulesy.append("svg:text")
		.attr("y", 0)
		.attr("x", -15)
		.attr("dy", ".5ex")
		.attr("text-anchor", "end")
		.text(function(d) {
		    return Math.floor(y.invert(d));
		});

	    var brush = d3.svg.brush()
		.x(x)
		.on("brushend", brushended);

	    var gbrush = plane.append("g")
		.attr("class", "brush")
		.call(brush)
		.call(brush.event);

	    gbrush.selectAll("rect")
		.attr("height", h);

	    function brushended() {
		if(!d3.event.sourceEvent) return; // only transition after input
		var extent = brush.extent().map(function(val) {
		    return Math.floor(val / 16777216) + '.' +
			Math.floor((val / 65536) % 256) + '.' +
			Math.floor((val / 256) % 256) + '.' +
			Math.floor(val % 256);
		});
		setparam(FILTER, "range", extent[0] + '-' + extent[1]);
		d3.select(this).transition()
		    .call(brush.extent(extent))
		    .call(brush.event);
	    }

	    this.add_download_button();
	}
    });

    return GraphIpPort;
})(Graph);

var GraphTimeline = (function(_super) {

    function GraphTimeline(chart, query, modulo) {
        _super.call(this, chart, query);
	this.modulo = modulo;
	this.filename = "Timeline";
    }

    $.extend(GraphTimeline.prototype, _super.prototype, {
	get_url: function() {
	    var url =  'cgi-bin/scanjson.py?action=timeline&ipsasnumbers=1&q=' +
		encodeURIComponent(this.query);
	    if(this.modulo) {
		url += "&modulo=" + this.modulo;
	    }
	    return url;
	},
	draw: function(ips) {
	    var chart = this.chart,
	    real_w = 500,
	    real_h = 450,
	    w = real_w - 100,
	    h = real_h - 50,
	    xmin = d3.min(ips, function(i) {return i[0];}),
	    xmax = d3.max(ips, function(i) {return i[0];}),
	    ymin = d3.min(ips, function(i) {return i[1];}),
	    ymax = d3.max(ips, function(i) {return i[1];}),
	    x = d3.scale.linear()
		.domain(d3.extent(ips, function(i) {return i[0];}))
		.range([0, w]),
	    y = d3.scale.linear()
		.domain(d3.extent(ips, function(i) {return i[1];}))
		.range([h, 0]),
	    colscale = d3.scale.log()
		.domain(d3.extent(ips, function(i) {return i[2] + 1;}))
		.range([0, 1]),
	    date2text;
	    this.title.html("Timeline");
	    if(xmax - xmin > 31536000) // 365 days
		date2text = function(d) {
		    return (d.getMonth() + 1) + '/' + d.getFullYear();
		};
	    else if (xmax - xmin > 2419200) // 28 days
		date2text = function(d) {
		    return d.getDate() + '/' + (d.getMonth() + 1);
		};
	    else if (xmax - xmin > 86400) // 1 day
		date2text = function(d) {
		    return d.getDate() + ' - ' + d.getHours() + 'h';
		};
	    else if (xmax - xmin > 3600)
		date2text = function(d) {
		    return d.getHours() + ':' + d.getMinutes();
		};
	    else
		date2text = function(d) {return d;};

	    var vis = d3.select(chart.selector)
		.append("svg:svg")
		.attr("viewBox", [0, 0, real_w, real_h])
		.attr("preserveAspectRatio", "xMidYMid meet")
		.append("svg:g")
		.attr("transform", "translate(70, 10)");

	    var plane = vis.append("g");

	    plane.selectAll("g.dot")
		.data(ips)
		.enter().append("svg:circle")
		.attr("class", "dot")
		.attr("r", 1.5)
		.attr("cx", function(d, i) {return x(ips[i][0]);})
		.attr("cy", function(d, i) {return y(ips[i][1]);})
		.attr("fill-opacity", 1)
		.attr("fill", function(d, i) {
		    return heatmapColour(colscale(ips[i][2] + 1));
		});

	    var xaxis = [];
	    var xstep = Math.max((xmax - xmin) / 6, 1);
	    for(var i = xmin; i <= (xmax+1); i += xstep) {
		xaxis.push(i);
	    }

	    var rulesx = vis.selectAll("g.rulex")
		.data(xaxis)
		.enter().append("svg:g")
		.attr("class", "rule")
		.attr("transform", function(d) {
		    return "translate(" + x(d) + ", 0)";
		});
    
	    rulesx.append("svg:line")
		.attr("y1", h)
		.attr("y2", h + 10)
		.attr("x1", 0)
		.attr("x2", 0)
		.attr("stroke", "black");
    
	    rulesx.append("svg:text")
		.attr("y", h + 15)
		.attr("x", 0)
		.attr("dy", ".71em")
		.attr("text-anchor", "middle")
		.attr("dominant-baseline", "middle")
		//.attr("transform", "rotate(45, 0, " + (h + 15) + ")")
		.text(function(d) {d = new Date(d*1000); return date2text(d);});

	    var yaxis = [];
	    var ystep = Math.max((ymax - ymin) / 20 / 16777216, 1) * 16777216;
	    for(i = ymin; i <= (ymax+1); i += ystep) {
		yaxis.push(i);
	    }

	    var rulesy = vis.selectAll("g.ruley")
		.data(yaxis)
		.enter().append("svg:g")
		.attr("class", "rule")
		.attr("transform", function(d) {
		    return "translate(0, " + y(d) + ")";
		});
    
	    rulesy.append("svg:line")
		.attr("y1", 0)
		.attr("y2", 0)
		.attr("x1", -10)
		.attr("x2", 0)
		.attr("stroke", "black");

	    rulesy.append("svg:text")
		.attr("y", 0)
		.attr("x", -15)
		.attr("dy", ".5ex")
		.attr("text-anchor", "end")
		.text(function(d) {
		    return Math.floor(d / 16777216) + '.' +
			(Math.floor(d / 65536) % 256);
		});

	    if(this.modulo === undefined) {
		function brushended() {
		    if (!d3.event.sourceEvent) return; // only transition after input
		    var extent = brush.extent();
		    setparam(FILTER, "timerange", extent[0] + '-' + extent[1]);
		    d3.select(this).transition()
			.call(brush.extent(extent))
			.call(brush.event);
		}

		var brush = d3.svg.brush()
		    .x(x)
		    .on("brushend", brushended);

		var gbrush = plane.append("g")
		    .attr("class", "brush")
		    .call(brush)
		    .call(brush.event);

		gbrush.selectAll("rect")
		    .attr("height", h);
	    }

	    this.add_download_button();
	}
    });

    return GraphTimeline;
})(Graph);

var GraphDiffCategories = (function(_super) {

    function GraphDiffCategories(chart, query, category1, category2,
				 onlydiff) {
	_super.call(this, chart, query);
	this.category1 = category1;
	this.category2 = category2;
	this.onlydiff = onlydiff;
	this.filename = "DiffCategories";
	this.colors = function(val) {
	    return heatmapColour((val + 1) / 2);
	};
    }

    $.extend(GraphDiffCategories.prototype, _super.prototype, {
	get_url: function() {
	    var url = 'cgi-bin/scanjson.py?action=diffcats&ipsasnumbers=1&cat1=' +
		encodeURIComponent(this.category1) + '&cat2=' +
		encodeURIComponent(this.category2) + '&query=' +
		encodeURIComponent(this.query);
	    if(this.onlydiff) {
		url += '&onlydiff=1';
	    }
	    return url;
	}
    });

    return GraphDiffCategories;
})(GraphIpPort);
