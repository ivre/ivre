/*
 * This file is part of IVRE.
 * Copyright 2011 - 2014 Pierre LALET <pierre.lalet@cea.fr>
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

function setdefaultconfig() {
    var defaultconfig = {
	"notesbase": "/dokuwiki/#IP#",
	"cgibase": "/cgi-bin/scanjson.py",
	"dflt": {
	    "skip": 0,
	    "limit": 10,
	},
	"warn_dots_count": 20000,
    };

    for(var k in defaultconfig) {
	if (config[k] === undefined) {
	    config[k] = defaultconfig[k];
	}
    }
}

setdefaultconfig();

/* global variables */
var parameters = [];
var parametersprotected = [];
var parametersobj = {};
var parametersobjunalias = {};
var clicktimeout = null;
var wanted_portscripts, wanted_hostscripts, wanted_hops;
// the initial prev_query has to be an object and to be different than
// any valid query
var prev_query = {"thiswillneverexist": []};
var query;

/* Chrome */
// if(String.prototype.repeat === undefined) {
//     String.prototype.repeat = function(num) {
// 	return new Array( num + 1 ).join(this);
//     };
// }
function repeat(string, num) {
    return new Array(num + 1).join(string);
}


function hideall() {
    var elts = Array.prototype.slice.call(
	document.getElementById('notes-container').children);
    for(var i in elts)
	elts[i].style.display = "none";
}

function hidecharts() {
    document.getElementById('charts').style.display = "none";
}

function build_top_chart(f) {
    var field = f.getElementsByTagName('input')[0].value;
    hideall();
    var c1 = document.getElementById('chart1');
    c1.innerHTML = "";
    var s = document.getElementById('chart1script');
    if(s) c1.parentNode.removeChild(s);
    document.getElementById('charts').style.display = 'inline';
    s = document.createElement('script');
    s.id = 'chart1script';
    s.src = config.cgibase + '?callback=' +
	encodeURIComponent("(function(data){build_chart('chart1', '" +
			   field + "', data);})") +
	'&countfield='+field+'&countnbr=15&q=' +
	encodeURIComponent(query);
    c1.parentNode.appendChild(s);
}

function add_download_button(div, title) {
    var a = document.createElement('a');
    a.onclick = function() {
	var blob = new Blob(
	    [this.parentNode.getElementsByTagName("svg")[0].outerHTML],
	    {type: "image/svg"});
	this.setAttribute('href', window.URL.createObjectURL(blob));
	return true;
    };
    if(title === undefined)
	title = "Graph";
    a.download = "IVRE-" + title + ".svg";
    a.href = "#";
    a.innerHTML = '<button><i class="icon-download-alt"></i></button>';
    a.setAttribute("title", "Download");
    div.appendChild(a);
}

// global graph stuff

// from http://stackoverflow.com/a/12935903/3223422
function heatmapColour(value) {
    // 0 == 360 : red
    // 120 : green
    // 240 : blue
    // 300 : purple
    var h = 240 * (1 - value);
    return "hsl(" + h + ", 100%, 50%)";
}

function build_chart_plane(chart, ips) {
    var w = 500,
    h = 450,
    ipsint = ips.map(function(i) {
	return [~~(i[0] / 65536), i[0] % 65536, i[1]];
    }),
    xmin = (d3.min(ipsint, function(i) {return i[0];}) / 256) * 256,
    xmax = (d3.max(ipsint, function(i) {return i[0];}) / 256) * 256,
    x = d3.scale.linear()
	.domain(d3.extent(ipsint, function(i) {return i[0];}))
	.range([0, w]),
    y = d3.scale.linear()
	.domain([65536, 0])
	.range([0, h]),
    colscale = d3.scale.log()
	.domain(d3.extent(ips, function(i) {return i[1] + 1;}))
	.range([0, 1]),
    same_slash_16 = false,
    yaxisvals = [0, 4096, 8192, 12288, 16384, 20480, 24576, 28672, 32768,
		 36864, 40960, 45056, 49152, 53248, 57344, 61440, 65536];
    if(xmin === xmax) {
	ipsint = ips.map(function(i) {
	    return [~~(i[0] / 256), i[0] % 256, i[1]];
	});
	xmin = (d3.min(ipsint, function(i) {return i[0];}) / 256) * 256;
	xmax = (d3.max(ipsint, function(i) {return i[0];}) / 256) * 256;
	x.domain(d3.extent(ipsint, function(i) {return i[0];}));
	y.domain([256, 0]);
	same_slash_16 = true;
	yaxisvals = [0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176,
		     192, 208, 224, 240, 256];
    }
    document.getElementById("chartstitle").innerHTML = 'IP addresses';
    
    var vis = d3.select("#"+chart)
	.append("svg:svg")
	.attr("width", w+70)
	.attr("height", h+50)
	.append("svg:g")
	.attr("transform", "translate(40, 10)");
    
    var xaxis = [];
    var xstep;
    if(same_slash_16)
	xstep = (Math.max((xmax - xmin) / 7, 1));
    else
	xstep = (Math.max((xmax - xmin) / 7 / 256, 1)) * 256;
    for(var i=xmin; i <= (xmax+1); i += xstep) {
	xaxis.push(i);
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
    	.data(yaxisvals)
    	.enter().append("svg:g")
    	.attr("class", "rule")
    	.attr("transform", function(d) {return "translate(0, " + y(d) + ")";});
    
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
	    setparam("range", extent[0] + '0-' + extent[1] + '255');
	}
	else {
	    extent = brush.extent().map(function(val) {
		return Math.floor(val / 256) + '.' +
		    Math.floor(val % 256) + '.';
	    });
	    setparam("range", extent[0] + '0.0-' + extent[1] + '255.255');
	}
	d3.select(this).transition()
	    .call(brush.extent(extent))
	    .call(brush.event);
    }

    add_download_button(document.getElementById(chart), "AddressSpace");
}

function build_chart_map(chart, locs, fullworld) {
    var w = 550,
    h = 300;

    document.getElementById("chartstitle").innerHTML = "Map";
    var vis = d3.select("#"+chart).append("svg")
	  .attr("width", w)
	  .attr("height", h);

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

	var path = d3.geo.path()
	    .projection(projection);
	world = topojson.feature(world, world.objects.world110m);
	var locations = topojson.feature(locs, locs);
	var maxcount = locations.features[0].properties.count;
	var mincount = locations.features[locations.features.length - 1].properties.count;
	var maxsize = 10, minsize = 1.2;
	var radiusscale = d3.scale.linear()
	    .domain([mincount, maxcount])
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
	    .attr("title", function(d) {
		return d.properties.name + " (" + d.id + ")";
	    })
	    .attr("class", "clickable")
	    .attr("onclick", function(d) {
		return 'setparam("country", "' + d.id + '", true);';
	    })
	    .attr("d", path)
	    .attr("fill", "lightgrey");
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

    add_download_button(document.getElementById(chart), "Map");

    var b;
    if(fullworld === true) {
	b = document.createElement('button');
	b.onclick = function() {
	    build_ip_map();
	};
	b.innerHTML = '<i class="icon-zoom-in"></i>';
	b.setAttribute("title", "Adjust zoom");
    }
    else {
	b = document.createElement('button');
	b.onclick = function() {
	    build_ip_map(true);
	};
	b.innerHTML = '<i class="icon-zoom-out"></i>';
	b.setAttribute("title", "Zoom out");
    }
    document.getElementById(chart).appendChild(b);
}

function build_chart_timeline(chart, ips) {
    //var w = 437.5, //500*57344./65536
    var w = 450,
    h = 450,
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
    document.getElementById("chartstitle").innerHTML = "Timeline";
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
    
    var vis = d3.select("#"+chart)
	.append("svg:svg")
	.attr("width", w+100)
	.attr("height", h+50)
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
	if (!d3.event.sourceEvent) return; // only transition after input
	var extent = brush.extent();
	setparam("timerange", extent[0] + '-' + extent[1]);
	d3.select(this).transition()
	    .call(brush.extent(extent))
	    .call(brush.event);
    }

    add_download_button(document.getElementById(chart), "Timeline");
}

function build_chart_ports(chart, ips) {
    var w = 450,
    h = 450,
    xmin = d3.min(ips, function(i) {return i[0];}),
    xmax = d3.max(ips, function(i) {return i[0];}),
    x = d3.scale.linear()
	.domain(d3.extent(ips, function(i) {return i[0];}))
	.range([0, w]),
    y = d3.scale.log()
	.domain([1, 65535])
	.range([h, 0]),
    colors = {"open": "green", "closed": "red", "filtered": "orange"},
    ips_ports = ips.map(function(x) {
	return x[1].map(function(t) {
	    return [x[0], t[0], t[1]];
	});
    }).reduce(function(x, y) {
	return x.concat(y);
    }, []);

    document.getElementById("chartstitle").innerHTML = "Ports status";

    var vis = d3.select("#"+chart)
	.append("svg:svg")
	.attr("width", w+100)
	.attr("height", h+60)
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
	.attr("fill", function(d) {return colors[d[2]];});

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
    for(i = 1; i <= h; i += ystep) {
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
	setparam("range", extent[0] + '-' + extent[1]);
	d3.select(this).transition()
	    .call(brush.extent(extent))
	    .call(brush.event);
    }

    add_download_button(document.getElementById(chart), "IPsPorts");
}

function build_chart(chart, field, dataset) {
    var w = 540,
    h = 30 * dataset.length,
    //labelpad = 60,
    labelpad = 10 + d3.max(dataset, function(t) {
	var v = d3.select("#"+chart)
	    .append('svg:svg')
	    .append('svg:text')
	    .text(t.value)[0][0]
	    .getComputedTextLength();
	d3.select("#"+chart)[0][0].innerHTML = '';
	return v;}),
    data = dataset.map(function(t) {return t.value;}),
    labels = dataset.map(function(t) {return t.label;}),
    x = d3.scale.linear()
	.domain([0, d3.max(data)])
	.range([0, w - labelpad]),
    y = d3.scale.ordinal()
	.domain(d3.range(data.length))
	.rangeBands([0, h], 0.2),
    //color = [ "grey", "lightgrey" ];
    color = [ "steelblue", "lightblue" ],
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
    if(field.substr(0, 9) === 'portlist:')
	prepareoutput = function(x) {
	    return (x.length === 1 && x[0] === 0) ? "None" : x.join(' / ');
	};
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
	    return 'setparam("asnum", "' + x + '", true);';
	};
    }
    else if(field.substr(0, 4) === 'smb.') {
	preparefilter = function(x) {
	    return 'setparam("' + field + '", "' +
		x.replace(/\\x/g, '\\\\\\\\x') + '", true);';
	};
    }
    else if(field === 'devicetype') {
	preparefilter = function(x) {
	    return 'setparam("devtype", "' + x + '", true);';
	};
    }
    else if(field === 'as') {
	prepareoutput = function(x) {
	    return x[1];
	};
	preparetitle = function(x) {
	    return x[0];
	};
	preparefilter = function(x) {
	    return 'setparam("asnum", "' + x[0] + '", true);';
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
	    return 'setparam("country", "' + x[0] + '", true);';
	};
    }
    else if(field === 'city') {
	prepareoutput = function(x) {
	    return x.join(' / ');
	};
	preparefilter = function(x) {
	    return 'setparam("country", "' + x[0] + '", true, true); setparam("city", "' + x[1] + '");';
	};
    }
    else if(field === 'category') {
	preparefilter = function(x) {
	    return 'setparam("category", "' + x + '");';
	};
    }
    else if(field === 'source') {
	preparefilter = function(x) {
	    return 'setparam("source", "' + x + '", true);';
	};
    }
    else if(field.substr(0, 5) === 'port:') {
	preparefilter = function(x) {
	    return 'setparam("' + field.substr(5) + '", "' + x + '");';
	};
    }
    else if(field === 'service') {
	preparefilter = function(x) {
	    return 'setparam("service", "' + x + '");';
	};
    }
    else if(field.substr(0, 8) === 'service:') {
	preparefilter = function(x) {
	    return 'setparam("service", "' + x + ':' + field.substr(8) + '");';
	};
    }
    else if(field === 'probedservice') {
	preparefilter = function(x) {
	    return 'setparam("probedservice", "' + x + '");';
	};
    }
    else if(field.substr(0, 14) === 'probedservice:') {
	preparefilter = function(x) {
	    return 'setparam("probedservice", "' + x + ':' +
		field.substr(14) + '");';
	};
    }
    else if(field.substr(0, 7) === 'product') {
	prepareoutput = function(x) {
	    return x[1];
	};
	preparetitle = function(x) {
	    return x[0];
	};
	if(field[7] === ':') {
	    preparefilter = function(x) {
		return 'setparam("product", "' + x[0] + ':' + x[1] + field.substr(7) + '");';
	    };
	}
	else {
	    preparefilter = function(x) {
		return 'setparam("product", "' + x[0] + ':' + x[1] + '");';
	    };
	}
    }
    else if(field.substr(0, 7) === 'version') {
	prepareoutput = function(x) {
	    return x[1] + " " + x[2];
	};
	preparetitle = function(x) {
	    return x[0];
	};
	if(field[7] === ':') {
	    preparefilter = function(x) {
		return 'setparam("version", "' + x[0] + ':' + x[1] + ':' + x[2] + field.substr(7) + '");';
	    };
	}
	else {
	    preparefilter = function(x) {
		return 'setparam("version", "' + x[0] + ':' + x[1] + ':' + x[2] + '");';
	    };
	}
    }
    else if(field.substr(0,3) === 'hop' && (field[3] === undefined ||
					    ':>'.indexOf(field[3]) !== -1)) {
	preparefilter = function(x) {
	    return 'setparam("hop", "' + x + '");';
	};
    }
    else if(field.substr(0,7) === 'domains' && (field[7] === undefined ||
						field[7] === ':')) {
	preparefilter = function(x) {
	    return 'setparam("domain", "' + x + '");';
	};
    }
    
    document.getElementById("chartstitle").innerHTML = data.length + (neg ? " least" : " most") + " common " + field.replace(/</g, '&lt;').replace(/>/g, '&gt;') + " value" + (data.length >= 2 ? "s" : "");
    
    var vis = d3.select("#"+chart)
	.append("svg:svg")
	.attr("width", w + 40)
	.attr("height", h + 20)
	.append("svg:g");
    
    var bars = vis.selectAll("g.bar")
	.data(data)
	.enter().append("svg:g")
	.attr("class", "bar")
	.attr("transform", function(d, i) {
	    return "translate(" + labelpad + "," + y(i) + ")";
	});
    
    var bar = bars.append("svg:rect")
	//.attr("fill", "steelblue")
	.attr("fill", function(d, i) { return color[i % color.length]; })
	//.attr("width", x)
	.attr("width", 0)
	.attr("height", y.rangeBand())
	.attr("class", preparefilter === undefined ? "" : "clickable")
	.attr("title", function(d, i) {
	    if (preparetitle !== undefined)
		return preparetitle(labels[i]);
	})
	.attr("onclick", function(d, i) {
	    return (preparefilter === undefined ?
		    undefined :
		    preparefilter(labels[i]));
	});
    
    bar.transition()
	.attr("width", x);
    
    bars.append("svg:text")
	.attr("x", -6)
	.attr("y", y.rangeBand() / 2)
	.attr("dy", ".35em")
	.attr("text-anchor", "end")
	.text(function(d) {return d;});
    
    bars.append("svg:text")
	.attr("x", function(d, i) {
	    return x(d, i) + (x(d, i) < (w-10)/2 ? 10 : -10);
	})
	.attr("y", y.rangeBand() / 2)
	.attr("dy", ".35em")
	.attr("text-anchor", function(d, i) {
	    return x(d, i) < (w - 10) / 2 ? "start" : "end" ;
	})
	.text(function(d, i) {return prepareoutput(labels[i]);})
	.attr("title", function(d, i) {
	    if (preparetitle !== undefined)
		return preparetitle(labels[i]);
	})
	.attr("class", preparefilter === undefined ? "" : "clickable")
	.attr("onclick", function(d, i) {
	    return (preparefilter === undefined ?
		    undefined :
		    preparefilter(labels[i]));
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

    add_download_button(document.getElementById(chart), "TopValues");
}

// http://stackoverflow.com/questions/3446170/escape-string-for-use-in-javascript-regex
function escapeRegExp(str) {
  return str.replace(/[\-\[\]\/\{\}\(\)\*\+\?\.\\\^\$\|]/g, "\\$&");
}

function str2regexp(str) {
    if (str.substr(0, 1) === '/') {
	str = str.substr(1).split('/',2);
	if (str.length == 1)
	    str = RegExp(str[0], 'g');
	else if (str[1].indexOf('g') === -1)
	    str = RegExp(str[0], str[1] + 'g');
	else
	    str = RegExp(str[0], str[1]);
    }
    else
	str = RegExp('^'+escapeRegExp(str)+'$', 'g');
    return str;
}

function protect(value) {
    var state = 1;
    var result = [];
    var curtoken = "";
    var needs_protection = false;
    function end_token() {
	if(needs_protection)
	    curtoken = '"' + curtoken + '"';
	result.push(curtoken);
	curtoken = "";
	needs_protection = false;
    }
    for(var i in value) {
	var c = value[i];
	switch(state) {
	case 1:
	    // not protected
	    switch(c) {
	    case " ":
		needs_protection = true;
		curtoken += c;
		break;
	    case "\\":
		state = 3;
		curtoken += c;
		break;
	    case '"':
		state = 2;
		end_token();
		curtoken += c;
		break;
	    case "'":
		state = 5;
		curtoken += c;
		break;
	    case ':':
		end_token();
		curtoken += c;
		end_token();
		break;
	    default:
		curtoken += c;
	    }
	    break;
	case 2:
	    // inside double quotes
	    curtoken += c;
	    switch(c) {
	    case "\\":
		state = 4;
		break;
	    case '"':
		state = 1;
		end_token();
		break;
	    }
	    break;
	case 3:
	    // protected backslash
	    curtoken += c;
	    state = 1;
	    break;
	case 4:
	    // protected by double quotes and backslash
	    curtoken += c;
	    state = 2;
	    break;
	case 5:
	    // inside simple quotes
	    curtoken += c;
	    switch(c) {
	    case "\\":
		state = 6;
		break;
	    case "'":
		state = 1;
		end_token();
		break;
	    }
	    break;
	case 6:
	    // protected by simple quotes and backslash
	    curtoken += c;
	    state = 5;
	    break;
	}
    }
    end_token();
    return result.join('');
}

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
    document.location.hash = '#' + res.substr(0, res.length - 1);
}

function parse_params() {
    // this is more or less an equivalent to shlex.split() and builds
    // the global parameters array and the global query string from
    // document.location.hash
    var state = 0;
    query = document.location.hash.substr(1);
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

    wanted_portscripts = array2object(
	getparamvalues("script", true)
	    .concat(getparamvalues("portscript", true)));
    wanted_hostscripts = array2object(getparamvalues("hostscript", true));
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

    // aliases
    if (p.substr(0, 7) === "banner:")
	add_param_object(parametersobjunalias, 'script',
			 [b, 'banner:' + p.substr(7)]);
    else if (p.substr(0, 7) === "sshkey:")
	add_param_object(parametersobjunalias, 'script',
			 [b, 'ssh-hostkey:' + p.substr(7)]);
    else if (p.substr(0, 5) === 'file:')
	add_param_object(parametersobjunalias, 'script',
			 [b, '/^(ftp-anon|afp-ls|gopher-ls|http-vlcstreamer-ls|nfs-ls|smb-ls)$/:' + p.substr(5)]);
    else if (p.substr(0, 7) === 'cookie:')
	add_param_object(parametersobjunalias, 'script',
			 [b, 'http-headers:/Set-Cookie: ' + p.substr(7) + '=/']);
    else if (p.substr(0, 8) === 'smbshare' && (p.length === 8 ||
					       p.substr(8, 1) === ':'))
	add_param_object(parametersobjunalias, 'hostscript',
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
	    add_param_object(parametersobjunalias, 'hostscript',
			     [b, 'smb-os-discovery:/^(OS|OS CPE): .*$/m']);
	    break;
	case 'server':
	    add_param_object(
		parametersobjunalias, 'hostscript',
		[b, 'smb-os-discovery:/^NetBIOS computer name: .*$/m']
	    );
	    break;
	case 'workgroup':
	    add_param_object(parametersobjunalias, 'hostscript',
			     [b, 'smb-os-discovery:/^Workgroup: .*$/m']);
	    break;
	case 'date':
	    add_param_object(parametersobjunalias, 'hostscript',
			     [b, 'smb-os-discovery:/^System time: .*$/m']);
	    break;
	case 'domain_dns':
	    add_param_object(
		parametersobjunalias, 'hostscript',
		[b, 'smb-os-discovery:/^Domain name: .*$/m']
	    );
	    break;
	case 'fqdn':
	    add_param_object(
		parametersobjunalias, 'hostscript',
		[b, 'smb-os-discovery:/^FQDN: .*$/m']
	    );
	    break;
	default:
	    add_param_object(parametersobjunalias, 'hostscript',
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
	add_param_object(parametersobjunalias, 'script',
			 [b, '/^http-(auth|default-accounts)$/:/HTTP server may accept|credentials found/']);
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
    // case 'x11srv': // TODO
    case 'x11open':
	add_param_object(parametersobjunalias, 'script',
			 [b, 'x11-access:X server access is granted']);
	break;
    case 'xp445':
	/* same as smb.os + tcp port 445*/
	add_param_object(parametersobjunalias, 'hostscript',
			 [b, 'smb-os-discovery:/^(OS|OS CPE): .*$/m']);
	add_param_object(parametersobjunalias, 'tcp/445',
			 [b, undefined]);
	break;
    case 'webfiles':
	add_param_object(parametersobjunalias, 'script',
			 [b, '/^(ftp-anon|afp-ls|gopher-ls|http-vlcstreamer-ls|nfs-ls|smb-ls)$/:/vhost|www|web\.config|\.htaccess|\.([aj]sp|php|html?|js|css)/i']);
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

function changefav(href) {
    var fav = document.createElement('link');
    var oldfav = document.getElementById('favicon');
    fav.id = 'favicon';
    fav.rel = 'icon';
    if(href.substr(-4) === '.gif')
	fav.type = 'image/x-icon';
    else if(href.substr(-4) === '.png')
	fav.type = 'image/png';
    fav.href = href;
    if(oldfav)
	document.head.removeChild(oldfav);
    document.head.appendChild(fav);
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
	    if(port.state_state in ports)
		ports[port.state_state].push({
		    'protocol': port.protocol,
		    'port': port.port
		});
	    else
		ports[port.state_state] = [{'protocol': port.protocol,
					       'port': port.port}];
	}
	for(status in ports) {
	    result.push({"type": "ports", "status": status,
			 "count": ports[status].length,
			 "ports": ports[status]});
	}
    }
    return result;
}


// Our AngularJS App

var ivreWebUi = angular.module('ivreWebUi', []);

function get_scope(controller) {
    return angular.element(
	document.querySelector(
	    '[ng-controller=' + controller + ']'
	)).scope();
}

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
		s.src = config.cgibase + '?callback=' + encodeURIComponent("(function(ips){build_chart_plane('chart1', ips);})")+ '&countopenports=1&ipsasnumbers=1&q=' + encodeURIComponent(query);
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
		s.src = config.cgibase + '?callback=' + encodeURIComponent("(function(ips){build_chart_timeline('chart1', ips);})")+ '&timeline=1&ipsasnumbers=1&q=' + encodeURIComponent(query);
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
		s.src = config.cgibase + '?callback=' + encodeURIComponent("(function(ips){build_chart_ports('chart1', ips);})")+ '&ipsports=1&ipsasnumbers=1&q=' + encodeURIComponent(query);
		c1.parentNode.appendChild(s);
	    }
	    else {
		hidecharts();
	    }
	};
    });

function build_ip_map(fullworld) {
    hideall();
    var c1 = document.getElementById('chart1');
    c1.innerHTML = "";
    var s = document.getElementById('chart1script');
    if(s) c1.parentNode.removeChild(s);
    document.getElementById('charts').style.display = 'inline';
    s = document.createElement('script');
    s.id = 'chart1script';
    s.src = config.cgibase + '?callback=' + encodeURIComponent("(function(ips){build_chart_map('chart1', ips, " + fullworld + ");})")+ '&coordinates=1&ipsasnumbers=1&q=' + encodeURIComponent(query);
    c1.parentNode.appendChild(s);
}


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
    })
    .directive('ivreMenu', function() {
	return {
	    templateUrl: 'templates/menu.html'
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
	var topvalues = [
	    "category", "source",
	    "domains", "domains:", "hop", "hop:",
	    // infos
	    "country", "city", "as",
	    // ports
	    "port", "port:open", "port:closed", "port:filtered",
	    // countports / portlist
	    "countports:open", "countports:filtered", "countports:closed",
	    "portlist:open", "portlist:closed", "portlist:filtered",
	    // service, products, etc. [:port]
	    "service", "service:",
	    "probedservice", "probedservice:",
	    "product", "product:",
	    "version", "version:",
	    "devicetype", "devicetype:",
	    // scripts
	    "ports.scripts.id", "scripts.id",
	    "script:", "portscript:", "hostscript:",
	    // smb (hostscript smb-os-discovery)
	    "smb.os", "smb.lanmanager",
	    "smb.domain", "smb.dnsdomain",
	    "smb.forest", "smb.workgroup",
	    // cert (portscript ssl-cert)
	    "cert.issuer", "cert.subject",
	    // modbus (portscript modbus-discover)
	    "modbus.deviceid",
	    // s7 (portscript s7-info)
	    "s7.Module", "s7.Version", "s7.Module Type",
	    // enip (portscript enip-info)
	    "enip.vendor", "enip.product", "enip.serial", "enip.devtype",
	    "enip.prodcode", "enip.rev", "enip.ip",
	];
	$scope.topvalues = topvalues;
	for(var i in topvalues) {
	    $scope.topvalues.push("-" + topvalues[i]);
	}
    })
    .directive('ivreFilters', function() {
	return {
	    templateUrl: 'templates/filters.html'
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
		.map(function(x) {return x.id;})
		.indexOf($scope.display_mode_args[0]) !== -1;
	};
	$scope.script_display_mode_needed_script = function(scriptid) {
	    if($scope.display_mode_args.length === 0)
		return true;
	    return scriptid === $scope.display_mode_args[0];
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
	$scope.wanted_script = function(type, value) {
	    return value in {
		"port": wanted_portscripts,
		"host": wanted_hostscripts
	    }[type];
	};
	$scope.class_from_port_status = function(status) {
	    switch(status) {
	    case "open": return "label-success";
	    case "closed": return "label-important";
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
    .directive('serviceSummary', function() {
	return {
	    templateUrl: 'templates/subview-service-summary.html'
	};
    })
    .directive('scriptOutput', function() {
	return {"link": function(scope, element, attr) {
	    var wanted = {
		'port': wanted_portscripts,
		'host': wanted_hostscripts
	    }[attr.scriptOutput][scope.script.id];
	    var output = scope.script.output
		.split('\n')
		.map(function(x) {return x.trim();})
		.filter(function(x) {return x;})
		.join('\n')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;');
	    if(scope.wanted_script(attr.scriptOutput, scope.script.id)) {
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
    var scope = get_scope('IvreResultListCtrl');
    if(mode === undefined)
	mode = "host"; // default
    scope.$apply(function() { 
	if(mode.substr(0, 7) === "script:") {
	    scope.display_mode_args = [mode.substr(7)];
	    mode = "script";
	}
	scope.display_mode = mode;
    });
}

ivreWebUi
    .controller('IvreAnalysisCtrl', function ($scope) {
    });

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

function common_prefix(strings) {
    var result = "";
    var i = 0;
    var curchar;
    if(strings.length === 0)
	return result;
    while(true) {
	curchar = strings[0][i];
	if(curchar === undefined) {
	    return result;
	}
	for(var j = 1; j < strings.length; j++)
	    if(curchar !== strings[j][i])
		return result;
	result += curchar;
	i++;
    }
    return result;
}

function set_tooltip_filter(elt) {
    var key, content;
    if(elt.value &&
       (elt.value.length > 1 || "!-".indexOf(elt.value[0]) === -1)) {
	var matching_keys = Object.keys(HELP).filter(
	    function(key) {
		return ((':/'.indexOf(key.slice(-1)) === -1
			 && key !== 'screenshot'
			 && key !== 'smbshare') ?
			elt.value === key.substr(0, elt.value.length) :
			elt.value.substr(0, key.length) === key.substr(0, elt.value.length));
	    }
	);
	var oldval = elt.getAttribute("oldval");
	if(oldval === null)
	    oldval = "";
	if(matching_keys.length == 1) {
	    key = matching_keys[0];
	    content = HELP[key];
	    if(elt.getAttribute('data-title') !== content.title) {
		set_tooltip(elt, content);
	    }
	    if(oldval.length < elt.value.length &&
	       elt.value.substr(0, oldval.length) === oldval &&
	       elt.value.length < key.length) {
		var start = elt.value.length;
		oldval = elt.value;
		elt.value = key;
		elt.selectionStart = start;
	    }
	    else {
		oldval = elt.value;
	    }
	    elt.setAttribute("oldval", oldval);
	    return;
	}
	if(matching_keys.length >= 2) {
	    key = common_prefix(matching_keys);
	    content = {
		"title": "Possible commands",
		"content": matching_keys.map(
		    function(x) {
			return x.substr(0, key.length) +
			    "<b><span style=\"color: red;\">" +
			    x.substr(key.length, 1) + "</span>" +
			    x.substr(key.length + 1) + "</b>";
		    }
		).join("<br>"),
	    };
	    if(elt.getAttribute('data-title') !== content.title ||
	       elt.getAttribute('data-content') !== content.content) {
		set_tooltip(elt, content);
	    }
	    if(oldval.length < elt.value.length &&
	       elt.value.substr(0, oldval.length) === oldval &&
	       elt.value.length < key.length) {
		var start = elt.value.length;
		oldval = elt.value
		elt.value = key;
		elt.selectionStart = start;
	    }
	    else {
		oldval = elt.value;
	    }
	    elt.setAttribute("oldval", oldval);
	    return;
	}
	elt.setAttribute("oldval", elt.value);
	if(elt.value.match(/^!?[0-9\.\/\,]*$/)) {
	    if(elt.value.indexOf('/') !== -1)
		content = HELP["net:"];
	    else if(elt.value.indexOf('.') !== -1)
		content = HELP["host:"];
	    else
		content = HELP["tcp/"];
	    if(elt.getAttribute('data-title') !== content.title) {
		set_tooltip(elt, content);
	    }
	    return;
	}
    }
    elt.setAttribute("oldval", elt.value);
    if(elt.hasAttribute('data-title'))
	remove_tooltip(elt);
}

function set_tooltip(elt, content) {
    remove_tooltip(elt);
    elt.setAttribute('data-title', content.title);
    elt.setAttribute('data-content', content.content);
    $('#' + elt.id).popover(content).popover('show');
}

function remove_tooltip(elt) {
    elt.removeAttribute('data-title');
    elt.removeAttribute('data-content');
    $('#' + elt.id).popover('destroy');
}

function remove_all_tooltips(parentelt) {
    var elements = parentelt.getElementsByTagName('input');
    for(var i = 0; i < elements.length; i++) {
	remove_tooltip(elements[i]);
    }
}

function load() {
    parse_params();
    if(getparam('skip') == config.dflt.skip) {
	unsetparam('skip');
	return;
    }
    if(getparam('limit') == config.dflt.limit) {
	unsetparam('limit');
	return;
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
    document.getElementById('results-container')
	.setAttribute('class', 'span5');
    s.onload = function() {
	var hostcount = count_displayed_hosts(),
	limit = getparam('limit'),
	skip = getparam('skip');
	if(limit === undefined)
	    limit = config.dflt.limit;
	else
	    limit = limit * 1;
	if(skip === undefined)
	    skip = config.dflt.skip;
	else {
	    skip = skip * 1;
	    if(skip < 0)
		setparam('skip', config.dflt.skip, true);
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
	    s.src = config.cgibase + '?callback=set_nbrres&count=&q=' +
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
