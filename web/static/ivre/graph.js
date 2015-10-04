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

/************* Graphing utilities **************/

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
	'&action=topvalues:' + encodeURIComponent(field) + ':15&q=' +
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
    a.innerHTML = '<button><i class="glyphicon glyphicon-download-alt download"></i></button>';
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
    var real_w = 500,
    real_h = 450,
    w = real_w - 100,
    h = real_h - 50,
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
	.attr("viewBox", [0, 0, real_w, real_h])
	.attr("preserveAspectRatio", "xMidYMid meet")
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

function build_ip_map(fullworld) {
    hideall();
    var c1 = document.getElementById('chart1');
    c1.innerHTML = "";
    var s = document.getElementById('chart1script');
    if(s) c1.parentNode.removeChild(s);
    document.getElementById('charts').style.display = 'inline';
    s = document.createElement('script');
    s.id = 'chart1script';
    s.src = config.cgibase + '?callback=' + encodeURIComponent("(function(ips){build_chart_map('chart1', ips, " + fullworld + ");})")+ '&action=coordinates&ipsasnumbers=1&q=' + encodeURIComponent(query);
    c1.parentNode.appendChild(s);
}

function build_chart_map(chart, locs, fullworld) {
    var w = 500,
    h = 250;

    document.getElementById("chartstitle").innerHTML = "Map";
    var vis = d3.select("#"+chart).append("svg")
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
	    projection.scale(w/7)
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
	b.innerHTML = '<i class="glyphicon glyphicon-zoom-in"></i>';
	b.setAttribute("title", "Adjust zoom");
    }
    else {
	b = document.createElement('button');
	b.onclick = function() {
	    build_ip_map(true);
	};
	b.innerHTML = '<i class="glyphicon glyphicon-zoom-out"></i>';
	b.setAttribute("title", "Zoom out");
    }
    document.getElementById(chart).appendChild(b);
}

function build_chart_timeline(chart, ips) {
    var real_w = 500,
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
    var real_w = 500,
    real_h = 450,
    w = real_w - 100,
    h = real_h - 60,
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

function build_chart(chart, field, dataset, size, colors) {

    if (size === undefined)
	size = 5;

    if (colors === undefined)
	colors = [ "steelblue", "lightblue" ];

    var w = 100 * size,
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
    color = colors,
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
	    return (x.length === 0) ? "None" : x.join(' / ');
	};
	if(field.substr(9) === 'open')
	    preparefilter = function(x) {
		if(x.length === 0)
		    return 'setparam("countports", "0", true);';
		else
		    return 'setparam("open", "' + x + '", true, true); setparam("countports", "' + x.length + '", true);';
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
	    return 'setparam("asnum", "' + x + '", true);';
	};
    }
    else if(field.substr(0, 4) === 'smb.') {
	preparefilter = function(x) {
	    return 'setparam("' + field + '", "' +
		x.replace(/\\x/g, '\\\\\\\\x') + '", true);';
	};
    }
    else if(field === 'sshkey.bits') {
	prepareoutput = function(x) {
	    return x.join(' / ');
	};
	preparefilter = function(x) {
	    return 'setparam("sshkey.type", "' + x[0] + '", false, true); setparam("sshkey.bits", "' + x[1] + '");';
	};
    }
    else if(field.substr(0, 7) === 'sshkey.') {
	preparefilter = function(x) {
	    return 'setparam("' + field + '", "' + x + '");';
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
    else if(field === 'label' || field.substr(0, 6) === 'label:') {
	preparefilter = function(x) {
	    return 'setparam("label", "' + x[0] + ':' + x[1] + '");';
	};
	prepareoutput = function(x) {
	    return x.join(' / ');
	};
    }
    else if(field === 'source') {
	preparefilter = function(x) {
	    return 'setparam("source", "' + x + '", true);';
	};
    }
    else if(field === 'script') {
	preparefilter = function(x) {
	    return 'setparam("script", "' + x + '");';
	};
    }
    else if(field.substr(0, 5) === 'port:') {
	var info = field.substr(5);
	switch(info) {
	case "open":
	case "filtered":
	case "closed":
	    preparefilter = function(x) {
		return 'setparam("' + info + '", "' + x + '");';
	    };
	    break;
	default:
	    preparefilter = function(x) {
		return 'setparam("service", "' + info + ':' + x + '");';
	    };
	    break;
	}
    }
    else if(field === 'countports:open') {
	preparefilter = function(x) {
	    return 'setparam("countports", "' + x + '");';
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
    else if(field.substr(0, 3) === 'cpe') {
	prepareoutput = function(x) {
	    return x.join(":");
	};
	preparefilter = function(x) {
	    return 'setparam("cpe", "' + x.join(":") + '")';
	};
    }
    else if(field === 'screenwords') {
	preparefilter = function(x) {
	    return 'setparam("screenwords", "' + x + '")';
	};
    }
    else if(field.substr(0, 3) === 'hop') {
	if(field[3] === ':')
	    preparefilter = function(x) {
		return 'setparam("hop", "' + x + '", ' + field.substr(4) + ');';
	    };
	else
	    preparefilter = function(x) {
		return 'setparam("hop", "' + x + '");';
	    };
    }
    else if(field.substr(0, 7) === 'domains' && (field[7] === undefined ||
						 field[7] === ':')) {
	preparefilter = function(x) {
	    return 'setparam("domain", "' + x + '");';
	};
    }
    
    document.getElementById("chartstitle").innerHTML = data.length + (neg ? " least" : " most") + " common " + field.replace(/</g, '&lt;').replace(/>/g, '&gt;') + " value" + (data.length >= 2 ? "s" : "");
    
    var vis = d3.select("#"+chart)
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

    colorBg = $("#" + chart).getBg();
    colorFg = getComputedStyle($("#" + chart)[0]).color;

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
