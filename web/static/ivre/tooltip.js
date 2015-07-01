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

/*********** Tooltip handling *********************/

var ToolTip = {
    common_prefix: function (strings) {
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
    },

    set_topvalues: function(elt) {
	if (!(elt.value))
	    return;

	// Prefix detection
	var asked, prefix = "";
	if (elt.value.length > 1 && "!-".indexOf(elt.value[0]) !== -1) {
	    prefix = elt.value[0];
	    asked = elt.value.substr(1);
	} else {
	    asked = elt.value;
	}

	// Match available commands
	if (asked.length >= 1) {
	    var matching_keys = HELP_TOPVALUES.filter(
		function(key) {
		    return (asked === key.substr(0, asked.length));
		}
	    );
	    // Get last answer
	    var oldval = elt.getAttribute("oldval");
	    if(oldval === null)
		oldval = "";

	    if(matching_keys.length >= 1) {
		// Some command match

		if(matching_keys.length == 1) {
		    // One result: auto-completion

		    key = matching_keys[0];
		    content = {
			"title": "Help",
			"content": key
		    };

		} else {
		    // Multiple results: display help
		    key = ToolTip.common_prefix(matching_keys);
		    content = {
			"title": "Possible commands",
			"content": matching_keys.map(
			function(x) {
			    return x.substr(0, key.length) +
				"<b><span style=\"color: red;\">" +
				x.substr(key.length, 1) + "</span>" +
				x.substr(key.length + 1) + "</b>";
			}).join("<br>"),
		    };
		}

		ToolTip.set(elt, content);
		if(oldval.length < elt.value.length &&
		   elt.value.substr(0, oldval.length) === oldval &&
		   elt.value.length < key.length) {
		    var start = elt.value.length;
		    elt.value = prefix + key;
		    elt.selectionStart = start;
		}
		elt.setAttribute("oldval", elt.value);
		return;
	    }

	}
	if (elt.hasAttribute('data-title'))
	    ToolTip.remove(elt);
	elt.setAttribute("oldval", elt.value);
    },

    set_filter: function(elt) {
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
		    ToolTip.set(elt, content);
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
		key = ToolTip.common_prefix(matching_keys);
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
		    ToolTip.set(elt, content);
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
		    ToolTip.set(elt, content);
		}
		return;
	    }
	}
	elt.setAttribute("oldval", elt.value);
	if(elt.hasAttribute('data-title'))
	    ToolTip.remove(elt);
    },

    set: function(elt, content) {
	ToolTip.remove(elt);
	elt.setAttribute('data-title', content.title);
	elt.setAttribute('data-content', content.content);
	$('#' + elt.id).popover(content).popover('show');
    },

    remove: function(elt) {
	elt.removeAttribute('data-title');
	elt.removeAttribute('data-content');
	$('#' + elt.id).popover('destroy');
    },

    remove_all: function(parentelt) {
	var elements = parentelt.getElementsByTagName('input');
	for(var i = 0; i < elements.length; i++) {
	    ToolTip.remove(elements[i]);
	}
    }
}
