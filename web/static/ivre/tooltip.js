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
	if(strings.length === 0) {
	    return result;
	}
	while(true) {
	    curchar = strings[0][i];
	    if(curchar === undefined) {
		return result;
	    }
	    for(var j = 1; j < strings.length; j++) {
		if(curchar !== strings[j][i]) {
		    return result;
		}
	    }
	    result += curchar;
	    i++;
	}
	return result;
    },

    handle: function(elt, HELP) {

	// Prefix detection
	if (!(elt.value) || (elt.value.length <= 1 && HELP.config.prefixes.indexOf(elt.value[0]) !== -1)) {
	    ToolTip.remove(elt);
	    elt.setAttribute("oldval", elt.value);
	    return;
	}
	var asked = elt.value;

	// Callbacks
	for (var cbid in HELP.callbacks) {
	    if (!(HELP.callbacks[cbid](elt, HELP, ToolTip))) {
		return;
	    }
	}

	// Match available commands
	var COMMANDS = Object.keys(HELP.content);
	var matching_keys = COMMANDS.filter(
	    function(key) {
		// Suffix detection
		if (HELP.config.suffixes.indexOf(key.substr(-1)) === -1) {
		    return (asked === key.substr(0, asked.length));
		}
		else {
		    if (COMMANDS.indexOf(
			key.substring(0, key.length - 1)) !== -1 &&
			(asked.length < key.length)) {
			/* 'command' and 'command + suffix' are both available
			 * -> only display the help / complete for 'command'
			 */
			return false;
		    }
		    return (asked.substr(0, key.length) === key.substr(0, asked.length));
		}
	    }
	);

	// Get last answer
	var oldval = elt.getAttribute("oldval");
	if (oldval === null) {
	    oldval = "";
	}

	if (matching_keys.length >= 1) {
	    // Some command match

	    if(matching_keys.length === 1) {
		// One result: auto-completion

		key = matching_keys[0];
		content = HELP.content[key];

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

	    // Update view
	    ToolTip.set(elt, content);
	    if (oldval.length < asked.length &&
	       asked.substr(0, oldval.length) === oldval &&
	       asked.length < key.length) {
		var start = asked.length;
		elt.value = key;
		elt.selectionStart = start;
	    }
	} else {
	    ToolTip.remove(elt);
	}
	elt.setAttribute("oldval", asked);
    },

    set: function(elt, content) {
	if (elt.getAttribute('data-content') === content.content &&
	    elt.getAttribute('data-original-title') === content.title) {
	    return;
	}
	elt.setAttribute('data-original-title', content.title);
	elt.setAttribute('data-content', content.content);
	$('#' + elt.id).popover('show');
    },

    remove: function(elt) {
	elt.removeAttribute('data-original-title');
	elt.removeAttribute('data-content');
	$('#' + elt.id).popover('destroy');
    },

    remove_all: function() {
	$("input")
	    .removeAttr("data-original-title")
	    .removeAttr("data-content")
	    .popover("destroy");
    }
};
