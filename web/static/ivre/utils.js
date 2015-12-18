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

/*********** Common util functions ***************/

/* Workaround for cross-browser handling of .hash: Firefox 41+ (at
   least) encodes document.location.hash, while Chromium (at least)
   does not. Hope there is a better solution. */

function are_hash_encoded() {
    var parser = document.createElement("a");
    parser.href = "# #";
    return parser.hash !== "# #";
}

var HASH_ENCODED = are_hash_encoded();

function get_hash() {
    var res = document.location.hash.substr(1);
    if(HASH_ENCODED){
	return decodeURIComponent(res);
    }
    return res;
}

function set_hash(value) {
    if(HASH_ENCODED){
	document.location.hash = '#' + encodeURIComponent(value);
    }
    else {
	document.location.hash = '#' + value;
    }
}

/* Chrome */
// if(String.prototype.repeat === undefined) {
//     String.prototype.repeat = function(num) {
// 	return new Array( num + 1 ).join(this);
//     };
// }
function repeat(string, num) {
    return new Array(num + 1).join(string);
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

jQuery.fn.getBg = function() {
    // Get the real computed background color (!= getComputedStyle)
    return $(this).parents().filter(function() {

	var color = $(this).css('background-color');

	if(color != 'transparent' && color != 'rgba(0, 0, 0, 0)' &&
	   color !== undefined)
	    return color;
    }).css('background-color');
};

function array_swap(arr, x, y) {
    var tmp = arr[x];
    arr[x] = arr[y];
    arr[y] = tmp;
    return arr;
}

function getPagePath() {
    var base = document.location.pathname;
    if(base.endsWith('/')) {
	return base;
    }
    var idx = base.lastIndexOf('/');
    if(idx === -1) {
	return base + '/';
    }
    if(base.endsWith('.html')) {
	return base.substring(0, idx + 1);
    }
    return base + '/';
}

function getPageName() {
    var base = document.location.pathname;
    if(base.endsWith('/')) {
	return 'index';
    }
    var idx = base.lastIndexOf('/');
    if(idx === -1) {
	return 'index';
    }
    if(base.endsWith('.html')) {
	return base.substring(idx + 1, base.length - 5);
    }
    return 'index';
}

function exportDOM() {
    // Get current DOM
    var reportDOM = $("body").clone();

    // Clean it
    reportDOM.find(".no-export").remove();
    reportDOM.find('style').remove();
    reportDOM.find('script').remove();

    // Get full CSS
    var cssText = "";
    $.each(document.styleSheets, function(sheetIndex, sheet) {
       $.each(sheet.cssRules || sheet.rules, function(ruleIndex, rule) {
	   cssText += rule.cssText;
       });
    });

    // Convert images
    reportDOM.find("img[src]").each(function(index, img) {
	var canvas = document.createElement('canvas');
	canvas.width = img.width;
	canvas.height = img.height;
	var context = canvas.getContext('2d');
	context.drawImage(img, 0, 0);
	img.src = canvas.toDataURL("image/png");
    });

    // Rebuild a web page
    var content = "<html><head><style>" + cssText + "</style></head><body>" + reportDOM.html() + "</body></html>";
    return new Blob([content], {"type": "text\/html" });
}

function download_blob(blob, title) {
    // Build a link element to download Blob
    var div = document.body;
    var a = document.createElement('a');
    a.onclick = function() {
	this.setAttribute('href', window.URL.createObjectURL(blob));
	return true;
    };
    if(title === undefined)
	title = "Unknown.bin";
    a.download = title;
    a.href = "#";

    // Trigger click event
    div.appendChild(a);
    a.click();

    // Clean
    document.removeElement(a);
    return false;
}

function find_parent(base, tagname) {
    tagname = tagname.toUpperCase();
    while(base.tagName !== tagname) {
	base = base.parentNode;
    }
    return base;
}
