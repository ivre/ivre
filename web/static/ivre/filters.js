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

var FILTERS = {}, FILTER;

var Filter = (function() {
    function Filter(name) {
	this.name = name;
	this.parameters = [];
	this.parametersprotected = [];
	this.parametersobj = {};
	this.parametersobjunalias = {};
	this.count = undefined;
	// the initial prev_query has to be an object and to be
	// different than any valid query
	this.prev_query = {"thiswillneverexist": []};
	if(name) {
	    FILTERS[name] = this;
	    this.idprefix = name + "-";
	}
	else {
	    FILTER = this;
	    this.idprefix = "";
	}
    }

    function _compare_params(store, other, count) {
	/* Returns true iff store "contains" other. "limit", "skip"
	 * and "sortby" are omitted when count is true. */
	for(var key in store) {
	    if((count && (key == 'limit' || key == 'skip'
			  || key == 'sortby')) ||
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

    $.extend(Filter.prototype, {
	end_new_query: function() {
	    this.prev_query = {};
	    for(var key in this.parametersobjunalias) {
		this.prev_query[key] = this.parametersobjunalias[key];
	    }
	},

	need_update: function() {
	    return ! this.compare_params(false);
	},

	need_count: function() {
	    return ! this.compare_params(true);
	},

	compare_params: function(count) {
	    if(_compare_params(this.parametersobjunalias,
			       this.prev_query, count)) {
		return _compare_params(this.prev_query,
				       this.parametersobjunalias, count);
	    }
	    return false;
	},

	do_count: function() {
	    var filterobject = this;
	    $.ajax({
		url: config.cgibase + '?action=count&q=' +
		    encodeURIComponent(this.query),
		jsonp: "callback",
		dataType: "jsonp",
		success: function(data) {
		    filterobject.count = data;
		}
	    });
	},

	do_get_results: function() {
	    if(this.callback_get_results !== undefined) {
		var filterobject = this;
		$.ajax({
		    url: config.cgibase + '?q=' +
			encodeURIComponent(this.query),
		    jsonp: "callback",
		    dataType: "jsonp",
		    beforeSend: function(data) {
			filterobject.callback_pre_get_results();
		    },
		    success: function(data) {
			filterobject.callback_get_results(data);
		    },
		    complete: function() {
			filterobject.callback_post_get_results();
			filterobject.end_new_query();
			filterobject.callback_final();
			for(var i in filterobject.need_apply) {
			    filterobject.need_apply[i].$apply();
			}
			filterobject.scope.$apply();
		    }
		});
	    }
	},

	on_param_update: function() {
	    this.scope.parametersprotected.push(this.scope.lastfiltervalue);
	    this.scope.lastfiltervalue = "";
	    this.query = this.scope.parametersprotected
		.filter(function(p){return p;})
		.join(" ");
	    set_hash(this.query);
	},

	on_query_update: function() {
	    if(this.need_update()) {
		if(this.need_count())
		    this.do_count();
		this.do_get_results();
	    }
	    else {
		this.callback_final();
	    }
	},

	callback_pre_get_results: function() {},
	callback_get_results: undefined,
	callback_post_get_results: function() {},
	callback_final: function() {},
	need_apply: []
    });

    return Filter;
})();
