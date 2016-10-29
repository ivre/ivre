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

var FILTERS = {}, FILTER;

var Filter = (function() {
    function Filter(name) {
        this.name = name;
        this.parameters = [];
        this.parametersprotected = [];
        this.parametersobj = {};
        this.parametersobjunalias = {};
        this.query = "";
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
        this.callbacks = {
            pre_get_results: [],
            get_results: [],
            post_get_results: [],
            end_update: [],
            param_update: [],
        };
        this.need_apply = [];
    }

    function _compare_params(store, other, count) {
        /* Returns true iff store "contains" other. "limit", "skip"
         * and "sortby" are omitted when count is true. */
        for(var key in store) {
            if((count && (key == 'limit' || key == 'skip' ||
                            key == 'sortby')) ||
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
        _call_callbacks: function() {
            var args = Array.from(arguments);
            var callbacks = args.shift();
            for(var i in callbacks) {
                callbacks[i].apply(this, args);
            }
        },

        add_callback: function(name, callback) {
            this.callbacks[name].push(callback);
        },

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
                url: 'cgi-bin/scanjson.py?action=count&q=' +
                    encodeURIComponent(this.query),
                jsonp: "callback",
                dataType: "jsonp",
                beforeSend: function() {
		    filterobject.count = undefined;
                },
                success: function(data) {
                    filterobject.count = data;
                    filterobject.update_scopes();
                }
            });
        },

        do_get_results: function() {
            var filterobject = this;
            if(this.callbacks.get_results.length > 0) {
                $.ajax({
                    url: 'cgi-bin/scanjson.py?q=' +
                        encodeURIComponent(this.query),
                    jsonp: "callback",
                    dataType: "jsonp",
                    beforeSend: function() {
                        filterobject._call_callbacks(
                                filterobject.callbacks.pre_get_results
                                );
                    },
                    success: function(data) {
                        filterobject._call_callbacks(
                                filterobject.callbacks.get_results, data
                                );
                    },
                    complete: function() {
                        filterobject._call_callbacks(
                                filterobject.callbacks.post_get_results
                                );
                        filterobject.end_new_query();
                        filterobject._call_callbacks(
                                filterobject.callbacks.end_update
                                );
                        filterobject.update_scopes();
                    }
                });
            }
            else {
                filterobject._call_callbacks(
                        filterobject.callbacks.pre_get_results
                        );
                filterobject._call_callbacks(filterobject.callbacks.post_get_results);
                filterobject.end_new_query();
                filterobject._call_callbacks(filterobject.callbacks.end_update);
                filterobject.update_scopes();
            }
        },

        on_param_update: function() {
            this.scope.parametersprotected.push(this.scope.lastfiltervalue);
            this.scope.lastfiltervalue = "";
            this.query = this.scope.parametersprotected
                .filter(function(p){return p;})
                .join(" ");
            this.update_query();
        },

        on_paramobj_update: function() {
            params2query(this);
            this.update_query();
        },

        update_query: function() {
            if(!load_params(this))
                return;
            this.on_query_update();
            this._call_callbacks(this.callbacks.param_update, this.query);
        },

        on_query_update: function() {
            if(this.need_update()) {
                if(this.need_count())
                    this.do_count();
                this.do_get_results();
            }
            else {
                this._call_callbacks(this.callbacks.end_update);
            }
        },

        update_scopes: function() {
            for(var i in this.need_apply) {
                this.need_apply[i].$apply();
            }
            /*
            if(this.scope) {
                this.scope.$apply();
            }
            */
        }
    });

    return Filter;
})();

var SubFilter = (function(_super) {

    /*
     * Special filter that includes the intersection of other filters
     */

    function SubFilter(name) {
        var args = Array.from(arguments);
        _super.call(this, args.shift());
        this.children = args;
        this._query = "";
        var parent = this;
        var callback_post_get_results = function() {
            // force parent update
            parent.prev_query = {"thiswillneverexist": []};
            parent.on_param_update();
        };
        for(var i in this.children) {
            var child = this.children[i];
            var index = i;
            child.add_callback("post_get_results", callback_post_get_results);
        }
    }

    $.extend(SubFilter.prototype, _super.prototype, {
        set_full_query: function() {
            if(this.query) {
                this.query += " ";
            }
            this.query += this.children
                .map(function(p) {return p.query;})
                .filter(function(p) {return p;})
                .join(" ");
            this.on_query_update();
        },

        on_param_update: function() {
            if(this.scope) {
                this.scope.parametersprotected.push(this.scope.lastfiltervalue);
                this.scope.lastfiltervalue = "";
                this.query = this.scope.parametersprotected
                    .filter(function(p){return p;})
                    .join(" ");
            }
            else
                this.query = "";
            load_params(this);
            this.set_full_query();
            this._call_callbacks(this.callbacks.param_update, this.query);
        }
    });

    return SubFilter;
})(Filter);
