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

var ALL_SETS;

function init_compare() {
    if(!(wait_filter(init_compare)))
	return;

    sync_hash_filter(FILTER);

    window.onhashchange();
    //var all_sets = [];
    for(var name in FILTERS) {
	if(name.substr(0, 3) === "set") {
	    var filter = FILTERS[name];
	    filter.on_query_update();
	    //all_sets.push(filter);
	}
    }
    // FIXME work w/ arbitrary number of sets
    ALL_SETS = new SubFilter("all_sets", FILTERS.set1, FILTERS.set2);
    ALL_SETS.on_query_update();
    var scope = get_scope("IvreCompareCtrl");
    scope.$apply(function() {
	scope.all_sets = ALL_SETS;
    });
    ALL_SETS.need_apply.push(scope);
}
