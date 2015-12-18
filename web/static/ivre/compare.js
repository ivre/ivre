var ALL_SETS;

function init_compare() {
    if(!(wait_filter(init_compare)))
	return;

    sync_hash_filter(FILTER)

    window.onhashchange();
    //var all_sets = [];
    for(name in FILTERS) {
	if(name.substr(0, 3) === "set") {
	    var filter = FILTERS[name];
	    filter.on_query_update();
	    //all_sets.push(filter);
	}
    }
    // FIXME work w/ arbitrary number of sets
    ALL_SETS = new SubFilter("all_sets", FILTERS.set1, FILTERS.set2);
    var scope = get_scope("IvreCompareCtrl");
    scope.$apply(function() {
	scope.all_sets = ALL_SETS;
    });
    ALL_SETS.need_apply.push(scope);
}
