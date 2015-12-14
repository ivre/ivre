var FILTERS = {}, FILTER;

function _compare_params(store, other, count) {
    /* Returns true iff store "contains" other. "limit", "skip" and
     * "sortby" are omitted when count is true. */
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

var Filter = function(name) {
    console.log("instanciating filter ", name);
    this.parameters = [];
    this.parametersprotected = [];
    this.parametersobj = {};
    this.parametersobjunalias = {};
    this.count = undefined;
    // the initial prev_query has to be an object and to be different
    // than any valid query
    this.prev_query = {"thiswillneverexist": []};
    if(name) {
	FILTERS[name] = this;
	this.idprefix = name + "-";
    }
    else {
	FILTER = this;
	this.idprefix = "";
    }
};

Filter.prototype.end_new_query = function() {
    this.prev_query = {};
    for(var key in this.parametersobjunalias) {
	this.prev_query[key] = this.parametersobjunalias[key];
    }
};

Filter.prototype.need_update = function() {
    return ! this.compare_params(false);
};

Filter.prototype.need_count = function() {
    return ! this.compare_params(true);
};

Filter.prototype.compare_params = function(count) {
    if(_compare_params(this.parametersobjunalias,
		       this.prev_query, count)) {
	return _compare_params(this.prev_query,
			       this.parametersobjunalias, count);
    }
    return false;
};
