//$.ivre = {};
//$.ivre.parsers = {
    gfilter2func = function(str) {
        // [!][#@]?<arg> [<op> <value>] [&& expr]
        var ret_true, ret_false;
        if (str.contains(" && ")) {
            sp = str.split(" && ", 2);
            return function(elt) {
                return gfilter2func(sp[0])(elt) && gfilter2func(sp[1])(elt)
            };
        }

        if (str.contains(" || ")) {
            sp = str.split(" || ", 2);
            return function(elt) {
                return gfilter2func(sp[0])(elt) || gfilter2func(sp[1])(elt)
            };
        }

        if (str.startsWith("!")) {
            ret_true = false;
            ret_false = true;
            str = str.substr(1);
        } else {
            ret_true = true;
            ret_false = false;
        }

        // Label filter
        if (str.startsWith("#")) {
            return function (elt) {
                var labels = elt.labels || [];
                var label = str.substr(1);
                for (i in labels) {
                    if (label == labels[i]) {
                        return ret_true;
                    }
                }
                return ret_false;
            };
        }
        
        // Attribute filter
        if (str.startsWith("@")) {
            var sp = str.substr(1).split(/\s+/, 3);
            var attr = sp[0];

            if (sp.length == 1) {
                return function (elt) {
                    var data = elt.data || {};
                    return data[attr] !== undefined ? ret_true:ret_false;
                };
            } else if (sp.length == 3) {
                var op = sp[1];
                var ref = sp[2];

                return function (elt) {
                    var data = elt.data || {};
                    var val = data[attr];
                    if (typeof val == "number") {
                        ref = Number(ref);
                    } else if (typeof val == "boolean") {
                        ref = Boolean(ref);
                    }
                    switch (op) {
                        case "==":
                            return val == ref ? ret_true:ret_false;
                        case "!=":
                            return val != ref ? ret_true:ret_false;
                        case "<":
                            return val < ref ? ret_true:ret_false;
                        case "<=":
                            return val <= ref ? ret_true:ret_false;
                        case ">":
                            return val > ref ? ret_true:ret_false;
                        case ">=":
                            return val >= ref ? ret_true:ret_false;
                        case "=~":
                            var re = RegExp(ref);
                            return typeof val === "string" &&
                                val.match(ref) ? ret_true:ret_false;
                    }
                    return ret_false;
                };
            }
        }

        return function (elt) { return true; };
    }

    test_gfilter2func = function() {
        var elt = {labels: ["Dns"], data: {a: 1, b: "abba"}};
        var cases = {
            "#Dns": true,
            "!#Dns": false,
            "@Dns": false,
            "!@Dns": true,
            "@b": true,
            "@c": false,
            "@a": true,
            "@a == 1": true,
            "@a == 2": false,
            "@a != 1": false,
            "@a < 1": false,
            "@a <= 1": true,
            "@b == abba": true,
            "@b =~ ab?.[ac]": true,
            "@a == 1 && @b == abba": true,
            "@a == 1 && @b != abba": false,
        };

        for (caze in cases) {
            if (gfilter2func(caze)(elt) != cases[caze]) {
                console.log("Error: " + caze);
                return false;
            }
        }
        return true;
    };
//};
