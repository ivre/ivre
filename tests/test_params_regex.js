// Test: backslash characters are preserved in regex filter input
// Tests the parse_params fix in web/static/ivre/params.js

function parse_params_curtoken(query) {
    var state = 0;
    var curtoken = "";
    var curchar;
    for (var i = 0; i < query.length; i++) {
        curchar = query[i];
        switch (state) {
            case 0:
                switch (curchar) {
                    case " ": break;
                    case "\\":
                        state = 3;
                        curtoken += curchar;
                        break;
                    default:
                        curtoken = curchar;
                        state = 1;
                }
                break;
            case 1:
                switch (curchar) {
                    case " ": state = 0; break;
                    case "\\":
                        state = 3;
                        curtoken += curchar;
                        break;
                    default:
                        curtoken += curchar;
                }
                break;
            case 3:
                curtoken += curchar;
                state = 1;
                break;
        }
    }
    return curtoken;
}

var passed = 0;
var failed = 0;

function assert(description, actual, expected) {
    if (actual === expected) {
        console.log("PASS: " + description);
        passed++;
    } else {
        console.log("FAIL: " + description);
        console.log("  Expected: " + expected);
        console.log("  Actual:   " + actual);
        failed++;
    }
}

assert("backslash preserved in regex filter",
    parse_params_curtoken("\\.google\\."), "\\.google\\.");

assert("normal filter without backslash works",
    parse_params_curtoken("google"), "google");

assert("multiple backslashes preserved",
    parse_params_curtoken("\\d+\\.\\d+"), "\\d+\\.\\d+");

console.log("\n" + passed + " passed, " + failed + " failed");
if (failed > 0) process.exit(1);