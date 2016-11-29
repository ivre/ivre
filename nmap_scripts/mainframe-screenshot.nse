-- This file is part of IVRE.
-- Copyright 2011 - 2016 Pierre LALET <pierre.lalet@cea.fr>
--
-- IVRE is free software: you can redistribute it and/or modify it
-- under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- IVRE is distributed in the hope that it will be useful, but WITHOUT
-- ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
-- or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
-- License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with IVRE. If not, see <http://www.gnu.org/licenses/>.

local shortport = require "shortport"

description = [[

Gets a screenshot from a Telnet service using s3270 (from the x3270
package) and a simple phantomjs script.

The programs phantomjs and s3270 must me installed somewhere in $PATH.

Adapted from the 3270_screen_grab script by mainframed, which creates
HTML pages.

]]

author = "Pierre LALET <pierre@droids-corp.org>"
license = "GPLv3"
categories = {"discovery", "safe", "screenshot"}

---
-- @usage
-- nmap -n -p 23 --script mainframe-screenshot 1.2.3.4
--
-- @output
-- PORT   STATE SERVICE
-- 23/tcp open  telnet
-- |_mainframe-screenshot: Saved to screenshot-1.2.3.4-23.jpg

portrule = function(host, port)
  return shortport.port_or_service({23, 992},
    {'telnet', 'ssl/telnet', 'telnets'}) and
    port.version.product:match("IBM")
end

action = function(host, port)
  local fname = ("screenshot-%s-%d."):format(host.ip, port.number)
  local proc = io.popen("s3270 >/dev/null 2>&1", "w")
  proc:write('Connect(' .. host.ip .. ':' .. port.number ..
	       ')\nPrintText(html, ' .. fname .. 'html)\nQuit\n')
  if not proc:close() then
    return "Failed"
  end
  local tmpfname = os.tmpname()
  local tmpfdesc = io.open(tmpfname, "w")
  tmpfdesc:write(([[
var system = require('system');
var webpage = require('webpage');
function capture(url, fname) {
    var page = webpage.create();
    page.open(url, function() {
        page.evaluate(function(){
            var pre = document.getElementsByTagName('pre')[0];
            pre.style.margin = "0px";
            document.body.innerHTML = pre.outerHTML;
            document.body.style.margin = "0px";

        });
        page.render(fname, {format: 'jpeg', quality: '90'});
        phantom.exit();
    });
}
capture("%shtml", "%sjpg");
]]):format(fname, fname))
  tmpfdesc:close()
  os.execute(("phantomjs %s >/dev/null 2>&1"):format(tmpfname))
  os.remove(tmpfname)
  os.remove(("%shtml"):format(fname))
  fname = ("%sjpg"):format(fname)
  return (os.rename(fname, fname)
	    and ("Saved to %s"):format(fname)
	    or "Failed")
end
