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
local stdnse = require "stdnse"

description = [[

Gets a screenshot from a Web service using a simple phantomjs script.

The program phantomjs must me installed somewhere in $PATH.

Adapted from the http-screenshot script by SpiderLabs, that uses
wkhtmltoimage.

The output of the script is similar to the one from SpiderLabs, so
that both can be used with IVRE.

]]

author = "Pierre LALET <pierre@droids-corp.org>"
license = "GPLv3"
categories = {"discovery", "safe", "screenshot"}

---
-- @usage
-- nmap -n -p 80 --script http-screenshot www.google.com
--
-- @args http-screenshot.vhost the vhost to use (default: use the
--       provided hostname or IP address)
-- @args http-screenshot.timeout timeout for the phantomjs script
--       (default: 300s)
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-screenshot: Saved to screenshot-173.194.45.82-www.google.com-80.jpg

portrule = shortport.http

local function get_hostname(host)
  local arg = stdnse.get_script_args(SCRIPT_NAME .. '.vhost')
  return arg or host.targetname or host.ip
end

action = function(host, port)
  local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. '.timeout')) or 300
  local ssl = port.version.service_tunnel == "ssl"
  local port = port.number
  local fname, strport
  local hostname = get_hostname(host)
  if hostname == host.ip then
    fname = ("screenshot-%s-%d.jpg"):format(host.ip, port)
  else
    fname = ("screenshot-%s-%s-%d.jpg"):format(host.ip, hostname, port)
  end
  if (port == 80 and not ssl) or (port == 443 and ssl) then
    strport = ""
  else
    strport = (":%d"):format(port)
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
            document.body.bgColor = 'white';
        });
        page.render(fname, {format: 'jpeg', quality: '90'});
        phantom.exit();
    });
}
capture("%s://%s%s", "%s");
setTimeout(phantom.exit, %d * 1000);
]]):format(ssl and "https" or "http", hostname, strport, fname, timeout))
  tmpfdesc:close()
  os.execute(("phantomjs %s >/dev/null 2>&1"):format(tmpfname))
  os.remove(tmpfname)
  return (os.rename(fname, fname)
	    and ("Saved to %s"):format(fname)
	    or "Failed")
end
