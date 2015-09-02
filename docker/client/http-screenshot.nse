-- This file is part of IVRE.
-- Copyright 2011 - 2015 Pierre LALET <pierre.lalet@cea.fr>
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
local string = require "string"

description = [[

Gets a screenshot from a Web service using a simple phantomjs script.

The script screenshot.js must me installed somewhere in $PATH, as well
as phantomjs.

Adapted from the http-screenshot script by SpiderLabs, that uses
wkhtmltoimage.

The output of the script is similar to the one from SpiderLabs, so
that both can be used with IVRE.

]]

author = "Pierre LALET <pierre@droids-corp.org>"
license = "GPLv3"
categories = {"discovery", "safe"}

---
-- @usage
-- nmap -n -p 80 --script http-screenshot www.google.com
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- |_http-screenshot: Saved to screenshot-173.194.45.80.jpg

portrule = shortport.http

action = function(host, port)
  local ssl = port.version.service_tunnel == "ssl"
  local port = port.number
  local fname = string.format("screenshot-%s-%d.jpg", host.ip, port)
  if (port == 80 and not ssl) or (port == 443 and ssl) then
    port = ""
  else
    port = string.format(":%d", port)
  end
  os.execute(string.format("screenshot.js %s://%s%s %s >/dev/null 2>&1",
			   ssl and "https" or "http", host.ip, port, fname))
  return (os.rename(fname, fname)
	    and string.format("Saved to %s", fname)
	    or "Failed")
end
