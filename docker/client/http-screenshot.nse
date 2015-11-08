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
local stdnse = require "stdnse"

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
-- @args http-screenshot.vhost the vhost to use (default: use the
--       provided hostname or IP address)
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
  local ssl = port.version.service_tunnel == "ssl"
  local port = port.number
  local fname, strport
  local hostname = get_hostname(host)
  if hostname == host.ip then
    fname = string.format("screenshot-%s-%d.jpg", host.ip, port)
  else
    fname = string.format("screenshot-%s-%s-%d.jpg", host.ip, hostname, port)
  end
  if (port == 80 and not ssl) or (port == 443 and ssl) then
    strport = ""
  else
    strport = string.format(":%d", port)
  end
  os.execute(string.format("screenshot.js %s://%s%s %s >/dev/null 2>&1",
			   ssl and "https" or "http", hostname, strport,
			   fname))
  return (os.rename(fname, fname)
	    and string.format("Saved to %s", fname)
	    or "Failed")
end
