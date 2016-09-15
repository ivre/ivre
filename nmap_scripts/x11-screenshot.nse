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

local stdnse = require "stdnse"

description = [[

Gets a screenshot from an X11 server using `convert`.

Imagemagick's `import` tool must me installed somewhere in $PATH.

]]

author = "Pierre Lalet"
license = "GPLv3"
categories = {"discovery", "safe", "screenshot"}

---
-- @usage
-- nmap -n -p 6000 --script x11-screenshot 1.2.3.4
--
-- @args x11-screenshot.timeout timeout for the import process
--       (default: 600s)
--
-- @output
-- PORT     STATE SERVICE
-- 6000/tcp open  X11
-- |_x11-screenshot: Saved to screenshot-1.2.3.4-6000.jpg

local function sh_timeout(cmd, timeout)
  return ("%s & CPID=${!}; (sleep %d; kill -9 ${CPID}) & SPID=${!}; wait ${CPID} 2>/dev/null; kill -9 ${SPID} 2>/dev/null"):format(cmd, timeout)
end


portrule = function(host, port)
  return (port.number >= 6000 and port.number <= 6019)
    or (port.service and port.service:match("^X11"))
end


action = function(host, port)
  local fname = ("screenshot-%s-%d.jpg"):format(host.ip, port.number)
  local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. '.timeout')) or 600
  os.execute(sh_timeout(("import -silent -window root -display %s:%d %s"):format(
		 host.ip, port.number - 6000, fname), timeout))
  if os.rename(fname, fname) then
    return ("Saved to %s"):format(fname)
  end
end
