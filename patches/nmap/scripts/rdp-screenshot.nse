-- This file is part of IVRE.
-- Copyright 2011 - 2023 Pierre LALET <pierre.lalet@cea.fr>
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

Gets a screenshot from an RDP server using `scrying`.

`scrying` tool must me installed somewhere in $PATH (see
<https://github.com/nccgroup/scrying>).

]]

author = "Pierre Lalet"
license = "GPLv3"
categories = {"discovery", "safe", "screenshot"}

---
-- @usage
-- nmap -n -p 3389 --script rdp-screenshot 1.2.3.4
--
-- @args rdp-screenshot.timeout timeout for the import process
--       (default: 600s)
--
-- @output
-- PORT     STATE SERVICE
-- 3389/tcp open  ms-wbt-server
-- |_rdp-screenshot: Saved to screenshot-1.2.3.4-3389.png

local function sh_timeout(cmd, timeout)
  return ("%s & CPID=${!}; (sleep %d; kill -9 ${CPID} 2>/dev/null) & SPID=${!}; wait ${CPID} 2>/dev/null; kill -- -${SPID} 2>/dev/null"):format(cmd, timeout)
end


portrule = shortport.port_or_service(3389, "ms-wbt-server")


action = function(host, port)
  local fname = ("%s-%d.png"):format(host.ip, port.number)
  local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. '.timeout')) or 600
  os.execute(sh_timeout(("scrying -t rdp://%s:%d/ --disable-report --output . > /dev/null"):format(
		 host.ip, port.number), timeout))
  if os.rename(("rdp/%s"):format(fname), ("screenshot-%s"):format(fname)) then
    return ("Saved to %s"):format(("screenshot-%s"):format(fname))
  end
end
