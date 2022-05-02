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
local table = require "table"

description = [[

Gets a banner from a Telnet service using s3270 (from the x3270
package).

The program s3270 must me installed somewhere in $PATH.

]]

author = "Pierre LALET <pierre@droids-corp.org>"
license = "GPLv3"
categories = {"discovery", "safe"}

---
-- @usage
-- nmap -n -p 23 --script mainframe-banner 1.2.3.4
--

portrule = function(host, port)
  return shortport.port_or_service({23, 992},
    {'telnet', 'ssl/telnet', 'telnets'}) and
    port.version.product:match("IBM")
end

action = function(host, port)
  local cmd = ("echo -e 'Connect(%s:%d)\nPrintText(string)\nQuit()' | s3270"):format(
    host.ip, port.number)
  local proc = io.popen(cmd, "r")
  local data = {""}
  proc:read()
  proc:read()
  local ndata = proc:read()
  while ndata do
    if ndata:sub(1, 6) == "data: " then
      data[#data + 1] = ndata:sub(7)
    end
    ndata = proc:read()
  end
  if not proc:close() then
    return "Failed"
  end
  return table.concat(data, "\n")
end
