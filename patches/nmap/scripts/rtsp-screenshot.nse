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

Get screenshots from an RTSP server. This script requires `ffmpeg` to
be installed in $PATH and a modified version of `rtsp-url-brute.nse`,
see `patches/rtsp-url-brute.patch`.

]]

author = {"Pierre Lalet", "Caroline Leman"}
license = "GPLv3"
categories = {"discovery", "safe", "screenshot"}

---
-- @usage
-- nmap -n -p 554 --script rtsp-screenshot,rtsp-url-brute 1.2.3.4
--
-- @args rtsp-screenshot.timeout timeout for the ffmpeg process
--       (default: 120s)
-- 
-- @output
-- PORT    STATE SERVICE REASON
-- 554/tcp open  rtsp    syn-ack
-- | rtsp-screenshot: 
-- |   Saved rtsp://1.2.3.4/mpeg4/1/media.amp to screenshot-1.2.3.4-554-1.jpg
-- |_  Saved rtsp://1.2.3.4/mpeg4/media.amp to screenshot-1.2.3.4-554-2.jpg
-- | rtsp-url-brute: 
-- |   Discovered URLs
-- |     rtsp://1.2.3.4/mpeg4/1/media.amp
-- |_    rtsp://1.2.3.4/mpeg4/media.amp


portrule = shortport.port_or_service(554, "rtsp", "tcp", "open")

dependencies = {"rtsp-url-brute"}

local function count_urls(urls)
  local count = 0
  for _ in pairs(urls) do
    count = count + 1
  end
  return count
end

local function sh_timeout(cmd, timeout)
  return ("%s & CPID=${!}; (sleep %d; kill -9 ${CPID}) & SPID=${!}; wait ${CPID} 2>/dev/null; kill -9 ${SPID} 2>/dev/null"):format(cmd, timeout)
end

action = function(host, port)
  local screenshots = {}
  local fname
  local timeout = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 120

  if host.registry['rtsp_urls'] == nil then
    return
  end
  if host.registry['rtsp_urls'][port.number] == nil then
    return
  end

  if count_urls(host.registry['rtsp_urls'][port.number]) > 3 then
    return "Too many 'valid' URLs"
  end
  
  for counter, url in ipairs(host.registry['rtsp_urls'][port.number]) do
    fname = ("screenshot-%s-%d-%d.jpg"):format(host.ip, port.number, counter)
    os.execute(sh_timeout(
		 ("ffmpeg -rtsp_transport tcp -y -i %s -frames 1 %s 2> /dev/null"):format(
		   url, fname), timeout))
    if os.rename(fname, fname) then
      table.insert(screenshots, ("Saved %s to %s"):format(url, fname))
    end
  end
  return stdnse.format_output(true, screenshots)
end
